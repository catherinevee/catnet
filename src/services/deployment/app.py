"""
Deployment microservice application.

Manages configuration deployments to network devices with various strategies.
"""

import asyncio
import json
import hashlib
from typing import Dict, Any, List, Optional, Set
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from pathlib import Path
import uuid

from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks, status, Query
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from prometheus_fastapi_instrumentator import Instrumentator
import uvicorn
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
import redis.asyncio as redis
import httpx

from src.core.config import get_settings
from src.core.logging import get_logger
from src.security.vault import VaultClient
from src.security.encryption import EncryptionService
from src.db.models import Base, Deployment, DeploymentDevice, DeploymentApproval
from .models import (
    DeploymentRequest,
    DeploymentResponse,
    DeploymentStatus,
    DeploymentStrategy,
    RollbackRequest,
    ApprovalRequest,
    ValidationRequest,
    ValidationResult,
    DeploymentMetrics,
    DeploymentHealth
)
from .strategies import (
    CanaryStrategy,
    RollingStrategy,
    BlueGreenStrategy,
    AllAtOnceStrategy,
    get_strategy
)
from .validators import (
    ConfigValidator,
    PreDeploymentValidator,
    PostDeploymentValidator
)
from .rollback import RollbackManager
from .approval import ApprovalManager
from .monitoring import DeploymentMonitor

logger = get_logger(__name__)
settings = get_settings()


class DeploymentService:
    """
    Main deployment service implementation.

    Handles:
    - Configuration deployment with multiple strategies
    - Pre/post deployment validation
    - Automatic rollback on failure
    - Approval workflows
    - Health monitoring during deployment
    - Deployment metrics and reporting
    """

    def __init__(self):
        self.vault = VaultClient()
        self.encryption = EncryptionService()
        self.redis = None
        self.db_session = None
        self.config_validator = ConfigValidator()
        self.pre_validator = PreDeploymentValidator()
        self.post_validator = PostDeploymentValidator()
        self.rollback_manager = RollbackManager()
        self.approval_manager = ApprovalManager()
        self.monitor = DeploymentMonitor()
        self.active_deployments: Set[str] = set()
        self.deployment_lock = asyncio.Lock()

    async def initialize(self):
        """Initialize service connections."""
        # Initialize Redis
        self.redis = await redis.from_url(
            settings.REDIS_URL,
            encoding="utf-8",
            decode_responses=True,
            ssl_cert_reqs="required" if settings.REDIS_SSL else None,
        )

        # Initialize database
        engine = create_async_engine(
            settings.DATABASE_URL,
            pool_size=20,
            max_overflow=0,
            pool_pre_ping=True,
            echo=False,
        )
        async_session = sessionmaker(
            engine, class_=AsyncSession, expire_on_commit=False
        )
        self.db_session = async_session

        # Initialize components
        await self.rollback_manager.initialize()
        await self.approval_manager.initialize()
        await self.monitor.initialize()

        logger.info("Deployment service initialized successfully")

    async def create_deployment(
        self,
        request: DeploymentRequest,
        user_id: str,
        dry_run: bool = False
    ) -> Deployment:
        """
        Create new deployment.

        Args:
            request: Deployment request
            user_id: User creating deployment
            dry_run: Perform dry run only

        Returns:
            Created deployment
        """
        try:
            # Generate deployment ID
            deployment_id = str(uuid.uuid4())

            # Validate configuration
            validation_result = await self.config_validator.validate(
                request.config,
                request.config_type
            )

            if not validation_result.valid:
                raise ValueError(f"Configuration validation failed: {validation_result.errors}")

            # Check for secrets
            if await self._contains_secrets(request.config):
                raise ValueError("Configuration contains secrets")

            # Hash configuration for integrity
            config_hash = hashlib.sha256(
                json.dumps(request.config, sort_keys=True).encode()
            ).hexdigest()

            # Encrypt configuration
            encrypted_config = await self.encryption.encrypt(
                json.dumps(request.config)
            )

            # Get target devices
            target_devices = await self._get_target_devices(request.target)

            if not target_devices:
                raise ValueError("No target devices found")

            # Create deployment record
            async with self.db_session() as session:
                deployment = Deployment(
                    id=deployment_id,
                    created_by=user_id,
                    config=request.config,
                    config_encrypted=encrypted_config,
                    config_hash=config_hash,
                    strategy=request.strategy.value,
                    target_devices=target_devices,
                    requires_approval=request.requires_approval,
                    approval_count=request.approval_count,
                    dry_run=dry_run,
                    scheduled_at=request.scheduled_at,
                    timeout_seconds=request.timeout_seconds,
                    max_parallel=request.max_parallel,
                    rollback_on_failure=request.rollback_on_failure,
                    status=DeploymentStatus.PENDING.value,
                    created_at=datetime.utcnow()
                )

                session.add(deployment)

                # Add device records
                for device_id in target_devices:
                    device_record = DeploymentDevice(
                        deployment_id=deployment_id,
                        device_id=device_id,
                        status="pending",
                        created_at=datetime.utcnow()
                    )
                    session.add(device_record)

                await session.commit()

            # Store in cache
            await self.redis.setex(
                f"deployment:{deployment_id}",
                3600,  # 1 hour TTL
                json.dumps({
                    "id": deployment_id,
                    "status": DeploymentStatus.PENDING.value,
                    "strategy": request.strategy.value,
                    "devices": target_devices,
                    "created_at": datetime.utcnow().isoformat()
                })
            )

            # Log deployment creation
            logger.info(f"Deployment created: {deployment_id} by user {user_id}")

            # If requires approval, notify approvers
            if request.requires_approval:
                await self.approval_manager.request_approval(
                    deployment_id,
                    request.approval_count
                )

            return deployment

        except Exception as e:
            logger.error(f"Failed to create deployment: {e}")
            raise

    async def execute_deployment(
        self,
        deployment_id: str,
        force: bool = False
    ) -> DeploymentResponse:
        """
        Execute deployment.

        Args:
            deployment_id: Deployment ID
            force: Force execution even if checks fail

        Returns:
            Deployment response
        """
        try:
            # Check if deployment is already running
            async with self.deployment_lock:
                if deployment_id in self.active_deployments:
                    raise ValueError("Deployment already in progress")
                self.active_deployments.add(deployment_id)

            try:
                # Get deployment
                async with self.db_session() as session:
                    result = await session.execute(
                        "SELECT * FROM deployments WHERE id = :id",
                        {"id": deployment_id}
                    )
                    deployment = result.fetchone()

                    if not deployment:
                        raise ValueError(f"Deployment not found: {deployment_id}")

                    # Check status
                    if deployment.status not in [
                        DeploymentStatus.PENDING.value,
                        DeploymentStatus.APPROVED.value
                    ]:
                        raise ValueError(f"Invalid deployment status: {deployment.status}")

                    # Check approval if required
                    if deployment.requires_approval and not force:
                        if deployment.status != DeploymentStatus.APPROVED.value:
                            approved = await self.approval_manager.check_approval(
                                deployment_id,
                                deployment.approval_count
                            )
                            if not approved:
                                raise ValueError("Deployment requires approval")

                    # Update status to running
                    await session.execute(
                        """
                        UPDATE deployments
                        SET status = :status, started_at = :now
                        WHERE id = :id
                        """,
                        {
                            "status": DeploymentStatus.IN_PROGRESS.value,
                            "now": datetime.utcnow(),
                            "id": deployment_id
                        }
                    )
                    await session.commit()

                # Pre-deployment validation
                if not force:
                    pre_validation = await self.pre_validator.validate(
                        deployment.config,
                        deployment.target_devices
                    )

                    if not pre_validation.passed:
                        await self._fail_deployment(
                            deployment_id,
                            f"Pre-deployment validation failed: {pre_validation.errors}"
                        )
                        raise ValueError("Pre-deployment validation failed")

                # Get deployment strategy
                strategy = get_strategy(deployment.strategy)

                # Start monitoring
                monitor_task = asyncio.create_task(
                    self.monitor.monitor_deployment(deployment_id)
                )

                # Execute deployment with strategy
                result = await strategy.execute(
                    deployment_id=deployment_id,
                    config=deployment.config,
                    devices=deployment.target_devices,
                    dry_run=deployment.dry_run,
                    max_parallel=deployment.max_parallel,
                    timeout=deployment.timeout_seconds
                )

                # Stop monitoring
                monitor_task.cancel()

                # Post-deployment validation
                post_validation = await self.post_validator.validate(
                    deployment.config,
                    result.successful_devices
                )

                # Check if rollback needed
                if not result.success and deployment.rollback_on_failure:
                    logger.warning(f"Deployment {deployment_id} failed, initiating rollback")
                    rollback_result = await self.rollback_manager.rollback(
                        deployment_id,
                        result.failed_devices
                    )
                    result.rollback_performed = True
                    result.rollback_result = rollback_result

                # Update deployment status
                final_status = (
                    DeploymentStatus.COMPLETED.value if result.success
                    else DeploymentStatus.FAILED.value
                )

                async with self.db_session() as session:
                    await session.execute(
                        """
                        UPDATE deployments
                        SET status = :status, completed_at = :now,
                            successful_devices = :successful,
                            failed_devices = :failed,
                            result = :result
                        WHERE id = :id
                        """,
                        {
                            "status": final_status,
                            "now": datetime.utcnow(),
                            "successful": result.successful_devices,
                            "failed": result.failed_devices,
                            "result": json.dumps(result.dict()),
                            "id": deployment_id
                        }
                    )
                    await session.commit()

                # Generate metrics
                metrics = await self._generate_metrics(deployment_id, result)

                return DeploymentResponse(
                    deployment_id=deployment_id,
                    status=final_status,
                    result=result,
                    metrics=metrics,
                    validation=post_validation
                )

            finally:
                # Remove from active deployments
                self.active_deployments.discard(deployment_id)

        except Exception as e:
            logger.error(f"Deployment execution failed: {e}")
            await self._fail_deployment(deployment_id, str(e))
            raise

    async def get_deployment_status(
        self,
        deployment_id: str
    ) -> Dict[str, Any]:
        """
        Get deployment status.

        Args:
            deployment_id: Deployment ID

        Returns:
            Deployment status information
        """
        try:
            # Check cache first
            cached = await self.redis.get(f"deployment:{deployment_id}")
            if cached:
                return json.loads(cached)

            # Get from database
            async with self.db_session() as session:
                result = await session.execute(
                    """
                    SELECT id, status, strategy, started_at, completed_at,
                           successful_devices, failed_devices, result
                    FROM deployments
                    WHERE id = :id
                    """,
                    {"id": deployment_id}
                )
                deployment = result.fetchone()

                if not deployment:
                    raise ValueError(f"Deployment not found: {deployment_id}")

                # Get device statuses
                devices_result = await session.execute(
                    """
                    SELECT device_id, status, started_at, completed_at, error
                    FROM deployment_devices
                    WHERE deployment_id = :deployment_id
                    """,
                    {"deployment_id": deployment_id}
                )
                devices = devices_result.fetchall()

                status = {
                    "id": deployment.id,
                    "status": deployment.status,
                    "strategy": deployment.strategy,
                    "started_at": deployment.started_at.isoformat() if deployment.started_at else None,
                    "completed_at": deployment.completed_at.isoformat() if deployment.completed_at else None,
                    "devices": {
                        "total": len(devices),
                        "successful": len(deployment.successful_devices or []),
                        "failed": len(deployment.failed_devices or []),
                        "pending": sum(1 for d in devices if d.status == "pending"),
                        "in_progress": sum(1 for d in devices if d.status == "in_progress")
                    },
                    "device_details": [
                        {
                            "device_id": d.device_id,
                            "status": d.status,
                            "started_at": d.started_at.isoformat() if d.started_at else None,
                            "completed_at": d.completed_at.isoformat() if d.completed_at else None,
                            "error": d.error
                        }
                        for d in devices
                    ]
                }

                # Cache status
                await self.redis.setex(
                    f"deployment:{deployment_id}",
                    60,  # 1 minute TTL
                    json.dumps(status, default=str)
                )

                return status

        except Exception as e:
            logger.error(f"Failed to get deployment status: {e}")
            raise

    async def approve_deployment(
        self,
        deployment_id: str,
        user_id: str,
        comment: Optional[str] = None
    ) -> bool:
        """
        Approve deployment.

        Args:
            deployment_id: Deployment ID
            user_id: Approving user ID
            comment: Optional approval comment

        Returns:
            True if approved
        """
        try:
            # Record approval
            async with self.db_session() as session:
                approval = DeploymentApproval(
                    deployment_id=deployment_id,
                    user_id=user_id,
                    action="approve",
                    comment=comment,
                    created_at=datetime.utcnow()
                )
                session.add(approval)

                # Check if enough approvals
                result = await session.execute(
                    """
                    SELECT COUNT(DISTINCT user_id) as approval_count
                    FROM deployment_approvals
                    WHERE deployment_id = :id AND action = 'approve'
                    """,
                    {"id": deployment_id}
                )
                approval_data = result.fetchone()

                # Get required approvals
                dep_result = await session.execute(
                    "SELECT approval_count FROM deployments WHERE id = :id",
                    {"id": deployment_id}
                )
                deployment = dep_result.fetchone()

                if approval_data.approval_count >= deployment.approval_count:
                    # Update deployment status
                    await session.execute(
                        """
                        UPDATE deployments
                        SET status = :status, approved_at = :now
                        WHERE id = :id
                        """,
                        {
                            "status": DeploymentStatus.APPROVED.value,
                            "now": datetime.utcnow(),
                            "id": deployment_id
                        }
                    )

                await session.commit()

                return approval_data.approval_count >= deployment.approval_count

        except Exception as e:
            logger.error(f"Failed to approve deployment: {e}")
            raise

    async def rollback_deployment(
        self,
        deployment_id: str,
        user_id: str,
        reason: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Rollback deployment.

        Args:
            deployment_id: Deployment ID
            user_id: User initiating rollback
            reason: Rollback reason

        Returns:
            Rollback result
        """
        try:
            # Get deployment
            async with self.db_session() as session:
                result = await session.execute(
                    "SELECT * FROM deployments WHERE id = :id",
                    {"id": deployment_id}
                )
                deployment = result.fetchone()

                if not deployment:
                    raise ValueError(f"Deployment not found: {deployment_id}")

                # Check if rollback is possible
                if deployment.status not in [
                    DeploymentStatus.COMPLETED.value,
                    DeploymentStatus.FAILED.value
                ]:
                    raise ValueError(f"Cannot rollback deployment in status: {deployment.status}")

            # Perform rollback
            result = await self.rollback_manager.rollback(
                deployment_id,
                deployment.successful_devices or []
            )

            # Update deployment
            async with self.db_session() as session:
                await session.execute(
                    """
                    UPDATE deployments
                    SET rollback_performed = true,
                        rollback_at = :now,
                        rollback_by = :user_id,
                        rollback_reason = :reason,
                        rollback_result = :result
                    WHERE id = :id
                    """,
                    {
                        "now": datetime.utcnow(),
                        "user_id": user_id,
                        "reason": reason,
                        "result": json.dumps(result),
                        "id": deployment_id
                    }
                )
                await session.commit()

            logger.info(f"Deployment {deployment_id} rolled back by {user_id}")

            return result

        except Exception as e:
            logger.error(f"Failed to rollback deployment: {e}")
            raise

    async def cancel_deployment(
        self,
        deployment_id: str,
        user_id: str,
        reason: Optional[str] = None
    ) -> bool:
        """
        Cancel running deployment.

        Args:
            deployment_id: Deployment ID
            user_id: User cancelling deployment
            reason: Cancellation reason

        Returns:
            True if cancelled
        """
        try:
            async with self.db_session() as session:
                # Check current status
                result = await session.execute(
                    "SELECT status FROM deployments WHERE id = :id",
                    {"id": deployment_id}
                )
                deployment = result.fetchone()

                if not deployment:
                    raise ValueError(f"Deployment not found: {deployment_id}")

                if deployment.status != DeploymentStatus.IN_PROGRESS.value:
                    raise ValueError(f"Cannot cancel deployment in status: {deployment.status}")

                # Update status
                await session.execute(
                    """
                    UPDATE deployments
                    SET status = :status, cancelled_at = :now,
                        cancelled_by = :user_id, cancel_reason = :reason
                    WHERE id = :id
                    """,
                    {
                        "status": DeploymentStatus.CANCELLED.value,
                        "now": datetime.utcnow(),
                        "user_id": user_id,
                        "reason": reason,
                        "id": deployment_id
                    }
                )
                await session.commit()

            # Send cancellation signal
            await self.redis.set(f"deployment:cancel:{deployment_id}", "1", ex=60)

            logger.info(f"Deployment {deployment_id} cancelled by {user_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to cancel deployment: {e}")
            raise

    async def get_deployment_health(
        self,
        deployment_id: str
    ) -> DeploymentHealth:
        """
        Get deployment health metrics.

        Args:
            deployment_id: Deployment ID

        Returns:
            Deployment health information
        """
        try:
            health = await self.monitor.get_health(deployment_id)
            return health

        except Exception as e:
            logger.error(f"Failed to get deployment health: {e}")
            raise

    async def validate_configuration(
        self,
        config: Dict[str, Any],
        config_type: str = "yaml"
    ) -> ValidationResult:
        """
        Validate configuration before deployment.

        Args:
            config: Configuration to validate
            config_type: Configuration type

        Returns:
            Validation result
        """
        try:
            # Validate configuration
            result = await self.config_validator.validate(config, config_type)

            # Check for device compatibility
            compatibility = await self._check_device_compatibility(config)
            result.compatibility = compatibility

            # Check for compliance
            compliance = await self._check_compliance(config)
            result.compliance = compliance

            return result

        except Exception as e:
            logger.error(f"Configuration validation failed: {e}")
            raise

    async def _get_target_devices(
        self,
        target: Dict[str, Any]
    ) -> List[str]:
        """Get target devices based on criteria."""
        devices = []

        # Get devices from device service
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"http://device-service:8084/devices/query",
                json=target,
                headers={"Authorization": f"Bearer {await self._get_service_token()}"}
            )

            if response.status_code == 200:
                result = response.json()
                devices = [d['id'] for d in result['devices']]

        return devices

    async def _contains_secrets(self, config: Any) -> bool:
        """Check if configuration contains secrets."""
        import re

        secret_patterns = [
            r'password\s*[:=]',
            r'secret\s*[:=]',
            r'api[_-]?key\s*[:=]',
            r'token\s*[:=]',
            r'-----BEGIN.*PRIVATE KEY-----'
        ]

        config_str = json.dumps(config) if isinstance(config, dict) else str(config)

        for pattern in secret_patterns:
            if re.search(pattern, config_str, re.IGNORECASE):
                return True

        return False

    async def _fail_deployment(
        self,
        deployment_id: str,
        error: str
    ):
        """Mark deployment as failed."""
        try:
            async with self.db_session() as session:
                await session.execute(
                    """
                    UPDATE deployments
                    SET status = :status, completed_at = :now, error = :error
                    WHERE id = :id
                    """,
                    {
                        "status": DeploymentStatus.FAILED.value,
                        "now": datetime.utcnow(),
                        "error": error,
                        "id": deployment_id
                    }
                )
                await session.commit()

        except Exception as e:
            logger.error(f"Failed to update deployment status: {e}")

    async def _generate_metrics(
        self,
        deployment_id: str,
        result: Any
    ) -> DeploymentMetrics:
        """Generate deployment metrics."""
        metrics = DeploymentMetrics(
            deployment_id=deployment_id,
            total_devices=len(result.successful_devices) + len(result.failed_devices),
            successful_devices=len(result.successful_devices),
            failed_devices=len(result.failed_devices),
            success_rate=(
                len(result.successful_devices) /
                (len(result.successful_devices) + len(result.failed_devices))
                if (result.successful_devices or result.failed_devices) else 0
            ),
            avg_device_time=result.avg_device_time,
            total_time=result.total_time
        )

        # Store metrics
        await self.redis.setex(
            f"deployment:metrics:{deployment_id}",
            86400,  # 24 hours
            json.dumps(metrics.dict())
        )

        return metrics

    async def _check_device_compatibility(
        self,
        config: Dict[str, Any]
    ) -> Dict[str, bool]:
        """Check device compatibility."""
        # Placeholder implementation
        return {
            "cisco_ios": True,
            "cisco_nxos": True,
            "juniper_junos": True
        }

    async def _check_compliance(
        self,
        config: Dict[str, Any]
    ) -> Dict[str, bool]:
        """Check compliance requirements."""
        return {
            "encryption_enabled": config.get("encryption") is not None,
            "audit_logging": config.get("audit_log", False),
            "access_control": config.get("acl") is not None,
            "secure_protocols": config.get("protocol", "").lower() not in ["telnet", "http"]
        }

    async def _get_service_token(self) -> str:
        """Get service-to-service authentication token."""
        token = await self.vault.get_secret("service/tokens/deployment")
        return token['token'] if token else ""

    async def shutdown(self):
        """Shutdown service connections."""
        if self.redis:
            await self.redis.close()
        await self.monitor.shutdown()
        logger.info("Deployment service shutdown complete")


deployment_service = DeploymentService()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    await deployment_service.initialize()
    yield
    await deployment_service.shutdown()


def create_app() -> FastAPI:
    """Create FastAPI application."""
    app = FastAPI(
        title="CatNet Deployment Service",
        description="Configuration deployment and management service",
        version="1.0.0",
        lifespan=lifespan,
        docs_url="/deploy/docs",
        redoc_url="/deploy/redoc",
        openapi_url="/deploy/openapi.json",
    )

    # Add middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.ALLOWED_ORIGINS.split(","),
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Add Prometheus metrics
    Instrumentator().instrument(app).expose(app, endpoint="/deploy/metrics")

    # Add routes
    @app.post("/deploy/create", response_model=DeploymentResponse)
    async def create_deployment(
        request: DeploymentRequest,
        user_id: str = Query(...),
        dry_run: bool = Query(False)
    ):
        """Create new deployment."""
        deployment = await deployment_service.create_deployment(
            request, user_id, dry_run
        )

        return DeploymentResponse(
            deployment_id=deployment.id,
            status=deployment.status,
            strategy=deployment.strategy,
            target_devices=deployment.target_devices,
            requires_approval=deployment.requires_approval,
            created_at=deployment.created_at
        )

    @app.post("/deploy/{deployment_id}/execute")
    async def execute_deployment(
        deployment_id: str,
        force: bool = Query(False),
        background_tasks: BackgroundTasks = BackgroundTasks()
    ):
        """Execute deployment."""
        # Execute in background
        background_tasks.add_task(
            deployment_service.execute_deployment,
            deployment_id,
            force
        )

        return {
            "status": "execution_started",
            "deployment_id": deployment_id
        }

    @app.get("/deploy/{deployment_id}/status")
    async def get_deployment_status(deployment_id: str):
        """Get deployment status."""
        status = await deployment_service.get_deployment_status(deployment_id)
        return status

    @app.post("/deploy/{deployment_id}/approve")
    async def approve_deployment(
        deployment_id: str,
        request: ApprovalRequest,
        user_id: str = Query(...)
    ):
        """Approve deployment."""
        approved = await deployment_service.approve_deployment(
            deployment_id,
            user_id,
            request.comment
        )

        return {
            "deployment_id": deployment_id,
            "approved": approved
        }

    @app.post("/deploy/{deployment_id}/rollback")
    async def rollback_deployment(
        deployment_id: str,
        request: RollbackRequest,
        user_id: str = Query(...)
    ):
        """Rollback deployment."""
        result = await deployment_service.rollback_deployment(
            deployment_id,
            user_id,
            request.reason
        )

        return result

    @app.post("/deploy/{deployment_id}/cancel")
    async def cancel_deployment(
        deployment_id: str,
        user_id: str = Query(...),
        reason: Optional[str] = Query(None)
    ):
        """Cancel running deployment."""
        cancelled = await deployment_service.cancel_deployment(
            deployment_id,
            user_id,
            reason
        )

        return {
            "deployment_id": deployment_id,
            "cancelled": cancelled
        }

    @app.get("/deploy/{deployment_id}/health")
    async def get_deployment_health(deployment_id: str):
        """Get deployment health metrics."""
        health = await deployment_service.get_deployment_health(deployment_id)
        return health

    @app.post("/deploy/validate", response_model=ValidationResult)
    async def validate_configuration(request: ValidationRequest):
        """Validate configuration."""
        result = await deployment_service.validate_configuration(
            request.config,
            request.config_type
        )
        return result

    @app.get("/deploy/health")
    async def health():
        """Health check endpoint."""
        return {
            "status": "healthy",
            "service": "deployment",
            "timestamp": datetime.utcnow().isoformat()
        }

    return app


if __name__ == "__main__":
    app = create_app()
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8083,
        ssl_keyfile=settings.SSL_KEY_PATH,
        ssl_certfile=settings.SSL_CERT_PATH,
        log_config={
            "version": 1,
            "disable_existing_loggers": False,
            "formatters": {
                "default": {
                    "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                },
            },
            "handlers": {
                "default": {
                    "formatter": "default",
                    "class": "logging.StreamHandler",
                    "stream": "ext://sys.stdout",
                },
            },
            "root": {
                "level": "INFO",
                "handlers": ["default"],
            },
        }
    )
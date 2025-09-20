"""
GitOps Workflow Orchestrator for CatNet

Orchestrates the complete GitOps workflow:
- Repository synchronization
- Configuration validation
- Secret scanning
- Deployment automation
"""

import asyncio
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import json

from .git_manager import GitManager
from .webhook_processor import WebhookProcessor, WebhookEvent, EventType
from .config_validator import ConfigValidator, ValidationResult
from .secret_scanner import SecretScanner, SecretScanResult



class DeploymentStrategy(Enum):
    """Deployment strategies"""

    CANARY = "canary"
    ROLLING = "rolling"
    BLUE_GREEN = "blue_green"
    DIRECT = "direct"



class WorkflowState(Enum):
    """Workflow execution states"""

    PENDING = "pending"
    VALIDATING = "validating"
    SCANNING = "scanning"
    APPROVED = "approved"
    DEPLOYING = "deploying"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


@dataclass

class WorkflowConfig:
    """GitOps workflow configuration"""

    auto_deploy: bool = False
    require_approval: bool = True
    validation_required: bool = True
    secret_scanning: bool = True
    deployment_strategy: DeploymentStrategy = DeploymentStrategy.CANARY
    canary_percentage: int = 10
    canary_wait_minutes: int = 5
    rollback_on_failure: bool = True
    notification_webhook: Optional[str] = None


@dataclass

class WorkflowExecution:
    """Represents a workflow execution"""

    id: str
    repository_id: str
    trigger_event: Optional[WebhookEvent]
    state: WorkflowState
    started_at: datetime
    completed_at: Optional[datetime]
    validation_results: List[ValidationResult] = field(default_factory=list)
    scan_results: List[SecretScanResult] = field(default_factory=list)
    deployment_id: Optional[str] = None
    errors: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)



class GitOpsWorkflow:
    """
    Orchestrates GitOps workflows
    """

    def __init__(
        self,
        git_manager: GitManager,
        webhook_processor: WebhookProcessor,
        config_validator: ConfigValidator,
        secret_scanner: SecretScanner,
    ):
        """
        Initialize GitOps workflow

        Args:
            git_manager: Git repository manager
            webhook_processor: Webhook processor
            config_validator: Configuration validator
            secret_scanner: Secret scanner
        """
        self.git_manager = git_manager
        self.webhook_processor = webhook_processor
        self.config_validator = config_validator
        self.secret_scanner = secret_scanner

        self.workflow_configs: Dict[str, WorkflowConfig] = {}
        self.executions: Dict[str, WorkflowExecution] = {}
        self.deployment_queue: List[WorkflowExecution] = []

        # Register webhook handlers
        self._register_webhook_handlers()

    def configure_repository(
        self,
        repository_url: str,
        branch: str = "main",
        webhook_secret: str = None,
        workflow_config: WorkflowConfig = None,
    ) -> str:
        """
        Configure repository for GitOps

        Args:
            repository_url: Repository URL
            branch: Branch to track
            webhook_secret: Webhook secret for verification
            workflow_config: Workflow configuration

        Returns:
            Repository ID
        """
        # Add repository to git manager
        repo = self.git_manager.add_repository(repository_url, branch)

        # Register webhook secret if provided
        if webhook_secret:
            self.webhook_processor.register_webhook_secret(
                repository_url, webhook_secret
            )

        # Store workflow configuration
        workflow_config = workflow_config or WorkflowConfig()
        self.workflow_configs[repo.id] = workflow_config

        # Clone repository
        success, error = self.git_manager.clone_repository(repo.id)
        if not success:
            raise Exception(f"Failed to clone repository: {error}")

        return repo.id

    async def process_webhook(
        self, headers: Dict[str, str], body: str
    ) -> Tuple[bool, Optional[WorkflowExecution]]:
        """
        Process incoming webhook

        Args:
            headers: HTTP headers
            body: Request body

        Returns:
            Tuple of (success, WorkflowExecution)
        """
        # Process webhook
        success, event = self.webhook_processor.process_webhook(headers, body)

        if not success or not event:
            return False, None

        # Find repository
        repo_id = self._find_repository_id(event.repository)
        if not repo_id:
            return False, None

        # Create workflow execution
        execution = await self._create_execution(repo_id, event)

        # Start workflow
        asyncio.create_task(self._execute_workflow(execution))

        return True, execution

    async def execute_manual_sync(
        self, repository_id: str, force: bool = False
    ) -> WorkflowExecution:
        """
        Execute manual repository sync

        Args:
            repository_id: Repository ID
            force: Force sync even with conflicts

        Returns:
            WorkflowExecution object
        """
        # Create execution
        execution = await self._create_execution(repository_id, None)

        # Pull latest changes
                success, changes = self.git_manager.pull_repository(
            repository_id,
            force
        )

        if not success:
            execution.state = WorkflowState.FAILED
            execution.errors.append(changes.get("error", "Pull failed"))
            return execution

        # Execute workflow
        await self._execute_workflow(execution)

        return execution

    async def _execute_workflow(self, execution: WorkflowExecution) -> None:
        """
        Execute GitOps workflow

        Args:
            execution: Workflow execution object
        """
        try:
            config = self.workflow_configs.get(
                execution.repository_id, WorkflowConfig()
            )

            # Step 1: Pull latest changes
            if execution.trigger_event:
                success, changes = self.git_manager.pull_repository(
                    execution.repository_id
                )
                if not success:
                    await self._fail_workflow(
                                                execution, f"Failed to pull changes: {changes.get(
                            'error'
                        )}"
                    )
                    return

            # Step 2: Get configuration files
            config_files = self.git_manager.list_files(
                execution.repository_id, pattern="*.yml"
            )
            config_files.extend(
                                self.git_manager.list_files(
                    execution.repository_id,
                    pattern="*.yaml"
                )
            )

            if not config_files:
                                await self._fail_workflow(
                    execution,
                    "No configuration files found"
                )
                return

            # Step 3: Validate configurations
            if config.validation_required:
                execution.state = WorkflowState.VALIDATING
                await self._validate_configurations(execution, config_files)

                # Check validation results
                has_critical = any(not r.is_valid for r in \
                    execution.validation_results)
                if has_critical:
                    await self._fail_workflow(
                        execution, "Configuration validation failed"
                    )
                    return

            # Step 4: Scan for secrets
            if config.secret_scanning:
                execution.state = WorkflowState.SCANNING
                await self._scan_for_secrets(execution, config_files)

                # Check scan results
                has_secrets = any(r.has_secrets for r in \
                    execution.scan_results)
                if has_secrets:
                    await self._quarantine_secrets(execution)
                    await self._fail_workflow(
                        execution, "Secrets detected in configuration"
                    )
                    return

            # Step 5: Create deployment
            if config.auto_deploy or not config.require_approval:
                execution.state = WorkflowState.DEPLOYING
                deployment_id = await self._create_deployment(
                    execution, config_files, config
                )
                execution.deployment_id = deployment_id

                # Execute deployment
                await self._execute_deployment(execution, config)

            else:
                execution.state = WorkflowState.APPROVED
                # Queue for manual approval
                self.deployment_queue.append(execution)
                await self._notify_approval_required(execution)

            # Mark as completed
            execution.state = WorkflowState.COMPLETED
            execution.completed_at = datetime.utcnow()

            # Send notifications
            if config.notification_webhook:
                await self._send_notification(execution, config)

        except Exception as e:
            await self._fail_workflow(execution, str(e))

    async def _validate_configurations(
        self, execution: WorkflowExecution, config_files: List[str]
    ) -> None:
        """
        Validate configuration files

        Args:
            execution: Workflow execution
            config_files: List of configuration files
        """
        for file_path in config_files:
            content = self.git_manager.get_file_content(
                execution.repository_id, file_path
            )

            if content:
                # Detect vendor from file
                vendor = self._detect_vendor(content)

                # Validate configuration
                result = self.config_validator.validate_configuration(
                    content, vendor, file_path
                )

                execution.validation_results.append(result)

    async def _scan_for_secrets(
        self, execution: WorkflowExecution, config_files: List[str]
    ) -> None:
        """
        Scan configuration files for secrets

        Args:
            execution: Workflow execution
            config_files: List of configuration files
        """
        for file_path in config_files:
            content = self.git_manager.get_file_content(
                execution.repository_id, file_path
            )

            if content:
                result = self.secret_scanner.scan_file(file_path, content)
                if result.has_secrets:
                    execution.scan_results.append(result)

    async def _create_deployment(
        self,
        execution: WorkflowExecution,
        config_files: List[str],
        config: WorkflowConfig,
    ) -> str:
        """
        Create deployment

        Args:
            execution: Workflow execution
            config_files: Configuration files
            config: Workflow configuration

        Returns:
            Deployment ID
        """
        # This would integrate with the deployment service
        deployment_id = f"dep-{execution.id}"

        # Store deployment metadata
        execution.metadata["deployment"] = {
            "id": deployment_id,
            "strategy": config.deployment_strategy.value,
            "files": config_files,
            "created_at": datetime.utcnow().isoformat(),
        }

        return deployment_id

    async def _execute_deployment(
        self, execution: WorkflowExecution, config: WorkflowConfig
    ) -> None:
        """
        Execute deployment based on strategy

        Args:
            execution: Workflow execution
            config: Workflow configuration
        """
        if config.deployment_strategy == DeploymentStrategy.CANARY:
            await self._canary_deployment(execution, config)
        elif config.deployment_strategy == DeploymentStrategy.ROLLING:
            await self._rolling_deployment(execution, config)
        elif config.deployment_strategy == DeploymentStrategy.BLUE_GREEN:
            await self._blue_green_deployment(execution, config)
        else:
            await self._direct_deployment(execution, config)

    async def _canary_deployment(
        self, execution: WorkflowExecution, config: WorkflowConfig
    ) -> None:
        """
        Execute canary deployment

        Args:
            execution: Workflow execution
            config: Workflow configuration
        """
        # This would integrate with the deployment service
        # For now, simulate canary deployment
        stages = [
            {
                "percentage": config.canary_percentage,
                "wait": config.canary_wait_minutes,
            },
            {"percentage": 50, "wait": 5},
            {"percentage": 100, "wait": 0},
        ]

        for stage in stages:
            execution.metadata["canary_stage"] = stage
            await asyncio.sleep(stage["wait"] * 60)  # Convert to seconds

            # Check health metrics (simulated)
            if not await self._check_deployment_health(execution):
                if config.rollback_on_failure:
                    await self._rollback_deployment(execution)
                    execution.state = WorkflowState.ROLLED_BACK
                    return

    async def _rolling_deployment(
        self, execution: WorkflowExecution, config: WorkflowConfig
    ) -> None:
        """
        Execute rolling deployment

        Args:
            execution: Workflow execution
            config: Workflow configuration
        """
        # Simulated rolling deployment
        execution.metadata["rolling_progress"] = "100%"

    async def _blue_green_deployment(
        self, execution: WorkflowExecution, config: WorkflowConfig
    ) -> None:
        """
        Execute blue-green deployment

        Args:
            execution: Workflow execution
            config: Workflow configuration
        """
        # Simulated blue-green deployment
        execution.metadata["active_environment"] = "green"

    async def _direct_deployment(
        self, execution: WorkflowExecution, config: WorkflowConfig
    ) -> None:
        """
        Execute direct deployment

        Args:
            execution: Workflow execution
            config: Workflow configuration
        """
        # Simulated direct deployment
        execution.metadata["deployment_status"] = "completed"

        async def _check_deployment_health(
        self,
        execution: WorkflowExecution
    ) -> bool:
        """
        Check deployment health

        Args:
            execution: Workflow execution

        Returns:
            Health status
        """
        # This would check actual deployment health metrics
        return True

    async def _rollback_deployment(self, execution: WorkflowExecution) -> None:
        """
        Rollback deployment

        Args:
            execution: Workflow execution
        """
        execution.metadata["rollback"] = {
            "timestamp": datetime.utcnow().isoformat(),
            "reason": "Health check failed",
        }

    async def _quarantine_secrets(self, execution: WorkflowExecution) -> None:
        """
        Quarantine files with detected secrets

        Args:
            execution: Workflow execution
        """
        for scan_result in execution.scan_results:
            report = self.secret_scanner.quarantine_file(
                scan_result.file_path, scan_result
            )
            execution.metadata["quarantine_reports"] = execution.metadata.get(
                "quarantine_reports", []
            )
            execution.metadata["quarantine_reports"].append(json.loads(report))

        async def _fail_workflow(
        self,
        execution: WorkflowExecution,
        error: str
    ) -> None:
        """
        Mark workflow as failed

        Args:
            execution: Workflow execution
            error: Error message
        """
        execution.state = WorkflowState.FAILED
        execution.errors.append(error)
        execution.completed_at = datetime.utcnow()

        async def _notify_approval_required(
        self,
        execution: WorkflowExecution
    ) -> None:
        """
        Send notification that approval is required

        Args:
            execution: Workflow execution
        """
        # This would send actual notifications
        execution.metadata["approval_requested"] = \
            datetime.utcnow().isoformat()

    async def _send_notification(
        self, execution: WorkflowExecution, config: WorkflowConfig
    ) -> None:
        """
        Send workflow notification

        Args:
            execution: Workflow execution
            config: Workflow configuration
        """
        # This would send actual webhook notification
        if config.notification_webhook:
            # Would make HTTP POST to webhook URL
            execution.metadata["notification_sent"] = \
                datetime.utcnow().isoformat()

    async def _create_execution(
        self, repository_id: str, event: Optional[WebhookEvent]
    ) -> WorkflowExecution:
        """
        Create workflow execution

        Args:
            repository_id: Repository ID
            event: Triggering webhook event

        Returns:
            WorkflowExecution object
        """
        import uuid

        execution = WorkflowExecution(
            id=str(uuid.uuid4())[:12],
            repository_id=repository_id,
            trigger_event=event,
            state=WorkflowState.PENDING,
            started_at=datetime.utcnow(),
            completed_at=None,
        )

        self.executions[execution.id] = execution
        return execution

    def _find_repository_id(self, repository_url: str) -> Optional[str]:
        """
        Find repository ID by URL

        Args:
            repository_url: Repository URL

        Returns:
            Repository ID or None
        """
        for repo_id, repo in self.git_manager.repositories.items():
            if repo.url == repository_url:
                return repo_id
        return None

    def _detect_vendor(self, content: str) -> str:
        """
        Detect vendor from configuration content

        Args:
            content: Configuration content

        Returns:
            Vendor name
        """
        # Simple vendor detection
        if "interface GigabitEthernet" in content or "router ospf" in content:
            return "cisco"
        elif "set interface" in content or "set protocols" in content:
            return "juniper"
        else:
            return "unknown"

    def _register_webhook_handlers(self) -> None:
        """
        Register webhook event handlers
        """

        async def handle_push(event: WebhookEvent):
            # Find repository
            repo_id = self._find_repository_id(event.repository)
            if repo_id:
                # Create and execute workflow
                execution = await self._create_execution(repo_id, event)
                await self._execute_workflow(execution)

        self.webhook_processor.register_handler(EventType.PUSH, handle_push)

        def get_execution_status(
        self,
        execution_id: str
    ) -> Optional[Dict[str, Any]]:
        """
        Get execution status

        Args:
            execution_id: Execution ID

        Returns:
            Status dictionary or None
        """
        execution = self.executions.get(execution_id)
        if not execution:
            return None

        return {
            "id": execution.id,
            "state": execution.state.value,
            "started_at": execution.started_at.isoformat(),
            "completed_at": execution.completed_at.isoformat()
            if execution.completed_at
            else None,
                        "validation_passed": all(
                r.is_valid for r in execution.validation_results
            ),
                        "secrets_detected": any(
                r.has_secrets for r in execution.scan_results
            ),
            "deployment_id": execution.deployment_id,
            "errors": execution.errors,
        }

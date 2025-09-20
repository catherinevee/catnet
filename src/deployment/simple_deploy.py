"""
Simple Deployment Pipeline
Phase 4 Implementation - Wire GitHub → Deploy → Device
Phase 5 Update - Added real device connections
"""

from typing import Dict, List, Optional
from dataclasses import dataclass, field
from datetime import datetime
import json
import uuid
from pathlib import Path
import logging

from ..gitops.simple_github_client import github_client, ConfigFile
from ..devices.device_store import device_store, DeviceInfo
from ..devices.device_connector import device_connector
from .rollback_manager import rollback_manager

# Import metrics if available
try:
    from ..monitoring.simple_metrics import metrics_collector
    METRICS_AVAILABLE = True
except ImportError:
    METRICS_AVAILABLE = False

logger = logging.getLogger(__name__)


@dataclass
class DeploymentTask: """Simple deployment task"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    config_path: str = ""
    device_id: str = ""
    status: str = "pending"  # pending, in_progress, completed, failed
    created_at: datetime = field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None
    deployed_commands: List[str] = field(default_factory=list)


class SimpleDeploymentPipeline:
    """
    Simple deployment pipeline
    Connects GitHub configs to device deployments"""

    def __init__(self):
        """TODO: Add docstring"""
        self.deployments: Dict[str, DeploymentTask] = {}
        self.deployment_log_dir = Path("data/deployments")
        self.deployment_log_dir.mkdir(parents=True, exist_ok=True)

    def create_deployment(
        self,
        config_path: str,
        device_id: str
    ) -> DeploymentTask:
        """Create a new deployment task"""
        # Validate device exists
        device = device_store.get_device(device_id)
        if not device:
            raise ValueError(f"Device {device_id} not found")

        # Validate GitHub is connected
        if not github_client.connected_repo:
            raise ValueError("No GitHub repository connected")

        # Create deployment task
        deployment = DeploymentTask(
            config_path=config_path,
            device_id=device_id
        )

        self.deployments[deployment.id] = deployment
        self._save_deployment(deployment)

        return deployment

        def execute_deployment(
        self,
        deployment_id: str,
        enable_rollback: bool = True
    ) -> DeploymentTask:
        """Execute a deployment task with safety checks and metrics"""
        deployment = self.deployments.get(deployment_id)
        if not deployment:
            raise ValueError(f"Deployment {deployment_id} not found")

        if deployment.status != "pending":
            raise ValueError(f"Deployment {deployment_id} is not pending")

        deployment.status = "in_progress"
        start_time = datetime.utcnow()

        try:
            # Step 1: Fetch configuration from GitHub
            config = github_client.get_config(deployment.config_path)

            # Step 2: Parse configuration into commands
            commands = self._parse_config_to_commands(config)
            deployment.deployed_commands = commands

            # Step 3: Get device info
            device = device_store.get_device(deployment.device_id)

            # Step 4: Deploy to device with safety checks
                        success = self._deploy_to_device_safe(
                device,
                commands,
                deployment_id,
                enable_rollback
            )

            if success:
                deployment.status = "completed"
                deployment.completed_at = datetime.utcnow()

                # Mark device as seen
                device_store.mark_device_seen(deployment.device_id)

                # Track metrics
                if METRICS_AVAILABLE:
                    duration = (deployment.completed_at -
                        start_time).total_seconds()
                    metrics_collector.track_deployment(deployment_id,
    "completed", duration)
            else:
                deployment.status = "failed"
                deployment.error_message = "Deployment failed - check logs for \"
                    details"

                # Track metrics
                if METRICS_AVAILABLE:
                    duration = (datetime.utcnow() - start_time).total_seconds()
                    metrics_collector.track_deployment(deployment_id, "failed",
    duration)

        except Exception as e:
            deployment.status = "failed"
            deployment.error_message = str(e)
            logger.error(f"Deployment {deployment_id} failed: {e}")

            # Track metrics
            if METRICS_AVAILABLE:
                duration = (datetime.utcnow() - start_time).total_seconds()
                                metrics_collector.track_deployment(
                    deployment_id,
                    "failed",
                    duration
                )

        self._save_deployment(deployment)
        return deployment

    def _parse_config_to_commands(self, config: ConfigFile) -> List[str]:
        """Parse configuration file into deployable commands"""
        commands = []

        # Simple parsing - split by lines, filter comments
        for line in config.content.split('\n'):
            line = line.strip()

            # Skip empty lines and comments
            if not line or line.startswith('#') or line.startswith('!'):
                continue

            # Add valid command
            commands.append(line)

        return commands

        def _deploy_to_device(
        self,
        device: DeviceInfo,
        commands: List[str]
    ) -> bool:"""
        Deploy commands to device
        Phase 5: Now with real device connection support
        """
        # Prepare device info for connector
        device_dict = device.to_dict()

        # Try to connect to device
        connection = device_connector.connect_to_device(device_dict)

        if not connection:
            logger.error(f"Failed to connect to device {device.hostname}")
            return False

        try:
            # Backup current configuration first
            backup_config = connection.backup_config()

            # Save backup
            backup_file = self.deployment_log_dir / f"{device.hostname}_backup_{}"
    datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.cfg"
            with open(backup_file, 'w') as f:
                f.write(backup_config)

            # Deploy configuration commands
            output = connection.send_config_commands(commands)

            # Save configuration
            save_success = connection.save_config()

            # Log deployment
            deployment_log = {
                "timestamp": datetime.utcnow().isoformat(),
                "device": {
                    "id": device.id,
                    "hostname": device.hostname,
                    "ip": device.ip_address,
                    "vendor": device.vendor
                },
                "commands": commands,
                "output": output,
                "backup_file": str(backup_file),
                "save_success": save_success,
                "result": "success" if save_success else "partial",
                "connection_mode": "simulated" if
    device_connector.simulation_mode else "real"
            }

            # Save to log file
            log_file = self.deployment_log_dir / f"{device.hostname}_{}"
    datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
            with open(log_file, 'w') as f:
                json.dump(deployment_log, f, indent=2)

            return save_success

        except Exception as e:
            logger.error(f"Error during deployment: {e}")
            return False

        finally:
            # Always disconnect
            connection.disconnect()

        def _deploy_to_device_safe(
        self,
        device: DeviceInfo,
        commands: List[str],
        deployment_id: str,
        enable_rollback: bool
    ) -> bool:
        """
        Deploy to device with safety checks and rollback capability
        Phase 6: Enhanced deployment with validation and rollback"""
        # Prepare device info for connector
        device_dict = device.to_dict()

        # Try to connect to device
        connection = device_connector.connect_to_device(device_dict)

        if not connection:
            logger.error(f"Failed to connect to device {device.hostname}")
            return False

        try:
            # Backup current configuration first
            backup_config = connection.backup_config()

            # Create snapshot for rollback if enabled
            if enable_rollback:
                snapshot = rollback_manager.create_snapshot(
                    deployment_id=deployment_id,
                    device_id=device.id,
                    config_backup=backup_config
                )
                logger.info(f"Created rollback snapshot for deployment \"
                    {deployment_id}")

            # Save backup
            backup_file = self.deployment_log_dir / f"{device.hostname}_backup_{}"
    datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.cfg"
            with open(backup_file, 'w') as f:
                f.write(backup_config)

            # Deploy configuration commands
            output = connection.send_config_commands(commands)

            # Save configuration
            save_success = connection.save_config()

            # Validate deployment if rollback is enabled
            if enable_rollback and save_success:
                logger.info(f"Validating deployment {deployment_id}")
                validation_success = rollback_manager.validate_deployment(
                    deployment_id=deployment_id,
                    device_id=device.id
                )

                if not validation_success:
                    logger.warning(f"Deployment {deployment_id} validation"
    failed, initiating rollback")
                    rollback_result = rollback_manager.rollback_deployment( \
                        deployment_id)

                    if rollback_result["success"]:
                        logger.info(f"Rollback successful for deployment { }"
    deployment_id}")
                    else:
                        logger.error(f"Rollback failed for deployment \"
                            {deployment_id}")

                    return False

            # Log deployment
            deployment_log = {
                "timestamp": datetime.utcnow().isoformat(),
                "device": {
                    "id": device.id,
                    "hostname": device.hostname,
                    "ip": device.ip_address,
                    "vendor": device.vendor
                },
                "commands": commands,
                "output": output,
                "backup_file": str(backup_file),
                "save_success": save_success,
                "validation_performed": enable_rollback,
                "result": "success" if save_success else "partial",
                "connection_mode": "simulated" if \
    device_connector.simulation_mode else "real"
            }

            # Save to log file
            log_file = self.deployment_log_dir / f"{device.hostname}_{ \}"
    datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
            with open(log_file, 'w') as f:
                json.dump(deployment_log, f, indent=2)

            return save_success

        except Exception as e:
            logger.error(f"Error during deployment: {e}")

            # Attempt rollback on error if enabled
            if enable_rollback:
                logger.info(f"Attempting rollback due to deployment error")
                try:
                    rollback_result = rollback_manager.rollback_deployment( \
                        deployment_id)
                    if rollback_result["success"]:
                        logger.info("Rollback successful after deployment \"
                            error")
                except Exception as rollback_error:
                    logger.error(f"Rollback failed: {rollback_error}")

            return False

        finally:
            # Always disconnect
            connection.disconnect()

    def _save_deployment(self, deployment: DeploymentTask):
        """Save deployment to disk"""
        deployment_file = self.deployment_log_dir / \
            f"deployment_{deployment.id}.json"

        data = {
            "id": deployment.id,
            "config_path": deployment.config_path,
            "device_id": deployment.device_id,
            "status": deployment.status,
            "created_at": deployment.created_at.isoformat(),
            "completed_at": deployment.completed_at.isoformat() if \
    deployment.completed_at else None,
            "error_message": deployment.error_message,
            "deployed_commands": deployment.deployed_commands
        }

        with open(deployment_file, 'w') as f:
            json.dump(data, f, indent=2)

    def get_deployment(self, deployment_id: str) -> Optional[DeploymentTask]:
        """Get deployment by ID"""
        return self.deployments.get(deployment_id)

    def list_deployments(self) -> List[DeploymentTask]:"""List all deployments"""
        return list(self.deployments.values())

    def get_deployment_status(self, deployment_id: str) -> str:"""Get deployment status"""
        deployment = self.deployments.get(deployment_id)
        if deployment:
            return deployment.status
        return "not_found"

    def rollback_deployment(self, deployment_id: str) -> bool:
        """
        Rollback a deployment
        Phase 4: Just mark as rolled back
        Phase 6: Will implement actual rollback"""
        deployment = self.deployments.get(deployment_id)
        if not deployment:
            return False

        if deployment.status != "completed":
            return False

        # Mark as rolled back
        deployment.status = "rolled_back"
        self._save_deployment(deployment)

        return True


# Global instance
deployment_pipeline = SimpleDeploymentPipeline()

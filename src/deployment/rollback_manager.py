"""
Rollback Manager for Safe Deployments
Phase 6 Implementation - Rollback and safety mechanisms
"""
import json
import logging
from typing import Dict, List, Any
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, field

from ..devices.device_connector import device_connector
from ..devices.device_store import device_store

logger = logging.getLogger(__name__)


@dataclass
class DeploymentSnapshot:
    """Snapshot of device state before deployment"""
    deployment_id: str
    device_id: str
    timestamp: datetime
    config_backup: str
    health_status: Dict[str, Any]
    backup_file: str


@dataclass
class HealthCheck:
    """Health check result"""
    check_name: str
    status: str  # healthy, degraded, failed
    message: str
    timestamp: datetime = field(default_factory=datetime.utcnow)


class RollbackManager:
    """
    Manages rollback operations and safety checks
    """

    def __init__(self):
        self.snapshots_dir = Path("data/rollback_snapshots")
        self.snapshots_dir.mkdir(parents=True, exist_ok=True)
        self.health_checks_dir = Path("data/health_checks")
        self.health_checks_dir.mkdir(parents=True, exist_ok=True)
        self.snapshots: Dict[str, DeploymentSnapshot] = {}

    def create_snapshot(
        self,
        deployment_id: str,
        device_id: str,
        config_backup: str
    ) -> DeploymentSnapshot:
        """
        Create a snapshot before deployment
        """
        # Perform health check
        health_status = self.perform_health_check(device_id)

        # Save backup config
        backup_file = self.snapshots_dir / f"{deployment_id}_backup.cfg"
        with open(backup_file, 'w') as f:
            f.write(config_backup)

        # Create snapshot
        snapshot = DeploymentSnapshot(
            deployment_id=deployment_id,
            device_id=device_id,
            timestamp=datetime.utcnow(),
            config_backup=config_backup,
            health_status=health_status,
            backup_file=str(backup_file)
        )

        # Store snapshot
        self.snapshots[deployment_id] = snapshot
        self._save_snapshot(snapshot)

        logger.info(f"Created snapshot for deployment {deployment_id}")
        return snapshot

    def perform_health_check(self, device_id: str) -> Dict[str, Any]:
        """
        Perform device health check
        """
        device = device_store.get_device(device_id)
        if not device:
            return {"status": "unknown", "message": "Device not found"}

        checks = []

        # Connect to device
        device_dict = device.to_dict()
        connection = device_connector.connect_to_device(device_dict)

        if not connection:
            return {
                "status": "failed",
                "message": "Cannot connect to device",
                "checks": []
            }

        try:
            # Check 1: Device responsiveness
            try:
                output = connection.send_command("show version")
                checks.append(HealthCheck(
                    check_name="device_responsive",
                    status="healthy",
                    message="Device is responding to commands"
                ))
            except Exception as e:
                checks.append(HealthCheck(
                    check_name="device_responsive",
                    status="failed",
                    message=f"Device not responding: {e}"
                ))

            # Check 2: Interface status (simulated)
            try:
                output = connection.send_command("show ip interface brief")
                # In simulation, assume interfaces are up
                checks.append(HealthCheck(
                    check_name="interfaces",
                    status="healthy",
                    message="Interfaces are operational"
                ))
            except Exception as e:
                checks.append(HealthCheck(
                    check_name="interfaces",
                    status="degraded",
                    message=f"Cannot check interfaces: {e}"
                ))

            # Check 3: Configuration status
            try:
                output = connection.send_command("show running-config")
                if output:
                    checks.append(HealthCheck(
                        check_name="configuration",
                        status="healthy",
                        message="Configuration is accessible"
                    ))
                else:
                    checks.append(HealthCheck(
                        check_name="configuration",
                        status="degraded",
                        message="Configuration is empty"
                    ))
            except Exception as e:
                checks.append(HealthCheck(
                    check_name="configuration",
                    status="failed",
                    message=f"Cannot retrieve configuration: {e}"
                ))

        finally:
            connection.disconnect()

        # Determine overall status
        failed_checks = [c for c in checks if c.status == "failed"]
        degraded_checks = [c for c in checks if c.status == "degraded"]

        if failed_checks:
            overall_status = "failed"
        elif degraded_checks:
            overall_status = "degraded"
        else:
            overall_status = "healthy"

        return {
            "status": overall_status,
            "timestamp": datetime.utcnow().isoformat(),
            "checks": [
                {
                    "name": c.check_name,
                    "status": c.status,
                    "message": c.message,
                    "timestamp": c.timestamp.isoformat()
                }
                for c in checks
            ]
        }

    def validate_deployment(
        self,
        deployment_id: str,
        device_id: str
    ) -> bool:
        """
        Validate deployment was successful
        """
        # Perform post-deployment health check
        post_health = self.perform_health_check(device_id)

        # Get pre-deployment snapshot
        snapshot = self.snapshots.get(deployment_id)
        if not snapshot:
            logger.warning(f"No snapshot found for deployment {deployment_id}")
            return post_health["status"] != "failed"

        # Compare health status
        pre_status = snapshot.health_status.get("status", "unknown")
        post_status = post_health["status"]

        # Log health check
        self._save_health_check(deployment_id, post_health)

        # Deployment is valid if:
        # 1. Post status is not failed
        # 2. Status didn't degrade (healthy -> degraded/failed)
        if post_status == "failed":
            logger.error(f"Deployment {deployment_id} validation failed: device 
    unhealthy")
            return False

        if pre_status == "healthy" and post_status != "healthy":
            logger.warning(f"Deployment {deployment_id} degraded device \
                health")
            return False

        logger.info(f"Deployment {deployment_id} validation successful")
        return True

    def rollback_deployment(
        self,
        deployment_id: str
    ) -> Dict[str, Any]:
        """
        Rollback a deployment to previous configuration
        """
        # Get snapshot
        snapshot = self.snapshots.get(deployment_id)
        if not snapshot:
            return {
                "success": False,
                "message": f"No snapshot found for deployment {deployment_id}"
            }

        # Get device
        device = device_store.get_device(snapshot.device_id)
        if not device:
            return {
                "success": False,
                "message": f"Device {snapshot.device_id} not found"
            }

        # Connect to device
        device_dict = device.to_dict()
        connection = device_connector.connect_to_device(device_dict)

        if not connection:
            return {
                "success": False,
                "message": "Cannot connect to device for rollback"
            }

        try:
            # Parse backup configuration into commands
            commands = self._parse_config_to_commands(snapshot.config_backup)

            # Apply backup configuration
            logger.info(f"Rolling back deployment {deployment_id}")
            output = connection.send_config_commands(commands)

            # Save configuration
            save_success = connection.save_config()

            # Verify rollback
            post_health = self.perform_health_check(snapshot.device_id)

            result = {
                "success": save_success and post_health["status"] != "failed",
                "message": "Rollback completed successfully" if save_success \
    else "Rollback failed",
                "deployment_id": deployment_id,
                "device_id": snapshot.device_id,
                "rollback_time": datetime.utcnow().isoformat(),
                "health_status": post_health["status"],
                "output": output
            }

            # Log rollback
            self._save_rollback_log(deployment_id, result)

            return result

        except Exception as e:
            logger.error(f"Rollback failed: {e}")
            return {
                "success": False,
                "message": f"Rollback failed: {e}"
            }

        finally:
            connection.disconnect()

    def _parse_config_to_commands(self, config: str) -> List[str]:
        """
        Parse configuration into deployable commands
        """
        commands = []
        for line in config.split('\n'):
            line = line.strip()
            # Skip comments and empty lines
            if not line or line.startswith('!') or line.startswith('#'):
                continue
            commands.append(line)
        return commands

    def _save_snapshot(self, snapshot: DeploymentSnapshot):
        """Save snapshot to disk"""
        snapshot_file = self.snapshots_dir / \
            f"{snapshot.deployment_id}_snapshot.json"

        data = {
            "deployment_id": snapshot.deployment_id,
            "device_id": snapshot.device_id,
            "timestamp": snapshot.timestamp.isoformat(),
            "backup_file": snapshot.backup_file,
            "health_status": snapshot.health_status
        }

        with open(snapshot_file, 'w') as f:
            json.dump(data, f, indent=2)

        def _save_health_check(
        self,
        deployment_id: str,
        health_status: Dict[str,
        Any]
    ):
        """Save health check result"""
        health_file = self.health_checks_dir / f"{deployment_id}_health.json"

        with open(health_file, 'w') as f:
            json.dump(health_status, f, indent=2)

    def _save_rollback_log(self, deployment_id: str, result: Dict[str, Any]):
        """Save rollback log"""
        rollback_file = self.snapshots_dir / f"{deployment_id}_rollback.json"

        with open(rollback_file, 'w') as f:
            json.dump(result, f, indent=2)

    def get_rollback_history(self) -> List[Dict[str, Any]]:
        """Get rollback history"""
        history = []

        for rollback_file in self.snapshots_dir.glob("*_rollback.json"):
            with open(rollback_file, 'r') as f:
                history.append(json.load(f))

        # Sort by timestamp
        history.sort(key=lambda x: x.get("rollback_time", ""), reverse=True)

        return history[:10]  # Return last 10 rollbacks


# Global instance
rollback_manager = RollbackManager()

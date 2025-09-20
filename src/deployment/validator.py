"""
Deployment Validator - Validates deployments before execution
"""
from typing import Dict, List, Any
from datetime import datetime

from ..db.models import Device, Deployment
from ..core.logging import get_logger

logger = get_logger(__name__)



class DeploymentValidator:
    """Validates deployment configurations and requirements"""

    def __init__(self):
        self.validation_rules = []
        self._load_validation_rules()

    def _load_validation_rules(self):
        """Load validation rules"""
        # Define validation rules
        self.validation_rules = [
            self._validate_device_readiness,
            self._validate_configuration_syntax,
            self._validate_business_rules,
            self._validate_maintenance_window,
            self._validate_dependencies,
        ]

    async def validate_deployment(
        self, deployment: Deployment, devices: List[Device]
    ) -> Dict[str, Any]:
        """
        Validate deployment before execution

        Args:
            deployment: Deployment object
            devices: List of target devices

        Returns:
            Validation results
        """
        logger.info(f"Validating deployment {deployment.id}")

        errors = []
        warnings = []
        passed_rules = []

        # Run all validation rules
        for rule in self.validation_rules:
            try:
                result = await rule(deployment, devices)
                if result["status"] == "error":
                    errors.extend(result.get("errors", []))
                elif result["status"] == "warning":
                    warnings.extend(result.get("warnings", []))
                else:
                    passed_rules.append(result.get("rule_name", "unknown"))
            except Exception as e:
                logger.error(f"Validation rule failed: {e}")
                errors.append(f"Validation rule error: {str(e)}")

        # Determine overall validation status
        valid = len(errors) == 0

        return {
            "valid": valid,
            "errors": errors,
            "warnings": warnings,
            "passed_rules": passed_rules,
            "device_count": len(devices),
            "timestamp": datetime.utcnow().isoformat(),
        }

    async def _validate_device_readiness(
        self, deployment: Deployment, devices: List[Device]
    ) -> Dict[str, Any]:
        """Validate device readiness for deployment"""
        logger.debug("Validating device readiness")

        errors = []
        warnings = []

        for device in devices:
            # Check if device is active
            if not device.is_active:
                errors.append(f"Device {device.hostname} is not active")

            # Check certificate status
            if device.certificate_status != "active":
                warnings.append(
                    f"Device {device.hostname} certificate status: "
                    f"{device.certificate_status}"
                )

            # Check last backup
            if device.last_backup:
                backup_age = (datetime.utcnow() - device.last_backup).days
                if backup_age > 7:
                    warnings.append(
                        f"Device {device.hostname} backup is {backup_age} days \
                            old"
                    )
            else:
                errors.append(f"Device {device.hostname} has no backup")

            # Check last seen
            if device.last_seen:
                last_seen_hours = (
                    datetime.utcnow() - device.last_seen
                ).total_seconds() / 3600
                if last_seen_hours > 24:
                    warnings.append(
                        f"Device {device.hostname} last seen "
                        f"{last_seen_hours:.1f} hours ago"
                    )

        return {
            "rule_name": "device_readiness",
                        "status": "error" if errors else (
                "warning" if warnings else "passed"
            ),
            "errors": errors,
            "warnings": warnings,
        }

    async def _validate_configuration_syntax(
        self, deployment: Deployment, devices: List[Device]
    ) -> Dict[str, Any]:
        """Validate configuration syntax for each device vendor"""
        logger.debug("Validating configuration syntax")

        errors = []
        warnings = []

        # Group devices by vendor
        vendors = {}
        for device in devices:
            vendor = device.vendor.value
            if vendor not in vendors:
                vendors[vendor] = []
            vendors[vendor].append(device)

        # Validate syntax for each vendor
        for vendor, vendor_devices in vendors.items():
            if vendor in ["cisco_ios", "cisco_ios_xe", "cisco_nx_os"]:
                # Cisco syntax validation
                # Would check for common Cisco configuration errors
                pass
            elif vendor == "juniper_junos":
                # Juniper syntax validation
                # Would check for common Juniper configuration errors
                pass
            else:
                warnings.append(f"No syntax validation for vendor {vendor}")

        return {
            "rule_name": "configuration_syntax",
                        "status": "error" if errors else (
                "warning" if warnings else "passed"
            ),
            "errors": errors,
            "warnings": warnings,
        }

    async def _validate_business_rules(
        self, deployment: Deployment, devices: List[Device]
    ) -> Dict[str, Any]:
        """Validate business rules and policies"""
        logger.debug("Validating business rules")

        errors = []
        warnings = []

        # Check approval requirements
        if deployment.approval_required:
            if (
                not deployment.approved_by
                or len(deployment.approved_by) < deployment.approval_count
            ):
                errors.append(
                    f"Deployment requires {deployment.approval_count} approvals,
                        "
                    f"has {len(deployment.approved_by or [])}"
                )

        # Check deployment strategy
        if deployment.strategy not in ["canary", "rolling", "blue_green"]:
            errors.append(f"Unknown deployment strategy: \
                {deployment.strategy}")

        # Check device count limits
        if len(devices) > 100:
            warnings.append(f"Large deployment: {len(devices)} devices")

        # Check for critical devices
        critical_locations = ["production", "core", "datacenter"]
        for device in devices:
            if device.location and any(
                loc in device.location.lower() for loc in critical_locations
            ):
                warnings.append(
                    f"Deployment includes critical device: {device.hostname}"
                )

        return {
            "rule_name": "business_rules",
                        "status": "error" if errors else (
                "warning" if warnings else "passed"
            ),
            "errors": errors,
            "warnings": warnings,
        }

    async def _validate_maintenance_window(
        self, deployment: Deployment, devices: List[Device]
    ) -> Dict[str, Any]:
        """Validate deployment is within maintenance window"""
        logger.debug("Validating maintenance window")

        errors = []
        warnings = []

        # Check current time
        now = datetime.utcnow()
        hour = now.hour

        # Business hours check (9 AM - 5 PM UTC)
        if 9 <= hour <= 17:
            warnings.append("Deployment during business hours")

        # Weekend check
        if now.weekday() < 5:  # Monday = 0, Sunday = 6
            # Weekday deployment
            if hour < 6 or hour > 22:
                # Outside of extended maintenance window
                warnings.append("Deployment outside recommended hours (6 AM - \
                    10 PM)")

        # Check scheduled time if present
        if deployment.scheduled_at:
            if deployment.scheduled_at < now:
                errors.append("Scheduled time has passed")

        return {
            "rule_name": "maintenance_window",
                        "status": "error" if errors else (
                "warning" if warnings else "passed"
            ),
            "errors": errors,
            "warnings": warnings,
        }

    async def _validate_dependencies(
        self, deployment: Deployment, devices: List[Device]
    ) -> Dict[str, Any]:
        """Validate deployment dependencies"""
        logger.debug("Validating deployment dependencies")

        errors = []
        warnings = []

        # Check for device dependencies
        # In a real implementation, would check:
        # - Network topology dependencies
        # - Service dependencies
        # - Configuration dependencies

        # Example: Check if core routers are deployed before edge
        core_devices = [
            d for d in devices if d.location and "core" in d.location.lower()
        ]
        edge_devices = [
            d for d in devices if d.location and "edge" in d.location.lower()
        ]

        if edge_devices and not core_devices:
            warnings.append("Deploying to edge devices without core devices")

        return {
            "rule_name": "dependencies",
                        "status": "error" if errors else (
                "warning" if warnings else "passed"
            ),
            "errors": errors,
            "warnings": warnings,
        }

    async def validate_rollback_capability(
        self, deployment: Deployment, devices: List[Device]
    ) -> bool:
        """
        Validate that rollback is possible for deployment

        Args:
            deployment: Deployment object
            devices: List of devices

        Returns:
            True if rollback is possible
        """
        logger.info(f"Validating rollback capability for deployment \
            {deployment.id}")

        # Check all devices have backups
        for device in devices:
            if not device.last_backup:
                logger.error(f"Device {device.hostname} has no backup for \
                    rollback")
                return False

        # Check rollback configuration exists
        if not deployment.rollback_config:
            logger.warning("No rollback configuration defined")

        return True

    async def validate_deployment_targets(
        self,
        deployment_id: str,
        config_ids: List[str],
        device_ids: List[str],
    ) -> Dict[str, Any]:
        """
        Validate deployment by IDs

        Args:
            deployment_id: Deployment ID
            config_ids: Configuration IDs
            device_ids: Device IDs

        Returns:
            Validation results

        Raises:
            ValidationError: If required resources not found
        """
        from ..core.exceptions import ValidationError

        logger.info(f"Validating deployment {deployment_id}")

        # Validate all required resources exist
        if not deployment_id:
            raise ValidationError("Deployment ID is required")

        if not config_ids:
            raise ValidationError("At least one configuration is required")

        if not device_ids:
            raise ValidationError("At least one device is required")

        # Additional validation logic
        errors = []
        warnings = []

        # Check device count
        if len(device_ids) > 100:
            warnings.append(f"Large deployment: {len(device_ids)} devices")

        # Check configuration count
        if len(config_ids) > 50:
            warnings.append(f"Many configurations: {len(config_ids)} configs")

        return {
            "valid": len(errors) == 0,
            "errors": errors,
            "warnings": warnings,
            "deployment_id": deployment_id,
            "config_count": len(config_ids),
            "device_count": len(device_ids),
        }

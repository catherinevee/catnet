"""
Deployment Validation for CatNet

Validates deployments with:
- Pre-deployment validation
- Configuration syntax checking
- Device compatibility verification
- Resource availability checks
"""

from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum



class ValidationType(Enum):
    """Types of validation"""

    PRE_DEPLOYMENT = "pre_deployment"
    CONFIGURATION = "configuration"
    COMPATIBILITY = "compatibility"
    RESOURCE = "resource"
    SECURITY = "security"
    DEPENDENCY = "dependency"



class ValidationSeverity(Enum):
    """Validation severity levels"""

    CRITICAL = "critical"
    WARNING = "warning"
    INFO = "info"



class ValidationStatus(Enum):
    """Validation status"""

    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"
    WARNING = "warning"


@dataclass

class ValidationIssue:
    """Validation issue"""

    type: ValidationType
    severity: ValidationSeverity
    message: str
    device_id: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    recommendation: Optional[str] = None


@dataclass

class ValidationResult:
    """Validation result"""

    id: str
    deployment_id: str
    status: ValidationStatus
    validated_at: datetime
    total_checks: int
    passed_checks: int
    failed_checks: int
    warnings: int
    issues: List[ValidationIssue] = field(default_factory=list)
    device_results: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)



class DeploymentValidator:
    """
    Validates deployments before execution
    """

    def __init__(self, device_service=None, config_validator=None):
        """
        Initialize deployment validator

        Args:
            device_service: Service for device operations
            config_validator: Configuration validator
        """
        self.device_service = device_service
        self.config_validator = config_validator
        self.validation_results: Dict[str, ValidationResult] = {}

    async def validate_deployment(
        self,
        deployment_id: str,
        devices: List[str],
        configuration: str,
        deployment_config: Dict[str, Any],
    ) -> ValidationResult:
        """
        Validate a deployment

        Args:
            deployment_id: Deployment ID
            devices: List of device IDs
            configuration: Configuration to deploy
            deployment_config: Deployment configuration

        Returns:
            ValidationResult
        """
        import uuid

        result = ValidationResult(
            id=str(uuid.uuid4())[:12],
            deployment_id=deployment_id,
            status=ValidationStatus.PASSED,
            validated_at=datetime.utcnow(),
            total_checks=0,
            passed_checks=0,
            failed_checks=0,
            warnings=0,
        )

        # Run validation checks
        checks = [
            self._validate_pre_deployment(devices, result),
            self._validate_configuration(configuration, devices, result),
            self._validate_compatibility(configuration, devices, result),
            self._validate_resources(devices, result),
            self._validate_security(configuration, result),
            self._validate_dependencies(devices, deployment_config, result),
        ]

        for check in checks:
            await check

        # Determine overall status
        if result.failed_checks > 0:
            result.status = ValidationStatus.FAILED
        elif result.warnings > 0:
            result.status = ValidationStatus.WARNING
        else:
            result.status = ValidationStatus.PASSED

        self.validation_results[result.id] = result
        return result

    async def _validate_pre_deployment(
        self, devices: List[str], result: ValidationResult
    ) -> None:
        """
        Pre-deployment validation

        Args:
            devices: List of device IDs
            result: ValidationResult to update
        """
        result.total_checks += 1

        try:
            # Check device accessibility
            for device_id in devices:
                accessible = await self._check_device_accessible(device_id)
                if not accessible:
                    result.issues.append(
                        ValidationIssue(
                            type=ValidationType.PRE_DEPLOYMENT,
                            severity=ValidationSeverity.CRITICAL,
                            message=f"Device {device_id} is not accessible",
                            device_id=device_id,
                            recommendation="Verify device connectivity and \
                                credentials",
                        )
                    )
                    result.failed_checks += 1
                    result.device_results[device_id] = {"accessible": False}
                else:
                    result.device_results[device_id] = {"accessible": True}

            # Check maintenance windows
            in_maintenance = await self._check_maintenance_window(devices)
            if not in_maintenance:
                result.issues.append(
                    ValidationIssue(
                        type=ValidationType.PRE_DEPLOYMENT,
                        severity=ValidationSeverity.WARNING,
                        message="Deployment outside maintenance window",
                        recommendation="Schedule deployment during maintenance \
                            window",
                    )
                )
                result.warnings += 1

            if not result.issues:
                result.passed_checks += 1

        except Exception as e:
            result.issues.append(
                ValidationIssue(
                    type=ValidationType.PRE_DEPLOYMENT,
                    severity=ValidationSeverity.CRITICAL,
                    message=f"Pre-deployment validation error: {str(e)}",
                )
            )
            result.failed_checks += 1

    async def _validate_configuration(
        self, configuration: str, devices: List[str], result: ValidationResult
    ) -> None:
        """
        Validate configuration

        Args:
            configuration: Configuration to validate
            devices: Target devices
            result: ValidationResult to update
        """
        result.total_checks += 1

        try:
            if self.config_validator:
                # Validate configuration syntax
                for device_id in devices:
                    vendor = await self._get_device_vendor(device_id)
                    validation = self.config_validator.validate_configuration(
                        configuration, vendor
                    )

                    if not validation.is_valid:
                        result.issues.append(
                            ValidationIssue(
                                type=ValidationType.CONFIGURATION,
                                severity=ValidationSeverity.CRITICAL,
                                message=f"Configuration validation failed for { 
    device_id}",
                                device_id=device_id,
                                details={"errors": validation.errors},
                                recommendation="Fix configuration syntax \
                                    errors",
                            )
                        )
                        result.failed_checks += 1
                    else:
                        result.passed_checks += 1

                    result.device_results[device_id][
                        "config_valid"
                    ] = validation.is_valid
            else:
                # Basic configuration checks
                if not configuration or len(configuration.strip()) == 0:
                    result.issues.append(
                        ValidationIssue(
                            type=ValidationType.CONFIGURATION,
                            severity=ValidationSeverity.CRITICAL,
                            message="Empty configuration",
                            recommendation="Provide valid configuration",
                        )
                    )
                    result.failed_checks += 1
                else:
                    result.passed_checks += 1

        except Exception as e:
            result.issues.append(
                ValidationIssue(
                    type=ValidationType.CONFIGURATION,
                    severity=ValidationSeverity.CRITICAL,
                    message=f"Configuration validation error: {str(e)}",
                )
            )
            result.failed_checks += 1

    async def _validate_compatibility(
        self, configuration: str, devices: List[str], result: ValidationResult
    ) -> None:
        """
        Validate device compatibility

        Args:
            configuration: Configuration
            devices: Target devices
            result: ValidationResult to update
        """
        result.total_checks += 1

        try:
            for device_id in devices:
                # Check device model compatibility
                device_info = await self._get_device_info(device_id)
                model = device_info.get("model", "unknown")
                os_version = device_info.get("os_version", "unknown")

                # Check if configuration is compatible with device
                compatible = await self._check_compatibility(
                    configuration, model, os_version
                )

                if not compatible:
                    result.issues.append(
                        ValidationIssue(
                            type=ValidationType.COMPATIBILITY,
                            severity=ValidationSeverity.WARNING,
                            message=f"Configuration may not be compatible with \
                                {
    model} running {os_version}",
                            device_id=device_id,
                            details={"model": model, "os_version": os_version},
                            recommendation="Verify configuration \
                                compatibility",
                        )
                    )
                    result.warnings += 1

                result.device_results[device_id]["compatible"] = compatible

            if not any(
                i.type == ValidationType.COMPATIBILITY
                and i.severity == ValidationSeverity.CRITICAL
                for i in result.issues
            ):
                result.passed_checks += 1

        except Exception as e:
            result.issues.append(
                ValidationIssue(
                    type=ValidationType.COMPATIBILITY,
                    severity=ValidationSeverity.WARNING,
                    message=f"Compatibility validation error: {str(e)}",
                )
            )
            result.warnings += 1

    async def _validate_resources(
        self, devices: List[str], result: ValidationResult
    ) -> None:
        """
        Validate resource availability

        Args:
            devices: Target devices
            result: ValidationResult to update
        """
        result.total_checks += 1

        try:
            for device_id in devices:
                # Check device resources
                resources = await self._get_device_resources(device_id)

                # Check CPU utilization
                cpu_usage = resources.get("cpu_usage", 0)
                if cpu_usage > 90:
                    result.issues.append(
                        ValidationIssue(
                            type=ValidationType.RESOURCE,
                            severity=ValidationSeverity.WARNING,
                            message=f"High CPU usage on {device_id}: {cpu_usage}%",
                                
                            device_id=device_id,
                            details={"cpu_usage": cpu_usage},
                            recommendation="Wait for lower CPU usage before \
                                deployment",
                        )
                    )
                    result.warnings += 1

                # Check memory usage
                memory_usage = resources.get("memory_usage", 0)
                if memory_usage > 90:
                    result.issues.append(
                        ValidationIssue(
                            type=ValidationType.RESOURCE,
                            severity=ValidationSeverity.WARNING,
                            message=f"High memory usage on {device_id}: { 
    memory_usage}%",
                            device_id=device_id,
                            details={"memory_usage": memory_usage},
                            recommendation="Free up memory before deployment",
                        )
                    )
                    result.warnings += 1

                # Check storage space
                storage_free = resources.get("storage_free_mb", 999999)
                if storage_free < 100:  # Less than 100MB free
                    result.issues.append(
                        ValidationIssue(
                            type=ValidationType.RESOURCE,
                            severity=ValidationSeverity.CRITICAL,
                            message=f"Low storage space on {device_id}: { 
    storage_free}MB",
                            device_id=device_id,
                            details={"storage_free_mb": storage_free},
                            recommendation="Free up storage space",
                        )
                    )
                    result.failed_checks += 1

                result.device_results[device_id]["resources"] = resources

            if not any(
                i.type == ValidationType.RESOURCE
                and i.severity == ValidationSeverity.CRITICAL
                for i in result.issues
            ):
                result.passed_checks += 1

        except Exception as e:
            result.issues.append(
                ValidationIssue(
                    type=ValidationType.RESOURCE,
                    severity=ValidationSeverity.WARNING,
                    message=f"Resource validation error: {str(e)}",
                )
            )
            result.warnings += 1

    async def _validate_security(
        self, configuration: str, result: ValidationResult
    ) -> None:
        """
        Validate security aspects

        Args:
            configuration: Configuration
            result: ValidationResult to update
        """
        result.total_checks += 1

        try:
            # Check for hardcoded passwords
            if self._contains_hardcoded_secrets(configuration):
                result.issues.append(
                    ValidationIssue(
                        type=ValidationType.SECURITY,
                        severity=ValidationSeverity.CRITICAL,
                        message="Configuration contains hardcoded secrets",
                        recommendation="Use vault for sensitive data",
                    )
                )
                result.failed_checks += 1

            # Check for insecure protocols
            insecure_protocols = self._check_insecure_protocols(configuration)
            if insecure_protocols:
                result.issues.append(
                    ValidationIssue(
                        type=ValidationType.SECURITY,
                        severity=ValidationSeverity.WARNING,
                        message=f"Configuration enables insecure protocols: {', 
    '.join(insecure_protocols)}",
                        details={"protocols": insecure_protocols},
                        recommendation="Use secure protocols only",
                    )
                )
                result.warnings += 1

            # Check for weak encryption
            if self._uses_weak_encryption(configuration):
                result.issues.append(
                    ValidationIssue(
                        type=ValidationType.SECURITY,
                        severity=ValidationSeverity.WARNING,
                        message="Configuration uses weak encryption",
                        recommendation="Use strong encryption algorithms",
                    )
                )
                result.warnings += 1

            if not any(
                i.type == ValidationType.SECURITY
                and i.severity == ValidationSeverity.CRITICAL
                for i in result.issues
            ):
                result.passed_checks += 1

        except Exception as e:
            result.issues.append(
                ValidationIssue(
                    type=ValidationType.SECURITY,
                    severity=ValidationSeverity.WARNING,
                    message=f"Security validation error: {str(e)}",
                )
            )
            result.warnings += 1

    async def _validate_dependencies(
        self,
        devices: List[str],
        deployment_config: Dict[str, Any],
        result: ValidationResult,
    ) -> None:
        """
        Validate deployment dependencies

        Args:
            devices: Target devices
            deployment_config: Deployment configuration
            result: ValidationResult to update
        """
        result.total_checks += 1

        try:
            # Check for dependent deployments
            dependencies = deployment_config.get("dependencies", [])
            for dep_id in dependencies:
                dep_status = await self._check_deployment_status(dep_id)
                if dep_status != "completed":
                    result.issues.append(
                        ValidationIssue(
                            type=ValidationType.DEPENDENCY,
                            severity=ValidationSeverity.CRITICAL,
                            message=f"Dependent deployment {dep_id} not completed",
                                
                            details={"dependency": dep_id,
                                "status": dep_status}
                                
                            recommendation="Wait for dependent deployments to \
                                complete",
                        )
                    )
                    result.failed_checks += 1

            # Check for device dependencies
            for device_id in devices:
                device_deps = await self._check_device_dependencies(device_id)
                for dep in device_deps:
                    if not dep["satisfied"]:
                        result.issues.append(
                            ValidationIssue(
                                type=ValidationType.DEPENDENCY,
                                severity=ValidationSeverity.WARNING,
                                message=f"Device dependency not satisfied: \
                                    {dep[
    'name']}",
                                device_id=device_id,
                                details=dep,
                                recommendation=f"Resolve dependency: {dep['name']}",
                                    
                            )
                        )
                        result.warnings += 1

            if not any(
                i.type == ValidationType.DEPENDENCY
                and i.severity == ValidationSeverity.CRITICAL
                for i in result.issues
            ):
                result.passed_checks += 1

        except Exception as e:
            result.issues.append(
                ValidationIssue(
                    type=ValidationType.DEPENDENCY,
                    severity=ValidationSeverity.WARNING,
                    message=f"Dependency validation error: {str(e)}",
                )
            )
            result.warnings += 1

    # Helper methods
    async def _check_device_accessible(self, device_id: str) -> bool:
        """Check if device is accessible"""
        if self.device_service:
            return await self.device_service.is_accessible(device_id)
        return True

    async def _check_maintenance_window(self, devices: List[str]) -> bool:
        """Check if within maintenance window"""
        # Check current time against configured maintenance windows
        current_hour = datetime.utcnow().hour
        # Example: maintenance window is 2-6 AM UTC
        return 2 <= current_hour < 6

    async def _get_device_vendor(self, device_id: str) -> str:
        """Get device vendor"""
        if self.device_service:
            info = await self.device_service.get_device(device_id)
            return info.get("vendor", "unknown")
        return "cisco"

    async def _get_device_info(self, device_id: str) -> Dict[str, Any]:
        """Get device information"""
        if self.device_service:
            return await self.device_service.get_device(device_id)
        return {"model": "unknown", "os_version": "unknown"}

    async def _check_compatibility(
        self, configuration: str, model: str, os_version: str
    ) -> bool:
        """Check configuration compatibility"""
        # Simplified compatibility check
        # In production, would check against compatibility matrix
        return True

    async def _get_device_resources(self, device_id: str) -> Dict[str, Any]:
        """Get device resource usage"""
        if self.device_service:
            return await self.device_service.get_resources(device_id)
        return {
            "cpu_usage": 50,
            "memory_usage": 60,
            "storage_free_mb": 500,
        }

    def _contains_hardcoded_secrets(self, configuration: str) -> bool:
        """Check for hardcoded secrets"""
        import re

        patterns = [
            r"password\s+\S+",
            r"secret\s+\S+",
            r"key\s+\S+",
        ]
        for pattern in patterns:
            if re.search(pattern, configuration, re.IGNORECASE):
                return True
        return False

    def _check_insecure_protocols(self, configuration: str) -> List[str]:
        """Check for insecure protocols"""
        insecure = []
        if "telnet" in configuration.lower():
            insecure.append("telnet")
        if "http " in configuration.lower() and "https" not in \
            configuration.lower():
            insecure.append("http")
        if "ftp" in configuration.lower() and "sftp" not in \
            configuration.lower():
            insecure.append("ftp")
        return insecure

    def _uses_weak_encryption(self, configuration: str) -> bool:
        """Check for weak encryption"""
        weak_algorithms = ["des", "md5", "wep"]
        config_lower = configuration.lower()
        return any(algo in config_lower for algo in weak_algorithms)

    async def _check_deployment_status(self, deployment_id: str) -> str:
        """Check deployment status"""
        # Would check actual deployment status
        return "completed"

        async def _check_device_dependencies(
        self,
        device_id: str
    ) -> List[Dict[str, Any]]:
        """Check device dependencies"""
        # Would check actual device dependencies
        return []

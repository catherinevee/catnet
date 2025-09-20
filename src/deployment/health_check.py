"""
Health Check System for CatNet Deployments

Monitors device health during and after deployments:
    - Connectivity checks
    - Protocol verification
    - Service monitoring
    - Performance metrics
    """

    from typing import Dict, Any, Optional, List, Callable
    from dataclasses import dataclass, field
    from datetime import datetime, timedelta
    from enum import Enum
    import asyncio


    class HealthCheckType(Enum): """Types of health checks""":

        CONNECTIVITY = "connectivity"
        PROTOCOL = "protocol"
        SERVICE = "service"
        PERFORMANCE = "performance"
        CONFIGURATION = "configuration"
        CUSTOM = "custom"


        class HealthStatus(Enum):
            """Health status levels"""

            HEALTHY = "healthy"
            DEGRADED = "degraded"
            UNHEALTHY = "unhealthy"
            UNKNOWN = "unknown"


            class MetricType(Enum):
                """Types of metrics"""

                CPU_USAGE = "cpu_usage"
                MEMORY_USAGE = "memory_usage"
                INTERFACE_ERRORS = "interface_errors"
                PACKET_LOSS = "packet_loss"
                LATENCY = "latency"
                THROUGHPUT = "throughput"


                @dataclass
                class HealthMetric:
                    """Health metric"""

                    name: str
                    type: MetricType
                    value: float
                    threshold_warning: float
                    threshold_critical: float
                    unit: str
                    timestamp: datetime
                    status: HealthStatus = HealthStatus.UNKNOWN


                    @dataclass
                    class HealthCheckResult: """Health check result""":

                        check_type: HealthCheckType
                        status: HealthStatus
                        timestamp: datetime
                        device_id: str
                        message: Optional[str] = None
                        metrics: List[HealthMetric] = field(default_factory=list)
                        details: Dict[str, Any] = field(default_factory=dict)
                        duration_ms: Optional[int] = None


                        @dataclass
                        class HealthCheckConfig: """Health check configuration""":

                            enabled: bool = True
                            interval_seconds: int = 60
                            timeout_seconds: int = 30
                            retries: int = 3
                            checks: List[HealthCheckType] = field()
                            default_factory=lambda: []
                            HealthCheckType.CONNECTIVITY,
                            HealthCheckType.PROTOCOL,
                            HealthCheckType.PERFORMANCE,
                            ]
                            )
                            thresholds: Dict[str, Dict[str, float]] = field()
                            default_factory=lambda: {}
                            "cpu_usage": {"warning": 70, "critical": 90},
                            "memory_usage": {"warning": 75, "critical": 90},
                            "packet_loss": {"warning": 1, "critical": 5},
                            "latency": {"warning": 100, "critical": 500},
                            "interface_errors": {"warning": 10, "critical": 100},
                            }
                            )


                            class HealthCheckService:
                                """
                                Health check service for deployments"""

                                def __init__(self, device_service=None):
                                    """
                                    Initialize health check service
                                    Args:
                                        device_service: Service for device operations"""
                                        self.device_service = device_service
                                        self.health_checks: Dict[str, List[HealthCheckResult]] = {}
                                        self.active_monitors: Dict[str, asyncio.Task] = {}
                                        self.custom_checks: Dict[str, Callable] = {}

                                        async def check_device_health()
                                        self,
                                        device_id: str,
                                        config: Optional[HealthCheckConfig] = None,
                                        ) -> HealthCheckResult:
                                            """
                                            Check device health
                                            Args:
                                                device_id: Device ID
                                                config: Health check configuration
                                                Returns:
                                                    HealthCheckResult"""
                                                    config = config or HealthCheckConfig()
                                                    start_time = datetime.utcnow()

        # Initialize result
                                                    overall_status = HealthStatus.HEALTHY
                                                    results = []

        # Run configured health checks
                                                    for check_type in config.checks:
                                                        if check_type == HealthCheckType.CONNECTIVITY:
                                                            result = await self._check_connectivity(device_id)
                                                        elif check_type == HealthCheckType.PROTOCOL:
                                                            result = await self._check_protocols(device_id)
                                                        elif check_type == HealthCheckType.SERVICE:
                                                            result = await self._check_services(device_id)
                                                        elif check_type == HealthCheckType.PERFORMANCE:
                                                            result = await self._check_performance()
                                                            device_id,
                                                            config.thresholds
                                                            )
                                                        elif check_type == HealthCheckType.CONFIGURATION:
                                                            result = await self._check_configuration(device_id)
                                                        elif check_type == HealthCheckType.CUSTOM:
                                                            result = await self._run_custom_checks(device_id)
                                                        else:
                                                            continue

                                                        results.append(result)

            # Update overall status
                                                        if result.status == HealthStatus.UNHEALTHY:
                                                            overall_status = HealthStatus.UNHEALTHY
                                                        elif (:):
                                                        result.status == HealthStatus.DEGRADED
                                                        and overall_status != HealthStatus.UNHEALTHY
                                                        ):
                                                            overall_status = HealthStatus.DEGRADED

        # Calculate duration
                                                            duration_ms = int((datetime.utcnow() - start_time).total_seconds() *)
                                                            1000)

        # Create overall result
                                                            overall_result = HealthCheckResult()
                                                            check_type=HealthCheckType.CUSTOM,
                                                            status=overall_status,
                                                            timestamp=start_time,
                                                            device_id=device_id,
                                                            message=self._generate_health_message(overall_status, results),
                                                            details={"individual_results": results},
                                                            duration_ms=duration_ms,
                                                            )

        # Store result
                                                            if device_id not in self.health_checks:
                                                                self.health_checks[device_id] = []
                                                                self.health_checks[device_id].append(overall_result)

        # Keep only last 100 results per device
                                                                if len(self.health_checks[device_id]) > 100:
                                                                    self.health_checks[device_id] = \
                                                                    self.health_checks[device_id][-100:]

                                                                    return overall_result

                                                                async def start_continuous_monitoring()
                                                                self,
                                                                device_id: str,
                                                                config: Optional[HealthCheckConfig] = None,
                                                                callback: Optional[Callable] = None,
                                                                ) -> None:
                                                                    """
                                                                    Start continuous health monitoring
                                                                    Args:
                                                                        device_id: Device ID
                                                                        config: Health check configuration
                                                                        callback: Callback for health check results"""
                                                                        config = config or HealthCheckConfig()

        # Stop existing monitor if running
                                                                        await self.stop_monitoring(device_id)

        # Create monitoring task
                                                                        async def monitor():
                                                                            """TODO: Add docstring"""
                                                                            while True:
                                                                                try:
                                                                                    result = await self.check_device_health(device_id, config)

                    # Call callback if provided
                                                                                    if callback:
                                                                                        await callback(result)

                    # Check if we should alert
                                                                                        if result.status == HealthStatus.UNHEALTHY:
                                                                                            await self._trigger_health_alert(device_id, result)

                    # Wait for next interval
                                                                                            await asyncio.sleep(config.interval_seconds)

                                                                                        except asyncio.CancelledError:
                                                                                            break
                                                                                    except Exception as e:
                                                                                        print(f"Health monitoring error for {device_id}: {str(e)}")
                                                                                        await asyncio.sleep(config.interval_seconds)

        # Start monitoring
                                                                                        self.active_monitors[device_id] = asyncio.create_task(monitor())

                                                                                        async def stop_monitoring(self, device_id: str) -> None:
                                                                                            """
                                                                                            Stop health monitoring
                                                                                            Args:
                                                                                                device_id: Device ID"""
                                                                                                if device_id in self.active_monitors:
                                                                                                    self.active_monitors[device_id].cancel()
                                                                                                    try:
                                                                                                        await self.active_monitors[device_id]
                                                                                                    except asyncio.CancelledError:
                                                                                                        pass
                                                                                                    del self.active_monitors[device_id]

                                                                                                    async def _check_connectivity(self, device_id: str) -> HealthCheckResult:
                                                                                                        """
                                                                                                        Check device connectivity
                                                                                                        Args:
                                                                                                            device_id: Device ID
                                                                                                            Returns:
                                                                                                                HealthCheckResult"""
                                                                                                                start_time = datetime.utcnow()

                                                                                                                try:
            # Ping device
                                                                                                                    reachable = await self._ping_device(device_id)

            # Check SSH/API connectivity
                                                                                                                    management_accessible = await \
                                                                                                                    self._check_management_access(device_id)

                                                                                                                    if reachable and management_accessible:
                                                                                                                        status = HealthStatus.HEALTHY
                                                                                                                        message = "Device is reachable and manageable"
                                                                                                                    elif reachable and not management_accessible:
                                                                                                                        status = HealthStatus.DEGRADED
                                                                                                                        message = "Device is reachable but management access failed"
                                                                                                                    else:
                                                                                                                        status = HealthStatus.UNHEALTHY
                                                                                                                        message = "Device is unreachable"

                                                                                                                        return HealthCheckResult()
                                                                                                                    check_type=HealthCheckType.CONNECTIVITY,
                                                                                                                    status=status,
                                                                                                                    timestamp=start_time,
                                                                                                                    device_id=device_id,
                                                                                                                    message=message,
                                                                                                                    details={}
                                                                                                                    "ping_reachable": reachable,
                                                                                                                    "management_accessible": management_accessible,
                                                                                                                    },
                                                                                                                    )

                                                                                                                except Exception as e:
                                                                                                                    return HealthCheckResult()
                                                                                                                check_type=HealthCheckType.CONNECTIVITY,
                                                                                                                status=HealthStatus.UNKNOWN,
                                                                                                                timestamp=start_time,
                                                                                                                device_id=device_id,
                                                                                                                message=f"Connectivity check failed: {str(e)}",
                                                                                                                )

                                                                                                                async def _check_protocols(self, device_id: str) -> HealthCheckResult:
                                                                                                                    """
                                                                                                                    Check protocol status
                                                                                                                    Args:
                                                                                                                        device_id: Device ID
                                                                                                                        Returns:
                                                                                                                            HealthCheckResult"""
                                                                                                                            start_time = datetime.utcnow()

                                                                                                                            try:
                                                                                                                                protocol_status = {}
                                                                                                                                unhealthy_protocols = []

            # Check routing protocols
                                                                                                                                routing_protocols = await self._get_routing_protocol_status()
                                                                                                                                device_id)
                                                                                                                                for protocol, status in routing_protocols.items():
                                                                                                                                    protocol_status[protocol] = status
                                                                                                                                    if status != "up":
                                                                                                                                        unhealthy_protocols.append(protocol)

            # Check spanning tree
                                                                                                                                        stp_status = await self._get_stp_status(device_id)
                                                                                                                                        protocol_status["stp"] = stp_status
                                                                                                                                        if stp_status == "blocking" or stp_status == "error":
                                                                                                                                            unhealthy_protocols.append("stp")

            # Determine overall status
                                                                                                                                            if not unhealthy_protocols:
                                                                                                                                                status = HealthStatus.HEALTHY
                                                                                                                                                message = "All protocols operational"
                                                                                                                                            elif len(unhealthy_protocols) == 1:
                                                                                                                                                status = HealthStatus.DEGRADED
                                                                                                                                                message = f"Protocol issue: {unhealthy_protocols[0]}"
                                                                                                                                            else:
                                                                                                                                                status = HealthStatus.UNHEALTHY
                                                                                                                                                message = f"Multiple protocol issues: {', '.join("}")}
                                                                                                                                                unhealthy_protocols}"
                                                                                                                                                )}"

                                                                                                                                                return HealthCheckResult()
                                                                                                                                            check_type=HealthCheckType.PROTOCOL,
                                                                                                                                            status=status,
                                                                                                                                            timestamp=start_time,
                                                                                                                                            device_id=device_id,
                                                                                                                                            message=message,
                                                                                                                                            details={"protocols": protocol_status},
                                                                                                                                            )

                                                                                                                                        except Exception as e:
                                                                                                                                            return HealthCheckResult()
                                                                                                                                        check_type=HealthCheckType.PROTOCOL,
                                                                                                                                        status=HealthStatus.UNKNOWN,
                                                                                                                                        timestamp=start_time,
                                                                                                                                        device_id=device_id,
                                                                                                                                        message=f"Protocol check failed: {str(e)}",
                                                                                                                                        )

                                                                                                                                        async def _check_services(self, device_id: str) -> HealthCheckResult:
                                                                                                                                            """
                                                                                                                                            Check critical services
                                                                                                                                            Args:
                                                                                                                                                device_id: Device ID
                                                                                                                                                Returns:
                                                                                                                                                    HealthCheckResult"""
                                                                                                                                                    start_time = datetime.utcnow()

                                                                                                                                                    try:
                                                                                                                                                        services_status = {}
                                                                                                                                                        failed_services = []

            # Check critical services
                                                                                                                                                        critical_services = ["ntp", "logging", "snmp", "aaa"]
                                                                                                                                                        for service in critical_services:
                                                                                                                                                            status = await self._get_service_status(device_id, service)
                                                                                                                                                            services_status[service] = status
                                                                                                                                                            if status != "running":
                                                                                                                                                                failed_services.append(service)

            # Determine overall status
                                                                                                                                                                if not failed_services:
                                                                                                                                                                    status = HealthStatus.HEALTHY
                                                                                                                                                                    message = "All critical services running"
                                                                                                                                                                elif len(failed_services) <= 1:
                                                                                                                                                                    status = HealthStatus.DEGRADED
                                                                                                                                                                    message = f"Service issue: {failed_services[0]}"
                                                                                                                                                                else:
                                                                                                                                                                    status = HealthStatus.UNHEALTHY
                                                                                                                                                                    message = f"Multiple service failures: {', '.join("}")}
                                                                                                                                                                    failed_services}"
                                                                                                                                                                    )}"

                                                                                                                                                                    return HealthCheckResult()
                                                                                                                                                                check_type=HealthCheckType.SERVICE,
                                                                                                                                                                status=status,
                                                                                                                                                                timestamp=start_time,
                                                                                                                                                                device_id=device_id,
                                                                                                                                                                message=message,
                                                                                                                                                                details={"services": services_status},
                                                                                                                                                                )

                                                                                                                                                            except Exception as e:
                                                                                                                                                                return HealthCheckResult()
                                                                                                                                                            check_type=HealthCheckType.SERVICE,
                                                                                                                                                            status=HealthStatus.UNKNOWN,
                                                                                                                                                            timestamp=start_time,
                                                                                                                                                            device_id=device_id,
                                                                                                                                                            message=f"Service check failed: {str(e)}",
                                                                                                                                                            )

                                                                                                                                                            async def _check_performance()
                                                                                                                                                            self, device_id: str, thresholds: Dict[str, Dict[str, float]]
                                                                                                                                                            ) -> HealthCheckResult:
                                                                                                                                                                """
                                                                                                                                                                Check performance metrics
                                                                                                                                                                Args:
                                                                                                                                                                    device_id: Device ID
                                                                                                                                                                    thresholds: Performance thresholds
                                                                                                                                                                    Returns:
                                                                                                                                                                        HealthCheckResult"""
                                                                                                                                                                        start_time = datetime.utcnow()

                                                                                                                                                                        try:
                                                                                                                                                                            metrics = []
                                                                                                                                                                            issues = []

            # Get performance metrics
                                                                                                                                                                            perf_data = await self._get_performance_metrics(device_id)

            # Check CPU usage
                                                                                                                                                                            cpu_usage = perf_data.get("cpu_usage", 0)
                                                                                                                                                                            cpu_metric = HealthMetric()
                                                                                                                                                                            name="CPU Usage",
                                                                                                                                                                            type=MetricType.CPU_USAGE,
                                                                                                                                                                            value=cpu_usage,
                                                                                                                                                                            threshold_warning=thresholds["cpu_usage"]["warning"],
                                                                                                                                                                            threshold_critical=thresholds["cpu_usage"]["critical"],
                                                                                                                                                                            unit="%",
                                                                                                                                                                            timestamp=start_time,
                                                                                                                                                                            )

                                                                                                                                                                            if cpu_usage >= thresholds["cpu_usage"]["critical"]:
                                                                                                                                                                                cpu_metric.status = HealthStatus.UNHEALTHY
                                                                                                                                                                                issues.append(f"Critical CPU usage: {cpu_usage}%")
                                                                                                                                                                            elif cpu_usage >= thresholds["cpu_usage"]["warning"]:
                                                                                                                                                                                cpu_metric.status = HealthStatus.DEGRADED
                                                                                                                                                                                issues.append(f"High CPU usage: {cpu_usage}%")
                                                                                                                                                                            else:
                                                                                                                                                                                cpu_metric.status = HealthStatus.HEALTHY

                                                                                                                                                                                metrics.append(cpu_metric)

            # Check memory usage
                                                                                                                                                                                memory_usage = perf_data.get("memory_usage", 0)
                                                                                                                                                                                memory_metric = HealthMetric()
                                                                                                                                                                                name="Memory Usage",
                                                                                                                                                                                type=MetricType.MEMORY_USAGE,
                                                                                                                                                                                value=memory_usage,
                                                                                                                                                                                threshold_warning=thresholds["memory_usage"]["warning"],
                                                                                                                                                                                threshold_critical=thresholds["memory_usage"]["critical"],
                                                                                                                                                                                unit="%",
                                                                                                                                                                                timestamp=start_time,
                                                                                                                                                                                )

                                                                                                                                                                                if memory_usage >= thresholds["memory_usage"]["critical"]:
                                                                                                                                                                                    memory_metric.status = HealthStatus.UNHEALTHY
                                                                                                                                                                                    issues.append(f"Critical memory usage: {memory_usage}%")
                                                                                                                                                                                elif memory_usage >= thresholds["memory_usage"]["warning"]:
                                                                                                                                                                                    memory_metric.status = HealthStatus.DEGRADED
                                                                                                                                                                                    issues.append(f"High memory usage: {memory_usage}%")
                                                                                                                                                                                else:
                                                                                                                                                                                    memory_metric.status = HealthStatus.HEALTHY

                                                                                                                                                                                    metrics.append(memory_metric)

            # Determine overall status
                                                                                                                                                                                    unhealthy_metrics = []
                                                                                                                                                                                    m for m in metrics if m.status == HealthStatus.UNHEALTHY
                                                                                                                                                                                    ]
                                                                                                                                                                                    degraded_metrics = [m for m in metrics if m.status ==]
                                                                                                                                                                                    HealthStatus.DEGRADED]

                                                                                                                                                                                    if unhealthy_metrics:
                                                                                                                                                                                        status = HealthStatus.UNHEALTHY
                                                                                                                                                                                        message = f"Performance issues: {', '.join(issues)}"
                                                                                                                                                                                    elif degraded_metrics:
                                                                                                                                                                                        status = HealthStatus.DEGRADED
                                                                                                                                                                                        message = f"Performance warnings: {', '.join(issues)}"
                                                                                                                                                                                    else:
                                                                                                                                                                                        status = HealthStatus.HEALTHY
                                                                                                                                                                                        message = "Performance metrics within normal range"

                                                                                                                                                                                        return HealthCheckResult()
                                                                                                                                                                                    check_type=HealthCheckType.PERFORMANCE,
                                                                                                                                                                                    status=status,
                                                                                                                                                                                    timestamp=start_time,
                                                                                                                                                                                    device_id=device_id,
                                                                                                                                                                                    message=message,
                                                                                                                                                                                    metrics=metrics,
                                                                                                                                                                                    details={"raw_metrics": perf_data},
                                                                                                                                                                                    )

                                                                                                                                                                                except Exception as e:
                                                                                                                                                                                    return HealthCheckResult()
                                                                                                                                                                                check_type=HealthCheckType.PERFORMANCE,
                                                                                                                                                                                status=HealthStatus.UNKNOWN,
                                                                                                                                                                                timestamp=start_time,
                                                                                                                                                                                device_id=device_id,
                                                                                                                                                                                message=f"Performance check failed: {str(e)}",
                                                                                                                                                                                )

                                                                                                                                                                                async def _check_configuration(self, device_id: str) -> HealthCheckResult:
                                                                                                                                                                                    """
                                                                                                                                                                                    Check configuration consistency
                                                                                                                                                                                    Args:
                                                                                                                                                                                        device_id: Device ID
                                                                                                                                                                                        Returns:
                                                                                                                                                                                            HealthCheckResult"""
                                                                                                                                                                                            start_time = datetime.utcnow()

                                                                                                                                                                                            try:
            # Check configuration consistency
                                                                                                                                                                                                config_consistent = await self._verify_configuration_consistency()
                                                                                                                                                                                                device_id)

            # Check for configuration drift
                                                                                                                                                                                                has_drift = await self._check_configuration_drift(device_id)

                                                                                                                                                                                                if config_consistent and not has_drift:
                                                                                                                                                                                                    status = HealthStatus.HEALTHY
                                                                                                                                                                                                    message = "Configuration is consistent"
                                                                                                                                                                                                elif config_consistent and has_drift:
                                                                                                                                                                                                    status = HealthStatus.DEGRADED
                                                                                                                                                                                                    message = "Configuration drift detected"
                                                                                                                                                                                                else:
                                                                                                                                                                                                    status = HealthStatus.UNHEALTHY
                                                                                                                                                                                                    message = "Configuration inconsistency detected"

                                                                                                                                                                                                    return HealthCheckResult()
                                                                                                                                                                                                check_type=HealthCheckType.CONFIGURATION,
                                                                                                                                                                                                status=status,
                                                                                                                                                                                                timestamp=start_time,
                                                                                                                                                                                                device_id=device_id,
                                                                                                                                                                                                message=message,
                                                                                                                                                                                                details={}
                                                                                                                                                                                                "consistent": config_consistent,
                                                                                                                                                                                                "has_drift": has_drift,
                                                                                                                                                                                                },
                                                                                                                                                                                                )

                                                                                                                                                                                            except Exception as e:
                                                                                                                                                                                                return HealthCheckResult()
                                                                                                                                                                                            check_type=HealthCheckType.CONFIGURATION,
                                                                                                                                                                                            status=HealthStatus.UNKNOWN,
                                                                                                                                                                                            timestamp=start_time,
                                                                                                                                                                                            device_id=device_id,
                                                                                                                                                                                            message=f"Configuration check failed: {str(e)}",
                                                                                                                                                                                            )

                                                                                                                                                                                            async def _run_custom_checks(self, device_id: str) -> HealthCheckResult:
                                                                                                                                                                                                """
                                                                                                                                                                                                Run custom health checks
                                                                                                                                                                                                Args:
                                                                                                                                                                                                    device_id: Device ID
                                                                                                                                                                                                    Returns:
                                                                                                                                                                                                        HealthCheckResult"""
                                                                                                                                                                                                        start_time = datetime.utcnow()

                                                                                                                                                                                                        if not self.custom_checks:
                                                                                                                                                                                                            return HealthCheckResult()
                                                                                                                                                                                                        check_type=HealthCheckType.CUSTOM,
                                                                                                                                                                                                        status=HealthStatus.HEALTHY,
                                                                                                                                                                                                        timestamp=start_time,
                                                                                                                                                                                                        device_id=device_id,
                                                                                                                                                                                                        message="No custom checks configured",
                                                                                                                                                                                                        )

                                                                                                                                                                                                        try:
                                                                                                                                                                                                            results = {}
                                                                                                                                                                                                            for check_name, check_func in self.custom_checks.items():
                                                                                                                                                                                                                results[check_name] = await check_func(device_id)

            # Aggregate results
                                                                                                                                                                                                                failed_checks = [name for name, result in results.items(

                                                                                                                                                                                                                ) if not result]

                                                                                                                                                                                                                if not failed_checks:
                                                                                                                                                                                                                    status = HealthStatus.HEALTHY
                                                                                                                                                                                                                    message = "All custom checks passed"
                                                                                                                                                                                                                else:
                                                                                                                                                                                                                    status = HealthStatus.UNHEALTHY
                                                                                                                                                                                                                    message = f"Custom checks failed: {', '.join(failed_checks)}"

                                                                                                                                                                                                                    return HealthCheckResult()
                                                                                                                                                                                                                check_type=HealthCheckType.CUSTOM,
                                                                                                                                                                                                                status=status,
                                                                                                                                                                                                                timestamp=start_time,
                                                                                                                                                                                                                device_id=device_id,
                                                                                                                                                                                                                message=message,
                                                                                                                                                                                                                details={"custom_results": results},
                                                                                                                                                                                                                )

                                                                                                                                                                                                            except Exception as e:
                                                                                                                                                                                                                return HealthCheckResult()
                                                                                                                                                                                                            check_type=HealthCheckType.CUSTOM,
                                                                                                                                                                                                            status=HealthStatus.UNKNOWN,
                                                                                                                                                                                                            timestamp=start_time,
                                                                                                                                                                                                            device_id=device_id,
                                                                                                                                                                                                            message=f"Custom checks failed: {str(e)}",
                                                                                                                                                                                                            )

                                                                                                                                                                                                            def register_custom_check(self, name: str, check_func: Callable) -> None:
                                                                                                                                                                                                                """
                                                                                                                                                                                                                Register a custom health check
                                                                                                                                                                                                                Args:
                                                                                                                                                                                                                    name: Check name
                                                                                                                                                                                                                    check_func: Check function"""
                                                                                                                                                                                                                    self.custom_checks[name] = check_func

                                                                                                                                                                                                                    def get_health_history(:):
                                                                                                                                                                                                                    self,
                                                                                                                                                                                                                    device_id: str,
                                                                                                                                                                                                                    hours: int = 24,
                                                                                                                                                                                                                    ) -> List[HealthCheckResult]:
                                                                                                                                                                                                                        """
                                                                                                                                                                                                                        Get health check history
                                                                                                                                                                                                                        Args:
                                                                                                                                                                                                                            device_id: Device ID
                                                                                                                                                                                                                            hours: Hours of history
                                                                                                                                                                                                                            Returns:
                                                                                                                                                                                                                                List of health check results"""
                                                                                                                                                                                                                                if device_id not in self.health_checks:
                                                                                                                                                                                                                                    return []

                                                                                                                                                                                                                                cutoff_time = datetime.utcnow() - timedelta(hours=hours)
                                                                                                                                                                                                                                return []
                                                                                                                                                                                                                            result
                                                                                                                                                                                                                            for result in self.health_checks[device_id]:
                                                                                                                                                                                                                                if result.timestamp >= cutoff_time:
                                                                                                                                                                                                                                    ]

                                                                                                                                                                                                                                    def _generate_health_message(:):
                                                                                                                                                                                                                                    self, status: HealthStatus, results: List[HealthCheckResult]
                                                                                                                                                                                                                                    ) -> str:
                                                                                                                                                                                                                                        """Generate health status message"""
                                                                                                                                                                                                                                        if status == HealthStatus.HEALTHY:
                                                                                                                                                                                                                                            return "All health checks passed"

                                                                                                                                                                                                                                        issues = []
                                                                                                                                                                                                                                        for result in results:
                                                                                                                                                                                                                                            if result.status != HealthStatus.HEALTHY:
                                                                                                                                                                                                                                                issues.append(f"{result.check_type.value}: {result.message}")

                                                                                                                                                                                                                                                return f"Health issues detected: {'; '.join(issues)}"

    # Helper methods (would integrate with actual device service)
                                                                                                                                                                                                                                            async def _ping_device(self, device_id: str) -> bool:
                                                                                                                                                                                                                                                """Ping device"""
                                                                                                                                                                                                                                                if self.device_service:
                                                                                                                                                                                                                                                    return await self.device_service.ping(device_id)
                                                                                                                                                                                                                                                return True

                                                                                                                                                                                                                                            async def _check_management_access(self, device_id: str) -> bool:"""Check management access"""
                                                                                                                                                                                                                                            if self.device_service:
                                                                                                                                                                                                                                                return await self.device_service.check_management_access(device_id)
                                                                                                                                                                                                                                            return True

                                                                                                                                                                                                                                        async def _get_routing_protocol_status()
                                                                                                                                                                                                                                        self,
                                                                                                                                                                                                                                        device_id: str
                                                                                                                                                                                                                                        ) -> Dict[str, str]:"""Get routing protocol status"""
                                                                                                                                                                                                                                        if self.device_service:
                                                                                                                                                                                                                                            return await self.device_service.get_routing_protocols(device_id)
                                                                                                                                                                                                                                        return {"ospf": "up", "bgp": "up"}

                                                                                                                                                                                                                                    async def _get_stp_status(self, device_id: str) -> str:
                                                                                                                                                                                                                                        """Get STP status"""
                                                                                                                                                                                                                                        if self.device_service:
                                                                                                                                                                                                                                            return await self.device_service.get_stp_status(device_id)
                                                                                                                                                                                                                                        return "forwarding"

                                                                                                                                                                                                                                    async def _get_service_status(self, device_id: str, service: str) -> str:
                                                                                                                                                                                                                                        """Get service status"""
                                                                                                                                                                                                                                        if self.device_service:
                                                                                                                                                                                                                                            return await self.device_service.get_service_status()
                                                                                                                                                                                                                                        device_id,
                                                                                                                                                                                                                                        service
                                                                                                                                                                                                                                        )
                                                                                                                                                                                                                                        return "running"

                                                                                                                                                                                                                                    async def _get_performance_metrics()
                                                                                                                                                                                                                                    self,
                                                                                                                                                                                                                                    device_id: str
                                                                                                                                                                                                                                    ) -> Dict[str, float]:
                                                                                                                                                                                                                                        """Get performance metrics"""
                                                                                                                                                                                                                                        if self.device_service:
                                                                                                                                                                                                                                            return await self.device_service.get_performance_metrics(device_id)
                                                                                                                                                                                                                                        return {}
                                                                                                                                                                                                                                    "cpu_usage": 45.0,
                                                                                                                                                                                                                                    "memory_usage": 60.0,
                                                                                                                                                                                                                                    "interface_errors": 0,
                                                                                                                                                                                                                                    "packet_loss": 0.0,
                                                                                                                                                                                                                                    }

                                                                                                                                                                                                                                    async def _verify_configuration_consistency(self, device_id: str) -> bool:
                                                                                                                                                                                                                                        """Verify configuration consistency"""
                                                                                                                                                                                                                                        if self.device_service:
                                                                                                                                                                                                                                            return await self.device_service.verify_config_consistency()
                                                                                                                                                                                                                                        device_id)
                                                                                                                                                                                                                                        return True

                                                                                                                                                                                                                                    async def _check_configuration_drift(self, device_id: str) -> bool:"""Check for configuration drift"""
                                                                                                                                                                                                                                    if self.device_service:
                                                                                                                                                                                                                                        return await self.device_service.check_config_drift(device_id)
                                                                                                                                                                                                                                    return False

                                                                                                                                                                                                                                async def _trigger_health_alert()
                                                                                                                                                                                                                                self, device_id: str, result: HealthCheckResult
                                                                                                                                                                                                                                ) -> None:"""Trigger health alert"""
        # Would send actual alert
                                                                                                                                                                                                                                print()
                                                                                                                                                                                                                                f"HEALTH ALERT: Device {device_id} is {result.status.value}: {}"
                                                                                                                                                                                                                                result.message}"
                                                                                                                                                                                                                                )

"""
Monitoring and Health Check API Endpoints
RESTful API for health monitoring, SLA tracking, and alerting
"""
from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks, Query
from typing import List, Optional
from datetime import datetime, timedelta
from pydantic import BaseModel, Field
import structlog

from src.db.session import get_db
from src.db.models.monitoring import (
    HealthCheck,
    HealthCheckResult,
    HealthCheckType,
    HealthStatus,
    SLA,
    SLAViolation,
    SLAMetric,
    SLAStatus,
    AlertRule,
    Alert,
    AlertStatus,
    AlertSeverity,
    MonitoringDashboard,
    MetricData
)
from src.monitoring.health_monitor import health_monitor, sla_monitor
from src.auth.dependencies import get_current_user, get_current_admin_user

logger = structlog.get_logger()

router = APIRouter(
    prefix="/api/v1/monitoring",
    tags=["monitoring"]
)


# Pydantic Models

class HealthCheckRequest(BaseModel):
    """Request model for creating health check"""
    name: str = Field(..., description="Health check name")
    description: Optional[str] = None
    check_type: HealthCheckType
    target: str = Field(..., description="Target IP, URL, or device ID")
    check_config: dict = Field({}, description="Type-specific configuration")
    interval_seconds: int = Field(60, ge=10, le=3600)
    timeout_seconds: int = Field(10, ge=1, le=60)
    retry_count: int = Field(3, ge=0, le=10)
    expected_response: Optional[dict] = None
    tags: List[str] = Field([], description="Tags for grouping")

    class Config:
        schema_extra = {
            "example": {
                "name": "Core Router HTTP Check",
                "check_type": "http",
                "target": "https://router1.example.com/health",
                "check_config": {
                    "method": "GET",
                    "expected_status": 200
                },
                "interval_seconds": 60,
                "timeout_seconds": 10,
                "tags": ["core", "router"]
            }
        }


class HealthCheckResponse(BaseModel):
    """Response model for health check"""
    id: str
    name: str
    check_type: HealthCheckType
    target: str
    current_status: HealthStatus
    enabled: bool
    last_check_at: Optional[datetime]
    consecutive_successes: int
    consecutive_failures: int
    interval_seconds: int

    class Config:
        orm_mode = True


class HealthCheckResultResponse(BaseModel):
    """Response model for health check result"""
    id: str
    health_check_id: str
    executed_at: datetime
    status: HealthStatus
    success: bool
    duration_ms: float
    response_time_ms: Optional[float]
    error_message: Optional[str]

    class Config:
        orm_mode = True


class SLARequest(BaseModel):
    """Request model for creating SLA"""
    name: str = Field(..., description="SLA name")
    description: Optional[str] = None
    target_type: str = Field(..., description="Target type (device, service, endpoint)")
    target_id: Optional[str] = None
    availability_target: Optional[float] = Field(None, ge=0, le=100)
    response_time_target_ms: Optional[float] = Field(None, ge=0)
    error_rate_target: Optional[float] = Field(None, ge=0, le=100)
    measurement_window_hours: int = Field(24, ge=1, le=720)
    tags: List[str] = Field([], description="Tags for grouping")

    class Config:
        schema_extra = {
            "example": {
                "name": "Core Infrastructure SLA",
                "target_type": "device",
                "target_id": "router-001",
                "availability_target": 99.9,
                "response_time_target_ms": 100.0,
                "measurement_window_hours": 24,
                "tags": ["production", "core"]
            }
        }


class SLAResponse(BaseModel):
    """Response model for SLA"""
    id: str
    name: str
    target_type: str
    target_id: Optional[str]
    availability_target: Optional[float]
    response_time_target_ms: Optional[float]
    current_availability: float
    current_response_time_ms: Optional[float]
    compliance_status: SLAStatus
    last_violation_at: Optional[datetime]
    violation_count: int
    enabled: bool

    class Config:
        orm_mode = True


class AlertRuleRequest(BaseModel):
    """Request model for creating alert rule"""
    name: str = Field(..., description="Alert rule name")
    description: Optional[str] = None
    health_check_id: Optional[str] = None
    sla_id: Optional[str] = None
    condition_type: str = Field(..., description="Condition type")
    condition_config: dict = Field(..., description="Condition configuration")
    severity: AlertSeverity
    message_template: str = Field(..., description="Alert message template")
    notification_channels: List[str] = Field(..., description="Notification channels")
    cooldown_minutes: int = Field(30, ge=0, le=1440)
    tags: List[str] = Field([], description="Tags for grouping")

    class Config:
        schema_extra = {
            "example": {
                "name": "Router Down Alert",
                "health_check_id": "check-uuid",
                "condition_type": "status_change",
                "condition_config": {"from": "healthy", "to": "unhealthy"},
                "severity": "critical",
                "message_template": "Health check {check_name} status: {status}",
                "notification_channels": ["email", "slack"],
                "cooldown_minutes": 30
            }
        }


class AlertRuleResponse(BaseModel):
    """Response model for alert rule"""
    id: str
    name: str
    severity: AlertSeverity
    enabled: bool
    last_triggered_at: Optional[datetime]
    trigger_count: int

    class Config:
        orm_mode = True


class AlertResponse(BaseModel):
    """Response model for alert"""
    id: str
    alert_rule_id: str
    severity: AlertSeverity
    title: str
    message: str
    status: AlertStatus
    triggered_at: datetime
    acknowledged_at: Optional[datetime]
    resolved_at: Optional[datetime]

    class Config:
        orm_mode = True


# Health Check Endpoints

@router.post("/health-checks", response_model=HealthCheckResponse, status_code=status.HTTP_201_CREATED)
async def create_health_check(
    request: HealthCheckRequest,
    db = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """
    Create new health check

    Creates a health check that will be executed on the specified interval.
    Supports HTTP, TCP, ICMP, SSH, SNMP, NETCONF, and custom checks.

    Requires: User authentication
    """
    logger.info(
        "Creating health check",
        name=request.name,
        type=request.check_type,
        user=current_user.id
    )

    health_check = HealthCheck(
        name=request.name,
        description=request.description,
        check_type=request.check_type,
        target=request.target,
        check_config=request.check_config,
        interval_seconds=request.interval_seconds,
        timeout_seconds=request.timeout_seconds,
        retry_count=request.retry_count,
        expected_response=request.expected_response,
        tags=request.tags,
        created_by=current_user.id
    )

    db.add(health_check)
    await db.commit()
    await db.refresh(health_check)

    logger.info("Health check created", check_id=health_check.id)

    return health_check


@router.get("/health-checks", response_model=List[HealthCheckResponse])
async def list_health_checks(
    status: Optional[HealthStatus] = None,
    enabled: Optional[bool] = None,
    tags: Optional[List[str]] = Query(None),
    limit: int = 100,
    offset: int = 0,
    db = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """
    List health checks

    Returns health checks with optional filters.

    Requires: User authentication
    """
    query = db.query(HealthCheck)

    if status:
        query = query.filter(HealthCheck.current_status == status)

    if enabled is not None:
        query = query.filter(HealthCheck.enabled == enabled)

    if tags:
        # Filter by tags (PostgreSQL array contains)
        for tag in tags:
            query = query.filter(HealthCheck.tags.contains([tag]))

    checks = await query.order_by(
        HealthCheck.created_at.desc()
    ).offset(offset).limit(limit).all()

    return checks


@router.get("/health-checks/{check_id}", response_model=HealthCheckResponse)
async def get_health_check(
    check_id: str,
    db = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """
    Get health check details

    Requires: User authentication
    """
    check = await db.query(HealthCheck).filter(
        HealthCheck.id == check_id
    ).first()

    if not check:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Health check {check_id} not found"
        )

    return check


@router.patch("/health-checks/{check_id}/enable")
async def enable_health_check(
    check_id: str,
    db = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """
    Enable health check

    Requires: User authentication
    """
    check = await db.query(HealthCheck).filter(
        HealthCheck.id == check_id
    ).first()

    if not check:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Health check {check_id} not found"
        )

    check.enabled = True
    await db.commit()

    logger.info("Health check enabled", check_id=check_id, user=current_user.id)

    return {"status": "enabled", "check_id": check_id}


@router.patch("/health-checks/{check_id}/disable")
async def disable_health_check(
    check_id: str,
    db = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """
    Disable health check

    Requires: User authentication
    """
    check = await db.query(HealthCheck).filter(
        HealthCheck.id == check_id
    ).first()

    if not check:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Health check {check_id} not found"
        )

    check.enabled = False
    await db.commit()

    logger.info("Health check disabled", check_id=check_id, user=current_user.id)

    return {"status": "disabled", "check_id": check_id}


@router.post("/health-checks/{check_id}/execute")
async def execute_health_check_now(
    check_id: str,
    background_tasks: BackgroundTasks,
    db = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """
    Execute health check immediately

    Triggers an immediate execution of the health check outside of its normal schedule.

    Requires: User authentication
    """
    check = await db.query(HealthCheck).filter(
        HealthCheck.id == check_id
    ).first()

    if not check:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Health check {check_id} not found"
        )

    # Execute in background
    background_tasks.add_task(
        health_monitor.execute_health_check,
        check,
        db
    )

    logger.info("Manual health check execution triggered", check_id=check_id, user=current_user.id)

    return {"status": "executing", "check_id": check_id}


@router.get("/health-checks/{check_id}/results", response_model=List[HealthCheckResultResponse])
async def get_health_check_results(
    check_id: str,
    hours: int = Query(24, ge=1, le=720),
    limit: int = 100,
    offset: int = 0,
    db = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """
    Get health check results

    Returns recent health check execution results.

    Requires: User authentication
    """
    since = datetime.utcnow() - timedelta(hours=hours)

    results = await db.query(HealthCheckResult).filter(
        HealthCheckResult.health_check_id == check_id,
        HealthCheckResult.executed_at >= since
    ).order_by(
        HealthCheckResult.executed_at.desc()
    ).offset(offset).limit(limit).all()

    return results


@router.delete("/health-checks/{check_id}")
async def delete_health_check(
    check_id: str,
    db = Depends(get_db),
    current_user = Depends(get_current_admin_user)
):
    """
    Delete health check

    Requires: Admin authentication
    """
    check = await db.query(HealthCheck).filter(
        HealthCheck.id == check_id
    ).first()

    if not check:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Health check {check_id} not found"
        )

    await db.delete(check)
    await db.commit()

    logger.info("Health check deleted", check_id=check_id, user=current_user.id)

    return {"status": "deleted", "check_id": check_id}


# SLA Endpoints

@router.post("/slas", response_model=SLAResponse, status_code=status.HTTP_201_CREATED)
async def create_sla(
    request: SLARequest,
    db = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """
    Create new SLA

    Defines service level agreement with availability and performance targets.

    Requires: User authentication
    """
    logger.info(
        "Creating SLA",
        name=request.name,
        target=request.target_type,
        user=current_user.id
    )

    sla = SLA(
        name=request.name,
        description=request.description,
        target_type=request.target_type,
        target_id=request.target_id,
        availability_target=request.availability_target,
        response_time_target_ms=request.response_time_target_ms,
        error_rate_target=request.error_rate_target,
        measurement_window_hours=request.measurement_window_hours,
        tags=request.tags,
        created_by=current_user.id
    )

    db.add(sla)
    await db.commit()
    await db.refresh(sla)

    logger.info("SLA created", sla_id=sla.id)

    return sla


@router.get("/slas", response_model=List[SLAResponse])
async def list_slas(
    compliance_status: Optional[SLAStatus] = None,
    limit: int = 100,
    offset: int = 0,
    db = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """
    List SLAs

    Returns SLAs with optional compliance status filter.

    Requires: User authentication
    """
    query = db.query(SLA)

    if compliance_status:
        query = query.filter(SLA.compliance_status == compliance_status)

    slas = await query.order_by(
        SLA.created_at.desc()
    ).offset(offset).limit(limit).all()

    return slas


@router.get("/slas/{sla_id}", response_model=SLAResponse)
async def get_sla(
    sla_id: str,
    db = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """
    Get SLA details

    Requires: User authentication
    """
    sla = await db.query(SLA).filter(SLA.id == sla_id).first()

    if not sla:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"SLA {sla_id} not found"
        )

    return sla


@router.get("/slas/{sla_id}/violations")
async def get_sla_violations(
    sla_id: str,
    hours: int = Query(168, ge=1, le=8760),
    limit: int = 100,
    offset: int = 0,
    db = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """
    Get SLA violations

    Returns violations for the specified SLA within the time window.

    Requires: User authentication
    """
    since = datetime.utcnow() - timedelta(hours=hours)

    violations = await db.query(SLAViolation).filter(
        SLAViolation.sla_id == sla_id,
        SLAViolation.detected_at >= since
    ).order_by(
        SLAViolation.detected_at.desc()
    ).offset(offset).limit(limit).all()

    return violations


@router.get("/slas/{sla_id}/metrics")
async def get_sla_metrics(
    sla_id: str,
    hours: int = Query(24, ge=1, le=720),
    limit: int = 1000,
    offset: int = 0,
    db = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """
    Get SLA metrics

    Returns time-series metrics for the specified SLA.

    Requires: User authentication
    """
    since = datetime.utcnow() - timedelta(hours=hours)

    metrics = await db.query(SLAMetric).filter(
        SLAMetric.sla_id == sla_id,
        SLAMetric.timestamp >= since
    ).order_by(
        SLAMetric.timestamp.desc()
    ).offset(offset).limit(limit).all()

    return metrics


# Alert Rule Endpoints

@router.post("/alert-rules", response_model=AlertRuleResponse, status_code=status.HTTP_201_CREATED)
async def create_alert_rule(
    request: AlertRuleRequest,
    db = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """
    Create alert rule

    Defines conditions and actions for generating alerts.

    Requires: User authentication
    """
    logger.info(
        "Creating alert rule",
        name=request.name,
        severity=request.severity,
        user=current_user.id
    )

    alert_rule = AlertRule(
        name=request.name,
        description=request.description,
        health_check_id=request.health_check_id,
        sla_id=request.sla_id,
        condition_type=request.condition_type,
        condition_config=request.condition_config,
        severity=request.severity,
        message_template=request.message_template,
        notification_channels=request.notification_channels,
        cooldown_minutes=request.cooldown_minutes,
        tags=request.tags,
        created_by=current_user.id
    )

    db.add(alert_rule)
    await db.commit()
    await db.refresh(alert_rule)

    logger.info("Alert rule created", rule_id=alert_rule.id)

    return alert_rule


@router.get("/alert-rules", response_model=List[AlertRuleResponse])
async def list_alert_rules(
    enabled: Optional[bool] = None,
    limit: int = 100,
    offset: int = 0,
    db = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """
    List alert rules

    Requires: User authentication
    """
    query = db.query(AlertRule)

    if enabled is not None:
        query = query.filter(AlertRule.enabled == enabled)

    rules = await query.order_by(
        AlertRule.created_at.desc()
    ).offset(offset).limit(limit).all()

    return rules


# Alert Endpoints

@router.get("/alerts", response_model=List[AlertResponse])
async def list_alerts(
    alert_status: Optional[AlertStatus] = None,
    severity: Optional[AlertSeverity] = None,
    hours: int = Query(24, ge=1, le=720),
    limit: int = 100,
    offset: int = 0,
    db = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """
    List alerts

    Returns alerts with optional filters.

    Requires: User authentication
    """
    since = datetime.utcnow() - timedelta(hours=hours)
    query = db.query(Alert).filter(Alert.triggered_at >= since)

    if alert_status:
        query = query.filter(Alert.status == alert_status)

    if severity:
        query = query.filter(Alert.severity == severity)

    alerts = await query.order_by(
        Alert.triggered_at.desc()
    ).offset(offset).limit(limit).all()

    return alerts


@router.post("/alerts/{alert_id}/acknowledge")
async def acknowledge_alert(
    alert_id: str,
    db = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """
    Acknowledge alert

    Requires: User authentication
    """
    alert = await db.query(Alert).filter(Alert.id == alert_id).first()

    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert {alert_id} not found"
        )

    alert.status = AlertStatus.ACKNOWLEDGED
    alert.acknowledged_at = datetime.utcnow()
    alert.acknowledged_by = current_user.id

    await db.commit()

    logger.info("Alert acknowledged", alert_id=alert_id, user=current_user.id)

    return {"status": "acknowledged", "alert_id": alert_id}


@router.post("/alerts/{alert_id}/resolve")
async def resolve_alert(
    alert_id: str,
    resolution_notes: Optional[str] = None,
    db = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """
    Resolve alert

    Requires: User authentication
    """
    alert = await db.query(Alert).filter(Alert.id == alert_id).first()

    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert {alert_id} not found"
        )

    alert.status = AlertStatus.RESOLVED
    alert.resolved_at = datetime.utcnow()
    alert.resolved_by = current_user.id
    alert.resolution_notes = resolution_notes

    await db.commit()

    logger.info("Alert resolved", alert_id=alert_id, user=current_user.id)

    return {"status": "resolved", "alert_id": alert_id}


@router.get("/dashboard/summary")
async def get_monitoring_summary(
    db = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """
    Get monitoring dashboard summary

    Returns overview of health checks, SLAs, and alerts.

    Requires: User authentication
    """
    # Health check summary
    total_checks = await db.query(HealthCheck).count()
    healthy_checks = await db.query(HealthCheck).filter(
        HealthCheck.current_status == HealthStatus.HEALTHY
    ).count()
    unhealthy_checks = await db.query(HealthCheck).filter(
        HealthCheck.current_status == HealthStatus.UNHEALTHY
    ).count()

    # SLA summary
    total_slas = await db.query(SLA).count()
    compliant_slas = await db.query(SLA).filter(
        SLA.compliance_status == SLAStatus.COMPLIANT
    ).count()
    violated_slas = await db.query(SLA).filter(
        SLA.compliance_status == SLAStatus.VIOLATED
    ).count()

    # Alert summary (last 24 hours)
    since = datetime.utcnow() - timedelta(hours=24)
    active_alerts = await db.query(Alert).filter(
        Alert.status == AlertStatus.ACTIVE,
        Alert.triggered_at >= since
    ).count()

    critical_alerts = await db.query(Alert).filter(
        Alert.severity == AlertSeverity.CRITICAL,
        Alert.status == AlertStatus.ACTIVE,
        Alert.triggered_at >= since
    ).count()

    return {
        "health_checks": {
            "total": total_checks,
            "healthy": healthy_checks,
            "unhealthy": unhealthy_checks,
            "degraded": total_checks - healthy_checks - unhealthy_checks
        },
        "slas": {
            "total": total_slas,
            "compliant": compliant_slas,
            "violated": violated_slas,
            "at_risk": total_slas - compliant_slas - violated_slas
        },
        "alerts": {
            "active": active_alerts,
            "critical": critical_alerts
        }
    }

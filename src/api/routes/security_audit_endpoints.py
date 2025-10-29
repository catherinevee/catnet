"""
Security Audit API Endpoints
RESTful API for security auditing, vulnerability management, and compliance reporting
"""
from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks, Query
from typing import List, Optional
from datetime import datetime, timedelta
from pydantic import BaseModel, Field
import structlog

from src.db.session import get_db
from src.db.models.security_audit import (
    SecurityAuditLog,
    AuditEventType,
    AuditSeverity,
    VulnerabilityScan,
    Vulnerability,
    VulnerabilitySeverity,
    SecurityPolicy,
    SecurityIncident,
    IncidentStatus,
    AccessReview,
    APIKey,
    ComplianceReport,
    ComplianceFramework
)
from src.security.security_scanner import security_scanner
from src.auth.dependencies import get_current_user, get_current_admin_user

logger = structlog.get_logger()

router = APIRouter(
    prefix="/api/v1/security",
    tags=["security"]
)


# Pydantic Models

class AuditLogQuery(BaseModel):
    """Query parameters for audit logs"""
    event_types: Optional[List[AuditEventType]] = None
    severity: Optional[AuditSeverity] = None
    user_id: Optional[str] = None
    resource_type: Optional[str] = None
    success: Optional[bool] = None
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    limit: int = Field(100, ge=1, le=1000)
    offset: int = Field(0, ge=0)


class AuditLogResponse(BaseModel):
    """Response model for audit log"""
    id: str
    event_type: AuditEventType
    severity: AuditSeverity
    timestamp: datetime
    username: Optional[str]
    action: str
    resource_type: Optional[str]
    resource_name: Optional[str]
    success: bool
    ip_address: Optional[str]

    class Config:
        orm_mode = True


class SecurityScanRequest(BaseModel):
    """Request model for starting security scan"""
    scan_type: str = Field(
        ...,
        description="Type of scan: password_policy, certificate, privilege, inactive_accounts, configuration, api_keys, full"
    )
    scan_target: str = Field("all", description="Target for scan: all, specific device_id, or user_id")

    class Config:
        schema_extra = {
            "example": {
                "scan_type": "full",
                "scan_target": "all"
            }
        }


class VulnerabilityScanResponse(BaseModel):
    """Response model for vulnerability scan"""
    id: str
    scan_type: str
    scan_target: str
    scan_started_at: datetime
    scan_completed_at: Optional[datetime]
    scan_status: str
    total_vulnerabilities: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int

    class Config:
        orm_mode = True


class VulnerabilityResponse(BaseModel):
    """Response model for vulnerability"""
    id: str
    vulnerability_id: str
    title: str
    description: str
    severity: VulnerabilitySeverity
    cvss_score: Optional[float]
    resource_type: str
    resource_name: Optional[str]
    category: Optional[str]
    status: str
    detected_at: datetime
    remediation_steps: Optional[str]

    class Config:
        orm_mode = True


class SecurityPolicyRequest(BaseModel):
    """Request model for security policy"""
    name: str
    description: Optional[str]
    policy_type: str

    # Password policy
    min_password_length: Optional[int] = Field(None, ge=8, le=128)
    require_uppercase: Optional[bool] = True
    require_lowercase: Optional[bool] = True
    require_numbers: Optional[bool] = True
    require_special_chars: Optional[bool] = True
    password_expiry_days: Optional[int] = Field(None, ge=0, le=365)

    # Session policy
    session_timeout_minutes: Optional[int] = Field(None, ge=5, le=1440)
    max_concurrent_sessions: Optional[int] = Field(None, ge=1, le=10)
    require_mfa: Optional[bool] = False

    class Config:
        schema_extra = {
            "example": {
                "name": "Corporate Security Policy",
                "policy_type": "password",
                "min_password_length": 12,
                "password_expiry_days": 90,
                "require_mfa": True
            }
        }


class SecurityPolicyResponse(BaseModel):
    """Response model for security policy"""
    id: str
    name: str
    policy_type: str
    enabled: bool
    created_at: datetime

    class Config:
        orm_mode = True


class SecurityIncidentRequest(BaseModel):
    """Request model for reporting security incident"""
    title: str = Field(..., min_length=5, max_length=500)
    description: str = Field(..., min_length=10)
    incident_type: str
    severity: VulnerabilitySeverity
    detected_at: Optional[datetime] = None
    occurred_at: Optional[datetime] = None
    affected_resources: Optional[dict] = {}

    class Config:
        schema_extra = {
            "example": {
                "title": "Unauthorized Access Attempt",
                "description": "Multiple failed login attempts from unusual IP address",
                "incident_type": "unauthorized_access",
                "severity": "high",
                "detected_at": "2025-01-15T10:30:00Z"
            }
        }


class SecurityIncidentResponse(BaseModel):
    """Response model for security incident"""
    id: str
    incident_id: str
    title: str
    severity: VulnerabilitySeverity
    status: IncidentStatus
    reported_at: datetime
    reported_by: str
    assigned_to: Optional[str]

    class Config:
        orm_mode = True


class VulnerabilityUpdateRequest(BaseModel):
    """Request model for updating vulnerability"""
    status: str = Field(..., description="open, in_progress, resolved, false_positive")
    resolution_notes: Optional[str] = None


# Audit Log Endpoints

@router.get("/audit-logs", response_model=List[AuditLogResponse])
async def get_audit_logs(
    event_type: Optional[AuditEventType] = None,
    severity: Optional[AuditSeverity] = None,
    user_id: Optional[str] = None,
    resource_type: Optional[str] = None,
    success: Optional[bool] = None,
    hours: int = Query(24, ge=1, le=8760),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db = Depends(get_db),
    current_user = Depends(get_current_admin_user)
):
    """
    Get security audit logs

    Returns audit logs with optional filters. Admin only.

    Requires: Admin authentication
    """
    since = datetime.utcnow() - timedelta(hours=hours)
    query = db.query(SecurityAuditLog).filter(SecurityAuditLog.timestamp >= since)

    if event_type:
        query = query.filter(SecurityAuditLog.event_type == event_type)

    if severity:
        query = query.filter(SecurityAuditLog.severity == severity)

    if user_id:
        query = query.filter(SecurityAuditLog.user_id == user_id)

    if resource_type:
        query = query.filter(SecurityAuditLog.resource_type == resource_type)

    if success is not None:
        query = query.filter(SecurityAuditLog.success == success)

    logs = await query.order_by(
        SecurityAuditLog.timestamp.desc()
    ).offset(offset).limit(limit).all()

    return logs


@router.get("/audit-logs/{log_id}")
async def get_audit_log_detail(
    log_id: str,
    db = Depends(get_db),
    current_user = Depends(get_current_admin_user)
):
    """
    Get detailed audit log entry

    Requires: Admin authentication
    """
    log = await db.query(SecurityAuditLog).filter(
        SecurityAuditLog.id == log_id
    ).first()

    if not log:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Audit log {log_id} not found"
        )

    return log


@router.get("/audit-logs/user/{user_id}/activity")
async def get_user_activity(
    user_id: str,
    hours: int = Query(168, ge=1, le=8760),
    limit: int = Query(100, ge=1, le=500),
    db = Depends(get_db),
    current_user = Depends(get_current_admin_user)
):
    """
    Get user activity from audit logs

    Requires: Admin authentication
    """
    since = datetime.utcnow() - timedelta(hours=hours)

    logs = await db.query(SecurityAuditLog).filter(
        SecurityAuditLog.user_id == user_id,
        SecurityAuditLog.timestamp >= since
    ).order_by(
        SecurityAuditLog.timestamp.desc()
    ).limit(limit).all()

    return logs


# Vulnerability Scanning Endpoints

@router.post("/scans", response_model=VulnerabilityScanResponse, status_code=status.HTTP_201_CREATED)
async def start_security_scan(
    request: SecurityScanRequest,
    background_tasks: BackgroundTasks,
    db = Depends(get_db),
    current_user = Depends(get_current_admin_user)
):
    """
    Start security vulnerability scan

    Initiates a security scan to detect vulnerabilities, policy violations,
    and compliance issues.

    Scan types:
    - password_policy: Check password policy compliance
    - certificate: Check certificate expiration
    - privilege: Check for excessive privileges
    - inactive_accounts: Check for inactive accounts
    - configuration: Check device configurations
    - api_keys: Check API key security
    - full: Run all scans

    Requires: Admin authentication
    """
    logger.info(
        "Starting security scan",
        scan_type=request.scan_type,
        target=request.scan_target,
        user=current_user.id
    )

    scan = await security_scanner.start_scan(
        scan_type=request.scan_type,
        scan_target=request.scan_target,
        db=db,
        user_id=current_user.id
    )

    return scan


@router.get("/scans", response_model=List[VulnerabilityScanResponse])
async def list_security_scans(
    scan_type: Optional[str] = None,
    scan_status: Optional[str] = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db = Depends(get_db),
    current_user = Depends(get_current_admin_user)
):
    """
    List security scans

    Requires: Admin authentication
    """
    query = db.query(VulnerabilityScan)

    if scan_type:
        query = query.filter(VulnerabilityScan.scan_type == scan_type)

    if scan_status:
        query = query.filter(VulnerabilityScan.scan_status == scan_status)

    scans = await query.order_by(
        VulnerabilityScan.scan_started_at.desc()
    ).offset(offset).limit(limit).all()

    return scans


@router.get("/scans/{scan_id}", response_model=VulnerabilityScanResponse)
async def get_security_scan(
    scan_id: str,
    db = Depends(get_db),
    current_user = Depends(get_current_admin_user)
):
    """
    Get security scan details

    Requires: Admin authentication
    """
    scan = await db.query(VulnerabilityScan).filter(
        VulnerabilityScan.id == scan_id
    ).first()

    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan {scan_id} not found"
        )

    return scan


@router.get("/scans/{scan_id}/vulnerabilities", response_model=List[VulnerabilityResponse])
async def get_scan_vulnerabilities(
    scan_id: str,
    severity: Optional[VulnerabilitySeverity] = None,
    status_filter: Optional[str] = Query(None, alias="status"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db = Depends(get_db),
    current_user = Depends(get_current_admin_user)
):
    """
    Get vulnerabilities from scan

    Requires: Admin authentication
    """
    query = db.query(Vulnerability).filter(Vulnerability.scan_id == scan_id)

    if severity:
        query = query.filter(Vulnerability.severity == severity)

    if status_filter:
        query = query.filter(Vulnerability.status == status_filter)

    vulnerabilities = await query.order_by(
        Vulnerability.cvss_score.desc()
    ).offset(offset).limit(limit).all()

    return vulnerabilities


@router.get("/vulnerabilities", response_model=List[VulnerabilityResponse])
async def list_all_vulnerabilities(
    severity: Optional[VulnerabilitySeverity] = None,
    status_filter: Optional[str] = Query(None, alias="status"),
    resource_type: Optional[str] = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db = Depends(get_db),
    current_user = Depends(get_current_admin_user)
):
    """
    List all vulnerabilities across all scans

    Requires: Admin authentication
    """
    query = db.query(Vulnerability)

    if severity:
        query = query.filter(Vulnerability.severity == severity)

    if status_filter:
        query = query.filter(Vulnerability.status == status_filter)

    if resource_type:
        query = query.filter(Vulnerability.resource_type == resource_type)

    vulnerabilities = await query.order_by(
        Vulnerability.detected_at.desc()
    ).offset(offset).limit(limit).all()

    return vulnerabilities


@router.get("/vulnerabilities/{vuln_id}")
async def get_vulnerability_detail(
    vuln_id: str,
    db = Depends(get_db),
    current_user = Depends(get_current_admin_user)
):
    """
    Get detailed vulnerability information

    Requires: Admin authentication
    """
    vulnerability = await db.query(Vulnerability).filter(
        Vulnerability.id == vuln_id
    ).first()

    if not vulnerability:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Vulnerability {vuln_id} not found"
        )

    return vulnerability


@router.patch("/vulnerabilities/{vuln_id}")
async def update_vulnerability(
    vuln_id: str,
    request: VulnerabilityUpdateRequest,
    db = Depends(get_db),
    current_user = Depends(get_current_admin_user)
):
    """
    Update vulnerability status

    Requires: Admin authentication
    """
    vulnerability = await db.query(Vulnerability).filter(
        Vulnerability.id == vuln_id
    ).first()

    if not vulnerability:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Vulnerability {vuln_id} not found"
        )

    vulnerability.status = request.status

    if request.resolution_notes:
        vulnerability.resolution_notes = request.resolution_notes

    if request.status == "resolved":
        vulnerability.resolved_at = datetime.utcnow()
        vulnerability.resolved_by = current_user.id

    await db.commit()

    logger.info(
        "Vulnerability updated",
        vuln_id=vuln_id,
        new_status=request.status,
        user=current_user.id
    )

    return vulnerability


# Security Policy Endpoints

@router.post("/policies", response_model=SecurityPolicyResponse, status_code=status.HTTP_201_CREATED)
async def create_security_policy(
    request: SecurityPolicyRequest,
    db = Depends(get_db),
    current_user = Depends(get_current_admin_user)
):
    """
    Create security policy

    Requires: Admin authentication
    """
    logger.info(
        "Creating security policy",
        name=request.name,
        type=request.policy_type,
        user=current_user.id
    )

    policy = SecurityPolicy(
        name=request.name,
        description=request.description,
        policy_type=request.policy_type,
        policy_rules={},
        min_password_length=request.min_password_length,
        require_uppercase=request.require_uppercase,
        require_lowercase=request.require_lowercase,
        require_numbers=request.require_numbers,
        require_special_chars=request.require_special_chars,
        password_expiry_days=request.password_expiry_days,
        session_timeout_minutes=request.session_timeout_minutes,
        max_concurrent_sessions=request.max_concurrent_sessions,
        require_mfa=request.require_mfa,
        created_by=current_user.id
    )

    db.add(policy)
    await db.commit()
    await db.refresh(policy)

    return policy


@router.get("/policies", response_model=List[SecurityPolicyResponse])
async def list_security_policies(
    enabled: Optional[bool] = None,
    db = Depends(get_db),
    current_user = Depends(get_current_admin_user)
):
    """
    List security policies

    Requires: Admin authentication
    """
    query = db.query(SecurityPolicy)

    if enabled is not None:
        query = query.filter(SecurityPolicy.enabled == enabled)

    policies = await query.order_by(SecurityPolicy.created_at.desc()).all()

    return policies


@router.get("/policies/{policy_id}")
async def get_security_policy(
    policy_id: str,
    db = Depends(get_db),
    current_user = Depends(get_current_admin_user)
):
    """
    Get security policy details

    Requires: Admin authentication
    """
    policy = await db.query(SecurityPolicy).filter(
        SecurityPolicy.id == policy_id
    ).first()

    if not policy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security policy {policy_id} not found"
        )

    return policy


# Security Incident Endpoints

@router.post("/incidents", response_model=SecurityIncidentResponse, status_code=status.HTTP_201_CREATED)
async def report_security_incident(
    request: SecurityIncidentRequest,
    db = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """
    Report security incident

    Any authenticated user can report a security incident.

    Requires: User authentication
    """
    # Generate incident ID
    incident_count = await db.query(SecurityIncident).count()
    incident_id = f"INC-{datetime.utcnow().strftime('%Y%m%d')}-{incident_count + 1:04d}"

    logger.info(
        "Reporting security incident",
        incident_id=incident_id,
        type=request.incident_type,
        severity=request.severity,
        user=current_user.id
    )

    incident = SecurityIncident(
        incident_id=incident_id,
        title=request.title,
        description=request.description,
        incident_type=request.incident_type,
        severity=request.severity,
        detected_at=request.detected_at or datetime.utcnow(),
        occurred_at=request.occurred_at,
        affected_resources=request.affected_resources,
        reported_by=current_user.id
    )

    db.add(incident)
    await db.commit()
    await db.refresh(incident)

    return incident


@router.get("/incidents", response_model=List[SecurityIncidentResponse])
async def list_security_incidents(
    incident_status: Optional[IncidentStatus] = None,
    severity: Optional[VulnerabilitySeverity] = None,
    days: int = Query(30, ge=1, le=365),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db = Depends(get_db),
    current_user = Depends(get_current_admin_user)
):
    """
    List security incidents

    Requires: Admin authentication
    """
    since = datetime.utcnow() - timedelta(days=days)
    query = db.query(SecurityIncident).filter(
        SecurityIncident.reported_at >= since
    )

    if incident_status:
        query = query.filter(SecurityIncident.status == incident_status)

    if severity:
        query = query.filter(SecurityIncident.severity == severity)

    incidents = await query.order_by(
        SecurityIncident.reported_at.desc()
    ).offset(offset).limit(limit).all()

    return incidents


@router.get("/incidents/{incident_id}")
async def get_security_incident(
    incident_id: str,
    db = Depends(get_db),
    current_user = Depends(get_current_admin_user)
):
    """
    Get security incident details

    Requires: Admin authentication
    """
    incident = await db.query(SecurityIncident).filter(
        SecurityIncident.incident_id == incident_id
    ).first()

    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security incident {incident_id} not found"
        )

    return incident


@router.patch("/incidents/{incident_id}/assign")
async def assign_security_incident(
    incident_id: str,
    assignee_id: str,
    db = Depends(get_db),
    current_user = Depends(get_current_admin_user)
):
    """
    Assign security incident to user

    Requires: Admin authentication
    """
    incident = await db.query(SecurityIncident).filter(
        SecurityIncident.incident_id == incident_id
    ).first()

    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security incident {incident_id} not found"
        )

    incident.assigned_to = assignee_id
    incident.assigned_at = datetime.utcnow()

    await db.commit()

    logger.info(
        "Security incident assigned",
        incident_id=incident_id,
        assignee=assignee_id,
        by=current_user.id
    )

    return incident


@router.patch("/incidents/{incident_id}/status")
async def update_incident_status(
    incident_id: str,
    new_status: IncidentStatus,
    notes: Optional[str] = None,
    db = Depends(get_db),
    current_user = Depends(get_current_admin_user)
):
    """
    Update security incident status

    Requires: Admin authentication
    """
    incident = await db.query(SecurityIncident).filter(
        SecurityIncident.incident_id == incident_id
    ).first()

    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security incident {incident_id} not found"
        )

    old_status = incident.status
    incident.status = new_status

    if new_status == IncidentStatus.CONTAINED and not incident.contained_at:
        incident.contained_at = datetime.utcnow()
    elif new_status == IncidentStatus.REMEDIATED and not incident.resolved_at:
        incident.resolved_at = datetime.utcnow()

    if notes:
        incident.investigation_notes = (incident.investigation_notes or "") + f"\n{datetime.utcnow()}: {notes}"

    await db.commit()

    logger.info(
        "Security incident status updated",
        incident_id=incident_id,
        old_status=old_status.value,
        new_status=new_status.value,
        by=current_user.id
    )

    return incident


# Dashboard/Summary Endpoints

@router.get("/dashboard/summary")
async def get_security_dashboard(
    db = Depends(get_db),
    current_user = Depends(get_current_admin_user)
):
    """
    Get security dashboard summary

    Returns overview of security posture including vulnerabilities,
    incidents, and recent audit events.

    Requires: Admin authentication
    """
    # Vulnerability counts
    total_vulns = await db.query(Vulnerability).filter(
        Vulnerability.status == "open"
    ).count()

    critical_vulns = await db.query(Vulnerability).filter(
        Vulnerability.status == "open",
        Vulnerability.severity == VulnerabilitySeverity.CRITICAL
    ).count()

    high_vulns = await db.query(Vulnerability).filter(
        Vulnerability.status == "open",
        Vulnerability.severity == VulnerabilitySeverity.HIGH
    ).count()

    # Incident counts (last 30 days)
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)

    active_incidents = await db.query(SecurityIncident).filter(
        SecurityIncident.status.in_([IncidentStatus.REPORTED, IncidentStatus.INVESTIGATING])
    ).count()

    recent_incidents = await db.query(SecurityIncident).filter(
        SecurityIncident.reported_at >= thirty_days_ago
    ).count()

    # Audit log summary (last 24 hours)
    yesterday = datetime.utcnow() - timedelta(hours=24)

    failed_logins = await db.query(SecurityAuditLog).filter(
        SecurityAuditLog.event_type == AuditEventType.AUTH_FAILED,
        SecurityAuditLog.timestamp >= yesterday
    ).count()

    total_events = await db.query(SecurityAuditLog).filter(
        SecurityAuditLog.timestamp >= yesterday
    ).count()

    return {
        "vulnerabilities": {
            "total": total_vulns,
            "critical": critical_vulns,
            "high": high_vulns,
            "medium": total_vulns - critical_vulns - high_vulns
        },
        "incidents": {
            "active": active_incidents,
            "recent_30_days": recent_incidents
        },
        "audit_events": {
            "last_24_hours": total_events,
            "failed_logins": failed_logins
        }
    }

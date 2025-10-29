"""
Compliance API Endpoints
RESTful API for compliance scanning and policy management
"""
from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from typing import List, Optional
from datetime import datetime
from pydantic import BaseModel, Field
import structlog

from src.db.session import get_db
from src.db.models.compliance import (
    CompliancePolicy,
    ComplianceScan,
    ComplianceReport,
    ComplianceException,
    ComplianceFramework,
    ComplianceSeverity,
    ComplianceStatus
)
from src.compliance.scanner import compliance_scanner
from src.auth.dependencies import get_current_user, get_current_admin_user

logger = structlog.get_logger()

router = APIRouter(
    prefix="/api/v1/compliance",
    tags=["compliance"]
)


# Pydantic Models

class CompliancePolicyCreate(BaseModel):
    """Request model for creating a compliance policy"""
    name: str = Field(..., description="Policy name")
    framework: ComplianceFramework = Field(..., description="Compliance framework")
    control_id: Optional[str] = Field(None, description="Framework control ID (e.g., CIS-1.1.1)")
    description: Optional[str] = Field(None, description="Policy description")
    rule_type: str = Field("regex", description="Rule type (regex, python)")
    rule: str = Field(..., description="Policy rule logic")
    expected_value: Optional[str] = Field(None, description="Expected value (present/absent)")
    remediation: Optional[str] = Field(None, description="Remediation instructions")
    severity: ComplianceSeverity = Field(..., description="Violation severity")
    vendor: str = Field("all", description="Applicable vendor (cisco, juniper, all)")
    enabled: bool = Field(True, description="Whether policy is active")

    class Config:
        schema_extra = {
            "example": {
                "name": "Password encryption must be enabled",
                "framework": "cis",
                "control_id": "CIS-1.1.1",
                "description": "Service password-encryption should be configured",
                "rule_type": "regex",
                "rule": "^service password-encryption",
                "expected_value": "present",
                "remediation": "Configure: service password-encryption",
                "severity": "high",
                "vendor": "cisco"
            }
        }


class CompliancePolicyResponse(BaseModel):
    """Response model for compliance policy"""
    id: str
    name: str
    framework: ComplianceFramework
    control_id: Optional[str]
    severity: ComplianceSeverity
    enabled: bool
    created_at: datetime

    class Config:
        orm_mode = True


class ComplianceScanTriggerRequest(BaseModel):
    """Request model for triggering compliance scan"""
    device_ids: List[str] = Field(..., description="Devices to scan")
    framework: Optional[ComplianceFramework] = Field(None, description="Specific framework to scan")
    policy_ids: Optional[List[str]] = Field(None, description="Specific policies to check")


class ComplianceScanResponse(BaseModel):
    """Response model for compliance scan"""
    id: str
    device_id: str
    policy_id: str
    scanned_at: datetime
    status: ComplianceStatus
    violation_summary: Optional[str]

    class Config:
        orm_mode = True


class ComplianceReportResponse(BaseModel):
    """Response model for compliance report"""
    id: str
    name: str
    framework: Optional[ComplianceFramework]
    generated_at: datetime
    total_policies: int
    compliant_count: int
    non_compliant_count: int
    compliance_percentage: int
    critical_violations: int
    high_violations: int

    class Config:
        orm_mode = True


# API Endpoints

@router.post("/policies", response_model=CompliancePolicyResponse, status_code=status.HTTP_201_CREATED)
async def create_compliance_policy(
    policy_data: CompliancePolicyCreate,
    db = Depends(get_db),
    current_user = Depends(get_current_admin_user)
):
    """
    Create a new compliance policy

    Creates a policy that can be used to check device compliance against
    industry standards (CIS, PCI-DSS, etc.) or custom requirements.

    Requires: Admin authentication
    """
    logger.info(
        "Creating compliance policy",
        name=policy_data.name,
        framework=policy_data.framework,
        user=current_user.id
    )

    policy = CompliancePolicy(
        **policy_data.dict(),
        created_by=current_user.id
    )

    db.add(policy)
    await db.commit()
    await db.refresh(policy)

    logger.info("Compliance policy created", policy_id=policy.id)

    return policy


@router.get("/policies", response_model=List[CompliancePolicyResponse])
async def list_compliance_policies(
    framework: Optional[ComplianceFramework] = None,
    severity: Optional[ComplianceSeverity] = None,
    enabled: Optional[bool] = None,
    limit: int = 100,
    offset: int = 0,
    db = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """
    List compliance policies

    Returns a list of compliance policies with optional filters.

    Requires: User authentication
    """
    query = db.query(CompliancePolicy)

    if framework:
        query = query.filter(CompliancePolicy.framework == framework)

    if severity:
        query = query.filter(CompliancePolicy.severity == severity)

    if enabled is not None:
        query = query.filter(CompliancePolicy.enabled == enabled)

    policies = await query.offset(offset).limit(limit).all()

    return policies


@router.get("/policies/{policy_id}", response_model=CompliancePolicyResponse)
async def get_compliance_policy(
    policy_id: str,
    db = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """
    Get a specific compliance policy

    Requires: User authentication
    """
    policy = await db.query(CompliancePolicy).filter(
        CompliancePolicy.id == policy_id
    ).first()

    if not policy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Policy {policy_id} not found"
        )

    return policy


@router.post("/scan", status_code=status.HTTP_202_ACCEPTED)
async def trigger_compliance_scan(
    request: ComplianceScanTriggerRequest,
    background_tasks: BackgroundTasks,
    db = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """
    Trigger compliance scan for devices

    Initiates a compliance scan for the specified devices against
    selected policies. Scan runs in the background.

    **Process:**
    1. Retrieves device configurations
    2. Checks against compliance policies
    3. Records violations
    4. Optionally auto-remediates violations

    Requires: User authentication
    """
    logger.info(
        "Triggering compliance scan",
        devices=len(request.device_ids),
        framework=request.framework,
        user=current_user.id
    )

    # Get policies to check
    query = db.query(CompliancePolicy).filter(CompliancePolicy.enabled == True)

    if request.framework:
        query = query.filter(CompliancePolicy.framework == request.framework)

    if request.policy_ids:
        query = query.filter(CompliancePolicy.id.in_(request.policy_ids))

    policies = await query.all()

    if not policies:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No enabled policies found for scan"
        )

    # Trigger scan in background
    background_tasks.add_task(
        _execute_compliance_scan,
        request.device_ids,
        [p.id for p in policies]
    )

    return {
        "message": "Compliance scan initiated",
        "devices": len(request.device_ids),
        "policies": len(policies)
    }


@router.post("/scan/{device_id}")
async def scan_device_compliance(
    device_id: str,
    framework: Optional[ComplianceFramework] = None,
    db = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """
    Scan a single device for compliance

    Synchronously scans one device and returns results immediately.
    For multiple devices, use POST /scan instead.

    Requires: User authentication
    """
    logger.info(
        "Scanning device compliance",
        device_id=device_id,
        framework=framework,
        user=current_user.id
    )

    # Get policies
    query = db.query(CompliancePolicy).filter(CompliancePolicy.enabled == True)

    if framework:
        query = query.filter(CompliancePolicy.framework == framework)

    policies = await query.all()

    # Run scan
    results = await compliance_scanner.scan_device(device_id, policies)

    # Save results
    for result in results:
        db.add(result)
    await db.commit()

    compliant = sum(1 for r in results if r.status == ComplianceStatus.COMPLIANT)
    non_compliant = sum(1 for r in results if r.status == ComplianceStatus.NON_COMPLIANT)

    return {
        "device_id": device_id,
        "total_checks": len(results),
        "compliant": compliant,
        "non_compliant": non_compliant,
        "compliance_percentage": int((compliant / len(results) * 100)) if results else 0
    }


@router.get("/scans", response_model=List[ComplianceScanResponse])
async def get_compliance_scans(
    device_id: Optional[str] = None,
    status: Optional[ComplianceStatus] = None,
    framework: Optional[ComplianceFramework] = None,
    limit: int = 100,
    offset: int = 0,
    db = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """
    Get compliance scan results

    Returns historical compliance scan results with optional filters.

    Requires: User authentication
    """
    query = db.query(ComplianceScan)

    if device_id:
        query = query.filter(ComplianceScan.device_id == device_id)

    if status:
        query = query.filter(ComplianceScan.status == status)

    # Join with policy for framework filter
    if framework:
        query = query.join(CompliancePolicy).filter(
            CompliancePolicy.framework == framework
        )

    scans = await query.order_by(
        ComplianceScan.scanned_at.desc()
    ).offset(offset).limit(limit).all()

    return scans


@router.get("/report/{device_id}")
async def get_device_compliance_report(
    device_id: str,
    framework: Optional[ComplianceFramework] = None,
    db = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """
    Get compliance report for a device

    Generates a comprehensive compliance report for a specific device,
    showing current compliance status across all policies.

    Requires: User authentication
    """
    logger.info(
        "Generating compliance report",
        device_id=device_id,
        framework=framework
    )

    query = db.query(ComplianceScan).filter(
        ComplianceScan.device_id == device_id
    )

    if framework:
        query = query.join(CompliancePolicy).filter(
            CompliancePolicy.framework == framework
        )

    # Get latest scans for each policy
    scans = await query.order_by(ComplianceScan.scanned_at.desc()).all()

    # Group by policy (keep latest)
    latest_scans = {}
    for scan in scans:
        if scan.policy_id not in latest_scans:
            latest_scans[scan.policy_id] = scan

    scans_list = list(latest_scans.values())

    # Calculate statistics
    total = len(scans_list)
    compliant = sum(1 for s in scans_list if s.status == ComplianceStatus.COMPLIANT)
    non_compliant = sum(1 for s in scans_list if s.status == ComplianceStatus.NON_COMPLIANT)

    # Get severity breakdown
    violations_by_severity = {}
    for scan in scans_list:
        if scan.status == ComplianceStatus.NON_COMPLIANT:
            # Get policy severity
            policy = await db.query(CompliancePolicy).filter(
                CompliancePolicy.id == scan.policy_id
            ).first()
            if policy:
                severity = policy.severity.value
                violations_by_severity[severity] = violations_by_severity.get(severity, 0) + 1

    return {
        "device_id": device_id,
        "framework": framework,
        "generated_at": datetime.utcnow(),
        "total_policies": total,
        "compliant": compliant,
        "non_compliant": non_compliant,
        "compliance_percentage": int((compliant / total * 100)) if total > 0 else 0,
        "violations_by_severity": violations_by_severity,
        "scans": scans_list
    }


@router.post("/reports/generate", response_model=ComplianceReportResponse, status_code=status.HTTP_201_CREATED)
async def generate_compliance_report(
    name: str,
    device_ids: List[str],
    framework: Optional[ComplianceFramework] = None,
    db = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """
    Generate comprehensive compliance report

    Creates a report summarizing compliance status across multiple devices.

    Requires: User authentication
    """
    logger.info(
        "Generating multi-device compliance report",
        name=name,
        devices=len(device_ids),
        framework=framework,
        user=current_user.id
    )

    # Get scans for all devices
    query = db.query(ComplianceScan).filter(
        ComplianceScan.device_id.in_(device_ids)
    )

    if framework:
        query = query.join(CompliancePolicy).filter(
            CompliancePolicy.framework == framework
        )

    scans = await query.all()

    # Calculate statistics
    total = len(scans)
    compliant = sum(1 for s in scans if s.status == ComplianceStatus.COMPLIANT)
    non_compliant = sum(1 for s in scans if s.status == ComplianceStatus.NON_COMPLIANT)
    not_applicable = sum(1 for s in scans if s.status == ComplianceStatus.NOT_APPLICABLE)

    # Severity breakdown
    critical = 0
    high = 0
    medium = 0
    low = 0

    for scan in scans:
        if scan.status == ComplianceStatus.NON_COMPLIANT:
            policy = await db.query(CompliancePolicy).filter(
                CompliancePolicy.id == scan.policy_id
            ).first()
            if policy:
                if policy.severity == ComplianceSeverity.CRITICAL:
                    critical += 1
                elif policy.severity == ComplianceSeverity.HIGH:
                    high += 1
                elif policy.severity == ComplianceSeverity.MEDIUM:
                    medium += 1
                elif policy.severity == ComplianceSeverity.LOW:
                    low += 1

    # Create report
    report = ComplianceReport(
        name=name,
        framework=framework,
        device_ids=device_ids,
        generated_at=datetime.utcnow(),
        total_policies=total,
        compliant_count=compliant,
        non_compliant_count=non_compliant,
        not_applicable_count=not_applicable,
        critical_violations=critical,
        high_violations=high,
        medium_violations=medium,
        low_violations=low,
        generated_by=current_user.id
    )

    report.compliance_percentage = report.calculate_compliance_percentage()

    db.add(report)
    await db.commit()
    await db.refresh(report)

    logger.info("Compliance report generated", report_id=report.id)

    return report


@router.get("/reports", response_model=List[ComplianceReportResponse])
async def list_compliance_reports(
    framework: Optional[ComplianceFramework] = None,
    limit: int = 50,
    offset: int = 0,
    db = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """
    List compliance reports

    Requires: User authentication
    """
    query = db.query(ComplianceReport)

    if framework:
        query = query.filter(ComplianceReport.framework == framework)

    reports = await query.order_by(
        ComplianceReport.generated_at.desc()
    ).offset(offset).limit(limit).all()

    return reports


# Background task helper

async def _execute_compliance_scan(device_ids: List[str], policy_ids: List[str]):
    """Execute compliance scan in background"""
    from src.db.session import get_db

    async with get_db() as db:
        # Get policies
        policies = await db.query(CompliancePolicy).filter(
            CompliancePolicy.id.in_(policy_ids)
        ).all()

        for device_id in device_ids:
            try:
                results = await compliance_scanner.scan_device(device_id, policies)

                # Save results
                for result in results:
                    db.add(result)

                    # Auto-remediate if enabled and non-compliant
                    if result.status == ComplianceStatus.NON_COMPLIANT:
                        policy = next((p for p in policies if p.id == result.policy_id), None)
                        if policy and policy.auto_remediate:
                            await compliance_scanner.auto_remediate_violation(
                                result,
                                policy,
                                device_id
                            )

                await db.commit()

            except Exception as e:
                logger.error(f"Scan failed for device {device_id}", error=str(e))

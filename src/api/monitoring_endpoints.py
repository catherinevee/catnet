"""
Monitoring and Metrics API Endpoints
Phase 7 Implementation - Observability endpoints
"""

from fastapi import APIRouter, Query
from typing import Optional, Dict, Any, List
from datetime import datetime

from ..monitoring.simple_metrics import metrics_collector

router = APIRouter(tags=["Monitoring"])


@router.get("/metrics")
async def get_metrics_summary() -> Dict[str, Any]:
    """
    Get current metrics summary

    Returns deployment statistics, rollback counts, and health check results"""
    return metrics_collector.get_metrics_summary()


@router.get("/metrics/prometheus")
async def get_prometheus_metrics() -> str:
    """
    Export metrics in Prometheus format

    Compatible with Prometheus scraping"""
    from fastapi.responses import PlainTextResponse

    metrics = metrics_collector.get_prometheus_metrics()
    return PlainTextResponse(content=metrics, media_type="text/plain")


@router.get("/metrics/recent")
async def get_recent_metrics(
    metric_name: Optional[str] = Query(None, description="Filter by metric name"),
    minutes: int = Query(60, description="Time window in minutes"),
) -> Dict[str, Any]:
    """
    Get recent metric events

    Useful for debugging and real-time monitoring"""
    recent = metrics_collector.get_recent_metrics(
        metric_name=metric_name, minutes=minutes
    )

    return {
        "metrics": recent,
        "count": len(recent),
        "time_window_minutes": minutes,
        "filtered_by": metric_name,
        "timestamp": datetime.utcnow().isoformat(),
    }


@router.post("/metrics/snapshot")
async def create_metrics_snapshot() -> Dict[str, Any]:
    """
    Save current metrics snapshot to disk

    Creates a persistent snapshot for historical analysis"""
    snapshot_file = metrics_collector.save_metrics_snapshot()

    return {
        "success": True,
        "snapshot_file": snapshot_file,
        "timestamp": datetime.utcnow().isoformat(),
    }


@router.get("/health")
async def get_system_health() -> Dict[str, Any]:
    """
    Get overall system health status

    Aggregates health from all components"""
    summary = metrics_collector.get_metrics_summary()

    # Calculate system health score
    total_deployments = summary["counters"]["deployments"]["total"]
    failed_deployments = summary["counters"]["deployments"]["failed"]
    success_rate = summary["statistics"]["deployment_success_rate"]

    # Determine health status
    if total_deployments == 0:
        health_status = "idle"
        health_score = 100
    elif success_rate >= 95:
        health_status = "healthy"
        health_score = 100
    elif success_rate >= 80:
        health_status = "degraded"
        health_score = 75
    else:
        health_status = "unhealthy"
        health_score = 50

    return {
        "status": health_status,
        "score": health_score,
        "metrics": {
            "deployment_success_rate": success_rate,
            "total_deployments": total_deployments,
            "failed_deployments": failed_deployments,
            "average_deployment_duration": summary["statistics"][
                "average_deployment_duration_seconds"
            ],
            "total_operations": summary["statistics"]["total_operations"],
        },
        "timestamp": datetime.utcnow().isoformat(),
    }


@router.get("/dashboard")
async def get_monitoring_dashboard() -> Dict[str, Any]:
    """
    Get complete monitoring dashboard data

    Provides all metrics formatted for dashboard display"""
    summary = metrics_collector.get_metrics_summary()
    recent_deployments = metrics_collector.get_recent_metrics("deployments_total", 60)
    health = await get_system_health()

    return {
        "overview": {
            "health_status": health["status"],
            "health_score": health["score"],
            "timestamp": datetime.utcnow().isoformat(),
        },
        "deployments": {
            "total": summary["counters"]["deployments"]["total"],
            "successful": summary["counters"]["deployments"]["success"],
            "failed": summary["counters"]["deployments"]["failed"],
            "success_rate": summary["statistics"]["deployment_success_rate"],
            "avg_duration_seconds": summary["statistics"][
                "average_deployment_duration_seconds"
            ],
        },
        "rollbacks": {
            "total": summary["counters"]["rollbacks"]["total"],
            "successful": summary["counters"]["rollbacks"].get("success", 0),
            "failed": summary["counters"]["rollbacks"].get("failed", 0),
        },
        "operations": {
            "health_checks": summary["counters"]["health_checks"],
            "device_connections": summary["counters"]["device_connections"],
            "github_connections": summary["counters"]["github_connections"],
            "total": summary["statistics"]["total_operations"],
        },
        "recent_activity": [
            {"type": "deployment", "timestamp": m["timestamp"], "value": m["value"]}
            for m in recent_deployments[:10]  # Last 10 deployments
        ],
        "alerts": get_active_alerts(summary),
    }


def get_active_alerts(summary: Dict[str, Any]) -> List[Dict[str, str]]:
    """
    Generate alerts based on current metrics"""
    alerts = []

    # Check deployment success rate
    success_rate = summary["statistics"]["deployment_success_rate"]
    if success_rate < 80:
        alerts.append(
            {
                "severity": "high" if success_rate < 50 else "medium",
                "message": f"Low deployment success rate: {success_rate}%",
                "metric": "deployment_success_rate",
            }
        )

    # Check for recent failures
    failed_deployments = summary["counters"]["deployments"]["failed"]
    if failed_deployments > 5:
        alerts.append(
            {
                "severity": "medium",
                "message": f"High number of failed deployments: {failed_deployments}",
                "metric": "deployments_failed",
            }
        )

    # Check rollback activity
    rollback_total = summary["counters"]["rollbacks"]["total"]
    if rollback_total > 3:
        alerts.append(
            {
                "severity": "low",
                "message": f"Elevated rollback activity: {rollback_total} rollbacks",
                "metric": "rollbacks_total",
            }
        )

    return alerts

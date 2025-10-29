#!/usr/bin/env python3
"""
Apply Week 1 changes to src/main.py
Adds custom Prometheus metrics and background tasks
"""

import sys
from pathlib import Path

def apply_changes():
    """Apply all Week 1 changes to src/main.py"""

    main_py_path = Path(__file__).parent.parent / "src" / "main.py"

    if not main_py_path.exists():
        print(f"❌ Error: {main_py_path} not found")
        sys.exit(1)

    print(f"📝 Reading {main_py_path}...")
    with open(main_py_path, 'r', encoding='utf-8') as f:
        content = f.read()

    # Backup
    backup_path = main_py_path.with_suffix('.py.before_week1')
    with open(backup_path, 'w', encoding='utf-8') as f:
        f.write(content)
    print(f"✅ Backup created: {backup_path}")

    # Change 1: Add time and asyncio imports
    print("🔧 Adding time and asyncio imports...")
    content = content.replace(
        "from typing import Any, Dict",
        "from typing import Any, Dict\nimport time\nimport asyncio"
    )

    # Change 2: Add prometheus_client import
    print("🔧 Adding prometheus_client import...")
    content = content.replace(
        "from prometheus_fastapi_instrumentator import Instrumentator",
        "from prometheus_fastapi_instrumentator import Instrumentator\nfrom prometheus_client import Counter, Histogram, Gauge"
    )

    # Change 3: Add custom metrics after limiter
    print("🔧 Adding custom Prometheus metrics...")
    custom_metrics = '''
# Custom Prometheus metrics
custom_request_count = Counter(
    'catnet_requests_total',
    'Total requests by method, endpoint, and status',
    ['method', 'endpoint', 'status']
)

custom_request_duration = Histogram(
    'catnet_request_duration_seconds',
    'Request duration in seconds',
    ['method', 'endpoint']
)

active_device_connections = Gauge(
    'catnet_active_device_connections',
    'Number of active device connections'
)

deployment_total = Counter(
    'catnet_deployments_total',
    'Total deployments by status and strategy',
    ['status', 'strategy']
)
'''

    content = content.replace(
        "# Initialize rate limiter\nlimiter = Limiter(key_func=get_remote_address)",
        f"# Initialize rate limiter\nlimiter = Limiter(key_func=get_remote_address){custom_metrics}"
    )

    # Change 4: Add background task functions before lifespan
    print("🔧 Adding background task functions...")
    background_tasks = '''
async def device_session_cleanup():
    """Background task to clean up stale device sessions"""
    while True:
        try:
            from src.devices.secure_connector import secure_device_connector
            await secure_device_connector.cleanup_stale_sessions()
            logger.debug("Device session cleanup completed")
        except Exception as e:
            logger.error("Device session cleanup error", error=str(e))

        # Run every 5 minutes
        await asyncio.sleep(300)


async def collect_metrics():
    """Background task to collect system metrics"""
    while True:
        try:
            # Update active connections metric
            from src.devices.secure_connector import secure_device_connector
            sessions = await secure_device_connector.get_active_sessions()
            active_device_connections.set(len(sessions))
            logger.debug("Metrics collected", active_sessions=len(sessions))
        except Exception as e:
            logger.error("Metric collection error", error=str(e))

        # Collect every 30 seconds
        await asyncio.sleep(30)


'''

    content = content.replace(
        "@asynccontextmanager\nasync def lifespan(app: FastAPI):",
        f"{background_tasks}@asynccontextmanager\nasync def lifespan(app: FastAPI):"
    )

    # Change 5: Add background task startup in lifespan
    print("🔧 Adding background task startup...")
    startup_code = '''

        # Start background tasks
        app.state.background_tasks = []

        # Device session cleanup task
        try:
            cleanup_task = asyncio.create_task(device_session_cleanup())
            app.state.background_tasks.append(cleanup_task)
            logger.info("Background task started: device_session_cleanup")
        except Exception as e:
            logger.warning("Failed to start device cleanup task", error=str(e))

        # Metric collection task
        try:
            metric_task = asyncio.create_task(collect_metrics())
            app.state.background_tasks.append(metric_task)
            logger.info("Background task started: collect_metrics")
        except Exception as e:
            logger.warning("Failed to start metric collection task", error=str(e))'''

    # Find the log message after feature flags and add background tasks there
    content = content.replace(
        '''        logger.info(
            "CatNet started successfully",
            version="1.0.0",
            environment=settings.environment,
            features={
                "mfa": settings.feature_mfa_enabled,
                "canary": settings.feature_canary_deployment,
                "compliance": settings.feature_compliance_scanning,
                "auto_remediation": settings.feature_auto_remediation
            }
        )

        yield''',
        f'''        logger.info(
            "CatNet started successfully",
            version="1.0.0",
            environment=settings.environment,
            features={{
                "mfa": settings.feature_mfa_enabled,
                "canary": settings.feature_canary_deployment,
                "compliance": settings.feature_compliance_scanning,
                "auto_remediation": settings.feature_auto_remediation
            }}
        ){startup_code}

        yield'''
    )

    # Change 6: Add background task shutdown
    print("🔧 Adding background task shutdown...")
    shutdown_code = '''
        # Cancel background tasks
        if hasattr(app.state, 'background_tasks'):
            logger.info("Cancelling background tasks")
            for task in app.state.background_tasks:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
            logger.info("Background tasks cancelled")

'''

    content = content.replace(
        "    finally:\n        # Shutdown\n        logger.info(\"Shutting down CatNet application\")",
        f"    finally:\n        # Shutdown\n        logger.info(\"Shutting down CatNet application\")\n{shutdown_code}"
    )

    # Change 7: Add custom metrics middleware before include_router calls
    print("🔧 Adding custom metrics middleware...")
    metrics_middleware = '''
@app.middleware("http")
async def custom_metrics_middleware(request: Request, call_next):
    """Collect custom Prometheus metrics"""
    start_time = time.time()

    try:
        response = await call_next(request)

        # Calculate duration
        duration = time.time() - start_time

        # Update metrics
        custom_request_count.labels(
            method=request.method,
            endpoint=request.url.path,
            status=response.status_code
        ).inc()

        custom_request_duration.labels(
            method=request.method,
            endpoint=request.url.path
        ).observe(duration)

        return response

    except Exception as e:
        # Update error metrics
        custom_request_count.labels(
            method=request.method,
            endpoint=request.url.path,
            status=500
        ).inc()
        raise


'''

    content = content.replace(
        "# Include routers\napp.include_router(",
        f"{metrics_middleware}# Include routers\napp.include_router("
    )

    # Write updated content
    print(f"💾 Writing updated file...")
    with open(main_py_path, 'w', encoding='utf-8') as f:
        f.write(content)

    print(f"\n✅ Successfully updated {main_py_path}")
    print(f"✅ Backup saved to {backup_path}")
    print("\n📋 Changes applied:")
    print("  ✅ Added time and asyncio imports")
    print("  ✅ Added prometheus_client import")
    print("  ✅ Added 4 custom Prometheus metrics")
    print("  ✅ Added device_session_cleanup() background task")
    print("  ✅ Added collect_metrics() background task")
    print("  ✅ Added background task startup in lifespan")
    print("  ✅ Added background task shutdown in lifespan")
    print("  ✅ Added custom_metrics_middleware")
    print("\n🚀 Next steps:")
    print("  1. Test locally: uvicorn src.main:app --reload")
    print("  2. Check http://localhost:8000/metrics for custom metrics")
    print("  3. Verify background tasks in logs")

if __name__ == "__main__":
    try:
        apply_changes()
    except Exception as e:
        print(f"\n❌ Error: {e}")
        sys.exit(1)

#!/usr/bin/env python
"""
Test script for Phase 7 Monitoring
"""
import json
from src.monitoring.simple_metrics import metrics_collector
from src.deployment.simple_deploy import deployment_pipeline
from src.gitops.simple_github_client import github_client
from src.devices.device_store import device_store



def test_metrics_collection():
    """Test metrics collection and reporting"""
    print("\n" + "="*60)
    print("Phase 7: Monitoring & Observability Test")
    print("="*60)

    # Simulate some activities to generate metrics
    print("\n1. Simulating deployment activities...")

    # Track some deployments
    for i in range(3):
        deployment_id = f"test-deploy-{i}"
        if i < 2:
            metrics_collector.track_deployment(deployment_id, "completed", 
    duration_seconds=10.5 + i)
        else:
            metrics_collector.track_deployment(deployment_id, "failed", 
    duration_seconds=5.0)

    # Track some rollbacks
    print("2. Simulating rollback activities...")
    metrics_collector.track_rollback("deploy-1", True)
    metrics_collector.track_rollback("deploy-2", False)

    # Track health checks
    print("3. Simulating health checks...")
    metrics_collector.track_health_check("device-1", "healthy")
    metrics_collector.track_health_check("device-2", "healthy")
    metrics_collector.track_health_check("device-3", "failed")

    # Track device connections
    print("4. Simulating device connections...")
    metrics_collector.track_device_connection("device-1", True)
    metrics_collector.track_device_connection("device-2", True)

    # Get metrics summary
    print("\n5. Metrics Summary:")
    print("-" * 40)
    summary = metrics_collector.get_metrics_summary()
    print(json.dumps(summary, indent=2))

    # Get Prometheus metrics
    print("\n6. Prometheus Format Metrics:")
    print("-" * 40)
    prometheus_metrics = metrics_collector.get_prometheus_metrics()
    print(prometheus_metrics[:500])  # Show first 500 chars

    # Get recent metrics
    print("\n7. Recent Metrics (last 5 minutes):")
    print("-" * 40)
    recent = metrics_collector.get_recent_metrics(minutes=5)
    for metric in recent[:5]:  # Show first 5
        print(f"  {metric['name']}: {metric['value']} ({metric['type']})")

    # Save snapshot
    print("\n8. Saving metrics snapshot...")
    snapshot_file = metrics_collector.save_metrics_snapshot()
    print(f"  Snapshot saved to: {snapshot_file}")

    # Test with actual deployment if devices exist
    if device_store.list_devices():
        print("\n9. Testing with real deployment...")
        device = device_store.list_devices()[0]

        # Create a test config if GitHub is connected
        if github_client.connected_repo:
            try:
                # Create deployment
                deployment = deployment_pipeline.create_deployment(
                    config_path="configs/test.cfg",
                    device_id=device.id
                )
                print(f"  Created deployment: {deployment.id}")

                # Execute deployment (will generate metrics)
                deployment = deployment_pipeline.execute_deployment( \
                    deployment.id)
                print(f"  Deployment status: {deployment.status}")

                # Check updated metrics
                summary = metrics_collector.get_metrics_summary()
                print(f"  Total deployments after test: {summary['counters'][ 
    'deployments']['total']}")
            except Exception as e:
                print(f"  Deployment test failed: {e}")
        else:
            print("  GitHub not connected, skipping deployment test")
    else:
        print("\n9. No devices available for deployment test")

    # Calculate test results
    print("\n" + "="*60)
    print("Test Results:")
    print("-" * 40)

    tests_passed = 0
    tests_total = 8

    # Verify counters
    if summary["counters"]["deployments"]["total"] >= 3:
        print("✓ Deployment tracking working")
        tests_passed += 1
    else:
        print("✗ Deployment tracking failed")

    if summary["counters"]["deployments"]["success"] >= 2:
        print("✓ Success tracking working")
        tests_passed += 1
    else:
        print("✗ Success tracking failed")

    if summary["counters"]["deployments"]["failed"] >= 1:
        print("✓ Failure tracking working")
        tests_passed += 1
    else:
        print("✗ Failure tracking failed")

    if summary["counters"]["rollbacks"]["total"] >= 2:
        print("✓ Rollback tracking working")
        tests_passed += 1
    else:
        print("✗ Rollback tracking failed")

    if summary["counters"]["health_checks"] >= 3:
        print("✓ Health check tracking working")
        tests_passed += 1
    else:
        print("✗ Health check tracking failed")

    if summary["statistics"]["deployment_success_rate"] > 0:
        print("✓ Success rate calculation working")
        tests_passed += 1
    else:
        print("✗ Success rate calculation failed")

    if summary["statistics"]["average_deployment_duration_seconds"] > 0:
        print("✓ Duration tracking working")
        tests_passed += 1
    else:
        print("✗ Duration tracking failed")

    if prometheus_metrics and "catnet_" in prometheus_metrics:
        print("✓ Prometheus export working")
        tests_passed += 1
    else:
        print("✗ Prometheus export failed")

    print("\n" + "="*60)
    print(f"PHASE 7 TEST COMPLETE: {tests_passed}/{tests_total} tests passed")

    if tests_passed == tests_total:
        print("✓ All monitoring tests passed!")
        return True
    else:
        print(f"✗ {tests_total - tests_passed} tests failed")
        return False


if __name__ == "__main__":
    success = test_metrics_collection()
    exit(0 if success else 1)

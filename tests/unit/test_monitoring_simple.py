#!/usr/bin/env python
"""
Simple test for Phase 7 monitoring
"""
import json
from src.monitoring.simple_metrics import metrics_collector

print("Testing Phase 7: Monitoring & Observability")
print("=" * 50)

# Track some test deployments
print("\n1. Tracking test deployments...")
metrics_collector.track_deployment("test-1", "completed", 10.5)
metrics_collector.track_deployment("test-2", "completed", 15.2)
metrics_collector.track_deployment("test-3", "failed", 5.0)
print("   Added 3 deployment metrics")

# Track rollbacks
print("\n2. Tracking test rollbacks...")
metrics_collector.track_rollback("test-1", True)
metrics_collector.track_rollback("test-2", False)
print("   Added 2 rollback metrics")

# Get summary
print("\n3. Metrics Summary:")
summary = metrics_collector.get_metrics_summary()
print(json.dumps(summary, indent=2))

# Test Prometheus export
print("\n4. Prometheus Export (first 300 chars):")
prometheus = metrics_collector.get_prometheus_metrics()
print(prometheus[:300])

print("\n" + "=" * 50)
print("✓ Phase 7 monitoring test complete!")

#!/bin/bash
# Script to run pytest with coverage and proper test environment

# Set test environment variables
export DATABASE_URL="sqlite+aiosqlite:///:memory:"
export REDIS_URL="redis://localhost:6379/0"
export SECRET_KEY="test-secret-key-for-testing-only"
export VAULT_URL="http://localhost:8200"
export VAULT_TOKEN="test-token"
export GIT_WEBHOOK_SECRET="test-webhook-secret"
export ENVIRONMENT="development"
export CANARY_STAGES="5,25,50,100"
export CANARY_WAIT_MINUTES="5,10,15,0"
export ROLLBACK_TIMEOUT_SECONDS="300"
export MAX_PARALLEL_DEPLOYMENTS="10"
export LOG_LEVEL="INFO"
export MTLS_ENABLED="false"
export VERIFY_CLIENT_CERT="false"
export SESSION_RECORDING_ENABLED="false"
export DEFAULT_DEVICE_TIMEOUT="30"
export ENABLE_TELNET="false"
export RATE_LIMIT_ENABLED="true"
export RATE_LIMIT_REQUESTS_PER_MINUTE="100"

echo "========================================="
echo "CatNet Test Coverage Report"
echo "========================================="
echo ""
echo "Running pytest with coverage..."
echo ""

# Run pytest with coverage
python -m pytest \
  --cov=src \
  --cov-report=html \
  --cov-report=term-missing \
  --cov-report=xml \
  -v \
  --tb=short \
  --maxfail=10

echo ""
echo "========================================="
echo "Coverage report generated!"
echo "HTML report: htmlcov/index.html"
echo "========================================="

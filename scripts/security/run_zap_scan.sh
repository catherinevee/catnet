#!/bin/bash
# OWASP ZAP Security Scanning Script for CatNet
#
# Usage:
#   ./scripts/security/run_zap_scan.sh [baseline|full|api]
#
# Scan types:
#   baseline - Quick passive scan (recommended for CI/CD)
#   full     - Full active scan with spidering
#   api      - API-specific scan with authentication

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
SCAN_TYPE="${1:-baseline}"
TARGET_URL="${TARGET_URL:-http://localhost:8000}"
ZAP_PORT="${ZAP_PORT:-8090}"
REPORT_DIR="./security-reports"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Create report directory
mkdir -p "$REPORT_DIR"

echo -e "${GREEN}=== OWASP ZAP Security Scan for CatNet ===${NC}"
echo -e "Scan type: ${YELLOW}$SCAN_TYPE${NC}"
echo -e "Target URL: ${YELLOW}$TARGET_URL${NC}"
echo -e "Report directory: ${YELLOW}$REPORT_DIR${NC}"
echo ""

# Function to wait for service
wait_for_service() {
    local url=$1
    local timeout=60
    local counter=0

    echo -n "Waiting for $url to be ready..."
    until curl -sf "$url/health" > /dev/null 2>&1; do
        sleep 1
        counter=$((counter + 1))
        if [ $counter -ge $timeout ]; then
            echo -e "${RED}FAILED${NC}"
            echo "Service did not start within $timeout seconds"
            exit 1
        fi
    done
    echo -e "${GREEN}OK${NC}"
}

# Function to get authentication token
get_auth_token() {
    echo "Obtaining authentication token..."

    # Get credentials from environment or use defaults
    USERNAME="${ZAP_USERNAME:-admin}"
    PASSWORD="${ZAP_PASSWORD:-admin}"

    # Login and extract token
    TOKEN=$(curl -s -X POST "$TARGET_URL/api/v1/auth/login" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"$USERNAME\",\"password\":\"$PASSWORD\"}" \
        | jq -r '.access_token')

    if [ "$TOKEN" == "null" ] || [ -z "$TOKEN" ]; then
        echo -e "${RED}Failed to obtain authentication token${NC}"
        exit 1
    fi

    echo -e "${GREEN}Token obtained successfully${NC}"
    export CATNET_API_TOKEN="$TOKEN"
}

# Function to run baseline scan
run_baseline_scan() {
    echo -e "${YELLOW}Running baseline scan (passive only)...${NC}"

    docker run --rm \
        --network host \
        -v "$(pwd):/zap/wrk/:rw" \
        -t owasp/zap2docker-stable \
        zap-baseline.py \
        -t "$TARGET_URL" \
        -c tests/security/zap-baseline.yml \
        -r "$REPORT_DIR/zap-baseline-report-$TIMESTAMP.html" \
        -J "$REPORT_DIR/zap-baseline-report-$TIMESTAMP.json" \
        -w "$REPORT_DIR/zap-baseline-markdown-$TIMESTAMP.md" \
        -I

    SCAN_EXIT_CODE=$?
}

# Function to run full scan
run_full_scan() {
    echo -e "${YELLOW}Running full scan (passive + active)...${NC}"

    docker run --rm \
        --network host \
        -v "$(pwd):/zap/wrk/:rw" \
        -t owasp/zap2docker-stable \
        zap-full-scan.py \
        -t "$TARGET_URL" \
        -c tests/security/zap-baseline.yml \
        -r "$REPORT_DIR/zap-full-report-$TIMESTAMP.html" \
        -J "$REPORT_DIR/zap-full-report-$TIMESTAMP.json" \
        -w "$REPORT_DIR/zap-full-markdown-$TIMESTAMP.md" \
        -I

    SCAN_EXIT_CODE=$?
}

# Function to run API scan
run_api_scan() {
    echo -e "${YELLOW}Running API scan with authentication...${NC}"

    # Get authentication token
    get_auth_token

    # Generate OpenAPI spec
    echo "Fetching OpenAPI specification..."
    curl -s "$TARGET_URL/api/openapi.json" > "$REPORT_DIR/openapi-$TIMESTAMP.json"

    # Run ZAP API scan
    docker run --rm \
        --network host \
        -v "$(pwd):/zap/wrk/:rw" \
        -e "CATNET_API_TOKEN=$CATNET_API_TOKEN" \
        -t owasp/zap2docker-stable \
        zap-api-scan.py \
        -t "$REPORT_DIR/openapi-$TIMESTAMP.json" \
        -f openapi \
        -c tests/security/zap-baseline.yml \
        -r "$REPORT_DIR/zap-api-report-$TIMESTAMP.html" \
        -J "$REPORT_DIR/zap-api-report-$TIMESTAMP.json" \
        -w "$REPORT_DIR/zap-api-markdown-$TIMESTAMP.md" \
        -I

    SCAN_EXIT_CODE=$?
}

# Wait for target service
wait_for_service "$TARGET_URL"

# Run appropriate scan
case "$SCAN_TYPE" in
    baseline)
        run_baseline_scan
        ;;
    full)
        run_full_scan
        ;;
    api)
        run_api_scan
        ;;
    *)
        echo -e "${RED}Invalid scan type: $SCAN_TYPE${NC}"
        echo "Valid options: baseline, full, api"
        exit 1
        ;;
esac

# Check results
echo ""
echo -e "${GREEN}=== Scan Complete ===${NC}"
echo "Reports generated in: $REPORT_DIR/"
ls -lh "$REPORT_DIR/"/*$TIMESTAMP*

# Parse results
if [ $SCAN_EXIT_CODE -eq 0 ]; then
    echo -e "${GREEN}✓ No high-risk vulnerabilities found${NC}"
elif [ $SCAN_EXIT_CODE -eq 1 ]; then
    echo -e "${YELLOW}⚠ Warnings found (medium/low severity)${NC}"
elif [ $SCAN_EXIT_CODE -eq 2 ]; then
    echo -e "${RED}✗ High-risk vulnerabilities found${NC}"

    # Extract high-severity issues
    if [ -f "$REPORT_DIR/zap-*-report-$TIMESTAMP.json" ]; then
        echo ""
        echo "High-severity issues:"
        jq -r '.site[].alerts[] | select(.riskcode == "3") | "  - \(.name) (\(.url))"' \
            "$REPORT_DIR"/zap-*-report-"$TIMESTAMP".json
    fi
else
    echo -e "${RED}✗ Scan failed with error${NC}"
fi

# Generate summary
echo ""
echo "=== Vulnerability Summary ==="
if [ -f "$REPORT_DIR"/zap-*-report-"$TIMESTAMP".json ]; then
    echo "High:   $(jq '[.site[].alerts[] | select(.riskcode == "3")] | length' "$REPORT_DIR"/zap-*-report-"$TIMESTAMP".json)"
    echo "Medium: $(jq '[.site[].alerts[] | select(.riskcode == "2")] | length' "$REPORT_DIR"/zap-*-report-"$TIMESTAMP".json)"
    echo "Low:    $(jq '[.site[].alerts[] | select(.riskcode == "1")] | length' "$REPORT_DIR"/zap-*-report-"$TIMESTAMP".json)"
    echo "Info:   $(jq '[.site[].alerts[] | select(.riskcode == "0")] | length' "$REPORT_DIR"/zap-*-report-"$TIMESTAMP".json)"
fi

# Exit with scan exit code
exit $SCAN_EXIT_CODE

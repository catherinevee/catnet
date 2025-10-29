# CatNet Security Testing Guide

**Version:** 1.0
**Last Updated:** 2025-10-25
**Owner:** Security Team

---

## Table of Contents

1. [Overview](#overview)
2. [SAST - Static Application Security Testing](#sast)
3. [DAST - Dynamic Application Security Testing](#dast)
4. [Dependency Scanning](#dependency-scanning)
5. [Container Security](#container-security)
6. [Secret Scanning](#secret-scanning)
7. [Penetration Testing](#penetration-testing)
8. [CI/CD Integration](#cicd-integration)
9. [Security Test Metrics](#security-test-metrics)

---

## Overview

CatNet implements a comprehensive security testing strategy following the "shift-left" principle:

| Test Type | Tool | When | Coverage |
|-----------|------|------|----------|
| **SAST** | Semgrep, Bandit | Pre-commit, CI | Code vulnerabilities |
| **DAST** | OWASP ZAP | CI, Weekly | Runtime vulnerabilities |
| **SCA** | Safety, Trivy | CI, Daily | Dependencies |
| **Secret Scan** | detect-secrets | Pre-commit, CI | Hardcoded secrets |
| **Container Scan** | Trivy | CI | Image vulnerabilities |
| **Pen Test** | Manual | Quarterly | Full application |

---

## SAST - Static Application Security Testing

### Tools

1. **Semgrep** - Modern SAST with custom rules
2. **Bandit** - Python-specific security linter
3. **mypy** - Type checking (prevents bugs)

### Running Semgrep

**Local:**
```bash
# Install
pip install semgrep

# Run scan
semgrep --config .semgrep.yml src/

# Generate report
semgrep --config .semgrep.yml src/ --json > semgrep-results.json

# CI mode (returns exit code)
semgrep ci
```

**Configuration:** [.semgrep.yml](../../.semgrep.yml)

### Custom Rules

We've implemented CatNet-specific rules:

#### 1. Hardcoded Secrets
```yaml
- id: hardcoded-secret
  pattern-either:
    - pattern: password = "..."
    - pattern: api_key = "..."
  severity: ERROR
```

#### 2. SQL Injection
```yaml
- id: sql-injection-raw-query
  patterns:
    - pattern: db.execute($QUERY)
    - pattern-not: db.execute("...")
  severity: ERROR
```

#### 3. Command Injection
```yaml
- id: command-injection
  patterns:
    - pattern: subprocess.call($CMD, shell=True)
  severity: ERROR
```

#### 4. Missing Authentication
```yaml
- id: missing-authentication-check
  patterns:
    - pattern: '@app.post(...)'
    - pattern-not: 'dependencies=[Depends(get_current_user)]'
  severity: WARNING
```

### Running Bandit

```bash
# Install
pip install bandit

# Run scan
bandit -r src/ -ll -f json -o bandit-report.json

# Specific severity
bandit -r src/ -ll  # Only high confidence, low severity+

# Exclude tests
bandit -r src/ -x tests/
```

### False Positives

Suppress false positives:

**Inline (specific line):**
```python
password = get_from_vault()  # nosec B105
```

**File-wide:**
```python
# bandit: skip_file
```

**Configuration (`.bandit`):**
```yaml
skips:
  - B101  # assert_used
  - B601  # paramiko_calls

exclude_dirs:
  - /tests/
  - /migrations/
```

### Expected Results

✅ **Pass Criteria:**
- Zero high-severity issues
- No hardcoded secrets
- No SQL injection vulnerabilities
- No command injection risks

⚠️ **Review Required:**
- Medium-severity issues
- Security hotspots
- Weak crypto warnings

---

## DAST - Dynamic Application Security Testing

### Tools

1. **OWASP ZAP** - Industry standard DAST scanner
2. **Burp Suite** - Manual penetration testing (optional)

### Running OWASP ZAP

We provide three scan types:

#### 1. Baseline Scan (CI/CD)

**Fast, passive-only scan:**
```bash
./scripts/security/run_zap_scan.sh baseline
```

**Duration:** 5-10 minutes
**Coverage:** Passive checks only
**Use case:** Every CI/CD run

#### 2. Full Scan (Weekly)

**Comprehensive active scan:**
```bash
./scripts/security/run_zap_scan.sh full
```

**Duration:** 30-60 minutes
**Coverage:** Active + passive scans
**Use case:** Weekly automated scans

#### 3. API Scan (Authentication Required)

**API-specific scan with auth:**
```bash
export ZAP_USERNAME="admin"
export ZAP_PASSWORD="your-password"
./scripts/security/run_zap_scan.sh api
```

**Duration:** 15-30 minutes
**Coverage:** API endpoints with authentication
**Use case:** After major API changes

### ZAP Configuration

**Configuration:** [tests/security/zap-baseline.yml](../../tests/security/zap-baseline.yml)

**Key Settings:**
- Target: `http://localhost:8000`
- Authentication: JWT bearer token
- Active scan rules: SQL injection, XSS, command injection, etc.
- Alert filters: Suppress false positives

### Manual Testing with ZAP

**1. Start ZAP proxy:**
```bash
docker run -u zap -p 8090:8090 \
  -i owasp/zap2docker-stable \
  zap.sh -daemon -port 8090 \
  -config api.addrs.addr.name=.* \
  -config api.addrs.addr.regex=true
```

**2. Configure browser to use proxy:**
- Proxy: localhost:8090
- Install ZAP CA certificate

**3. Browse application manually**

**4. Review findings in ZAP UI**

### ZAP Reports

Reports generated in `./security-reports/`:

- **HTML:** Human-readable report
- **JSON:** Machine-readable for parsing
- **Markdown:** For documentation

**Example:**
```bash
security-reports/
├── zap-baseline-report-20251025_143000.html
├── zap-baseline-report-20251025_143000.json
└── zap-baseline-markdown-20251025_143000.md
```

### Expected Results

✅ **Pass Criteria:**
- No high-risk vulnerabilities
- No critical SQL injection
- No XSS vulnerabilities
- Proper authentication required

⚠️ **Review Required:**
- Medium-risk findings
- Information disclosure
- Security headers missing

---

## Dependency Scanning

### Tools

1. **Safety** - Python package vulnerability scanner
2. **pip-audit** - Official Python audit tool
3. **Trivy** - Multi-purpose scanner (deps + containers)

### Running Safety

```bash
# Install
pip install safety

# Scan requirements.txt
safety check --file requirements.txt

# JSON output
safety check --file requirements.txt --json > safety-report.json

# Full report
safety check --full-report

# Ignore specific vulnerabilities
safety check --ignore 12345
```

### Running pip-audit

```bash
# Install
pip install pip-audit

# Scan installed packages
pip-audit

# Scan requirements file
pip-audit -r requirements.txt

# Fix automatically
pip-audit --fix
```

### Running Trivy (Dependency Mode)

```bash
# Install
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -

# Scan Python dependencies
trivy fs --scanners vuln,config .

# Scan specific file
trivy config requirements.txt

# Output JSON
trivy fs --format json --output trivy-deps.json .
```

### Vulnerability Severity

| Severity | Action Required |
|----------|----------------|
| **CRITICAL** | Fix immediately (< 24 hours) |
| **HIGH** | Fix within 1 week |
| **MEDIUM** | Fix within 1 month |
| **LOW** | Review and plan |

### Example Workflow

```bash
# 1. Check for vulnerabilities
safety check --file requirements.txt

# 2. If found, check details
safety check --full-report

# 3. Update vulnerable package
pip install --upgrade vulnerable-package

# 4. Test application
pytest

# 5. Update requirements.txt
pip freeze > requirements.txt

# 6. Commit fix
git add requirements.txt
git commit -m "fix: upgrade vulnerable-package (CVE-2024-12345)"
```

---

## Container Security

### Tools

1. **Trivy** - Container image scanner
2. **Docker Scout** - Docker's built-in scanner
3. **Snyk** - Third-party service (optional)

### Running Trivy

**Scan local image:**
```bash
# Build image
docker build -t catnet:latest .

# Scan image
trivy image catnet:latest

# High/Critical only
trivy image --severity HIGH,CRITICAL catnet:latest

# JSON output
trivy image --format json -o trivy-image.json catnet:latest

# With SBOM
trivy image --format cyclonedx catnet:latest > sbom.json
```

**Scan in CI/CD:**
```bash
trivy image --exit-code 1 --severity CRITICAL catnet:latest
# Exit code 1 if CRITICAL vulnerabilities found
```

### Running Docker Scout

```bash
# Analyze image
docker scout cves catnet:latest

# Compare with base image
docker scout compare --to python:3.11 catnet:latest

# Recommendations
docker scout recommendations catnet:latest
```

### Best Practices

1. **Use specific base image versions:**
   ```dockerfile
   # Bad
   FROM python:3.11

   # Good
   FROM python:3.11.6-slim@sha256:abc123...
   ```

2. **Multi-stage builds:**
   ```dockerfile
   FROM python:3.11-slim as builder
   # Build dependencies

   FROM python:3.11-slim as runtime
   # Only runtime dependencies
   ```

3. **Run as non-root:**
   ```dockerfile
   USER catnet:catnet
   ```

4. **Minimize layers:**
   ```dockerfile
   RUN apt-get update && apt-get install -y \
       package1 \
       package2 \
       && rm -rf /var/lib/apt/lists/*
   ```

### Expected Results

✅ **Pass Criteria:**
- No critical vulnerabilities
- No high-severity OS packages
- Base image up-to-date
- Non-root user configured

---

## Secret Scanning

### Tools

1. **detect-secrets** - Pre-commit + CI scanning
2. **Gitleaks** - Git repository scanner
3. **TruffleHog** - Deep secret scanner

### Running detect-secrets

**Initialize baseline:**
```bash
detect-secrets scan > .secrets.baseline
```

**Scan for new secrets:**
```bash
detect-secrets scan --baseline .secrets.baseline
```

**Audit findings:**
```bash
detect-secrets audit .secrets.baseline
```

**Pre-commit integration:**
```yaml
# .pre-commit-config.yaml
- repo: https://github.com/Yelp/detect-secrets
  rev: v1.4.0
  hooks:
    - id: detect-secrets
      args: ['--baseline', '.secrets.baseline']
```

### Running Gitleaks

**Scan entire repository:**
```bash
# Install
brew install gitleaks  # or download from releases

# Scan
gitleaks detect --source . --verbose

# Scan with report
gitleaks detect --report-path gitleaks-report.json
```

**Scan commits:**
```bash
# Protect (CI/CD)
gitleaks protect --staged --verbose

# Scan specific commit range
gitleaks detect --log-opts="origin/main..HEAD"
```

### Running TruffleHog

**Scan Git history:**
```bash
# Install
pip install trufflehog

# Scan repository
trufflehog git https://github.com/your-org/catnet

# Scan filesystem
trufflehog filesystem ./src
```

### What to Look For

Common secret patterns:
- AWS access keys: `AKIA[0-9A-Z]{16}`
- API keys: `[a-zA-Z0-9]{32,}`
- Private keys: `-----BEGIN PRIVATE KEY-----`
- JWT tokens: `eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*`
- Database URLs: `postgresql://user:pass@host/db`

### Remediation

**If secret leaked:**

1. **Revoke immediately**
2. **Rotate credentials**
3. **Remove from Git history:**
   ```bash
   git filter-branch --force --index-filter \
     "git rm --cached --ignore-unmatch path/to/file" \
     --prune-empty --tag-name-filter cat -- --all
   ```
4. **Force push** (if safe)
5. **Notify security team**

---

## Penetration Testing

### Manual Testing Checklist

#### Authentication
- [ ] Brute force protection
- [ ] MFA bypass attempts
- [ ] Token replay attacks
- [ ] Session fixation
- [ ] Password reset flaws

#### Authorization
- [ ] IDOR (Insecure Direct Object Reference)
- [ ] Privilege escalation
- [ ] Missing function-level access control
- [ ] API key enumeration

#### Input Validation
- [ ] SQL injection (all inputs)
- [ ] XSS (reflected, stored, DOM-based)
- [ ] Command injection
- [ ] LDAP injection
- [ ] Template injection

#### Business Logic
- [ ] Rate limit bypass
- [ ] Workflow bypass
- [ ] Mass assignment
- [ ] Price manipulation (if applicable)

#### Configuration
- [ ] Debug mode disabled
- [ ] Error messages sanitized
- [ ] Sensitive endpoints protected
- [ ] Default credentials changed

### Tools for Manual Testing

1. **Burp Suite Community**
   - Proxy and intercept requests
   - Repeater for fuzzing
   - Scanner (limited in free version)

2. **Postman**
   - API testing
   - Collection runner
   - Environment variables

3. **cURL**
   - Command-line HTTP testing
   - Scripting attacks

**Example attacks:**

**1. SQL Injection:**
```bash
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin'\'' OR '\''1'\''='\''1", "password": "test"}'
```

**2. XSS:**
```bash
curl -X POST http://localhost:8000/api/v1/devices \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"hostname": "<script>alert(1)</script>"}'
```

**3. IDOR:**
```bash
# Try accessing other user's resource
curl -X GET http://localhost:8000/api/v1/devices/12345 \
  -H "Authorization: Bearer $USER2_TOKEN"
```

---

## CI/CD Integration

### GitHub Actions Workflow

**File:** `.github/workflows/security.yml`

```yaml
name: Security Scanning

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main, develop]
  schedule:
    - cron: '0 0 * * 0'  # Weekly on Sunday

jobs:
  sast:
    name: Static Analysis (SAST)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Run Semgrep
        uses: returntocorp/semgrep-action@v1
        with:
          config: .semgrep.yml

      - name: Run Bandit
        run: |
          pip install bandit
          bandit -r src/ -ll -f json -o bandit-report.json
          # Fail if high-severity issues found
          bandit -r src/ -ll --exit-zero=false

      - name: Upload SAST results
        uses: actions/upload-artifact@v3
        with:
          name: sast-results
          path: |
            bandit-report.json
            semgrep-results.json

  dependency-scan:
    name: Dependency Scanning
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Run Safety
        run: |
          pip install safety
          safety check --file requirements.txt --json > safety-report.json

      - name: Run Trivy (Dependencies)
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: 'fs'
          scan-ref: '.'
          format: 'json'
          output: 'trivy-deps.json'

      - name: Check for critical vulnerabilities
        run: |
          python scripts/check_vulnerabilities.py trivy-deps.json
          # Fail if CRITICAL found

  container-scan:
    name: Container Security
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Build image
        run: docker build -t catnet:${{ github.sha }} .

      - name: Run Trivy (Container)
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: 'catnet:${{ github.sha }}'
          format: 'sarif'
          output: 'trivy-container.sarif'
          severity: 'CRITICAL,HIGH'

      - name: Upload to GitHub Security
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: 'trivy-container.sarif'

  secret-scan:
    name: Secret Scanning
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
        with:
          fetch-depth: 0  # Full history for Gitleaks

      - name: Run Gitleaks
        uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

      - name: Run detect-secrets
        run: |
          pip install detect-secrets
          detect-secrets scan --baseline .secrets.baseline

  dast:
    name: Dynamic Analysis (DAST)
    runs-on: ubuntu-latest
    if: github.event_name == 'schedule'  # Only on weekly schedule
    steps:
      - uses: actions/checkout@v3

      - name: Start services
        run: docker-compose up -d

      - name: Wait for services
        run: sleep 30

      - name: Run OWASP ZAP
        run: |
          chmod +x scripts/security/run_zap_scan.sh
          ./scripts/security/run_zap_scan.sh baseline

      - name: Upload ZAP results
        uses: actions/upload-artifact@v3
        with:
          name: zap-results
          path: security-reports/

  security-report:
    name: Generate Security Report
    needs: [sast, dependency-scan, container-scan, secret-scan]
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Download all artifacts
        uses: actions/download-artifact@v3

      - name: Generate combined report
        run: python scripts/generate_security_report.py

      - name: Upload combined report
        uses: actions/upload-artifact@v3
        with:
          name: security-report
          path: security-report.html
```

### Quality Gates

**Fail build if:**
- ❌ CRITICAL vulnerabilities in dependencies
- ❌ HIGH severity SAST findings
- ❌ Secrets detected in code
- ❌ CRITICAL container vulnerabilities

**Warn but don't fail:**
- ⚠️ MEDIUM severity vulnerabilities
- ⚠️ LOW severity findings
- ⚠️ Missing security headers

---

## Security Test Metrics

### Key Metrics to Track

1. **Vulnerability Density**
   - Vulnerabilities per 1000 lines of code
   - Target: < 0.5 high/critical per 1000 LOC

2. **Time to Remediation**
   - CRITICAL: < 24 hours
   - HIGH: < 7 days
   - MEDIUM: < 30 days

3. **Security Test Coverage**
   - % of endpoints tested with DAST
   - % of code covered by SAST
   - Target: > 90%

4. **False Positive Rate**
   - % of findings that are false positives
   - Target: < 10%

5. **Trend Analysis**
   - Vulnerabilities over time
   - Should be decreasing

### Dashboard

Track metrics in Grafana:

**Prometheus Queries:**
```promql
# Total vulnerabilities by severity
sum(security_vulnerabilities_total) by (severity)

# Mean time to remediation
avg(security_vulnerability_remediation_time_hours) by (severity)

# SAST coverage
(security_sast_lines_covered / security_total_lines_of_code) * 100
```

---

## Appendix

### Useful Commands

```bash
# Full security scan (local)
make security-scan

# Individual scans
make sast
make dast
make dependency-scan
make container-scan
make secret-scan

# Generate reports
make security-report
```

### Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP ZAP Documentation](https://www.zaproxy.org/docs/)
- [Semgrep Rules](https://semgrep.dev/r)
- [Trivy Documentation](https://aquasecurity.github.io/trivy/)
- [CWE Database](https://cwe.mitre.org/)

---

**Last Updated:** 2025-10-25
**Next Review:** Quarterly

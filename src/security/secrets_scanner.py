import re
import logging
from typing import List, Dict, Any, Optional
from pathlib import Path
import hashlib
import json
from datetime import datetime

logger = logging.getLogger(__name__)

class SecretsScanner:
    def __init__(self):
        self.patterns = self._load_patterns()
        self.false_positive_patterns = self._load_false_positive_patterns()
        self.quarantine_dir = Path("/var/catnet/quarantine")
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)

    def _load_patterns(self) -> Dict[str, re.Pattern]:
        return {
            "aws_access_key": re.compile(r'AKIA[0-9A-Z]{16}'),
            "aws_secret_key": re.compile(r'[A-Za-z0-9/+=]{40}'),
            "github_token": re.compile(r'ghp_[A-Za-z0-9]{36}'),
            "github_oauth": re.compile(r'gho_[A-Za-z0-9]{36}'),
            "github_app": re.compile(r'(ghs_|ghu_)[A-Za-z0-9]{36}'),
            "github_refresh": re.compile(r'ghr_[A-Za-z0-9]{36}'),
            "gitlab_token": re.compile(r'glpat-[A-Za-z0-9\-\_]{20}'),
            "slack_token": re.compile(r'xox[baprs]-[A-Za-z0-9\-]+'),
            "slack_webhook": re.compile(r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+'),
            "stripe_secret": re.compile(r'sk_(live|test)_[A-Za-z0-9]{24,}'),
            "stripe_publishable": re.compile(r'pk_(live|test)_[A-Za-z0-9]{24,}'),
            "pypi_token": re.compile(r'pypi-[A-Za-z0-9_\-]+'),
            "google_api": re.compile(r'AIza[A-Za-z0-9_\-]{35}'),
            "google_oauth": re.compile(r'[0-9]+-[A-Za-z0-9_]{32}\.apps\.googleusercontent\.com'),
            "heroku_api": re.compile(r'[hH][eE][rR][oO][kK][uU].*[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'),
            "mailgun_api": re.compile(r'key-[A-Za-z0-9]{32}'),
            "mailchimp_api": re.compile(r'[A-Za-z0-9]{32}-us[0-9]{1,2}'),
            "twilio_api": re.compile(r'SK[A-Za-z0-9]{32}'),
            "npm_token": re.compile(r'npm_[A-Za-z0-9]{36}'),
            "private_key": re.compile(r'-----BEGIN (RSA |EC |DSA |OPENSSH |)PRIVATE KEY-----'),
            "api_key": re.compile(r'[aA][pP][iI][_]?[kK][eE][yY].*[:=].*["\']?[A-Za-z0-9_\-]{32,}["\']?'),
            "password": re.compile(r'[pP][aA][sS][sS][wW][oO][rR][dD].*[:=].*["\']?[^\s"\']{8,}["\']?'),
            "secret": re.compile(r'[sS][eE][cC][rR][eE][tT].*[:=].*["\']?[A-Za-z0-9_\-]{16,}["\']?'),
            "token": re.compile(r'[tT][oO][kK][eE][nN].*[:=].*["\']?[A-Za-z0-9_\-]{16,}["\']?'),
            "bearer": re.compile(r'[bB][eE][aA][rR][eE][rR].*[A-Za-z0-9_\-\.]{20,}'),
            "basic_auth": re.compile(r'[bB][aA][sS][iI][cC]\s+[A-Za-z0-9+/]{20,}={0,2}'),
            "jwt": re.compile(r'eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+'),
            "ssh_dsa": re.compile(r'ssh-dss\s+AAAA[A-Za-z0-9+/]+[=]{0,2}'),
            "ssh_rsa": re.compile(r'ssh-rsa\s+AAAA[A-Za-z0-9+/]+[=]{0,2}'),
            "ssh_ed25519": re.compile(r'ssh-ed25519\s+AAAA[A-Za-z0-9+/]+[=]{0,2}'),
            "pgp_private": re.compile(r'-----BEGIN PGP PRIVATE KEY BLOCK-----'),
            "facebook_token": re.compile(r'EAA[A-Za-z0-9]+'),
            "twitter_token": re.compile(r'[tT][wW][iI][tT][tT][eE][rR].*[A-Za-z0-9]{35,44}'),
            "github_pat": re.compile(r'github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}'),
            "shopify_token": re.compile(r'shppa_[a-fA-F0-9]{32}'),
            "shopify_access": re.compile(r'shpat_[a-fA-F0-9]{32}'),
            "shopify_custom": re.compile(r'shpca_[a-fA-F0-9]{32}'),
            "shopify_private": re.compile(r'shpss_[a-fA-F0-9]{32}'),
            "pypi_upload": re.compile(r'pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}'),
            "discord_token": re.compile(r'[MN][A-Za-z0-9]{23}\.[A-Za-z0-9]{6}\.[A-Za-z0-9_\-]{27}'),
            "discord_webhook": re.compile(r'https://discord(app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_\-]+'),
            "telegram_token": re.compile(r'[0-9]{8,10}:[A-Za-z0-9_\-]{35}'),
            "vault_token": re.compile(r's\.[A-Za-z0-9]{24}'),
            "cisco_password": re.compile(r'(password|secret)\s+(0|5|7)\s+[A-Za-z0-9./]+'),
            "juniper_password": re.compile(r'\$9\$[A-Za-z0-9./]+'),
            "snmp_community": re.compile(r'snmp-server\s+community\s+[^\s]+'),
            "database_url": re.compile(r'(postgres|postgresql|mysql|mongodb|redis)://[^:]+:[^@]+@[^/]+/[^\s]+'),
            "ldap_password": re.compile(r'ldap[s]?://[^:]+:[^@]+@[^\s]+'),
            "ftp_url": re.compile(r'ftp[s]?://[^:]+:[^@]+@[^\s]+'),
            "generic_credential": re.compile(r'["\']?(user|username|login|email)["\']?\s*[:=]\s*["\'][^"\']+["\'].*["\']?(pass|password|pwd|secret|token)["\']?\s*[:=]\s*["\'][^"\']+["\']')
        }

    def _load_false_positive_patterns(self) -> List[re.Pattern]:
        return [
            re.compile(r'example\.com'),
            re.compile(r'localhost'),
            re.compile(r'127\.0\.0\.1'),
            re.compile(r'<[A-Z_]+>'),
            re.compile(r'\$\{[^}]+\}'),
            re.compile(r'{{[^}]+}}'),
            re.compile(r'%\([^)]+\)s'),
            re.compile(r'your[_\-]?api[_\-]?key'),
            re.compile(r'your[_\-]?password'),
            re.compile(r'your[_\-]?token'),
            re.compile(r'dummy'),
            re.compile(r'fake'),
            re.compile(r'test'),
            re.compile(r'sample'),
            re.compile(r'placeholder'),
            re.compile(r'xxx+'),
            re.compile(r'[*]{3,}'),
            re.compile(r'#\s*(password|token|secret|key)'),
        ]

    async def scan_file(self, file_path: str, content: str) -> List[Dict[str, Any]]:
        findings = []
        lines = content.split('\n')

        for line_num, line in enumerate(lines, 1):
            if self._is_false_positive(line):
                continue

            for secret_type, pattern in self.patterns.items():
                matches = pattern.finditer(line)
                for match in matches:
                    finding = {
                        "file": file_path,
                        "line": line_num,
                        "column": match.start() + 1,
                        "type": secret_type,
                        "severity": self._get_severity(secret_type),
                        "match": self._redact_secret(match.group()),
                        "hash": hashlib.sha256(match.group().encode()).hexdigest(),
                        "context": self._get_context(lines, line_num)
                    }
                    findings.append(finding)
                    logger.warning(f"Potential secret found: {secret_type} in {file_path}:{line_num}")

        return findings

    def _is_false_positive(self, line: str) -> bool:
        line_lower = line.lower()

        if any(pattern.search(line_lower) for pattern in self.false_positive_patterns):
            return True

        if line.strip().startswith('#') or line.strip().startswith('//'):
            return True

        if 'example' in line_lower or 'sample' in line_lower:
            return True

        return False

    def _get_severity(self, secret_type: str) -> str:
        critical_types = [
            "aws_secret_key", "private_key", "stripe_secret",
            "database_url", "vault_token", "cisco_password", "juniper_password"
        ]
        high_types = [
            "aws_access_key", "github_token", "api_key", "password",
            "jwt", "ssh_rsa", "ssh_dsa", "ssh_ed25519"
        ]

        if secret_type in critical_types:
            return "CRITICAL"
        elif secret_type in high_types:
            return "HIGH"
        else:
            return "MEDIUM"

    def _redact_secret(self, secret: str) -> str:
        if len(secret) <= 8:
            return "*" * len(secret)

        visible_chars = 4
        return secret[:visible_chars] + "*" * (len(secret) - visible_chars * 2) + secret[-visible_chars:]

    def _get_context(self, lines: List[str], line_num: int, context_size: int = 2) -> List[str]:
        start = max(0, line_num - context_size - 1)
        end = min(len(lines), line_num + context_size)
        return lines[start:end]

    async def scan_repository(self, repo_path: str) -> Dict[str, Any]:
        repo_path = Path(repo_path)
        all_findings = []
        scanned_files = 0
        skip_patterns = [
            "*.pyc", "*.pyo", "*.so", "*.dll", "*.dylib",
            "*.exe", "*.bin", "*.jpg", "*.jpeg", "*.png",
            "*.gif", "*.svg", "*.ico", "*.pdf", "*.zip",
            "*.tar", "*.gz", "*.rar", "*.7z", ".git/*",
            "node_modules/*", "__pycache__/*", "venv/*",
            ".env/*", "vendor/*", "target/*", "dist/*"
        ]

        for file_path in repo_path.rglob("*"):
            if file_path.is_file():
                if any(file_path.match(pattern) for pattern in skip_patterns):
                    continue

                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()

                    findings = await self.scan_file(str(file_path), content)
                    all_findings.extend(findings)
                    scanned_files += 1

                except Exception as e:
                    logger.debug(f"Could not scan {file_path}: {e}")

        return {
            "scanned_files": scanned_files,
            "total_findings": len(all_findings),
            "critical_findings": len([f for f in all_findings if f["severity"] == "CRITICAL"]),
            "high_findings": len([f for f in all_findings if f["severity"] == "HIGH"]),
            "medium_findings": len([f for f in all_findings if f["severity"] == "MEDIUM"]),
            "findings": all_findings[:100]
        }

    async def scan_commits(self, commits: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        all_findings = []

        for commit in commits:
            for file_change in commit.get("files", []):
                if file_change.get("patch"):
                    findings = await self.scan_file(
                        file_change["filename"],
                        file_change["patch"]
                    )

                    for finding in findings:
                        finding["commit_sha"] = commit["sha"]
                        finding["commit_author"] = commit["author"]
                        finding["commit_message"] = commit["message"]

                    all_findings.extend(findings)

        return all_findings

    async def quarantine_and_alert(self, findings: List[Dict[str, Any]]):
        if not findings:
            return

        quarantine_file = self.quarantine_dir / f"quarantine_{hashlib.sha256(str(findings).encode()).hexdigest()}.json"

        with open(quarantine_file, 'w') as f:
            json.dump({
                "timestamp": datetime.now().isoformat(),
                "findings": findings,
                "action": "quarantined"
            }, f, indent=2)

        critical_count = len([f for f in findings if f["severity"] == "CRITICAL"])
        if critical_count > 0:
            logger.critical(f"CRITICAL SECURITY ALERT: {critical_count} critical secrets found and quarantined")

        for finding in findings:
            if finding["severity"] == "CRITICAL":
                await self._notify_security_team(finding)

    async def _notify_security_team(self, finding: Dict[str, Any]):
        logger.critical(f"Security team notification: Critical secret found - {finding}")

    def validate_no_secrets(self, content: str, file_type: str = "config") -> bool:
        for secret_type, pattern in self.patterns.items():
            if pattern.search(content):
                logger.error(f"Secret detected in {file_type}: {secret_type}")
                return False
        return True
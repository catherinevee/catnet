"""
Secret Scanner for CatNet GitOps

Scans configurations for secrets and sensitive data:
- API keys and tokens
- Passwords and credentials
- Private keys and certificates
- Connection strings
"""

import re
import hashlib
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass, field
from enum import Enum
import base64
import json


class SecretType(Enum):
    """Types of secrets"""

    PASSWORD = "password"
    API_KEY = "api_key"
    PRIVATE_KEY = "private_key"
    CERTIFICATE = "certificate"
    TOKEN = "token"
    CONNECTION_STRING = "connection_string"
    SSH_KEY = "ssh_key"
    AWS_CREDENTIALS = "aws_credentials"
    DATABASE_URL = "database_url"
    GENERIC_SECRET = "generic_secret"


@dataclass
class SecretMatch:
    """Represents a detected secret"""

    secret_type: SecretType
    line_number: int
    column_start: int
    column_end: int
    matched_text: str
    redacted_text: str
    confidence: float  # 0.0 to 1.0
    entropy: float
    rule_id: str


@dataclass
class SecretScanResult:
    """Result of secret scanning"""

    file_path: str
    has_secrets: bool
    secret_count: int
    secrets: List[SecretMatch] = field(default_factory=list)
    scan_time: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


class SecretScanner:
    """
    Scans for secrets and sensitive data in configurations
    """

    def __init__(self):
        """Initialize secret scanner"""
        # Define secret detection patterns
        self.patterns = {
            # Passwords
            "password_literal": {
                "pattern": r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]?([^'\"}\s]{4,})['\"]?",
                "type": SecretType.PASSWORD,
                "confidence": 0.9,
            },
            "cisco_password": {
                "pattern": r"(?i)(enable\s+password|username\s+\S+\s+password)\s+(?:0\s+)?(\S+)",
                "type": SecretType.PASSWORD,
                "confidence": 0.95,
            },
            # API Keys
            "api_key_generic": {
                "pattern": r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"]?([a-zA-Z0-9]{32,})['\"]?",
                "type": SecretType.API_KEY,
                "confidence": 0.85,
            },
            "aws_access_key": {
                "pattern": r"(?i)(aws[_-]?access[_-]?key[_-]?id|AKIA[0-9A-Z]{16})",
                "type": SecretType.AWS_CREDENTIALS,
                "confidence": 0.95,
            },
            "aws_secret_key": {
                "pattern": r"(?i)(aws[_-]?secret[_-]?access[_-]?key)\s*[:=]\s*['\"]?([a-zA-Z0-9/+=]{40})['\"]?",
                "type": SecretType.AWS_CREDENTIALS,
                "confidence": 0.95,
            },
            # Tokens
            "bearer_token": {
                "pattern": r"(?i)bearer\s+([a-zA-Z0-9\-._~+/]+=*)",
                "type": SecretType.TOKEN,
                "confidence": 0.8,
            },
            "github_token": {
                "pattern": r"ghp_[a-zA-Z0-9]{36}|github[_-]?token\s*[:=]\s*['\"]?([a-zA-Z0-9]{40})['\"]?",
                "type": SecretType.TOKEN,
                "confidence": 0.95,
            },
            # Private Keys
            "private_key_header": {
                "pattern": r"-----BEGIN\s+(RSA|DSA|EC|OPENSSH)?\s*PRIVATE KEY-----",
                "type": SecretType.PRIVATE_KEY,
                "confidence": 1.0,
            },
            "ssh_private_key": {
                "pattern": r"-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]+?-----END OPENSSH PRIVATE KEY-----",
                "type": SecretType.SSH_KEY,
                "confidence": 1.0,
            },
            # Certificates
            "certificate": {
                "pattern": r"-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----",
                "type": SecretType.CERTIFICATE,
                "confidence": 1.0,
            },
            # Connection Strings
            "connection_string": {
                "pattern": r"(?i)(mongodb|postgres|postgresql|mysql|redis|amqp|jdbc):\/\/[^:]+:[^@]+@[^\s]+",
                "type": SecretType.CONNECTION_STRING,
                "confidence": 0.95,
            },
            "database_url": {
                "pattern": r"(?i)database[_-]?url\s*[:=]\s*['\"]?([^'\"}\s]+)['\"]?",
                "type": SecretType.DATABASE_URL,
                "confidence": 0.85,
            },
            # SNMP Community
            "snmp_community": {
                "pattern": r"(?i)snmp-server\s+community\s+(\S+)",
                "type": SecretType.PASSWORD,
                "confidence": 0.9,
            },
            # Generic secrets
            "secret_literal": {
                "pattern": r"(?i)(secret|private[_-]?key|auth[_-]?token)\s*[:=]\s*['\"]?([^'\"}\s]{8,})['\"]?",
                "type": SecretType.GENERIC_SECRET,
                "confidence": 0.7,
            },
        }

        # High entropy thresholds
        self.entropy_thresholds = {
            "base64": 4.5,
            "hex": 3.0,
            "generic": 3.5,
        }

        # Whitelist patterns (false positives)
        self.whitelist_patterns = [
            r"^\$\{.*\}$",  # Variable references ${VAR}
            r"^%\(.*\)s$",  # Python format strings
            r"^{{.*}}$",  # Template variables
            r"^<.*>$",  # Placeholders
            r"^(example|test|demo|sample)",  # Example values
            r"^(password|secret|key|token)$",  # Literal words
            r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",  # UUIDs
        ]

    def scan_file(self, file_path: str, content: str) -> SecretScanResult:
        """
        Scan a file for secrets

        Args:
            file_path: Path to file being scanned
            content: File content

        Returns:
            SecretScanResult object
        """
        import time

        start_time = time.time()
        result = SecretScanResult(
            file_path=file_path,
            has_secrets=False,
            secret_count=0,
        )

        lines = content.splitlines()

        # Scan using patterns
        for line_num, line in enumerate(lines, 1):
            # Skip comments
            if line.strip().startswith("#") or line.strip().startswith("//"):
                continue

            for rule_id, rule in self.patterns.items():
                pattern = rule["pattern"]
                matches = re.finditer(pattern, line)

                for match in matches:
                    matched_text = match.group(0)

                    # Extract the actual secret value
                    if len(match.groups()) > 0:
                        secret_value = match.group(len(match.groups()))
                    else:
                        secret_value = matched_text

                    # Check whitelist
                    if self._is_whitelisted(secret_value):
                        continue

                    # Calculate entropy
                    entropy = self._calculate_entropy(secret_value)

                    # Determine confidence based on entropy
                    confidence = rule["confidence"]
                    if entropy < 2.0:
                        confidence *= 0.5  # Low entropy reduces confidence

                    # Create secret match
                    secret_match = SecretMatch(
                        secret_type=rule["type"],
                        line_number=line_num,
                        column_start=match.start(),
                        column_end=match.end(),
                        matched_text=matched_text,
                        redacted_text=self._redact_secret(matched_text, secret_value),
                        confidence=confidence,
                        entropy=entropy,
                        rule_id=rule_id,
                    )

                    result.secrets.append(secret_match)

            # High entropy detection
            tokens = line.split()
            for token in tokens:
                if len(token) >= 20:  # Minimum length for entropy check
                    entropy = self._calculate_entropy(token)

                    if self._is_high_entropy(token, entropy):
                        # Check if it's not already detected
                        already_detected = any(
                            token in s.matched_text for s in result.secrets
                        )

                        if not already_detected and not self._is_whitelisted(token):
                            secret_match = SecretMatch(
                                secret_type=SecretType.GENERIC_SECRET,
                                line_number=line_num,
                                column_start=line.find(token),
                                column_end=line.find(token) + len(token),
                                matched_text=token,
                                redacted_text=self._redact_secret(token, token),
                                confidence=0.6,
                                entropy=entropy,
                                rule_id="high_entropy",
                            )
                            result.secrets.append(secret_match)

        # Update result
        result.has_secrets = len(result.secrets) > 0
        result.secret_count = len(result.secrets)
        result.scan_time = time.time() - start_time

        # Add metadata
        result.metadata = {
            "lines_scanned": len(lines),
            "patterns_used": len(self.patterns),
            "high_confidence_secrets": len(
                [s for s in result.secrets if s.confidence >= 0.8]
            ),
        }

        return result

    def scan_directory(
        self, directory_path: str, extensions: List[str] = None
    ) -> List[SecretScanResult]:
        """
        Scan directory for secrets

        Args:
            directory_path: Path to directory
            extensions: File extensions to scan

        Returns:
            List of SecretScanResult objects
        """
        import os

        results = []
        extensions = extensions or [
            ".yml",
            ".yaml",
            ".json",
            ".conf",
            ".cfg",
            ".ini",
            ".env",
        ]

        for root, dirs, files in os.walk(directory_path):
            # Skip .git directory
            if ".git" in root:
                continue

            for file in files:
                file_path = os.path.join(root, file)

                # Check extension
                if any(file.endswith(ext) for ext in extensions):
                    try:
                        with open(
                            file_path, "r", encoding="utf-8", errors="ignore"
                        ) as f:
                            content = f.read()
                        result = self.scan_file(file_path, content)
                        if result.has_secrets:
                            results.append(result)
                    except Exception as e:
                        print(f"Error scanning {file_path}: {str(e)}")

        return results

    def _calculate_entropy(self, text: str) -> float:
        """
        Calculate Shannon entropy of text

        Args:
            text: Text to analyze

        Returns:
            Entropy value
        """
        if not text:
            return 0.0

        # Calculate character frequency
        freq = {}
        for char in text:
            freq[char] = freq.get(char, 0) + 1

        # Calculate entropy
        entropy = 0.0
        text_len = len(text)

        for count in freq.values():
            probability = count / text_len
            if probability > 0:
                entropy -= probability * (probability and probability * 2.0 or 0.0)

        return entropy

    def _is_high_entropy(self, text: str, entropy: float) -> bool:
        """
        Check if text has high entropy

        Args:
            text: Text to check
            entropy: Calculated entropy

        Returns:
            True if high entropy
        """
        # Check if it looks like base64
        if re.match(r"^[A-Za-z0-9+/]+=*$", text):
            return entropy > self.entropy_thresholds["base64"]

        # Check if it's hex
        if re.match(r"^[0-9a-fA-F]+$", text):
            return entropy > self.entropy_thresholds["hex"]

        # Generic high entropy
        return entropy > self.entropy_thresholds["generic"]

    def _is_whitelisted(self, text: str) -> bool:
        """
        Check if text matches whitelist patterns

        Args:
            text: Text to check

        Returns:
            True if whitelisted
        """
        for pattern in self.whitelist_patterns:
            if re.match(pattern, text, re.IGNORECASE):
                return True
        return False

    def _redact_secret(self, full_text: str, secret_value: str) -> str:
        """
        Redact secret value in text

        Args:
            full_text: Full matched text
            secret_value: Secret value to redact

        Returns:
            Redacted text
        """
        if len(secret_value) <= 4:
            redacted = "*" * len(secret_value)
        else:
            # Show first 2 and last 2 characters
            redacted = (
                secret_value[:2] + "*" * (len(secret_value) - 4) + secret_value[-2:]
            )

        return full_text.replace(secret_value, redacted)

    def quarantine_file(self, file_path: str, scan_result: SecretScanResult) -> str:
        """
        Quarantine file with detected secrets

        Args:
            file_path: Original file path
            scan_result: Scan result with secrets

        Returns:
            Quarantine report
        """
        import tempfile
        import shutil

        # Create quarantine directory
        quarantine_dir = tempfile.mkdtemp(prefix="catnet_quarantine_")

        # Copy file to quarantine
        quarantine_file = os.path.join(
            quarantine_dir, os.path.basename(file_path) + ".quarantined"
        )
        shutil.copy2(file_path, quarantine_file)

        # Generate report
        report = {
            "original_file": file_path,
            "quarantine_location": quarantine_file,
            "detected_secrets": len(scan_result.secrets),
            "secret_types": list(set(s.secret_type.value for s in scan_result.secrets)),
            "high_confidence_count": len(
                [s for s in scan_result.secrets if s.confidence >= 0.8]
            ),
            "recommendations": [
                "Remove all hardcoded secrets",
                "Use environment variables or vault for sensitive data",
                "Rotate any exposed credentials immediately",
            ],
        }

        # Save report
        report_file = os.path.join(quarantine_dir, "report.json")
        with open(report_file, "w") as f:
            json.dump(report, f, indent=2)

        return json.dumps(report, indent=2)

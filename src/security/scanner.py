"""
Secret Scanner - Scans configurations and code for exposed secrets
"""
import re
import hashlib
import json
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime
import asyncio
from pathlib import Path
import base64
from enum import Enum

from ..core.exceptions import SecurityError
from ..core.logger import get_logger, log_security

logger = get_logger(__name__)


class SecretType(Enum):
    """Types of secrets that can be detected"""
    PASSWORD = "password"
    API_KEY = "api_key"
    PRIVATE_KEY = "private_key"
    TOKEN = "token"
    SECRET = "secret"
    CERTIFICATE = "certificate"
    AWS_CREDENTIALS = "aws_credentials"
    AZURE_CREDENTIALS = "azure_credentials"
    GCP_CREDENTIALS = "gcp_credentials"
    DATABASE_URL = "database_url"
    WEBHOOK_URL = "webhook_url"
    ENCRYPTION_KEY = "encryption_key"
    SSH_KEY = "ssh_key"
    SNMP_COMMUNITY = "snmp_community"
    ENABLE_SECRET = "enable_secret"


class SecretSeverity(Enum):
    """Severity levels for detected secrets"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class SecretMatch:
    """Represents a detected secret"""

    def __init__(
        self,
        secret_type: SecretType,
        severity: SecretSeverity,
        pattern_name: str,
        match_text: str,
        file_path: Optional[str] = None,
        line_number: Optional[int] = None,
        column_start: Optional[int] = None,
        column_end: Optional[int] = None,
        context: Optional[str] = None,
        confidence: float = 1.0
    ):
        self.secret_type = secret_type
        self.severity = severity
        self.pattern_name = pattern_name
        self.match_text = match_text
        self.file_path = file_path
        self.line_number = line_number
        self.column_start = column_start
        self.column_end = column_end
        self.context = context
        self.confidence = confidence
        self.timestamp = datetime.utcnow()
        self.hash = self._calculate_hash()

    def _calculate_hash(self) -> str:
        """Calculate unique hash for this secret match"""
        content = f"{self.secret_type.value}:{self.match_text}:{self.file_path}:{self.line_number}"
        return hashlib.sha256(content.encode()).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'type': self.secret_type.value,
            'severity': self.severity.value,
            'pattern': self.pattern_name,
            'match': self._redact_secret(self.match_text),
            'file': self.file_path,
            'line': self.line_number,
            'column': {'start': self.column_start, 'end': self.column_end},
            'context': self.context,
            'confidence': self.confidence,
            'timestamp': self.timestamp.isoformat(),
            'hash': self.hash
        }

    def _redact_secret(self, secret: str) -> str:
        """Redact secret for safe display"""
        if len(secret) <= 8:
            return "***REDACTED***"
        return f"{secret[:4]}...{secret[-4:]}"


class SecretPattern:
    """Defines a pattern for detecting secrets"""

    def __init__(
        self,
        name: str,
        pattern: str,
        secret_type: SecretType,
        severity: SecretSeverity,
        confidence: float = 1.0,
        validator: Optional[callable] = None
    ):
        self.name = name
        self.pattern = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
        self.secret_type = secret_type
        self.severity = severity
        self.confidence = confidence
        self.validator = validator


class SecretScanner:
    """
    Comprehensive secret scanner for configurations and code
    """

    def __init__(self):
        self.patterns = self._initialize_patterns()
        self.whitelist = self._initialize_whitelist()
        self.entropy_threshold = 4.5  # Shannon entropy threshold
        self.min_secret_length = 6
        self.max_secret_length = 1000

    def _initialize_patterns(self) -> List[SecretPattern]:
        """Initialize secret detection patterns"""
        patterns = [
            # Passwords
            SecretPattern(
                "password_assignment",
                r'(?:password|passwd|pwd)\s*[=:]\s*["\']?([^"\'\s]+)["\']?',
                SecretType.PASSWORD,
                SecretSeverity.CRITICAL
            ),
            SecretPattern(
                "cisco_enable_secret",
                r'enable\s+(?:secret|password)\s+(?:\d+\s+)?([^\s]+)',
                SecretType.ENABLE_SECRET,
                SecretSeverity.CRITICAL
            ),

            # API Keys
            SecretPattern(
                "generic_api_key",
                r'(?:api[_-]?key|apikey)\s*[=:]\s*["\']?([a-zA-Z0-9\-_]{20,})["\']?',
                SecretType.API_KEY,
                SecretSeverity.HIGH
            ),
            SecretPattern(
                "aws_access_key",
                r'(AKIA[0-9A-Z]{16})',
                SecretType.AWS_CREDENTIALS,
                SecretSeverity.CRITICAL,
                validator=self._validate_aws_key
            ),
            SecretPattern(
                "aws_secret_key",
                r'(?:aws_secret_access_key|aws_secret_key)\s*[=:]\s*["\']?([a-zA-Z0-9/+=]{40})["\']?',
                SecretType.AWS_CREDENTIALS,
                SecretSeverity.CRITICAL
            ),

            # Tokens
            SecretPattern(
                "generic_token",
                r'(?:token|auth[_-]?token|bearer)\s*[=:]\s*["\']?([a-zA-Z0-9\-_\.]{20,})["\']?',
                SecretType.TOKEN,
                SecretSeverity.HIGH
            ),
            SecretPattern(
                "github_token",
                r'(gh[ps]_[a-zA-Z0-9]{36})',
                SecretType.TOKEN,
                SecretSeverity.CRITICAL
            ),
            SecretPattern(
                "jwt_token",
                r'(eyJ[a-zA-Z0-9\-_]+\.eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+)',
                SecretType.TOKEN,
                SecretSeverity.HIGH,
                validator=self._validate_jwt
            ),

            # Private Keys
            SecretPattern(
                "private_key_header",
                r'-----BEGIN\s+(RSA|DSA|EC|OPENSSH|PGP)\s+PRIVATE KEY-----',
                SecretType.PRIVATE_KEY,
                SecretSeverity.CRITICAL
            ),
            SecretPattern(
                "ssh_private_key",
                r'-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]+?-----END OPENSSH PRIVATE KEY-----',
                SecretType.SSH_KEY,
                SecretSeverity.CRITICAL
            ),

            # Certificates
            SecretPattern(
                "certificate",
                r'-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----',
                SecretType.CERTIFICATE,
                SecretSeverity.MEDIUM
            ),

            # Database URLs
            SecretPattern(
                "database_url",
                r'(?:mongodb|postgresql|mysql|redis|amqp)://[^:]+:([^@]+)@[^\s]+',
                SecretType.DATABASE_URL,
                SecretSeverity.CRITICAL
            ),

            # SNMP
            SecretPattern(
                "snmp_community",
                r'snmp[_-]?community\s+([^\s]+)',
                SecretType.SNMP_COMMUNITY,
                SecretSeverity.HIGH
            ),

            # Azure
            SecretPattern(
                "azure_key",
                r'(?:AccountKey|SharedAccessKey)\s*=\s*([a-zA-Z0-9+/]{86}==)',
                SecretType.AZURE_CREDENTIALS,
                SecretSeverity.CRITICAL
            ),

            # GCP
            SecretPattern(
                "gcp_service_account",
                r'"private_key"\s*:\s*"(-----BEGIN\s+[^"]+-----)"',
                SecretType.GCP_CREDENTIALS,
                SecretSeverity.CRITICAL
            ),

            # Webhook URLs with tokens
            SecretPattern(
                "webhook_url",
                r'https://(?:hooks|api|webhook)[^\s]*\?(?:token|key|auth)=([a-zA-Z0-9\-_]+)',
                SecretType.WEBHOOK_URL,
                SecretSeverity.HIGH
            ),

            # Encryption Keys
            SecretPattern(
                "hex_encryption_key",
                r'(?:encryption[_-]?key|aes[_-]?key)\s*[=:]\s*["\']?([0-9a-fA-F]{32,})["\']?',
                SecretType.ENCRYPTION_KEY,
                SecretSeverity.CRITICAL
            ),
            SecretPattern(
                "base64_key",
                r'(?:key|secret)\s*[=:]\s*["\']?([a-zA-Z0-9+/]{32,}={0,2})["\']?',
                SecretType.SECRET,
                SecretSeverity.HIGH,
                validator=self._validate_base64
            ),
        ]

        return patterns

    def _initialize_whitelist(self) -> List[str]:
        """Initialize whitelist of safe patterns"""
        return [
            'example.com',
            'localhost',
            '127.0.0.1',
            'placeholder',
            'your-',
            'changeme',
            '<.*>',  # Template variables
            r'\$\{.*\}',  # Environment variables
            'xxx',
            'dummy',
            'test',
            'sample'
        ]

    async def scan_text(
        self,
        text: str,
        file_path: Optional[str] = None,
        context_lines: int = 2
    ) -> List[SecretMatch]:
        """
        Scan text for exposed secrets

        Args:
            text: Text to scan
            file_path: Optional file path for context
            context_lines: Number of context lines to include

        Returns:
            List of detected secrets
        """
        matches = []
        lines = text.split('\n')

        # Pattern-based detection
        for pattern in self.patterns:
            for match in pattern.pattern.finditer(text):
                # Get line number
                line_start = text[:match.start()].count('\n')
                line_number = line_start + 1

                # Get the matched secret
                if match.groups():
                    secret_text = match.group(1)
                else:
                    secret_text = match.group(0)

                # Skip if whitelisted
                if self._is_whitelisted(secret_text):
                    continue

                # Skip if too short or too long
                if not self.min_secret_length <= len(secret_text) <= self.max_secret_length:
                    continue

                # Validate if validator exists
                confidence = pattern.confidence
                if pattern.validator:
                    if not pattern.validator(secret_text):
                        continue

                # Get context
                context = self._get_context(lines, line_number - 1, context_lines)

                # Calculate column positions
                line_text = lines[line_number - 1] if line_number <= len(lines) else ""
                column_start = line_text.find(secret_text) if line_text else None
                column_end = column_start + len(secret_text) if column_start else None

                secret_match = SecretMatch(
                    secret_type=pattern.secret_type,
                    severity=pattern.severity,
                    pattern_name=pattern.name,
                    match_text=secret_text,
                    file_path=file_path,
                    line_number=line_number,
                    column_start=column_start,
                    column_end=column_end,
                    context=context,
                    confidence=confidence
                )

                matches.append(secret_match)

        # Entropy-based detection for high-entropy strings
        entropy_matches = await self._detect_high_entropy_strings(text, file_path)
        matches.extend(entropy_matches)

        # Remove duplicates
        unique_matches = self._deduplicate_matches(matches)

        return unique_matches

    async def scan_file(self, file_path: Path) -> List[SecretMatch]:
        """Scan a file for secrets"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            return await self.scan_text(content, str(file_path))

        except Exception as e:
            logger.error(f"Error scanning file {file_path}: {e}")
            return []

    async def scan_directory(
        self,
        directory: Path,
        extensions: Optional[List[str]] = None,
        exclude_patterns: Optional[List[str]] = None
    ) -> Dict[str, List[SecretMatch]]:
        """
        Scan directory recursively for secrets

        Args:
            directory: Directory to scan
            extensions: File extensions to scan (None for all)
            exclude_patterns: Patterns to exclude

        Returns:
            Dictionary mapping file paths to detected secrets
        """
        results = {}
        exclude_patterns = exclude_patterns or ['.git', '__pycache__', 'node_modules', '.env']

        for file_path in directory.rglob('*'):
            # Skip directories
            if file_path.is_dir():
                continue

            # Skip excluded patterns
            if any(pattern in str(file_path) for pattern in exclude_patterns):
                continue

            # Check extensions
            if extensions and file_path.suffix not in extensions:
                continue

            # Scan file
            matches = await self.scan_file(file_path)
            if matches:
                results[str(file_path)] = matches

        return results

    async def scan_git_diff(self, diff_text: str) -> List[SecretMatch]:
        """Scan git diff for secrets in added lines"""
        matches = []
        current_file = None
        line_number = 0

        for line in diff_text.split('\n'):
            # Track current file
            if line.startswith('diff --git'):
                parts = line.split()
                if len(parts) >= 4:
                    current_file = parts[3].replace('b/', '')
                line_number = 0

            # Track line numbers
            elif line.startswith('@@'):
                # Parse line numbers from diff header
                match = re.search(r'\+(\d+)', line)
                if match:
                    line_number = int(match.group(1)) - 1

            # Check added lines for secrets
            elif line.startswith('+') and not line.startswith('+++'):
                line_number += 1
                line_content = line[1:]  # Remove the + prefix

                # Scan the added line
                line_matches = await self.scan_text(
                    line_content,
                    file_path=current_file
                )

                # Update line numbers
                for match in line_matches:
                    match.line_number = line_number

                matches.extend(line_matches)

            elif not line.startswith('-'):
                line_number += 1

        return matches

    async def _detect_high_entropy_strings(
        self,
        text: str,
        file_path: Optional[str] = None
    ) -> List[SecretMatch]:
        """Detect high-entropy strings that might be secrets"""
        matches = []

        # Find potential secret strings (alphanumeric sequences)
        potential_secrets = re.findall(
            r'["\']([a-zA-Z0-9+/=_\-]{20,})["\']',
            text
        )

        for secret in potential_secrets:
            # Skip if whitelisted
            if self._is_whitelisted(secret):
                continue

            # Calculate Shannon entropy
            entropy = self._calculate_entropy(secret)

            if entropy >= self.entropy_threshold:
                # Try to determine type based on characteristics
                secret_type = self._guess_secret_type(secret)

                line_number = text[:text.find(secret)].count('\n') + 1 if secret in text else None

                match = SecretMatch(
                    secret_type=secret_type,
                    severity=SecretSeverity.MEDIUM,
                    pattern_name="high_entropy",
                    match_text=secret,
                    file_path=file_path,
                    line_number=line_number,
                    confidence=min(entropy / 6.0, 1.0)  # Normalize confidence
                )

                matches.append(match)

        return matches

    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of a string"""
        if not text:
            return 0

        # Calculate character frequency
        freq = {}
        for char in text:
            freq[char] = freq.get(char, 0) + 1

        # Calculate entropy
        entropy = 0
        text_len = len(text)

        for count in freq.values():
            probability = count / text_len
            if probability > 0:
                import math
                entropy -= probability * math.log2(probability)

        return entropy

    def _guess_secret_type(self, secret: str) -> SecretType:
        """Guess the type of secret based on its characteristics"""
        # Check for specific formats
        if secret.startswith('AKIA'):
            return SecretType.AWS_CREDENTIALS
        elif secret.startswith('eyJ'):
            return SecretType.TOKEN
        elif len(secret) == 40 and all(c in '0123456789abcdef' for c in secret.lower()):
            return SecretType.API_KEY
        elif '=' in secret and self._validate_base64(secret):
            return SecretType.ENCRYPTION_KEY
        else:
            return SecretType.SECRET

    def _is_whitelisted(self, text: str) -> bool:
        """Check if text matches whitelist patterns"""
        text_lower = text.lower()

        for pattern in self.whitelist:
            if pattern in text_lower:
                return True

        # Check for placeholder patterns
        if re.match(r'^[A-Z_]+$', text):  # All uppercase (likely a constant)
            return True

        if re.match(r'^\$\{.*\}$', text):  # Environment variable
            return True

        return False

    def _validate_aws_key(self, key: str) -> bool:
        """Validate AWS access key format"""
        return bool(re.match(r'^AKIA[0-9A-Z]{16}$', key))

    def _validate_jwt(self, token: str) -> bool:
        """Validate JWT token format"""
        parts = token.split('.')
        if len(parts) != 3:
            return False

        try:
            for part in parts[:2]:
                # Add padding if necessary
                padding = 4 - len(part) % 4
                if padding != 4:
                    part += '=' * padding
                base64.b64decode(part)
            return True
        except Exception:
            return False

    def _validate_base64(self, text: str) -> bool:
        """Validate if string is valid base64"""
        try:
            # Check if it's valid base64
            decoded = base64.b64decode(text, validate=True)
            # Check if decoded content has reasonable entropy (not all zeros/ones)
            if len(set(decoded)) < 2:
                return False
            return True
        except Exception:
            return False

    def _get_context(self, lines: List[str], line_index: int, context_lines: int) -> str:
        """Get context lines around a match"""
        start = max(0, line_index - context_lines)
        end = min(len(lines), line_index + context_lines + 1)

        context = []
        for i in range(start, end):
            prefix = '> ' if i == line_index else '  '
            context.append(f"{i + 1:4d}{prefix}{lines[i]}")

        return '\n'.join(context)

    def _deduplicate_matches(self, matches: List[SecretMatch]) -> List[SecretMatch]:
        """Remove duplicate matches"""
        seen_hashes = set()
        unique_matches = []

        for match in matches:
            if match.hash not in seen_hashes:
                seen_hashes.add(match.hash)
                unique_matches.append(match)

        return unique_matches

    def generate_report(self, matches: List[SecretMatch]) -> str:
        """Generate a human-readable report of detected secrets"""
        if not matches:
            return "No secrets detected."

        report = []
        report.append("=" * 60)
        report.append("SECRET SCANNER REPORT")
        report.append("=" * 60)
        report.append(f"Total secrets detected: {len(matches)}")
        report.append("")

        # Group by severity
        by_severity = {}
        for match in matches:
            severity = match.severity.value
            if severity not in by_severity:
                by_severity[severity] = []
            by_severity[severity].append(match)

        # Report by severity
        for severity in [SecretSeverity.CRITICAL, SecretSeverity.HIGH,
                        SecretSeverity.MEDIUM, SecretSeverity.LOW, SecretSeverity.INFO]:
            if severity.value in by_severity:
                report.append(f"{severity.value.upper()} ({len(by_severity[severity.value])} found):")
                report.append("-" * 40)

                for match in by_severity[severity.value][:10]:  # Limit to 10 per severity
                    report.append(f"  Type: {match.secret_type.value}")
                    report.append(f"  File: {match.file_path or 'N/A'}")
                    if match.line_number:
                        report.append(f"  Line: {match.line_number}")
                    report.append(f"  Pattern: {match.pattern_name}")
                    report.append(f"  Match: {match._redact_secret(match.match_text)}")
                    report.append(f"  Confidence: {match.confidence:.2%}")
                    report.append("")

                if len(by_severity[severity.value]) > 10:
                    report.append(f"  ... and {len(by_severity[severity.value]) - 10} more")
                    report.append("")

        report.append("=" * 60)
        report.append("RECOMMENDATIONS:")
        report.append("-" * 40)
        report.append("1. Remove all detected secrets from code/configurations")
        report.append("2. Rotate any exposed credentials immediately")
        report.append("3. Use environment variables or secret management systems")
        report.append("4. Add pre-commit hooks to prevent future secret commits")
        report.append("5. Review git history for previously committed secrets")
        report.append("=" * 60)

        return "\n".join(report)

    async def quarantine_secrets(self, matches: List[SecretMatch], quarantine_dir: Path):
        """Move files containing secrets to quarantine directory"""
        quarantine_dir.mkdir(parents=True, exist_ok=True)
        quarantined = set()

        for match in matches:
            if match.file_path and match.severity in [SecretSeverity.CRITICAL, SecretSeverity.HIGH]:
                source = Path(match.file_path)
                if source.exists() and str(source) not in quarantined:
                    # Create quarantine path maintaining directory structure
                    relative_path = source.relative_to(source.anchor)
                    dest = quarantine_dir / relative_path
                    dest.parent.mkdir(parents=True, exist_ok=True)

                    # Move file to quarantine
                    source.rename(dest)
                    quarantined.add(str(source))

                    # Log security event
                    log_security(
                        event_type="secret_quarantine",
                        severity="high",
                        description=f"File quarantined due to exposed secrets",
                        details={
                            'file': str(source),
                            'quarantine_location': str(dest),
                            'secret_type': match.secret_type.value
                        }
                    )

        return list(quarantined)


# Global scanner instance
secret_scanner = SecretScanner()


# Convenience functions
async def scan_for_secrets(text: str, file_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """Scan text for exposed secrets"""
    matches = await secret_scanner.scan_text(text, file_path)
    return [match.to_dict() for match in matches]


async def scan_file_for_secrets(file_path: Path) -> List[Dict[str, Any]]:
    """Scan a file for exposed secrets"""
    matches = await secret_scanner.scan_file(file_path)
    return [match.to_dict() for match in matches]


async def scan_directory_for_secrets(
    directory: Path,
    extensions: Optional[List[str]] = None
) -> Dict[str, List[Dict[str, Any]]]:
    """Scan directory for exposed secrets"""
    results = await secret_scanner.scan_directory(directory, extensions)
    return {
        path: [match.to_dict() for match in matches]
        for path, matches in results.items()
    }
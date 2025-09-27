from typing import List, Dict, Any
import re
import structlog
import base64
import git

logger = structlog.get_logger()

class SecretScanner:
    def __init__(self):
        self.secret_patterns = {
            'aws_access_key': r'AKIA[0-9A-Z]{16}',
            'aws_secret_key': r'[0-9a-zA-Z/+]{40}',
            'github_token': r'ghp_[0-9a-zA-Z]{36}',
            'private_key': r'-----BEGIN [A-Z]+ PRIVATE KEY-----',
            'password': r'password["\']?\s*[:=]\s*["\'][^"\']+["\']',
            'api_key': r'api[_-]?key["\']?\s*[:=]\s*["\'][^"\']+["\']',
            'secret': r'secret["\']?\s*[:=]\s*["\'][^"\']+["\']',
            'token': r'token["\']?\s*[:=]\s*["\'][^"\']+["\']',
            'jwt': r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*',
            'connection_string': r'[a-zA-Z]+://[^:]+:[^@]+@[^/]+',
            'ssh_key': r'ssh-rsa AAAAB3NzaC1yc2[0-9A-Za-z+/]+[=]*',
            'certificate': r'-----BEGIN CERTIFICATE-----',
            'mongodb_uri': r'mongodb(\+srv)?://[^:]+:[^@]+@[^/]+',
            'database_url': r'(postgres|mysql|redis)://[^:]+:[^@]+@[^/]+'
        }

        self.entropy_threshold = 4.5
        self.min_string_length = 20

    async def scan_commits(
        self,
        repo_path: str,
        old_commit: str,
        new_commit: str
    ) -> List[Dict[str, Any]]:
        try:
            repo = git.Repo(repo_path)
            secrets = []

            diff = repo.git.diff(f"{old_commit}..{new_commit}", unified=0)

            for line in diff.split('\n'):
                if line.startswith('+') and not line.startswith('+++'):
                    content = line[1:]
                    file_secrets = self._scan_content(content, "diff")
                    secrets.extend(file_secrets)

            return secrets

        except Exception as e:
            logger.error(f"Failed to scan commits: {e}")
            return []

    async def scan_webhook_files(
        self,
        files: List[str],
        payload: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        secrets = []

        for file_path in files:
            if self._should_scan_file(file_path):
                file_content = self._extract_file_content_from_payload(
                    file_path, payload
                )
                if file_content:
                    file_secrets = self._scan_content(file_content, file_path)
                    secrets.extend(file_secrets)

        return secrets

    def _should_scan_file(self, file_path: str) -> bool:
        scan_extensions = [
            '.py', '.js', '.ts', '.java', '.go', '.rb', '.php',
            '.yaml', '.yml', '.json', '.xml', '.conf', '.env',
            '.sh', '.bash', '.ps1', '.sql', '.md', '.txt'
        ]

        skip_patterns = [
            'node_modules/', '.git/', '__pycache__/', '.pytest_cache/',
            'vendor/', 'dist/', 'build/', '.venv/', 'venv/'
        ]

        for pattern in skip_patterns:
            if pattern in file_path:
                return False

        for ext in scan_extensions:
            if file_path.endswith(ext):
                return True

        return False

    def _extract_file_content_from_payload(
        self,
        file_path: str,
        payload: Dict[str, Any]
    ) -> str:
        commits = payload.get('commits', [])
        for commit in commits:
            for added_file in commit.get('added', []):
                if added_file == file_path:
                    return commit.get('content', '')
            for modified_file in commit.get('modified', []):
                if modified_file == file_path:
                    return commit.get('content', '')

        return ""

    def _scan_content(self, content: str, source: str) -> List[Dict[str, Any]]:
        secrets = []

        for secret_type, pattern in self.secret_patterns.items():
            matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                secret_value = match.group()

                if self._is_likely_secret(secret_value):
                    secrets.append({
                        'type': secret_type,
                        'value': secret_value[:20] + '...' if len(secret_value) > 20 else secret_value,
                        'pattern': pattern,
                        'file': source,
                        'line': self._get_line_number(content, match.start()),
                        'entropy': self._calculate_entropy(secret_value)
                    })

        high_entropy_strings = self._find_high_entropy_strings(content)
        for entropy_string in high_entropy_strings:
            secrets.append({
                'type': 'high_entropy',
                'value': entropy_string['value'][:20] + '...',
                'pattern': 'entropy_analysis',
                'file': source,
                'line': entropy_string['line'],
                'entropy': entropy_string['entropy']
            })

        return secrets

    def _is_likely_secret(self, value: str) -> bool:
        false_positives = [
            'example', 'test', 'dummy', 'placeholder', 'sample',
            'todo', 'fixme', 'xxx', 'yyy', 'zzz', 'abc123',
            'password123', 'secret123', '12345', 'qwerty'
        ]

        value_lower = value.lower()
        for fp in false_positives:
            if fp in value_lower:
                return False

        if len(value) < 8:
            return False

        entropy = self._calculate_entropy(value)
        return entropy >= self.entropy_threshold

    def _calculate_entropy(self, string: str) -> float:
        import math
        from collections import Counter

        if not string:
            return 0

        counts = Counter(string)
        length = len(string)

        entropy = -sum(
            (count / length) * math.log2(count / length)
            for count in counts.values()
        )

        return entropy

    def _find_high_entropy_strings(self, content: str) -> List[Dict[str, Any]]:
        high_entropy_strings = []

        string_patterns = [
            r'["\'][A-Za-z0-9+/=]{20,}["\']',
            r'[A-Za-z0-9+/=]{32,}',
            r'[A-Fa-f0-9]{32,}'
        ]

        for pattern in string_patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                value = match.group().strip('"\'')

                if len(value) >= self.min_string_length:
                    entropy = self._calculate_entropy(value)

                    if entropy >= self.entropy_threshold:
                        high_entropy_strings.append({
                            'value': value,
                            'entropy': entropy,
                            'line': self._get_line_number(content, match.start())
                        })

        return high_entropy_strings

    def _get_line_number(self, content: str, position: int) -> int:
        return content[:position].count('\n') + 1

    def scan_base64_content(self, content: str) -> List[Dict[str, Any]]:
        secrets = []
        base64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'

        matches = re.finditer(base64_pattern, content)
        for match in matches:
            try:
                decoded = base64.b64decode(match.group()).decode('utf-8')
                decoded_secrets = self._scan_content(decoded, "base64_decoded")
                secrets.extend(decoded_secrets)
            except:
                pass

        return secrets

    def validate_secret_patterns(self) -> Dict[str, bool]:
        validation_results = {}

        test_strings = {
            'aws_access_key': 'AKIAIOSFODNN7EXAMPLE',
            'github_token': 'ghp_1234567890abcdef1234567890abcdef12',
            'jwt': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'
        }

        for secret_type, test_string in test_strings.items():
            if secret_type in self.secret_patterns:
                pattern = self.secret_patterns[secret_type]
                match = re.search(pattern, test_string, re.IGNORECASE)
                validation_results[secret_type] = match is not None
            else:
                validation_results[secret_type] = False

        return validation_results
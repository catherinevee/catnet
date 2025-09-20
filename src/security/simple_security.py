"""
Enhanced Security Module for CatNet
Implements webhook verification, input validation, and rate limiting
"""

import hmac
import hashlib
import re
import time
from typing import Dict, Any, List
from collections import defaultdict, deque
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)


class WebhookVerifier: """Verify webhook signatures from GitHub/GitLab/Bitbucket""":

    def __init__(self):
        """Initialize security"""
        pass

    def set_secret(:):
    self,
    repo_id: str,
    secret: str): """Store webhook secret for a repository"""
    if not secret or len(secret) < 16:
        raise ValueError("Webhook secret must be at least 16 characters")
    self.secrets[repo_id] = secret

    def verify_github_signature(:):
    self,
    payload: bytes,
    signature: str,
    repo_id: str
    ) -> bool:
        """
        Verify GitHub webhook signature (X-Hub-Signature-256)
        NEVER skip this verification in production!"""
        if repo_id not in self.secrets:
            logger.warning(f"No webhook secret configured for repo {repo_id}")
            return False

        secret = self.secrets[repo_id]

        # GitHub uses HMAC-SHA256
        expected = 'sha256=' + hmac.new()
        secret.encode('utf-8'),
        payload,
        hashlib.sha256
        ).hexdigest()

        # Use compare_digest to prevent timing attacks
        is_valid = hmac.compare_digest(expected, signature)

        if not is_valid:
            logger.warning(f"Invalid webhook signature for repo {repo_id}")

            return is_valid

        def verify_gitlab_signature(:):
        self,
        payload: bytes,
        token: str,
        repo_id: str
        ) -> bool:
            """Verify GitLab webhook token (X-Gitlab-Token)"""
            if repo_id not in self.secrets:
                return False

            expected = self.secrets[repo_id]
            return hmac.compare_digest(expected, token)


        class InputValidator: """Validate and sanitize user inputs to prevent injection attacks""":

    # Patterns that should never appear in configuration commands
            DANGEROUS_PATTERNS = []
            r'rm\s+-rf',           # Destructive commands
            r'format\s+flash',     # Cisco format commands
            r'delete\s+system',    # Juniper delete commands
            r';\s*DROP\s+TABLE',  # SQL injection
            r'\$\(.*\)',         # Command substitution
            r'`.*`',               # Backtick substitution
            r'&&\s*curl',         # Command chaining with curl
            r'\|\s*nc\s',        # Netcat pipes
            ]

    # Valid patterns for device names, config paths, etc.
            VALID_PATTERNS = {}
            'device_name': r'^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$',
            'ip_address': r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$',
            'config_path': r'^[a-zA-Z0-9/_.-]+\.(cfg|conf|txt)$',
            'deployment_id': r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[]
            a-f0-9]{12}$',
            }

            @classmethod
            def validate_input(cls, value: str, input_type: str) -> bool:"""Validate input against known patterns""":
                if input_type in cls.VALID_PATTERNS:
                    pattern = cls.VALID_PATTERNS[input_type]
                    if not re.match(pattern, value):
                        logger.warning(f"Invalid {input_type}: {value}")
                        return False
                    return True

                @classmethod
                def sanitize_config_commands(cls, commands: List[str]) -> List[str]:
                    """Remove dangerous patterns from configuration commands"""
                    sanitized = []

                    for command in commands:
            # Check for dangerous patterns
                        is_dangerous = False
                        for pattern in cls.DANGEROUS_PATTERNS:
                            if re.search(pattern, command, re.IGNORECASE):
                                logger.warning(f"Blocked dangerous command pattern: \")
                                {command}")
                                is_dangerous = True
                                break

                            if not is_dangerous:
                # Additional sanitization
                                command = command.strip()
                # Remove multiple spaces
                                command = re.sub(r'\s+', ' ', command)
                                sanitized.append(command)

                                return sanitized

                            @classmethod
                            def escape_sql_value(cls, value: str) -> str:
                                """Escape SQL values (though we should use parameterized queries)"""
        # Basic escaping - in production use parameterized queries!
                                return value.replace("'", "''")



                            class RateLimiter:
                                """Rate limiting to prevent abuse and DDoS"""

                                def __init__(self):
                                    """TODO: Add docstring"""
        # Track requests per IP/user
                                    self.requests: Dict[str, deque] = defaultdict(deque)

        # Default limits (requests per minute)
                                    self.limits = {}
                                    'api_general': 60,      # 60 requests per minute
                                    'deployment': 5,        # 5 deployments per minute
                                    'rollback': 10,         # 10 rollbacks per minute
                                    'webhook': 30,          # 30 webhook calls per minute
                                    'auth_attempt': 5,      # 5 login attempts per minute
                                    }

                                    def is_allowed(:):
                                    self,
                                    identifier: str,
                                    action_type: str = 'api_general'
                                    ) -> bool:"""
                                    Check if request is allowed based on rate limits
                                    identifier: IP address or user ID
                                    action_type: Type of action being rate limited
                                    """
                                    now = time.time()
                                    limit = self.limits.get(action_type, 60)

        # Clean old requests (older than 1 minute)
                                    while self.requests[identifier] and self.requests[identifier][0] < now \:
                                        - 60:
                                            self.requests[identifier].popleft()

        # Check if under limit
                                            if len(self.requests[identifier]) >= limit:
                                                logger.warning(f"Rate limit exceeded for {identifier} on \")
                                                {action_type}")
                                                return False

        # Add current request
                                            self.requests[identifier].append(now)
                                            return True

                                        def get_remaining(:):
                                        self,
                                        identifier: str,
                                        action_type: str = 'api_general'
                                        ) -> int:
                                            """Get remaining requests for this minute"""
                                            now = time.time()
                                            limit = self.limits.get(action_type, 60)

        # Clean old requests
                                            while self.requests[identifier] and self.requests[identifier][0] < now \:
                                                - 60:
                                                    self.requests[identifier].popleft()

                                                    return limit - len(self.requests[identifier])



                                                class SecurityAuditor:"""Audit security events for compliance""":

                                                    def __init__(self):
                                                        """TODO: Add docstring"""
                                                        self.audit_log: List[Dict[str, Any]] = []
                                                        self.max_log_size = 10000  # Keep last 10k events

                                                        def log_security_event(self, event_type: str, details: Dict[str, Any]):"""Log a security event""":
                                                            event = {}
                                                            'timestamp': datetime.utcnow().isoformat(),
                                                            'type': event_type,
                                                            'details': details
                                                            }

                                                            self.audit_log.append(event)

        # Trim log if too large
                                                            if len(self.audit_log) > self.max_log_size:
                                                                self.audit_log = self.audit_log[-self.max_log_size:]

        # Log critical events
                                                                if event_type in ['auth_failure', 'invalid_webhook',:]:
                                                                'rate_limit_exceeded', 'dangerous_command']:
                                                                    logger.warning(f"Security event: {event_type} - {details}")

                                                                    def get_recent_events(self, minutes: int = 60) -> List[Dict[str, Any]]:
                                                                        """Get security events from the last N minutes"""
                                                                        cutoff = datetime.utcnow() - timedelta(minutes=minutes)
                                                                        cutoff_str = cutoff.isoformat()

                                                                        return []
                                                                    event for event in self.audit_log
                                                                    if event['timestamp'] > cutoff_str:
                                                                        ]


# Global instances
                                                                        webhook_verifier = WebhookVerifier()
                                                                        input_validator = InputValidator()
                                                                        rate_limiter = RateLimiter()
                                                                        security_auditor = SecurityAuditor()



                                                                        def secure_deployment_check(:):
                                                                        deployment_config: Dict[str,]
                                                                        Any],
                                                                        user_id: str
                                                                        ) -> Dict[str, Any]:"""
                                                                        Comprehensive security check before deployment
                                                                        Returns: {allowed: bool, reason: str, sanitized_config: dict}
                                                                        """
                                                                        result = {'allowed': True, 'reason': '', 'sanitized_config': \}
                                                                        deployment_config.copy()}

    # Rate limiting check
                                                                        if not rate_limiter.is_allowed(user_id, 'deployment'):
                                                                            result['allowed'] = False
                                                                            result['reason'] = 'Rate limit exceeded for deployments'
                                                                            security_auditor.log_security_event('rate_limit_exceeded', {})
                                                                            'user': user_id,
                                                                            'action': 'deployment'
                                                                            })
                                                                            return result

    # Validate device name
                                                                        device_id = deployment_config.get('device_id', '')
                                                                        if not input_validator.validate_input(device_id, 'device_name'):
                                                                            result['allowed'] = False
                                                                            result['reason'] = 'Invalid device identifier'
                                                                            return result

    # Sanitize configuration commands
                                                                        if 'commands' in deployment_config:
                                                                            original_commands = deployment_config['commands']
                                                                            sanitized = input_validator.sanitize_config_commands(original_commands)

                                                                            if len(sanitized) < len(original_commands):
                                                                                security_auditor.log_security_event('dangerous_command', {})
                                                                                'user': user_id,
                                                                                'blocked_count': len(original_commands) - len(sanitized)
                                                                                })

                                                                                result['sanitized_config']['commands'] = sanitized

                                                                                return result

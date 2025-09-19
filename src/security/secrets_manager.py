"""
Secrets Management for CatNet

Handles:
- Credential management
- API key management
- Token management
- Secret rotation
- Access control
"""

from typing import Dict, Any, Optional, List, Set
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import asyncio
import secrets
import string
from collections import defaultdict
import hashlib
import hmac


class CredentialType(Enum):
    """Types of credentials"""

    PASSWORD = "password"
    API_KEY = "api_key"
    TOKEN = "token"
    SSH_KEY = "ssh_key"
    CERTIFICATE = "certificate"
    DATABASE = "database"
    SERVICE_ACCOUNT = "service_account"


class AccessLevel(Enum):
    """Access levels for secrets"""

    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    ROTATE = "rotate"
    ADMIN = "admin"


@dataclass
class Credential:
    """Credential object"""

    id: str
    name: str
    type: CredentialType
    username: Optional[str]
    value: str  # Encrypted value
    created_at: datetime
    expires_at: Optional[datetime]
    last_used: Optional[datetime] = None
    last_rotated: Optional[datetime] = None
    rotation_period: Optional[timedelta] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    tags: Set[str] = field(default_factory=set)
    access_count: int = 0
    active: bool = True


@dataclass
class SecretPolicy:
    """Policy for secret management"""

    name: str
    credential_types: List[CredentialType]
    min_length: int = 12
    max_length: int = 128
    require_rotation: bool = True
    rotation_days: int = 90
    require_uppercase: bool = True
    require_lowercase: bool = True
    require_numbers: bool = True
    require_special: bool = True
    allowed_special: str = "!@#$%^&*()-_=+[]{}|;:,.<>?"
    complexity_score: int = 3  # 1-5 scale
    max_reuse: int = 5
    expiry_days: Optional[int] = None


@dataclass
class AccessRequest:
    """Request for secret access"""

    request_id: str
    credential_id: str
    requester: str
    purpose: str
    access_level: AccessLevel
    requested_at: datetime
    expires_at: datetime
    approved: bool = False
    approved_by: Optional[str] = None
    approved_at: Optional[datetime] = None
    revoked: bool = False


class SecretsManager:
    """
    Manages secrets and credentials
    """

    def __init__(self, vault_service=None, audit_service=None):
        """
        Initialize secrets manager

        Args:
            vault_service: Vault service for storage
            audit_service: Audit service for logging
        """
        self.vault_service = vault_service
        self.audit_service = audit_service

        # In-memory credential store (encrypted values)
        self.credentials: Dict[str, Credential] = {}

        # Access control
        self.access_control: Dict[str, Dict[str, Set[AccessLevel]]] = defaultdict(
            lambda: defaultdict(set)
        )
        self.access_requests: Dict[str, AccessRequest] = {}

        # Policies
        self.policies: Dict[str, SecretPolicy] = {}
        self._initialize_default_policies()

        # Password history for reuse prevention
        self.password_history: Dict[str, List[str]] = defaultdict(list)

        # Rotation scheduler
        self.rotation_tasks: Dict[str, asyncio.Task] = {}

    def _initialize_default_policies(self):
        """Initialize default security policies"""
        # Strong password policy
        self.policies["strong_password"] = SecretPolicy(
            name="strong_password",
            credential_types=[CredentialType.PASSWORD],
            min_length=16,
            max_length=128,
            require_rotation=True,
            rotation_days=90,
            require_uppercase=True,
            require_lowercase=True,
            require_numbers=True,
            require_special=True,
            complexity_score=4,
            max_reuse=5,
        )

        # API key policy
        self.policies["api_key"] = SecretPolicy(
            name="api_key",
            credential_types=[CredentialType.API_KEY],
            min_length=32,
            max_length=64,
            require_rotation=True,
            rotation_days=365,
            require_uppercase=True,
            require_lowercase=True,
            require_numbers=True,
            require_special=False,
            complexity_score=3,
            expiry_days=365,
        )

        # Token policy
        self.policies["token"] = SecretPolicy(
            name="token",
            credential_types=[CredentialType.TOKEN],
            min_length=32,
            max_length=256,
            require_rotation=True,
            rotation_days=7,
            complexity_score=3,
            expiry_days=30,
        )

        # Database credential policy
        self.policies["database"] = SecretPolicy(
            name="database",
            credential_types=[CredentialType.DATABASE],
            min_length=20,
            max_length=64,
            require_rotation=True,
            rotation_days=30,
            require_uppercase=True,
            require_lowercase=True,
            require_numbers=True,
            require_special=True,
            complexity_score=5,
        )

    async def create_credential(
        self,
        name: str,
        type: CredentialType,
        username: Optional[str] = None,
        value: Optional[str] = None,
        policy_name: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        tags: Optional[Set[str]] = None,
        auto_rotate: bool = True,
    ) -> Credential:
        """
        Create a new credential

        Args:
            name: Credential name
            type: Credential type
            username: Associated username
            value: Credential value (generated if not provided)
            policy_name: Policy to apply
            metadata: Additional metadata
            tags: Credential tags
            auto_rotate: Enable automatic rotation

        Returns:
            Created credential
        """
        import uuid

        # Get applicable policy
        policy = self._get_policy(type, policy_name)

        # Generate value if not provided
        if not value:
            value = self._generate_credential(type, policy)

        # Validate credential against policy
        if not self._validate_credential(value, policy):
            raise ValueError("Credential does not meet policy requirements")

        # Check for reuse
        if type == CredentialType.PASSWORD:
            if self._check_password_reuse(name, value, policy.max_reuse):
                raise ValueError("Password has been used recently")

        # Encrypt value
        if self.vault_service:
            encrypted_value, key_id = await self.vault_service.encrypt_data(
                value.encode()
            )
            # Store in vault
            await self.vault_service.store_secret(
                path=f"credentials/{type.value}/{name}",
                key="value",
                value=encrypted_value.hex(),
                metadata={"key_id": key_id},
            )
        else:
            encrypted_value = value.encode()

        # Create credential object
        credential = Credential(
            id=str(uuid.uuid4())[:12],
            name=name,
            type=type,
            username=username,
            value=encrypted_value.hex(),
            created_at=datetime.utcnow(),
            expires_at=(
                datetime.utcnow() + timedelta(days=policy.expiry_days)
                if policy.expiry_days
                else None
            ),
            rotation_period=(
                timedelta(days=policy.rotation_days)
                if policy.require_rotation
                else None
            ),
            metadata=metadata or {},
            tags=tags or set(),
        )

        # Store credential
        self.credentials[credential.id] = credential

        # Add to password history
        if type == CredentialType.PASSWORD:
            self.password_history[name].append(
                hashlib.sha256(value.encode()).hexdigest()
            )

        # Schedule rotation if required
        if auto_rotate and policy.require_rotation:
            self._schedule_rotation(credential.id, timedelta(days=policy.rotation_days))

        # Audit log
        if self.audit_service:
            await self.audit_service.log_event(
                "credential.created",
                credential_id=credential.id,
                type=type.value,
                name=name,
            )

        return credential

    async def get_credential(
        self,
        credential_id: str,
        requester: str,
        purpose: str = "access",
        decrypt: bool = True,
    ) -> Optional[str]:
        """
        Get a credential value

        Args:
            credential_id: Credential ID
            requester: Who is requesting
            purpose: Purpose of access
            decrypt: Whether to decrypt the value

        Returns:
            Credential value or None
        """
        if credential_id not in self.credentials:
            return None

        credential = self.credentials[credential_id]

        # Check access control
        if not self._check_access(credential_id, requester, AccessLevel.READ):
            # Create access request
            await self._create_access_request(
                credential_id,
                requester,
                purpose,
                AccessLevel.READ,
            )
            return None

        # Check if expired
        if credential.expires_at and credential.expires_at < datetime.utcnow():
            return None

        # Update access metrics
        credential.last_used = datetime.utcnow()
        credential.access_count += 1

        # Decrypt value if requested
        if decrypt:
            if self.vault_service:
                # Retrieve from vault
                secret = await self.vault_service.get_secret(
                    f"credentials/{credential.type.value}/{credential.name}",
                    "value",
                )
                if secret:
                    encrypted = bytes.fromhex(secret.value)
                    key_id = secret.metadata.get("key_id")
                    decrypted = await self.vault_service.decrypt_data(
                        encrypted,
                        key_id,
                    )
                    value = decrypted.decode()
                else:
                    value = bytes.fromhex(credential.value).decode()
            else:
                value = bytes.fromhex(credential.value).decode()
        else:
            value = credential.value

        # Audit log
        if self.audit_service:
            await self.audit_service.log_event(
                "credential.accessed",
                credential_id=credential_id,
                requester=requester,
                purpose=purpose,
            )

        return value

    async def rotate_credential(
        self,
        credential_id: str,
        new_value: Optional[str] = None,
    ) -> bool:
        """
        Rotate a credential

        Args:
            credential_id: Credential ID
            new_value: New value (generated if not provided)

        Returns:
            Success status
        """
        if credential_id not in self.credentials:
            return False

        credential = self.credentials[credential_id]

        # Get policy
        policy = self._get_policy(credential.type)

        # Generate new value if not provided
        if not new_value:
            new_value = self._generate_credential(credential.type, policy)

        # Validate new credential
        if not self._validate_credential(new_value, policy):
            return False

        # Check for reuse
        if credential.type == CredentialType.PASSWORD:
            if self._check_password_reuse(credential.name, new_value, policy.max_reuse):
                return False

        # Store old value for rollback
        old_value = credential.value

        try:
            # Encrypt new value
            if self.vault_service:
                encrypted_value, key_id = await self.vault_service.encrypt_data(
                    new_value.encode()
                )
                # Rotate in vault
                await self.vault_service.rotate_secret(
                    path=f"credentials/{credential.type.value}/{credential.name}",
                    key="value",
                    new_value=encrypted_value.hex(),
                )
            else:
                encrypted_value = new_value.encode()

            # Update credential
            credential.value = encrypted_value.hex()
            credential.last_rotated = datetime.utcnow()

            # Update password history
            if credential.type == CredentialType.PASSWORD:
                self.password_history[credential.name].append(
                    hashlib.sha256(new_value.encode()).hexdigest()
                )
                # Limit history size
                if len(self.password_history[credential.name]) > policy.max_reuse * 2:
                    self.password_history[credential.name] = (
                        self.password_history[credential.name][-policy.max_reuse:]
                    )

            # Reschedule rotation
            if policy.require_rotation:
                self._schedule_rotation(
                    credential.id,
                    timedelta(days=policy.rotation_days),
                )

            # Audit log
            if self.audit_service:
                await self.audit_service.log_event(
                    "credential.rotated",
                    credential_id=credential_id,
                )

            return True

        except Exception as e:
            # Rollback on error
            credential.value = old_value
            return False

    async def delete_credential(
        self,
        credential_id: str,
        requester: str,
    ) -> bool:
        """
        Delete a credential

        Args:
            credential_id: Credential ID
            requester: Who is requesting deletion

        Returns:
            Success status
        """
        if credential_id not in self.credentials:
            return False

        # Check access control
        if not self._check_access(credential_id, requester, AccessLevel.DELETE):
            return False

        credential = self.credentials[credential_id]

        # Delete from vault
        if self.vault_service:
            await self.vault_service.delete_secret(
                f"credentials/{credential.type.value}/{credential.name}"
            )

        # Cancel rotation task
        if credential_id in self.rotation_tasks:
            self.rotation_tasks[credential_id].cancel()
            del self.rotation_tasks[credential_id]

        # Delete credential
        del self.credentials[credential_id]

        # Audit log
        if self.audit_service:
            await self.audit_service.log_event(
                "credential.deleted",
                credential_id=credential_id,
                requester=requester,
            )

        return True

    def grant_access(
        self,
        credential_id: str,
        principal: str,
        access_levels: Set[AccessLevel],
    ):
        """
        Grant access to a credential

        Args:
            credential_id: Credential ID
            principal: User/service to grant access
            access_levels: Access levels to grant
        """
        self.access_control[credential_id][principal].update(access_levels)

    def revoke_access(
        self,
        credential_id: str,
        principal: str,
        access_levels: Optional[Set[AccessLevel]] = None,
    ):
        """
        Revoke access to a credential

        Args:
            credential_id: Credential ID
            principal: User/service to revoke access
            access_levels: Specific levels to revoke (all if None)
        """
        if access_levels:
            self.access_control[credential_id][principal] -= access_levels
        else:
            del self.access_control[credential_id][principal]

    def _generate_credential(
        self,
        type: CredentialType,
        policy: SecretPolicy,
    ) -> str:
        """Generate a credential based on type and policy"""
        if type == CredentialType.PASSWORD:
            return self._generate_password(policy)
        elif type == CredentialType.API_KEY:
            return self._generate_api_key(policy)
        elif type == CredentialType.TOKEN:
            return self._generate_token(policy)
        else:
            # Default to random string
            chars = string.ascii_letters + string.digits
            length = max(policy.min_length, 32)
            return "".join(secrets.choice(chars) for _ in range(length))

    def _generate_password(self, policy: SecretPolicy) -> str:
        """Generate a password meeting policy requirements"""
        chars = ""
        password = []

        # Build character set and ensure requirements
        if policy.require_uppercase:
            chars += string.ascii_uppercase
            password.append(secrets.choice(string.ascii_uppercase))
        if policy.require_lowercase:
            chars += string.ascii_lowercase
            password.append(secrets.choice(string.ascii_lowercase))
        if policy.require_numbers:
            chars += string.digits
            password.append(secrets.choice(string.digits))
        if policy.require_special:
            chars += policy.allowed_special
            password.append(secrets.choice(policy.allowed_special))

        # Fill remaining length
        remaining = max(policy.min_length - len(password), 0)
        password.extend(secrets.choice(chars) for _ in range(remaining))

        # Shuffle to avoid predictable patterns
        secrets.SystemRandom().shuffle(password)
        return "".join(password)

    def _generate_api_key(self, policy: SecretPolicy) -> str:
        """Generate an API key"""
        # Generate URL-safe base64 encoded random bytes
        num_bytes = (policy.min_length * 3) // 4  # Base64 encoding ratio
        random_bytes = secrets.token_urlsafe(num_bytes)
        return random_bytes[:policy.min_length]

    def _generate_token(self, policy: SecretPolicy) -> str:
        """Generate a token"""
        return secrets.token_hex(policy.min_length // 2)

    def _validate_credential(self, value: str, policy: SecretPolicy) -> bool:
        """Validate credential against policy"""
        # Check length
        if not (policy.min_length <= len(value) <= policy.max_length):
            return False

        # Check character requirements
        if policy.require_uppercase and not any(c.isupper() for c in value):
            return False
        if policy.require_lowercase and not any(c.islower() for c in value):
            return False
        if policy.require_numbers and not any(c.isdigit() for c in value):
            return False
        if policy.require_special and not any(c in policy.allowed_special for c in value):
            return False

        # Check complexity score
        score = self._calculate_complexity(value)
        if score < policy.complexity_score:
            return False

        return True

    def _calculate_complexity(self, value: str) -> int:
        """Calculate password complexity score (1-5)"""
        score = 0

        # Length score
        if len(value) >= 8:
            score += 1
        if len(value) >= 12:
            score += 1
        if len(value) >= 16:
            score += 1

        # Character variety
        has_upper = any(c.isupper() for c in value)
        has_lower = any(c.islower() for c in value)
        has_digit = any(c.isdigit() for c in value)
        has_special = any(c in "!@#$%^&*()-_=+[]{}|;:,.<>?" for c in value)

        variety = sum([has_upper, has_lower, has_digit, has_special])
        if variety >= 3:
            score += 1
        if variety == 4:
            score += 1

        return min(score, 5)

    def _check_password_reuse(
        self,
        name: str,
        password: str,
        max_reuse: int,
    ) -> bool:
        """Check if password was recently used"""
        if name not in self.password_history:
            return False

        password_hash = hashlib.sha256(password.encode()).hexdigest()
        recent_hashes = self.password_history[name][-max_reuse:]
        return password_hash in recent_hashes

    def _get_policy(
        self,
        type: CredentialType,
        policy_name: Optional[str] = None,
    ) -> SecretPolicy:
        """Get applicable policy for credential type"""
        if policy_name and policy_name in self.policies:
            return self.policies[policy_name]

        # Find default policy for type
        for policy in self.policies.values():
            if type in policy.credential_types:
                return policy

        # Return default strong policy
        return self.policies["strong_password"]

    def _check_access(
        self,
        credential_id: str,
        principal: str,
        level: AccessLevel,
    ) -> bool:
        """Check if principal has access level"""
        if principal in self.access_control[credential_id]:
            allowed_levels = self.access_control[credential_id][principal]
            return level in allowed_levels or AccessLevel.ADMIN in allowed_levels
        return False

    async def _create_access_request(
        self,
        credential_id: str,
        requester: str,
        purpose: str,
        access_level: AccessLevel,
        duration: timedelta = timedelta(hours=1),
    ) -> AccessRequest:
        """Create an access request"""
        import uuid

        request = AccessRequest(
            request_id=str(uuid.uuid4())[:12],
            credential_id=credential_id,
            requester=requester,
            purpose=purpose,
            access_level=access_level,
            requested_at=datetime.utcnow(),
            expires_at=datetime.utcnow() + duration,
        )

        self.access_requests[request.request_id] = request
        return request

    def _schedule_rotation(
        self,
        credential_id: str,
        interval: timedelta,
    ):
        """Schedule credential rotation"""
        # Cancel existing task if any
        if credential_id in self.rotation_tasks:
            self.rotation_tasks[credential_id].cancel()

        # Create new rotation task
        async def rotate_task():
            await asyncio.sleep(interval.total_seconds())
            await self.rotate_credential(credential_id)

        self.rotation_tasks[credential_id] = asyncio.create_task(rotate_task())

    def get_expiring_credentials(
        self,
        days: int = 7,
    ) -> List[Credential]:
        """Get credentials expiring soon"""
        cutoff = datetime.utcnow() + timedelta(days=days)
        expiring = []

        for credential in self.credentials.values():
            if credential.expires_at and credential.expires_at <= cutoff:
                expiring.append(credential)

        return sorted(expiring, key=lambda c: c.expires_at)

    def get_rotation_due(self) -> List[Credential]:
        """Get credentials due for rotation"""
        due = []

        for credential in self.credentials.values():
            if not credential.rotation_period:
                continue

            next_rotation = (
                credential.last_rotated or credential.created_at
            ) + credential.rotation_period

            if next_rotation <= datetime.utcnow():
                due.append(credential)

        return due
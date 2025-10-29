"""
API Key Management
Handles API key creation, validation, and lifecycle
"""
import secrets
import hashlib
import structlog
from typing import Optional, List
from datetime import datetime, timedelta
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.models.security_audit import APIKey

logger = structlog.get_logger()


class APIKeyManager:
    """API Key Management"""

    def generate_api_key(self) -> tuple[str, str, str]:
        """Generate new API key. Returns (key, key_hash, key_prefix)"""
        key = f"ck_{secrets.token_urlsafe(32)}"
        key_hash = hashlib.sha256(key.encode()).hexdigest()
        key_prefix = key[:12]
        return key, key_hash, key_prefix

    async def create_api_key(self, key_name: str, user_id: str, scopes: List[str], expires_days: int, db: AsyncSession) -> tuple[APIKey, str]:
        """Create API key"""
        key, key_hash, key_prefix = self.generate_api_key()
        expires_at = datetime.utcnow() + timedelta(days=expires_days) if expires_days else None
        api_key = APIKey(key_name=key_name, key_hash=key_hash, key_prefix=key_prefix, user_id=user_id, scopes=scopes, expires_at=expires_at)
        db.add(api_key)
        await db.commit()
        await db.refresh(api_key)
        logger.info("API key created", key_id=api_key.id, user_id=user_id)
        return api_key, key

    async def validate_api_key(self, key: str, db: AsyncSession) -> Optional[APIKey]:
        """Validate API key"""
        key_hash = hashlib.sha256(key.encode()).hexdigest()
        result = await db.execute(select(APIKey).filter(APIKey.key_hash == key_hash, APIKey.enabled == True))
        api_key = result.scalar_one_or_none()
        if not api_key:
            return None
        if api_key.expires_at and api_key.expires_at < datetime.utcnow():
            return None
        api_key.last_used_at = datetime.utcnow()
        api_key.usage_count += 1
        await db.commit()
        return api_key

    async def revoke_api_key(self, key_id: str, user_id: str, reason: str, db: AsyncSession) -> bool:
        """Revoke API key"""
        result = await db.execute(select(APIKey).filter(APIKey.id == key_id))
        api_key = result.scalar_one_or_none()
        if not api_key:
            return False
        api_key.enabled = False
        api_key.revoked_at = datetime.utcnow()
        api_key.revoked_by = user_id
        api_key.revocation_reason = reason
        await db.commit()
        logger.info("API key revoked", key_id=key_id, by=user_id)
        return True


api_key_manager = APIKeyManager()

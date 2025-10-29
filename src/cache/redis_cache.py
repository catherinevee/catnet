"""
Redis Caching Layer
Implements caching for API responses and frequently accessed data
"""
import json
import pickle
from typing import Any, Optional, Union, List, Dict
from datetime import timedelta
import structlog
import redis.asyncio as aioredis
from functools import wraps

logger = structlog.get_logger()


class RedisCache:
    """
    Redis-based caching layer for CatNet

    Provides high-performance caching with automatic serialization,
    key management, and cache invalidation.
    """

    def __init__(self, redis_url: str):
        """
        Initialize Redis cache

        Args:
            redis_url: Redis connection URL (redis://host:port/db)
        """
        self.redis_url = redis_url
        self.redis: Optional[aioredis.Redis] = None
        self._connected = False

    async def connect(self):
        """Establish Redis connection"""
        try:
            self.redis = await aioredis.from_url(
                self.redis_url,
                encoding="utf-8",
                decode_responses=False,  # We'll handle serialization
                max_connections=50,
                socket_timeout=5,
                socket_connect_timeout=5
            )

            # Test connection
            await self.redis.ping()
            self._connected = True

            logger.info("Redis cache connected", url=self.redis_url)

        except Exception as e:
            logger.error(f"Failed to connect to Redis: {e}")
            self._connected = False
            raise

    async def disconnect(self):
        """Close Redis connection"""
        if self.redis:
            await self.redis.close()
            self._connected = False
            logger.info("Redis cache disconnected")

    async def get(self, key: str) -> Optional[Any]:
        """
        Get value from cache

        Args:
            key: Cache key

        Returns:
            Cached value or None if not found
        """
        if not self._connected:
            logger.warning("Redis not connected, skipping cache get")
            return None

        try:
            value = await self.redis.get(key)

            if value is None:
                logger.debug(f"Cache miss: {key}")
                return None

            # Deserialize
            deserialized = self._deserialize(value)
            logger.debug(f"Cache hit: {key}")

            return deserialized

        except Exception as e:
            logger.error(f"Cache get error for key {key}: {e}")
            return None

    async def set(
        self,
        key: str,
        value: Any,
        ttl: Optional[int] = None
    ) -> bool:
        """
        Set value in cache

        Args:
            key: Cache key
            value: Value to cache
            ttl: Time to live in seconds (None = no expiration)

        Returns:
            True if successful, False otherwise
        """
        if not self._connected:
            logger.warning("Redis not connected, skipping cache set")
            return False

        try:
            # Serialize value
            serialized = self._serialize(value)

            # Set with optional TTL
            if ttl:
                await self.redis.setex(key, ttl, serialized)
            else:
                await self.redis.set(key, serialized)

            logger.debug(f"Cache set: {key} (TTL: {ttl}s)")
            return True

        except Exception as e:
            logger.error(f"Cache set error for key {key}: {e}")
            return False

    async def delete(self, key: str) -> bool:
        """
        Delete key from cache

        Args:
            key: Cache key

        Returns:
            True if key was deleted, False otherwise
        """
        if not self._connected:
            return False

        try:
            result = await self.redis.delete(key)
            logger.debug(f"Cache delete: {key}")
            return result > 0

        except Exception as e:
            logger.error(f"Cache delete error for key {key}: {e}")
            return False

    async def delete_pattern(self, pattern: str) -> int:
        """
        Delete all keys matching pattern

        Args:
            pattern: Key pattern (e.g., "user:*")

        Returns:
            Number of keys deleted
        """
        if not self._connected:
            return 0

        try:
            # Get all matching keys
            keys = []
            async for key in self.redis.scan_iter(match=pattern):
                keys.append(key)

            # Delete in batch
            if keys:
                deleted = await self.redis.delete(*keys)
                logger.info(f"Cache delete pattern: {pattern} ({deleted} keys)")
                return deleted

            return 0

        except Exception as e:
            logger.error(f"Cache delete pattern error for {pattern}: {e}")
            return 0

    async def exists(self, key: str) -> bool:
        """
        Check if key exists in cache

        Args:
            key: Cache key

        Returns:
            True if key exists, False otherwise
        """
        if not self._connected:
            return False

        try:
            result = await self.redis.exists(key)
            return result > 0

        except Exception as e:
            logger.error(f"Cache exists error for key {key}: {e}")
            return False

    async def get_ttl(self, key: str) -> Optional[int]:
        """
        Get remaining TTL for key

        Args:
            key: Cache key

        Returns:
            TTL in seconds, or None if key doesn't exist or has no expiration
        """
        if not self._connected:
            return None

        try:
            ttl = await self.redis.ttl(key)

            if ttl == -2:  # Key doesn't exist
                return None
            elif ttl == -1:  # Key exists but has no expiration
                return None
            else:
                return ttl

        except Exception as e:
            logger.error(f"Cache get_ttl error for key {key}: {e}")
            return None

    async def increment(self, key: str, amount: int = 1) -> Optional[int]:
        """
        Increment numeric value

        Args:
            key: Cache key
            amount: Amount to increment

        Returns:
            New value after increment, or None on error
        """
        if not self._connected:
            return None

        try:
            result = await self.redis.incrby(key, amount)
            return result

        except Exception as e:
            logger.error(f"Cache increment error for key {key}: {e}")
            return None

    async def decrement(self, key: str, amount: int = 1) -> Optional[int]:
        """
        Decrement numeric value

        Args:
            key: Cache key
            amount: Amount to decrement

        Returns:
            New value after decrement, or None on error
        """
        if not self._connected:
            return None

        try:
            result = await self.redis.decrby(key, amount)
            return result

        except Exception as e:
            logger.error(f"Cache decrement error for key {key}: {e}")
            return None

    async def get_many(self, keys: List[str]) -> Dict[str, Any]:
        """
        Get multiple values at once

        Args:
            keys: List of cache keys

        Returns:
            Dictionary of key-value pairs (only includes found keys)
        """
        if not self._connected or not keys:
            return {}

        try:
            values = await self.redis.mget(keys)
            result = {}

            for key, value in zip(keys, values):
                if value is not None:
                    result[key] = self._deserialize(value)

            logger.debug(f"Cache get_many: {len(result)}/{len(keys)} found")
            return result

        except Exception as e:
            logger.error(f"Cache get_many error: {e}")
            return {}

    async def set_many(
        self,
        mapping: Dict[str, Any],
        ttl: Optional[int] = None
    ) -> bool:
        """
        Set multiple values at once

        Args:
            mapping: Dictionary of key-value pairs
            ttl: Time to live in seconds (applied to all keys)

        Returns:
            True if successful, False otherwise
        """
        if not self._connected or not mapping:
            return False

        try:
            # Serialize all values
            serialized = {
                key: self._serialize(value)
                for key, value in mapping.items()
            }

            # Use pipeline for efficiency
            async with self.redis.pipeline() as pipe:
                # Set all values
                await pipe.mset(serialized)

                # Set TTL for each key if specified
                if ttl:
                    for key in serialized.keys():
                        await pipe.expire(key, ttl)

                await pipe.execute()

            logger.debug(f"Cache set_many: {len(mapping)} keys (TTL: {ttl}s)")
            return True

        except Exception as e:
            logger.error(f"Cache set_many error: {e}")
            return False

    async def clear(self) -> bool:
        """
        Clear all cache entries (USE WITH CAUTION)

        Returns:
            True if successful, False otherwise
        """
        if not self._connected:
            return False

        try:
            await self.redis.flushdb()
            logger.warning("Cache cleared (all keys deleted)")
            return True

        except Exception as e:
            logger.error(f"Cache clear error: {e}")
            return False

    async def get_stats(self) -> Dict[str, Any]:
        """
        Get cache statistics

        Returns:
            Dictionary with cache statistics
        """
        if not self._connected:
            return {"connected": False}

        try:
            info = await self.redis.info()

            return {
                "connected": True,
                "used_memory": info.get("used_memory_human"),
                "total_keys": await self.redis.dbsize(),
                "connected_clients": info.get("connected_clients"),
                "uptime_seconds": info.get("uptime_in_seconds"),
                "hit_rate": self._calculate_hit_rate(info)
            }

        except Exception as e:
            logger.error(f"Cache get_stats error: {e}")
            return {"connected": False, "error": str(e)}

    def _serialize(self, value: Any) -> bytes:
        """
        Serialize value for storage

        Uses pickle for Python objects, JSON for simple types
        """
        # Try JSON first (faster and human-readable)
        try:
            return json.dumps(value).encode('utf-8')
        except (TypeError, ValueError):
            # Fall back to pickle for complex objects
            return pickle.dumps(value)

    def _deserialize(self, value: bytes) -> Any:
        """
        Deserialize value from storage
        """
        # Try JSON first
        try:
            return json.loads(value.decode('utf-8'))
        except (json.JSONDecodeError, UnicodeDecodeError):
            # Fall back to pickle
            return pickle.loads(value)

    def _calculate_hit_rate(self, info: Dict) -> Optional[float]:
        """Calculate cache hit rate from Redis info"""
        try:
            hits = info.get("keyspace_hits", 0)
            misses = info.get("keyspace_misses", 0)
            total = hits + misses

            if total == 0:
                return None

            return (hits / total) * 100

        except Exception:
            return None


# Decorator for caching function results

def cache_result(
    ttl: int = 300,
    key_prefix: str = "",
    key_builder: Optional[callable] = None
):
    """
    Decorator to cache function results

    Args:
        ttl: Cache TTL in seconds
        key_prefix: Prefix for cache key
        key_builder: Custom function to build cache key from args

    Example:
        @cache_result(ttl=600, key_prefix="user")
        async def get_user(user_id: str):
            return await db.query(User).get(user_id)
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Build cache key
            if key_builder:
                cache_key = key_builder(*args, **kwargs)
            else:
                # Default key builder
                key_parts = [key_prefix, func.__name__]
                key_parts.extend(str(arg) for arg in args)
                key_parts.extend(f"{k}={v}" for k, v in sorted(kwargs.items()))
                cache_key = ":".join(filter(None, key_parts))

            # Try to get from cache
            cached_value = await redis_cache.get(cache_key)

            if cached_value is not None:
                logger.debug(f"Cache hit for {func.__name__}")
                return cached_value

            # Execute function
            logger.debug(f"Cache miss for {func.__name__}")
            result = await func(*args, **kwargs)

            # Cache result
            await redis_cache.set(cache_key, result, ttl=ttl)

            return result

        return wrapper
    return decorator


# Cache key builders

class CacheKeys:
    """Standard cache key patterns for CatNet"""

    @staticmethod
    def device(device_id: str) -> str:
        return f"device:{device_id}"

    @staticmethod
    def device_config(device_id: str) -> str:
        return f"device:{device_id}:config"

    @staticmethod
    def deployment(deployment_id: str) -> str:
        return f"deployment:{deployment_id}"

    @staticmethod
    def user(user_id: str) -> str:
        return f"user:{user_id}"

    @staticmethod
    def health_check(check_id: str) -> str:
        return f"health_check:{check_id}"

    @staticmethod
    def sla(sla_id: str) -> str:
        return f"sla:{sla_id}"

    @staticmethod
    def inventory() -> str:
        return "inventory:all"

    @staticmethod
    def topology(topology_id: str) -> str:
        return f"topology:{topology_id}"

    @staticmethod
    def api_response(method: str, path: str, user_id: str = "") -> str:
        """Build key for API response caching"""
        return f"api:{method}:{path}:{user_id}".replace("/", ":")


# Singleton instance
redis_cache = RedisCache(redis_url="redis://localhost:6379/0")

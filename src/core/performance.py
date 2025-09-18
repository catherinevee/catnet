"""
Performance Optimization - Database pooling, caching, and async tasks
"""
import asyncio
import json
import pickle
from typing import Any, Optional, Union, Callable, Dict, List
from functools import wraps
from datetime import datetime, timedelta
import redis.asyncio as redis
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.pool import NullPool, QueuePool
from celery import Celery
import aiohttp
from contextlib import asynccontextmanager

from ..core.logging import get_logger
from ..core.config import settings

logger = get_logger(__name__)


class DatabasePoolManager:
    """
    Manages database connection pooling for optimal performance
    """

    def __init__(
        self,
        database_url: str,
        pool_size: int = 20,
        max_overflow: int = 10,
        pool_timeout: int = 30,
        pool_recycle: int = 3600,
    ):
        """
        Initialize database pool manager

        Args:
            database_url: Database connection URL
            pool_size: Number of connections to maintain in pool
            max_overflow: Maximum overflow connections
            pool_timeout: Timeout for getting connection from pool
            pool_recycle: Time to recycle connections (seconds)
        """
        self.database_url = database_url
        self.pool_size = pool_size
        self.max_overflow = max_overflow
        self.pool_timeout = pool_timeout
        self.pool_recycle = pool_recycle
        self.engine = None
        self.session_factory = None

    async def initialize(self):
        """Initialize connection pool"""
        try:
            # Create async engine with connection pooling
            self.engine = create_async_engine(
                self.database_url,
                poolclass=QueuePool,
                pool_size=self.pool_size,
                max_overflow=self.max_overflow,
                pool_timeout=self.pool_timeout,
                pool_recycle=self.pool_recycle,
                pool_pre_ping=True,  # Check connections before use
                echo_pool=True,  # Log pool checkouts/checkins
                future=True,
            )

            # Create session factory
            self.session_factory = async_sessionmaker(
                self.engine,
                class_=AsyncSession,
                expire_on_commit=False,
            )

            # Test connection
            async with self.engine.begin() as conn:
                await conn.execute("SELECT 1")

            logger.info(f"Database pool initialized with {self.pool_size} connections")

        except Exception as e:
            logger.error(f"Failed to initialize database pool: {e}")
            raise

    async def close(self):
        """Close all connections in pool"""
        if self.engine:
            await self.engine.dispose()
            logger.info("Database pool closed")

    @asynccontextmanager
    async def get_session(self) -> AsyncSession:
        """Get database session from pool"""
        async with self.session_factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise
            finally:
                await session.close()

    async def get_pool_status(self) -> Dict[str, int]:
        """Get current pool status"""
        if self.engine and hasattr(self.engine.pool, "status"):
            return {
                "size": self.engine.pool.size(),
                "checked_in": self.engine.pool.checkedin(),
                "checked_out": self.engine.pool.checkedout(),
                "overflow": self.engine.pool.overflow(),
                "total": self.engine.pool.total(),
            }
        return {}


class RedisCacheManager:
    """
    Redis caching manager for improved performance
    """

    def __init__(
        self,
        redis_url: str = "redis://localhost:6379",
        default_ttl: int = 300,
        key_prefix: str = "catnet:",
        max_connections: int = 50,
    ):
        """
        Initialize Redis cache manager

        Args:
            redis_url: Redis connection URL
            default_ttl: Default TTL in seconds
            key_prefix: Prefix for all cache keys
            max_connections: Maximum connections in pool
        """
        self.redis_url = redis_url
        self.default_ttl = default_ttl
        self.key_prefix = key_prefix
        self.redis_client = None
        self.max_connections = max_connections

    async def initialize(self):
        """Initialize Redis connection pool"""
        try:
            # Create connection pool
            self.redis_client = await redis.from_url(
                self.redis_url,
                max_connections=self.max_connections,
                decode_responses=False,  # Handle binary data
                socket_connect_timeout=5,
                socket_timeout=5,
            )

            # Test connection
            await self.redis_client.ping()
            logger.info("Redis cache initialized")

        except Exception as e:
            logger.warning(f"Redis not available, caching disabled: {e}")
            self.redis_client = None

    async def close(self):
        """Close Redis connections"""
        if self.redis_client:
            await self.redis_client.close()

    def _make_key(self, key: str) -> str:
        """Create namespaced cache key"""
        return f"{self.key_prefix}{key}"

    async def get(self, key: str, default: Any = None, deserialize: bool = True) -> Any:
        """Get value from cache"""
        if not self.redis_client:
            return default

        try:
            full_key = self._make_key(key)
            value = await self.redis_client.get(full_key)

            if value is None:
                return default

            if deserialize:
                try:
                    # Try JSON first
                    return json.loads(value)
                except (json.JSONDecodeError, TypeError):
                    # Fall back to pickle
                    return pickle.loads(value)
            else:
                return value

        except Exception as e:
            logger.error(f"Cache get error for {key}: {e}")
            return default

    async def set(
        self,
        key: str,
        value: Any,
        ttl: Optional[int] = None,
        serialize: bool = True,
    ) -> bool:
        """Set value in cache"""
        if not self.redis_client:
            return False

        try:
            full_key = self._make_key(key)
            ttl = ttl or self.default_ttl

            if serialize:
                try:
                    # Try JSON for simple types
                    serialized = json.dumps(value)
                except (TypeError, ValueError):
                    # Fall back to pickle for complex objects
                    serialized = pickle.dumps(value)
            else:
                serialized = value

            await self.redis_client.set(full_key, serialized, ex=ttl)
            return True

        except Exception as e:
            logger.error(f"Cache set error for {key}: {e}")
            return False

    async def delete(self, key: str) -> bool:
        """Delete value from cache"""
        if not self.redis_client:
            return False

        try:
            full_key = self._make_key(key)
            result = await self.redis_client.delete(full_key)
            return result > 0

        except Exception as e:
            logger.error(f"Cache delete error for {key}: {e}")
            return False

    async def invalidate_pattern(self, pattern: str) -> int:
        """Invalidate all keys matching pattern"""
        if not self.redis_client:
            return 0

        try:
            full_pattern = self._make_key(pattern)
            keys = []

            # Use SCAN to avoid blocking
            async for key in self.redis_client.scan_iter(match=full_pattern):
                keys.append(key)

            if keys:
                return await self.redis_client.delete(*keys)

            return 0

        except Exception as e:
            logger.error(f"Cache invalidation error for pattern {pattern}: {e}")
            return 0

    def cached(
        self,
        ttl: Optional[int] = None,
        key_func: Optional[Callable] = None,
        invalidate_on: Optional[List[str]] = None,
    ):
        """
        Decorator for caching function results

        Args:
            ttl: Cache TTL in seconds
            key_func: Function to generate cache key
            invalidate_on: List of events that invalidate cache

        Example:
            @cache.cached(ttl=300)
            async def get_expensive_data(param):
                return await expensive_operation(param)
        """

        def decorator(func):
            @wraps(func)
            async def wrapper(*args, **kwargs):
                # Generate cache key
                if key_func:
                    cache_key = key_func(*args, **kwargs)
                else:
                    # Default key from function name and args
                    key_parts = [func.__name__]
                    key_parts.extend(str(arg) for arg in args)
                    key_parts.extend(f"{k}={v}" for k, v in sorted(kwargs.items()))
                    cache_key = ":".join(key_parts)

                # Try to get from cache
                cached_value = await self.get(cache_key)
                if cached_value is not None:
                    logger.debug(f"Cache hit for {cache_key}")
                    return cached_value

                # Execute function
                result = await func(*args, **kwargs)

                # Store in cache
                await self.set(cache_key, result, ttl=ttl)
                logger.debug(f"Cached result for {cache_key}")

                return result

            return wrapper

        return decorator


class AsyncTaskQueue:
    """
    Async task queue using Celery for background processing
    """

    def __init__(
        self,
        broker_url: str = "redis://localhost:6379/0",
        backend_url: str = "redis://localhost:6379/1",
        task_default_queue: str = "catnet",
    ):
        """
        Initialize async task queue

        Args:
            broker_url: Message broker URL (Redis/RabbitMQ)
            backend_url: Result backend URL
            task_default_queue: Default queue name
        """
        self.app = Celery(
            "catnet",
            broker=broker_url,
            backend=backend_url,
            include=["src.workers.tasks"],
        )

        # Configure Celery
        self.app.conf.update(
            task_serializer="json",
            accept_content=["json"],
            result_serializer="json",
            timezone="UTC",
            enable_utc=True,
            task_default_queue=task_default_queue,
            task_default_exchange=task_default_queue,
            task_default_routing_key=task_default_queue,
            task_track_started=True,
            task_time_limit=3600,  # 1 hour hard limit
            task_soft_time_limit=3000,  # 50 minutes soft limit
            worker_prefetch_multiplier=4,
            worker_max_tasks_per_child=1000,
            broker_connection_retry_on_startup=True,
        )

    def task(self, *args, **kwargs):
        """Decorator to register async task"""
        return self.app.task(*args, **kwargs)

    async def send_task(
        self,
        name: str,
        args: tuple = None,
        kwargs: dict = None,
        queue: str = None,
        priority: int = 5,
        countdown: int = None,
        eta: datetime = None,
    ) -> str:
        """
        Send task to queue

        Args:
            name: Task name
            args: Task arguments
            kwargs: Task keyword arguments
            queue: Target queue
            priority: Task priority (0-9, 0 highest)
            countdown: Delay in seconds
            eta: Exact time to execute

        Returns:
            Task ID
        """
        result = self.app.send_task(
            name,
            args=args or (),
            kwargs=kwargs or {},
            queue=queue,
            priority=priority,
            countdown=countdown,
            eta=eta,
        )
        return result.id

    async def get_task_result(self, task_id: str, timeout: int = None) -> Any:
        """Get task result by ID"""
        result = self.app.AsyncResult(task_id)

        if timeout:
            return await asyncio.wait_for(
                asyncio.to_thread(result.get),
                timeout=timeout,
            )
        else:
            return await asyncio.to_thread(result.get)

    def get_task_status(self, task_id: str) -> str:
        """Get task status"""
        result = self.app.AsyncResult(task_id)
        return result.status


class HTTPConnectionPool:
    """
    HTTP connection pooling for external API calls
    """

    def __init__(
        self,
        connector_limit: int = 100,
        connector_limit_per_host: int = 30,
        timeout: int = 30,
    ):
        """
        Initialize HTTP connection pool

        Args:
            connector_limit: Total connection limit
            connector_limit_per_host: Per-host connection limit
            timeout: Request timeout
        """
        self.connector = None
        self.session = None
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.connector_limit = connector_limit
        self.connector_limit_per_host = connector_limit_per_host

    async def initialize(self):
        """Initialize connection pool"""
        self.connector = aiohttp.TCPConnector(
            limit=self.connector_limit,
            limit_per_host=self.connector_limit_per_host,
            ttl_dns_cache=300,
            enable_cleanup_closed=True,
        )

        self.session = aiohttp.ClientSession(
            connector=self.connector,
            timeout=self.timeout,
            headers={"User-Agent": "CatNet/1.0"},
        )

        logger.info("HTTP connection pool initialized")

    async def close(self):
        """Close connection pool"""
        if self.session:
            await self.session.close()
        if self.connector:
            await self.connector.close()

    async def request(
        self,
        method: str,
        url: str,
        **kwargs,
    ) -> aiohttp.ClientResponse:
        """Make HTTP request using connection pool"""
        if not self.session:
            await self.initialize()

        return await self.session.request(method, url, **kwargs)


# Global instances
db_pool = DatabasePoolManager(
    database_url=settings.DATABASE_URL,
    pool_size=settings.DB_POOL_SIZE,
    max_overflow=settings.DB_MAX_OVERFLOW,
)

cache = RedisCacheManager(
    redis_url=settings.REDIS_URL,
    default_ttl=settings.CACHE_TTL,
)

task_queue = AsyncTaskQueue(
    broker_url=settings.CELERY_BROKER_URL,
    backend_url=settings.CELERY_RESULT_BACKEND,
)

http_pool = HTTPConnectionPool()


async def initialize_performance_systems():
    """Initialize all performance systems"""
    await db_pool.initialize()
    await cache.initialize()
    await http_pool.initialize()
    logger.info("Performance systems initialized")


async def shutdown_performance_systems():
    """Shutdown all performance systems"""
    await db_pool.close()
    await cache.close()
    await http_pool.close()
    logger.info("Performance systems shutdown")

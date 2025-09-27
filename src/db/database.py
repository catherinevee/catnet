from typing import AsyncGenerator, Optional
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, AsyncEngine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool
from contextlib import asynccontextmanager
import logging
from ..core.config import settings
from .models import Base

logger = logging.getLogger(__name__)


class Database:
    """Database connection manager with async support"""

    def __init__(self):
        self.engine: Optional[AsyncEngine] = None
        self.async_session_maker = None
        self._initialized = False

    async def initialize(self):
        """Initialize database connection"""
        if self._initialized:
            return

        try:
            # Create async engine with connection pooling
            self.engine = create_async_engine(
                settings.database_url,
                echo=settings.is_development,
                pool_pre_ping=True,
                pool_size=20,
                max_overflow=40,
                pool_recycle=3600,
                pool_timeout=30,
                connect_args={
                    "server_settings": {
                        "application_name": "catnet",
                        "jit": "off"
                    },
                    "command_timeout": 60,
                    "ssl": "require" if settings.is_production else "prefer"
                }
            )

            # Create async session factory
            self.async_session_maker = sessionmaker(
                self.engine,
                class_=AsyncSession,
                expire_on_commit=False,
                autoflush=False,
                autocommit=False
            )

            self._initialized = True
            logger.info("Database connection initialized successfully")

        except Exception as e:
            logger.error(f"Failed to initialize database: {e}")
            raise

    async def create_tables(self):
        """Create all database tables"""
        if not self.engine:
            await self.initialize()

        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
            logger.info("Database tables created successfully")

    async def drop_tables(self):
        """Drop all database tables (use with caution)"""
        if not self.engine:
            await self.initialize()

        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
            logger.warning("All database tables dropped")

    @asynccontextmanager
    async def get_session(self) -> AsyncGenerator[AsyncSession, None]:
        """Get async database session"""
        if not self._initialized:
            await self.initialize()

        async with self.async_session_maker() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise
            finally:
                await session.close()

    async def close(self):
        """Close database connection"""
        if self.engine:
            await self.engine.dispose()
            self._initialized = False
            logger.info("Database connection closed")

    async def health_check(self) -> bool:
        """Check database health"""
        try:
            async with self.get_session() as session:
                result = await session.execute("SELECT 1")
                return result.scalar() == 1
        except Exception as e:
            logger.error(f"Database health check failed: {e}")
            return False


# Global database instance
db = Database()


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Dependency for FastAPI endpoints"""
    async with db.get_session() as session:
        yield session


async def init_db():
    """Initialize database on application startup"""
    await db.initialize()
    await db.create_tables()


async def close_db():
    """Close database on application shutdown"""
    await db.close()
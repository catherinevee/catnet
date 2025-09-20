import os
from typing import AsyncGenerator, Optional
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    create_async_engine,
    async_sessionmaker,
)
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from .models import Base
from contextlib import asynccontextmanager
import logging

logger = logging.getLogger(__name__)


class DatabaseManager:
    def __init__(
        self,
        database_url: Optional[str] = None,
        echo: bool = False,
        pool_size: int = 20,
        max_overflow: int = 40,
    ):
        self.database_url = database_url or os.getenv(
            "DATABASE_URL",
            "postgresql+asyncpg://catnet:catnet@localhost/catnet",
        )

        # Ensure asyncpg driver for async operations
        if "postgresql://" in self.database_url and "+asyncpg" not in self.database_url:
            self.database_url = self.database_url.replace(
                "postgresql://", "postgresql+asyncpg://"
            )

        # SQLite doesn't support pool settings
        if "sqlite" in self.database_url.lower():
            self.engine = create_async_engine(
                self.database_url,
                echo=echo,
            )
        else:
            self.engine = create_async_engine(
                self.database_url,
                echo=echo,
                pool_size=pool_size,
                max_overflow=max_overflow,
                pool_pre_ping=True,  # Verify connections before using
                pool_recycle=3600,  # Recycle connections after 1 hour
            )

        self.async_session = async_sessionmaker(
            self.engine, class_=AsyncSession, expire_on_commit=False
        )

        # For synchronous operations (migrations)
        if "sqlite" in self.database_url:
            sync_url = self.database_url.replace("+aiosqlite", "")
        else:
            sync_url = self.database_url.replace("+asyncpg", "")
        self.sync_engine = create_engine(sync_url, echo=echo)

    async def create_all(self):
        """TODO: Add docstring"""
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    async def drop_all(self):
        """TODO: Add docstring"""
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)

    async def get_session(self) -> AsyncGenerator[AsyncSession, None]:
        async with self.async_session() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise
            finally:
                await session.close()

    @asynccontextmanager
    async def session_scope(self):
        """TODO: Add docstring"""
        async with self.async_session() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise
            finally:
                await session.close()

    async def close(self):
        """TODO: Add docstring"""
        await self.engine.dispose()

    async def health_check(self) -> bool:
        try:
            from sqlalchemy import text

            async with self.engine.begin() as conn:
                await conn.execute(text("SELECT 1"))
            return True
        except Exception as e:
            logger.error(f"Database health check failed: {e}")
            return False

    def get_sync_session(self):
        """TODO: Add docstring"""
        Session = sessionmaker(bind=self.sync_engine)
        return Session()


# Global database manager instance
db_manager = None


def init_database(database_url: Optional[str] = None, **kwargs) -> DatabaseManager:
    global db_manager
    db_manager = DatabaseManager(database_url=database_url, **kwargs)
    return db_manager


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    if db_manager is None:
        init_database()

    async with db_manager.session_scope() as session:
        yield session

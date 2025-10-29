"""
Pytest configuration and fixtures for CatNet tests
"""
import asyncio
import pytest
from typing import AsyncGenerator, Generator
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.pool import NullPool
from httpx import AsyncClient
import redis.asyncio as aioredis

from src.main import app
from src.db.database import Base, get_db
from src.core.config import get_settings
from src.cache.redis_cache import redis_cache


# Test database URL
TEST_DATABASE_URL = "postgresql+asyncpg://test:test@localhost:5432/catnet_test"


@pytest.fixture(scope="session")
def event_loop() -> Generator:
    """Create event loop for async tests"""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session")
async def engine():
    """Create test database engine"""
    engine = create_async_engine(
        TEST_DATABASE_URL,
        echo=False,
        poolclass=NullPool,
    )
    
    # Create tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    yield engine
    
    # Drop tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    
    await engine.dispose()


@pytest.fixture
async def db_session(engine) -> AsyncGenerator[AsyncSession, None]:
    """Create test database session"""
    async_session = async_sessionmaker(
        engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )
    
    async with async_session() as session:
        yield session
        await session.rollback()


@pytest.fixture
async def client(db_session) -> AsyncGenerator[AsyncClient, None]:
    """Create test HTTP client"""
    
    async def override_get_db():
        yield db_session
    
    app.dependency_overrides[get_db] = override_get_db
    
    async with AsyncClient(app=app, base_url="http://test") as client:
        yield client
    
    app.dependency_overrides.clear()


@pytest.fixture
async def test_user(db_session):
    """Create test user"""
    from src.db.models.user import User
    from src.auth.password import hash_password
    
    user = User(
        username="testuser",
        email="test@example.com",
        password_hash=hash_password("testpassword123"),
        is_active=True,
        is_admin=False
    )
    
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    
    return user


@pytest.fixture
async def admin_user(db_session):
    """Create test admin user"""
    from src.db.models.user import User
    from src.auth.password import hash_password
    
    user = User(
        username="admin",
        email="admin@example.com",
        password_hash=hash_password("adminpassword123"),
        is_active=True,
        is_admin=True
    )
    
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    
    return user


@pytest.fixture
async def auth_headers(test_user, client):
    """Get authentication headers for test user"""
    from src.auth.jwt import create_access_token
    
    token = create_access_token({"sub": str(test_user.id)})
    
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
async def admin_headers(admin_user, client):
    """Get authentication headers for admin user"""
    from src.auth.jwt import create_access_token
    
    token = create_access_token({"sub": str(admin_user.id)})
    
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
async def test_device(db_session, test_user):
    """Create test device"""
    from src.db.models.device import Device
    
    device = Device(
        hostname="test-router-01",
        ip_address="192.168.1.1",
        vendor="cisco",
        device_type="router",
        created_by=test_user.id
    )
    
    db_session.add(device)
    await db_session.commit()
    await db_session.refresh(device)
    
    return device


@pytest.fixture
async def redis_client():
    """Create test Redis client"""
    client = await aioredis.from_url(
        "redis://localhost:6379/15",  # Use database 15 for tests
        encoding="utf-8",
        decode_responses=False
    )
    
    yield client
    
    # Clean up
    await client.flushdb()
    await client.close()


@pytest.fixture(autouse=True)
async def clear_redis(redis_client):
    """Clear Redis before each test"""
    await redis_client.flushdb()
    yield
    await redis_client.flushdb()

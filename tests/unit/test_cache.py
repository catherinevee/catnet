"""Unit tests for Redis cache"""
import pytest
from src.cache.redis_cache import RedisCache


@pytest.mark.asyncio
async def test_cache_set_get(redis_client):
    """Test basic cache set and get"""
    cache = RedisCache("redis://localhost:6379/15")
    await cache.connect()
    
    await cache.set("test_key", "test_value", ttl=60)
    value = await cache.get("test_key")
    
    assert value == "test_value"
    
    await cache.disconnect()


@pytest.mark.asyncio
async def test_cache_delete(redis_client):
    """Test cache delete"""
    cache = RedisCache("redis://localhost:6379/15")
    await cache.connect()
    
    await cache.set("test_key", "test_value")
    deleted = await cache.delete("test_key")
    
    assert deleted is True
    
    value = await cache.get("test_key")
    assert value is None
    
    await cache.disconnect()


@pytest.mark.asyncio
async def test_cache_ttl(redis_client):
    """Test cache TTL"""
    cache = RedisCache("redis://localhost:6379/15")
    await cache.connect()
    
    await cache.set("test_key", "test_value", ttl=60)
    ttl = await cache.get_ttl("test_key")
    
    assert ttl is not None
    assert 0 < ttl <= 60
    
    await cache.disconnect()


@pytest.mark.asyncio
async def test_cache_increment(redis_client):
    """Test cache increment"""
    cache = RedisCache("redis://localhost:6379/15")
    await cache.connect()
    
    value1 = await cache.increment("counter")
    value2 = await cache.increment("counter", amount=5)
    
    assert value1 == 1
    assert value2 == 6
    
    await cache.disconnect()


@pytest.mark.asyncio
async def test_cache_get_many(redis_client):
    """Test getting multiple values"""
    cache = RedisCache("redis://localhost:6379/15")
    await cache.connect()
    
    await cache.set("key1", "value1")
    await cache.set("key2", "value2")
    await cache.set("key3", "value3")
    
    values = await cache.get_many(["key1", "key2", "key3", "key4"])
    
    assert len(values) == 3
    assert values["key1"] == "value1"
    assert values["key2"] == "value2"
    assert values["key3"] == "value3"
    
    await cache.disconnect()

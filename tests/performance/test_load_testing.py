"""
Performance and load testing for CatNet system.
Tests system performance under various load conditions and stress scenarios.
"""

import pytest
import asyncio
import time
import statistics
from typing import List, Dict, Any
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import Mock, AsyncMock

from httpx import AsyncClient
import psutil

from src.devices.device_service import DeviceService
from src.services.deployment_service import DeploymentService
from src.monitoring.metrics import MetricsCollector


class TestPerformance:
    """Test system performance under various conditions."""

    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_api_response_times(self, async_test_client: AsyncClient, auth_headers):
        """Test API response times under normal load."""
        endpoints = [
            "/api/v1/health",
            "/api/v1/auth/me",
            "/api/v1/devices",
            "/api/v1/deployments"
        ]

        response_times = []

        for endpoint in endpoints:
            times = []
            for _ in range(100):  # 100 requests per endpoint
                start_time = time.time()

                response = await async_test_client.get(endpoint, headers=auth_headers)

                end_time = time.time()
                times.append(end_time - start_time)

                # Basic assertion that request succeeded
                assert response.status_code in [200, 401]  # 401 if auth required

            response_times.extend(times)

        # Performance assertions
        avg_response_time = statistics.mean(response_times)
        p95_response_time = sorted(response_times)[int(0.95 * len(response_times))]

        assert avg_response_time < 0.5  # Average under 500ms
        assert p95_response_time < 1.0   # 95th percentile under 1s
        assert max(response_times) < 5.0 # No request over 5s

    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_concurrent_requests(self, async_test_client: AsyncClient):
        """Test handling concurrent requests."""
        async def make_request():
            response = await async_test_client.get("/api/v1/health")
            return response.status_code, time.time()

        # Launch 50 concurrent requests
        start_time = time.time()
        tasks = [make_request() for _ in range(50)]
        results = await asyncio.gather(*tasks)
        total_time = time.time() - start_time

        # All requests should succeed
        status_codes = [result[0] for result in results]
        assert all(code == 200 for code in status_codes)

        # Should handle 50 concurrent requests quickly
        assert total_time < 5.0  # Under 5 seconds total

        # Calculate requests per second
        rps = len(results) / total_time
        assert rps > 10  # At least 10 requests per second

    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_database_query_performance(self, test_session):
        """Test database query performance."""
        from src.auth.models import User
        from src.devices.models import Device

        # Create test data
        users = []
        devices = []

        for i in range(1000):
            user = User(
                username=f"user_{i}",
                email=f"user_{i}@test.com",
                password_hash="hashed_password",
                first_name=f"User",
                last_name=f"{i}"
            )
            users.append(user)

            device = Device(
                name=f"device_{i}",
                hostname=f"device{i}.test.com",
                ip_address=f"192.168.{i//254}.{i%254}",
                vendor="cisco",
                platform="ios"
            )
            devices.append(device)

        test_session.add_all(users + devices)
        await test_session.commit()

        # Test query performance
        query_times = []

        # Test user queries
        for _ in range(100):
            start_time = time.time()

            result = await test_session.execute(
                "SELECT * FROM users WHERE username LIKE 'user_%' LIMIT 10"
            )
            users_found = result.fetchall()

            query_times.append(time.time() - start_time)
            assert len(users_found) == 10

        # Test device queries
        for _ in range(100):
            start_time = time.time()

            result = await test_session.execute(
                "SELECT * FROM devices WHERE vendor = 'cisco' LIMIT 10"
            )
            devices_found = result.fetchall()

            query_times.append(time.time() - start_time)
            assert len(devices_found) == 10

        # Performance assertions
        avg_query_time = statistics.mean(query_times)
        max_query_time = max(query_times)

        assert avg_query_time < 0.1  # Average under 100ms
        assert max_query_time < 0.5   # Max under 500ms

    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_device_connection_performance(self, mock_device_service):
        """Test device connection performance."""
        device_service = mock_device_service

        # Test sequential connections
        sequential_times = []
        for _ in range(20):
            start_time = time.time()

            session_id = await device_service.connect_to_device(
                "test_device",
                {"user_id": "test_user"}
            )

            sequential_times.append(time.time() - start_time)
            assert session_id is not None

        # Test concurrent connections
        async def connect_device():
            start_time = time.time()
            session_id = await device_service.connect_to_device(
                f"device_{asyncio.current_task().get_name()}",
                {"user_id": "test_user"}
            )
            return time.time() - start_time

        concurrent_tasks = [connect_device() for _ in range(20)]
        concurrent_times = await asyncio.gather(*concurrent_tasks)

        # Performance assertions
        avg_sequential = statistics.mean(sequential_times)
        avg_concurrent = statistics.mean(concurrent_times)

        assert avg_sequential < 1.0  # Under 1 second each
        assert avg_concurrent < 2.0  # Concurrent shouldn't be much slower

    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_deployment_performance(self, mock_deployment_service):
        """Test deployment performance with multiple devices."""
        deployment_service = mock_deployment_service

        # Test deployment to multiple devices
        device_counts = [1, 5, 10, 20, 50]
        deployment_times = []

        for device_count in device_counts:
            devices = [f"device_{i}" for i in range(device_count)]

            start_time = time.time()

            deployment_id = await deployment_service.create_deployment({
                "name": f"test_deployment_{device_count}",
                "devices": devices,
                "config": {"test": "config"}
            }, {"user_id": "test_user"})

            result = await deployment_service.execute_deployment(
                deployment_id,
                {"user_id": "test_user"}
            )

            deployment_time = time.time() - start_time
            deployment_times.append(deployment_time)

            assert result["success"] is True

        # Performance should scale reasonably
        # Time shouldn't increase exponentially with device count
        for i in range(1, len(deployment_times)):
            ratio = deployment_times[i] / deployment_times[i-1]
            device_ratio = device_counts[i] / device_counts[i-1]

            # Time increase should be less than linear with device count
            assert ratio < device_ratio * 1.5

    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_memory_usage(self):
        """Test memory usage under load."""
        process = psutil.Process()
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB

        # Simulate memory-intensive operations
        large_data = []
        for i in range(1000):
            # Create some data structures
            data = {
                "id": i,
                "config": "x" * 1000,  # 1KB config
                "metadata": list(range(100))
            }
            large_data.append(data)

        peak_memory = process.memory_info().rss / 1024 / 1024  # MB

        # Clean up
        del large_data

        # Force garbage collection
        import gc
        gc.collect()

        final_memory = process.memory_info().rss / 1024 / 1024  # MB

        # Memory assertions
        memory_increase = peak_memory - initial_memory
        memory_cleanup = peak_memory - final_memory

        assert memory_increase < 500  # Under 500MB increase
        assert memory_cleanup > memory_increase * 0.5  # At least 50% cleanup

    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_cpu_usage_under_load(self):
        """Test CPU usage under computational load."""
        import hashlib

        start_cpu = psutil.cpu_percent(interval=1)

        # CPU-intensive task
        start_time = time.time()
        for i in range(10000):
            # Simulate configuration validation
            data = f"config_data_{i}" * 100
            hash_result = hashlib.sha256(data.encode()).hexdigest()

        end_time = time.time()
        end_cpu = psutil.cpu_percent(interval=1)

        # Performance assertions
        execution_time = end_time - start_time
        assert execution_time < 30  # Should complete in under 30 seconds

        # CPU usage should be reasonable
        cpu_increase = end_cpu - start_cpu
        assert cpu_increase < 80  # Should not peg CPU at 100%

    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_metrics_collection_performance(self, mock_metrics_collector):
        """Test metrics collection performance."""
        metrics = mock_metrics_collector

        # Test metric recording performance
        start_time = time.time()

        for i in range(10000):
            await metrics.record_request("GET", "/api/test", 200, 0.1)
            await metrics.record_deployment(f"deploy_{i}", "rolling", "success", 30.0)

        collection_time = time.time() - start_time

        # Should handle 10,000 metrics quickly
        assert collection_time < 5.0  # Under 5 seconds

        # Test metrics retrieval performance
        start_time = time.time()
        all_metrics = metrics.collect_all()
        retrieval_time = time.time() - start_time

        assert retrieval_time < 1.0  # Under 1 second to collect all metrics

    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_configuration_validation_performance(self):
        """Test configuration validation performance."""
        from src.core.validator import ConfigValidator

        validator = ConfigValidator()

        # Create large configuration
        large_config = {
            "vendor": "cisco",
            "platform": "ios",
            "hostname": "large-switch",
            "version": "1.0",
            "interfaces": {},
            "vlans": {},
            "access_lists": {}
        }

        # Add many interfaces
        for i in range(500):
            large_config["interfaces"][f"GigabitEthernet0/{i}"] = {
                "description": f"Interface {i}",
                "switchport": {
                    "mode": "access",
                    "access_vlan": (i % 100) + 1
                }
            }

        # Add many VLANs
        for i in range(100):
            large_config["vlans"][str(i + 1)] = {
                "name": f"VLAN_{i + 1}"
            }

        # Test validation performance
        validation_times = []

        for _ in range(10):
            start_time = time.time()

            result = await validator.validate_configuration(large_config)

            validation_time = time.time() - start_time
            validation_times.append(validation_time)

            assert result.is_valid

        # Performance assertions
        avg_validation_time = statistics.mean(validation_times)
        max_validation_time = max(validation_times)

        assert avg_validation_time < 2.0  # Average under 2 seconds
        assert max_validation_time < 5.0  # Max under 5 seconds

    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_git_operations_performance(self, temp_dir):
        """Test Git operations performance."""
        import git
        import os

        # Initialize test repository
        repo_path = os.path.join(temp_dir, "test_repo")
        repo = git.Repo.init(repo_path)

        # Create many files to simulate large config repository
        file_creation_time = time.time()
        for i in range(100):
            file_path = os.path.join(repo_path, f"config_{i}.yml")
            with open(file_path, 'w') as f:
                f.write(f"# Configuration file {i}\n" * 100)  # ~2KB per file

        file_creation_time = time.time() - file_creation_time

        # Test Git add performance
        add_start = time.time()
        repo.git.add('.')
        add_time = time.time() - add_start

        # Test Git commit performance
        commit_start = time.time()
        repo.git.commit('-m', 'Initial commit with 100 config files')
        commit_time = time.time() - commit_start

        # Performance assertions
        assert file_creation_time < 10.0  # File creation under 10s
        assert add_time < 5.0             # Git add under 5s
        assert commit_time < 5.0          # Git commit under 5s

    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_encryption_performance(self):
        """Test encryption/decryption performance."""
        from cryptography.fernet import Fernet

        # Generate key
        key = Fernet.generate_key()
        cipher = Fernet(key)

        # Test data of various sizes
        test_data_sizes = [1024, 10240, 102400, 1024000]  # 1KB to 1MB
        encryption_times = []
        decryption_times = []

        for size in test_data_sizes:
            data = b"x" * size

            # Test encryption
            start_time = time.time()
            encrypted = cipher.encrypt(data)
            encryption_time = time.time() - start_time
            encryption_times.append(encryption_time)

            # Test decryption
            start_time = time.time()
            decrypted = cipher.decrypt(encrypted)
            decryption_time = time.time() - start_time
            decryption_times.append(decryption_time)

            assert decrypted == data

        # Performance assertions
        # Encryption/decryption should be fast even for large data
        assert max(encryption_times) < 1.0  # All encryptions under 1s
        assert max(decryption_times) < 1.0  # All decryptions under 1s

        # Performance should scale reasonably with data size
        assert encryption_times[-1] > encryption_times[0]  # Should take longer for larger data
        assert encryption_times[-1] / encryption_times[0] < 100  # But not 100x longer


class TestStressTesting:
    """Stress testing under extreme conditions."""

    @pytest.mark.performance
    @pytest.mark.slow
    @pytest.mark.asyncio
    async def test_high_concurrency_stress(self, async_test_client: AsyncClient):
        """Test system under high concurrency stress."""
        async def stress_request():
            try:
                response = await async_test_client.get("/api/v1/health")
                return response.status_code == 200
            except Exception:
                return False

        # Launch high number of concurrent requests
        concurrency_levels = [100, 200, 500]
        success_rates = []

        for concurrency in concurrency_levels:
            tasks = [stress_request() for _ in range(concurrency)]

            start_time = time.time()
            results = await asyncio.gather(*tasks, return_exceptions=True)
            execution_time = time.time() - start_time

            # Calculate success rate
            successes = sum(1 for r in results if r is True)
            success_rate = successes / len(results)
            success_rates.append(success_rate)

            print(f"Concurrency {concurrency}: {success_rate:.2%} success rate in {execution_time:.2f}s")

            # Should handle at least 80% successfully even under stress
            assert success_rate >= 0.8

        # Success rate shouldn't degrade too much with higher concurrency
        assert success_rates[-1] >= success_rates[0] * 0.8

    @pytest.mark.performance
    @pytest.mark.slow
    @pytest.mark.asyncio
    async def test_memory_stress(self):
        """Test system under memory stress."""
        import gc

        process = psutil.Process()
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB

        # Create memory stress
        memory_hogs = []
        try:
            for i in range(100):
                # Create large data structures
                large_list = list(range(100000))  # ~800KB per list
                large_dict = {j: f"data_{j}" * 100 for j in range(1000)}  # ~100KB per dict
                memory_hogs.append((large_list, large_dict))

                current_memory = process.memory_info().rss / 1024 / 1024
                memory_increase = current_memory - initial_memory

                # Stop if we've used too much memory
                if memory_increase > 1000:  # 1GB limit
                    break

            # Test that system is still responsive under memory pressure
            start_time = time.time()
            test_data = list(range(10000))
            test_data.sort()
            response_time = time.time() - start_time

            # Should still be responsive
            assert response_time < 5.0

        finally:
            # Cleanup
            del memory_hogs
            gc.collect()

    @pytest.mark.performance
    @pytest.mark.slow
    @pytest.mark.asyncio
    async def test_sustained_load(self, async_test_client: AsyncClient):
        """Test system under sustained load."""
        duration = 60  # 1 minute sustained test
        request_interval = 0.1  # 10 requests per second

        start_time = time.time()
        request_times = []
        error_count = 0

        while time.time() - start_time < duration:
            request_start = time.time()

            try:
                response = await async_test_client.get("/api/v1/health")
                if response.status_code != 200:
                    error_count += 1
            except Exception:
                error_count += 1

            request_time = time.time() - request_start
            request_times.append(request_time)

            # Wait for next request
            await asyncio.sleep(max(0, request_interval - request_time))

        # Calculate statistics
        total_requests = len(request_times)
        error_rate = error_count / total_requests
        avg_response_time = statistics.mean(request_times)

        print(f"Sustained load test: {total_requests} requests, {error_rate:.2%} error rate, {avg_response_time:.3f}s avg response")

        # Performance assertions
        assert error_rate < 0.05  # Less than 5% error rate
        assert avg_response_time < 1.0  # Average response under 1s
        assert total_requests > duration * 5  # At least 5 requests per second sustained
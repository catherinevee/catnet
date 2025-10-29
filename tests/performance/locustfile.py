"""
CatNet Load Testing with Locust

Run with:
    locust -f tests/performance/locustfile.py --host http://localhost:8000

Web UI will be available at: http://localhost:8089
"""

from locust import HttpUser, task, between, SequentialTaskSet
from typing import Dict, Any
import json
import random


class AuthenticationFlow(SequentialTaskSet):
    """Sequential authentication flow: login -> get profile -> logout"""

    def on_start(self):
        """Setup test user credentials"""
        self.username = f"test_user_{random.randint(1000, 9999)}"
        self.password = "SecurePassword123!"
        self.token = None

    @task
    def register(self):
        """Register a new user"""
        response = self.client.post(
            "/api/v1/auth/register",
            json={
                "username": self.username,
                "email": f"{self.username}@example.com",
                "password": self.password,
                "full_name": f"Test User {self.username}",
            },
            name="/api/v1/auth/register",
        )
        if response.status_code == 201:
            print(f"✓ User registered: {self.username}")

    @task
    def login(self):
        """Login and obtain JWT token"""
        response = self.client.post(
            "/api/v1/auth/login",
            json={"username": self.username, "password": self.password},
            name="/api/v1/auth/login",
        )
        if response.status_code == 200:
            data = response.json()
            self.token = data.get("access_token")
            print(f"✓ User logged in: {self.username}")

    @task
    def get_profile(self):
        """Get user profile"""
        if self.token:
            response = self.client.get(
                "/api/v1/auth/me",
                headers={"Authorization": f"Bearer {self.token}"},
                name="/api/v1/auth/me",
            )
            if response.status_code == 200:
                print(f"✓ Profile retrieved for: {self.username}")

    @task
    def logout(self):
        """Logout user"""
        if self.token:
            response = self.client.post(
                "/api/v1/auth/logout",
                headers={"Authorization": f"Bearer {self.token}"},
                name="/api/v1/auth/logout",
            )
            if response.status_code == 200:
                print(f"✓ User logged out: {self.username}")
        self.interrupt()  # End the task sequence


class DeviceOperations(SequentialTaskSet):
    """Device management operations"""

    def on_start(self):
        """Authenticate before device operations"""
        self.token = None
        self.device_id = None
        self._authenticate()

    def _authenticate(self):
        """Get authentication token"""
        response = self.client.post(
            "/api/v1/auth/login",
            json={"username": "admin", "password": "admin"},
        )
        if response.status_code == 200:
            self.token = response.json().get("access_token")

    def _auth_headers(self) -> Dict[str, str]:
        """Return authorization headers"""
        return {"Authorization": f"Bearer {self.token}"} if self.token else {}

    @task
    def list_devices(self):
        """List all devices"""
        response = self.client.get(
            "/api/v1/devices",
            headers=self._auth_headers(),
            name="/api/v1/devices [LIST]",
        )
        if response.status_code == 200:
            devices = response.json()
            if devices and len(devices) > 0:
                self.device_id = devices[0].get("id")

    @task
    def get_device_details(self):
        """Get specific device details"""
        if self.device_id:
            response = self.client.get(
                f"/api/v1/devices/{self.device_id}",
                headers=self._auth_headers(),
                name="/api/v1/devices/:id [GET]",
            )

    @task
    def get_device_health(self):
        """Check device health"""
        if self.device_id:
            response = self.client.get(
                f"/api/v1/devices/{self.device_id}/health",
                headers=self._auth_headers(),
                name="/api/v1/devices/:id/health",
            )


class DeploymentOperations(SequentialTaskSet):
    """Deployment workflow operations"""

    def on_start(self):
        """Authenticate and setup"""
        self.token = None
        self.deployment_id = None
        self._authenticate()

    def _authenticate(self):
        """Get authentication token"""
        response = self.client.post(
            "/api/v1/auth/login",
            json={"username": "admin", "password": "admin"},
        )
        if response.status_code == 200:
            self.token = response.json().get("access_token")

    def _auth_headers(self) -> Dict[str, str]:
        """Return authorization headers"""
        return {"Authorization": f"Bearer {self.token}"} if self.token else {}

    @task
    def list_deployments(self):
        """List all deployments"""
        response = self.client.get(
            "/api/v1/deployments",
            headers=self._auth_headers(),
            name="/api/v1/deployments [LIST]",
        )
        if response.status_code == 200:
            deployments = response.json()
            if deployments and len(deployments) > 0:
                self.deployment_id = deployments[0].get("id")

    @task
    def get_deployment_status(self):
        """Get deployment status"""
        if self.deployment_id:
            response = self.client.get(
                f"/api/v1/deployments/{self.deployment_id}/status",
                headers=self._auth_headers(),
                name="/api/v1/deployments/:id/status",
            )

    @task
    def create_deployment(self):
        """Create a new deployment"""
        response = self.client.post(
            "/api/v1/deployments",
            headers=self._auth_headers(),
            json={
                "name": f"Load Test Deployment {random.randint(1000, 9999)}",
                "strategy": random.choice(["rolling", "canary", "parallel"]),
                "device_ids": [],
                "config_source": "git",
            },
            name="/api/v1/deployments [CREATE]",
        )
        if response.status_code == 201:
            self.deployment_id = response.json().get("id")


class HealthCheckUser(HttpUser):
    """User that performs health checks and monitoring"""

    wait_time = between(1, 3)
    weight = 1

    @task(5)
    def health_check(self):
        """Basic health check"""
        self.client.get("/health", name="/health")

    @task(3)
    def ready_check(self):
        """Readiness probe"""
        self.client.get("/ready", name="/ready")

    @task(2)
    def detailed_health(self):
        """Detailed health status"""
        self.client.get("/api/v1/health/detailed", name="/api/v1/health/detailed")

    @task(1)
    def prometheus_metrics(self):
        """Prometheus metrics endpoint"""
        self.client.get("/metrics", name="/metrics")


class AuthenticationUser(HttpUser):
    """User that performs authentication operations"""

    wait_time = between(2, 5)
    weight = 3
    tasks = [AuthenticationFlow]


class DeviceManagementUser(HttpUser):
    """User that manages network devices"""

    wait_time = between(3, 7)
    weight = 2
    tasks = [DeviceOperations]


class DeploymentUser(HttpUser):
    """User that performs deployment operations"""

    wait_time = between(5, 10)
    weight = 2
    tasks = [DeploymentOperations]


class APIBrowser(HttpUser):
    """User that browses various API endpoints"""

    wait_time = between(1, 5)
    weight = 1

    def on_start(self):
        """Authenticate on start"""
        response = self.client.post(
            "/api/v1/auth/login",
            json={"username": "admin", "password": "admin"},
        )
        if response.status_code == 200:
            self.token = response.json().get("access_token")
        else:
            self.token = None

    def _auth_headers(self) -> Dict[str, str]:
        """Return authorization headers"""
        return {"Authorization": f"Bearer {self.token}"} if self.token else {}

    @task(2)
    def list_devices(self):
        """Browse device list"""
        self.client.get(
            "/api/v1/devices",
            headers=self._auth_headers(),
            name="/api/v1/devices",
        )

    @task(2)
    def list_deployments(self):
        """Browse deployment list"""
        self.client.get(
            "/api/v1/deployments",
            headers=self._auth_headers(),
            name="/api/v1/deployments",
        )

    @task(1)
    def deployment_analytics(self):
        """View deployment analytics"""
        self.client.get(
            "/api/v1/deployments/analytics",
            headers=self._auth_headers(),
            name="/api/v1/deployments/analytics",
        )

    @task(1)
    def api_docs(self):
        """View API documentation"""
        self.client.get("/api/docs", name="/api/docs")


# Performance test scenarios
class StressTestUser(HttpUser):
    """
    Stress test user for high-load scenarios

    Run with:
        locust -f tests/performance/locustfile.py --host http://localhost:8000 \\
               --users 1000 --spawn-rate 50 --run-time 5m
    """

    wait_time = between(0.5, 2)
    weight = 5

    @task(10)
    def rapid_health_checks(self):
        """Rapid health check requests"""
        self.client.get("/health")

    @task(5)
    def rapid_ready_checks(self):
        """Rapid readiness checks"""
        self.client.get("/ready")

    @task(3)
    def api_root(self):
        """Access API root"""
        self.client.get("/")


# Custom load shapes
from locust import LoadTestShape


class StepLoadShape(LoadTestShape):
    """
    Step load pattern: gradually increase load

    Stages:
    - 100 users for 2 minutes
    - 250 users for 2 minutes
    - 500 users for 2 minutes
    - 750 users for 2 minutes
    - 1000 users for 2 minutes
    """

    step_time = 120  # 2 minutes per step
    step_load = 50  # spawn rate
    spawn_rate = 50
    time_limit = 600  # 10 minutes total

    def tick(self):
        run_time = self.get_run_time()

        if run_time > self.time_limit:
            return None

        current_step = int(run_time // self.step_time)
        target_users = [100, 250, 500, 750, 1000]

        if current_step < len(target_users):
            return (target_users[current_step], self.spawn_rate)

        return None


class SpikeLoadShape(LoadTestShape):
    """
    Spike load pattern: sudden traffic bursts

    Pattern:
    - 50 users baseline
    - Spike to 500 users at 1 min
    - Back to 50 users at 2 min
    - Spike to 1000 users at 3 min
    - Back to 50 users at 4 min
    """

    def tick(self):
        run_time = self.get_run_time()

        if run_time < 60:
            return (50, 10)
        elif run_time < 120:
            return (500, 50)
        elif run_time < 180:
            return (50, 10)
        elif run_time < 240:
            return (1000, 100)
        elif run_time < 300:
            return (50, 10)
        else:
            return None

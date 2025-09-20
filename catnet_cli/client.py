"""
API client wrapper for CatNet CLI
"""
import aiohttp
import asyncio
import json
from typing import Dict, Any, Optional, List
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


class CatNetAPIClient:
    """Async API client for CatNet services"""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.session: Optional[aiohttp.ClientSession] = None
        self.token: Optional[str] = None
        self._load_token()

    def _load_token(self):
        """Load authentication token from storage"""
        token_file = Path.home() / '.catnet' / 'tokens.json'
        if token_file.exists():
            try:
                with open(token_file, 'r') as f:
                    token_data = json.load(f)
                    self.token = token_data.get('access_token')
            except Exception as e:
                logger.error(f"Failed to load token: {e}")

    async def __aenter__(self):
        """Async context manager entry"""
        self.session = aiohttp.ClientSession()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()

    def _get_headers(self) -> Dict[str, str]:
        """Get request headers with authentication"""
        headers = {
            'Content-Type': 'application/json',
            'User-Agent': 'CatNet-CLI/0.1.0'
        }

        if self.token:
            headers['Authorization'] = f'Bearer {self.token}'

        return headers

    def _get_service_url(self, service: str) -> str:
        """Get URL for specific service"""
        service_map = {
            'auth': self.config['api']['auth_url'],
            'gitops': self.config['api']['gitops_url'],
            'deploy': self.config['api']['deploy_url'],
            'device': self.config['api']['device_url'],
            'base': self.config['api']['base_url'],
        }
        return service_map.get(service, self.config['api']['base_url'])

    async def request(
        self,
        method: str,
        endpoint: str,
        service: str = 'base',
        data: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """Make authenticated API request"""
        if not self.session:
            self.session = aiohttp.ClientSession()

        url = f"{self._get_service_url(service)}{endpoint}"
        request_headers = self._get_headers()
        if headers:
            request_headers.update(headers)

        logger.debug(f"{method} {url}")

        try:
            async with self.session.request(
                method=method,
                url=url,
                json=data,
                params=params,
                headers=request_headers,
                timeout=aiohttp.ClientTimeout(
                    total=self.config['api']['timeout']
                ),
                ssl=self.config['security']['verify_ssl']
            ) as response:
                response_text = await response.text()

                # Handle different status codes
                if response.status == 401:
                    raise AuthenticationError("Authentication required. Please \
                        login.")
                elif response.status == 403:
                    raise AuthorizationError("Permission denied")
                elif response.status == 404:
                    raise NotFoundError(f"Resource not found: {endpoint}")
                elif response.status >= 500:
                    raise ServerError(f"Server error: {response.status}")
                elif response.status >= 400:
                    try:
                        error_data = json.loads(response_text)
                        raise APIError(error_data.get('detail', response_text))
                    except json.JSONDecodeError:
                        raise APIError(response_text)

                # Parse successful response
                if response_text:
                    try:
                        return json.loads(response_text)
                    except json.JSONDecodeError:
                        return {'message': response_text}
                else:
                    return {}

        except aiohttp.ClientError as e:
            raise ConnectionError(f"Failed to connect to API: {e}")
        except asyncio.TimeoutError:
            raise TimeoutError(f"Request timeout after \
                {self.config['api']['timeout']} seconds")

    # Convenience methods for common operations

        async def login(
            self,
            username: str,
            password: str,
            mfa_token: Optional[str] = None
        ) -> Dict[str, Any]:
        """Authenticate and get token"""
        data = {
            'username': username,
            'password': password
        }
        if mfa_token:
            data['mfa_token'] = mfa_token

            result = await self.request(
                'POST',
                '/auth/login',
                service='auth',
                data=data
            )

        # Save token
        if 'access_token' in result:
            self.token = result['access_token']
            self._save_token(result)

        return result

    async def logout(self) -> Dict[str, Any]:
        """Logout and clear token"""
        if self.token:
            try:
                result = await self.request(
                    'POST',
                    '/auth/logout',
                    service='auth'
                )
            except Exception:
                result = {'message': 'Logged out locally'}

            self.token = None
            self._clear_token()
            return result
        else:
            return {'message': 'Not logged in'}

    async def refresh_token(self) -> Dict[str, Any]:
        """Refresh authentication token"""
        result = await self.request('POST', '/auth/refresh', service='auth')

        if 'access_token' in result:
            self.token = result['access_token']
            self._save_token(result)

        return result

    def _save_token(self, token_data: Dict[str, Any]):
        """Save token to file"""
        token_dir = Path.home() / '.catnet'
        token_dir.mkdir(exist_ok=True)
        token_file = token_dir / 'tokens.json'

        with open(token_file, 'w') as f:
            json.dump(token_data, f, indent=2)

        # Set restrictive permissions on Unix
        import os
        if hasattr(os, 'chmod'):
            os.chmod(token_file, 0o600)

    def _clear_token(self):
        """Clear saved token"""
        token_file = Path.home() / '.catnet' / 'tokens.json'
        if token_file.exists():
            token_file.unlink()

    # Device operations
        async def list_devices(
            self,
            vendor: Optional[str] = None,
            status: Optional[str] = None
        ) -> List[Dict[str, Any]]:
        """List devices with optional filters"""
        params = {}
        if vendor:
            params['vendor'] = vendor
        if status:
            params['status'] = status

            return await self.request(
                'GET',
                '/devices',
                service='device',
                params=params
            )

    async def add_device(self, device_data: Dict[str, Any]) -> Dict[str, Any]:
        """Add new device"""
        return await self.request(
            'POST',
            '/devices',
            service='device',
            data=device_data
        )

    async def backup_device(self, device_id: str) -> Dict[str, Any]:
        """Create device backup"""
        return await self.request(
            'POST',
            f'/devices/{device_id}/backup',
            service='device'
        )

        async def execute_command(
            self,
            device_id: str,
            command: str
        ) -> Dict[str, Any]:
        """Execute command on device"""
        return await self.request(
            'POST',
            f'/devices/{device_id}/execute',
            service='device',
            data={'command': command}
        )

    # GitOps operations
        async def connect_repository(
            self,
            url: str,
            branch: str = 'main',
            webhook_secret: Optional[str] = None
        ) -> Dict[str, Any]:
        """Connect Git repository"""
        data = {
            'url': url,
            'branch': branch
        }
        if webhook_secret:
            data['webhook_secret'] = webhook_secret

            return await self.request(
                'POST',
                '/gitops/connect',
                service='gitops',
                data=data
            )

        async def sync_repository(
            self,
            repo_id: str,
            force: bool = False
        ) -> Dict[str, Any]:
        """Sync repository"""
        return await self.request(
            'POST',
            f'/gitops/{repo_id}/sync',
            service='gitops',
            data={'force': force}
        )

    async def list_repositories(self) -> List[Dict[str, Any]]:
        """List connected repositories"""
        return await self.request(
            'GET',
            '/gitops/repositories',
            service='gitops'
        )

    # Deployment operations
    async def create_deployment(
        self,
        config_file: str,
        targets: List[str],
        strategy: str = 'rolling',
        dry_run: bool = False
    ) -> Dict[str, Any]:
        """Create new deployment"""
        # Load configuration from file
        config_path = Path(config_file)
        if not config_path.exists():
            raise FileNotFoundError(f"Configuration file not found: \
                {config_file}")

        with open(config_path, 'r') as f:
            if config_path.suffix in ['.yml', '.yaml']:
                import yaml
                config_content = yaml.safe_load(f)
            elif config_path.suffix == '.json':
                config_content = json.load(f)
            else:
                config_content = f.read()

        data = {
            'configuration': config_content,
            'targets': targets,
            'strategy': strategy,
            'dry_run': dry_run
        }

        return await self.request(
            'POST',
            '/deployments',
            service='deploy',
            data=data
        )

        async def get_deployment_status(
            self,
            deployment_id: str
        ) -> Dict[str, Any]:
        """Get deployment status"""
        return await self.request(
            'GET',
            f'/deployments/{deployment_id}',
            service='deploy'
        )

        async def approve_deployment(
            self,
            deployment_id: str,
            comment: Optional[str] = None
        ) -> Dict[str, Any]:
        """Approve deployment"""
        data = {}
        if comment:
            data['comment'] = comment

            return await self.request(
                'POST',
                f'/deployments/{deployment_id}/approve',
                service='deploy',
                data=data
            )

        async def rollback_deployment(
            self,
            deployment_id: str,
            reason: str
        ) -> Dict[str, Any]:
        """Rollback deployment"""
        return await self.request(
            'POST',
            f'/deployments/{deployment_id}/rollback',
            service='deploy',
            data={'reason': reason}
        )

        async def get_deployment_history(
            self,
            limit: int = 10
        ) -> List[Dict[str, Any]]:
        """Get deployment history"""
        return await self.request(
            'GET',
            '/deployments/history',
            service='deploy',
            params={'limit': limit}
        )

    # Vault operations
    async def check_vault_status(self) -> Dict[str, Any]:
        """Check Vault status"""
        vault_url = self.config['vault']['url']
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{vault_url}/v1/sys/health") as response:
                return await response.json()

    async def rotate_credentials(self, device_id: str) -> Dict[str, Any]:
        """Rotate device credentials"""
        return await self.request(
            'POST',
            f'/vault/rotate/{device_id}',
            service='base'
        )


# Custom exception classes

class CatNetAPIError(Exception):
    """Base exception for API errors"""
    pass


class AuthenticationError(CatNetAPIError):
    """Authentication failed"""
    pass


class AuthorizationError(CatNetAPIError):
    """Authorization failed"""
    pass


class NotFoundError(CatNetAPIError):
    """Resource not found"""
    pass


class ServerError(CatNetAPIError):
    """Server error"""
    pass


class APIError(CatNetAPIError):
    """Generic API error"""
    pass


class ConnectionError(CatNetAPIError):
    """Connection failed"""
    pass


class TimeoutError(CatNetAPIError):
    """Request timeout"""
    pass

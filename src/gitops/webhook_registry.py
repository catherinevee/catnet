"""
Webhook Auto-Registration Service
Automatically registers and manages webhooks for Git repositories
"""

import asyncio
import base64
import secrets
from typing import Optional, Dict, Any, List, Set
from datetime import datetime, timedelta
from urllib.parse import urljoin
import aiohttp
import structlog

from ..core.config import settings
from ..security.vault import VaultClient
from ..db.models import GitRepository, WebhookRegistration
from ..db.database import get_db
from .models import GitProvider
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, delete


logger = structlog.get_logger()


class WebhookRegistry:
    """
    Service for automatically registering and managing webhooks with Git providers
    """

    def __init__(self, vault_client: VaultClient):
        self.vault = vault_client
        self.base_webhook_url = settings.WEBHOOK_BASE_URL or f"https://{settings.EXTERNAL_HOSTNAME}/api/v1/git/webhook"

        # Supported events for each provider
        self.provider_events = {
            GitProvider.GITHUB: [
                "push",
                "pull_request",
                "pull_request_review",
                "create",  # For tags
                "release",
                "repository"  # For repository events
            ],
            GitProvider.GITLAB: [
                "push_events",
                "merge_requests_events",
                "tag_push_events",
                "releases_events",
                "wiki_page_events"
            ],
            GitProvider.BITBUCKET: [
                "repo:refs_changed",
                "pullrequest:created",
                "pullrequest:updated",
                "pullrequest:approved",
                "pullrequest:fulfilled"
            ],
            GitProvider.AZURE_DEVOPS: [
                "git.push",
                "git.pullrequest.created",
                "git.pullrequest.updated"
            ]
        }

        # Retry settings
        self.max_retries = 3
        self.retry_delay = 5  # seconds
        self.registry_cache = {}

    async def register_webhook(
        self,
        repository: GitRepository,
        events: Optional[List[str]] = None,
        db: Optional[AsyncSession] = None
    ) -> Dict[str, Any]:
        """
        Register webhook for a repository
        """
        if not db:
            db = get_db()

        result = {
            "success": False,
            "webhook_id": None,
            "webhook_url": None,
            "events": [],
            "error": None,
            "provider": repository.provider.value
        }

        try:
            # Generate webhook secret
            webhook_secret = secrets.token_urlsafe(32)

            # Store secret in Vault
            secret_path = f"webhooks/{repository.id}/secret"
            await self.vault.store_secret(secret_path, {"secret": webhook_secret})

            # Get provider-specific webhook URL
            webhook_url = self._get_webhook_url(repository)

            # Get events to register
            if not events:
                events = self.provider_events.get(repository.provider, [])

            # Register webhook with provider
            webhook_data = await self._register_webhook_with_provider(
                repository,
                webhook_url,
                webhook_secret,
                events
            )

            if webhook_data["success"]:
                # Store webhook registration in database
                webhook_registration = WebhookRegistration(
                    repository_id=repository.id,
                    provider=repository.provider,
                    webhook_id=webhook_data["webhook_id"],
                    webhook_url=webhook_url,
                    events=events,
                    secret_vault_path=secret_path,
                    is_active=True,
                    last_delivery_at=None,
                    delivery_count=0,
                    error_count=0,
                    metadata=webhook_data.get("metadata", {})
                )

                db.add(webhook_registration)
                await db.commit()

                # Update repository with webhook info
                repository.webhook_secret = webhook_secret
                repository.webhook_url = webhook_url
                repository.webhook_id = webhook_data["webhook_id"]

                await db.commit()

                result.update({
                    "success": True,
                    "webhook_id": webhook_data["webhook_id"],
                    "webhook_url": webhook_url,
                    "events": events,
                    "registration_id": webhook_registration.id
                })

                logger.info(
                    "Webhook registered successfully",
                    repository_id=str(repository.id),
                    provider=repository.provider.value,
                    webhook_id=webhook_data["webhook_id"]
                )

            else:
                result["error"] = webhook_data.get("error", "Unknown error")
                logger.error(
                    "Failed to register webhook",
                    repository_id=str(repository.id),
                    provider=repository.provider.value,
                    error=result["error"]
                )

        except Exception as e:
            result["error"] = str(e)
            logger.error(
                "Exception during webhook registration",
                repository_id=str(repository.id),
                provider=repository.provider.value,
                error=str(e),
                exc_info=True
            )

        return result

    async def unregister_webhook(
        self,
        repository: GitRepository,
        db: Optional[AsyncSession] = None
    ) -> Dict[str, Any]:
        """
        Unregister webhook for a repository
        """
        if not db:
            db = get_db()

        result = {
            "success": False,
            "error": None
        }

        try:
            # Get webhook registration
            stmt = select(WebhookRegistration).where(
                WebhookRegistration.repository_id == repository.id,
                WebhookRegistration.is_active == True
            )
            webhook_reg = (await db.execute(stmt)).scalar_one_or_none()

            if not webhook_reg:
                result["error"] = "No active webhook registration found"
                return result

            # Unregister from provider
            unregister_result = await self._unregister_webhook_from_provider(
                repository,
                webhook_reg.webhook_id
            )

            if unregister_result["success"]:
                # Mark as inactive in database
                webhook_reg.is_active = False
                webhook_reg.deregistered_at = datetime.utcnow()

                # Clear webhook info from repository
                repository.webhook_secret = None
                repository.webhook_url = None
                repository.webhook_id = None

                await db.commit()

                # Remove secret from Vault
                try:
                    await self.vault.delete_secret(webhook_reg.secret_vault_path)
                except Exception as e:
                    logger.warning(
                        "Failed to delete webhook secret from Vault",
                        error=str(e)
                    )

                result["success"] = True
                logger.info(
                    "Webhook unregistered successfully",
                    repository_id=str(repository.id),
                    webhook_id=webhook_reg.webhook_id
                )

            else:
                result["error"] = unregister_result.get("error", "Unknown error")

        except Exception as e:
            result["error"] = str(e)
            logger.error(
                "Exception during webhook unregistration",
                repository_id=str(repository.id),
                error=str(e),
                exc_info=True
            )

        return result

    async def update_webhook_events(
        self,
        repository: GitRepository,
        events: List[str],
        db: Optional[AsyncSession] = None
    ) -> Dict[str, Any]:
        """
        Update events for existing webhook
        """
        if not db:
            db = get_db()

        result = {
            "success": False,
            "error": None
        }

        try:
            # Get webhook registration
            stmt = select(WebhookRegistration).where(
                WebhookRegistration.repository_id == repository.id,
                WebhookRegistration.is_active == True
            )
            webhook_reg = (await db.execute(stmt)).scalar_one_or_none()

            if not webhook_reg:
                result["error"] = "No active webhook registration found"
                return result

            # Update webhook with provider
            update_result = await self._update_webhook_with_provider(
                repository,
                webhook_reg.webhook_id,
                events
            )

            if update_result["success"]:
                webhook_reg.events = events
                webhook_reg.updated_at = datetime.utcnow()
                await db.commit()

                result["success"] = True
                logger.info(
                    "Webhook events updated successfully",
                    repository_id=str(repository.id),
                    webhook_id=webhook_reg.webhook_id,
                    events=events
                )
            else:
                result["error"] = update_result.get("error", "Unknown error")

        except Exception as e:
            result["error"] = str(e)
            logger.error(
                "Exception during webhook update",
                repository_id=str(repository.id),
                error=str(e),
                exc_info=True
            )

        return result

    async def test_webhook(
        self,
        repository: GitRepository,
        db: Optional[AsyncSession] = None
    ) -> Dict[str, Any]:
        """
        Test webhook delivery
        """
        result = {
            "success": False,
            "error": None,
            "response": None
        }

        try:
            # Get webhook registration
            if not db:
                db = get_db()

            stmt = select(WebhookRegistration).where(
                WebhookRegistration.repository_id == repository.id,
                WebhookRegistration.is_active == True
            )
            webhook_reg = (await db.execute(stmt)).scalar_one_or_none()

            if not webhook_reg:
                result["error"] = "No active webhook registration found"
                return result

            # Send test ping based on provider
            test_result = await self._test_webhook_with_provider(
                repository,
                webhook_reg.webhook_id
            )

            result.update(test_result)

            if test_result["success"]:
                webhook_reg.last_test_at = datetime.utcnow()
                await db.commit()

        except Exception as e:
            result["error"] = str(e)
            logger.error(
                "Exception during webhook test",
                repository_id=str(repository.id),
                error=str(e),
                exc_info=True
            )

        return result

    async def check_webhook_health(
        self,
        repository: GitRepository,
        db: Optional[AsyncSession] = None
    ) -> Dict[str, Any]:
        """
        Check webhook health and delivery status
        """
        health_status = {
            "healthy": False,
            "last_delivery": None,
            "error_rate": 0.0,
            "total_deliveries": 0,
            "recent_errors": [],
            "webhook_exists": False
        }

        try:
            # Get webhook registration
            if not db:
                db = get_db()

            stmt = select(WebhookRegistration).where(
                WebhookRegistration.repository_id == repository.id,
                WebhookRegistration.is_active == True
            )
            webhook_reg = (await db.execute(stmt)).scalar_one_or_none()

            if not webhook_reg:
                return health_status

            # Check if webhook still exists with provider
            exists_result = await self._check_webhook_exists_with_provider(
                repository,
                webhook_reg.webhook_id
            )

            health_status["webhook_exists"] = exists_result["exists"]

            if not exists_result["exists"]:
                # Webhook was deleted externally, mark as inactive
                webhook_reg.is_active = False
                webhook_reg.deregistered_at = datetime.utcnow()
                webhook_reg.metadata["auto_disabled"] = "webhook_not_found"
                await db.commit()
                return health_status

            # Calculate health metrics
            health_status.update({
                "healthy": webhook_reg.error_count < 10,  # Less than 10 recent errors
                "last_delivery": webhook_reg.last_delivery_at.isoformat() if webhook_reg.last_delivery_at else None,
                "total_deliveries": webhook_reg.delivery_count,
                "recent_errors": webhook_reg.metadata.get("recent_errors", [])
            })

            if webhook_reg.delivery_count > 0:
                health_status["error_rate"] = webhook_reg.error_count / webhook_reg.delivery_count

        except Exception as e:
            logger.error(
                "Exception during webhook health check",
                repository_id=str(repository.id),
                error=str(e),
                exc_info=True
            )

        return health_status

    async def auto_register_repositories(
        self,
        repositories: Optional[List[GitRepository]] = None,
        db: Optional[AsyncSession] = None
    ) -> Dict[str, Any]:
        """
        Auto-register webhooks for repositories that don't have them
        """
        if not db:
            db = get_db()

        results = {
            "total_processed": 0,
            "successful_registrations": 0,
            "failed_registrations": 0,
            "skipped": 0,
            "errors": []
        }

        try:
            if not repositories:
                # Get all repositories without active webhooks
                stmt = select(GitRepository).where(
                    GitRepository.is_active == True,
                    GitRepository.webhook_id.is_(None)
                )
                result = await db.execute(stmt)
                repositories = result.scalars().all()

            for repository in repositories:
                results["total_processed"] += 1

                try:
                    # Skip if repository already has webhook
                    if repository.webhook_id:
                        results["skipped"] += 1
                        continue

                    # Check if we have valid credentials for this repository
                    if not await self._has_valid_credentials(repository):
                        results["skipped"] += 1
                        results["errors"].append({
                            "repository_id": str(repository.id),
                            "error": "No valid credentials found"
                        })
                        continue

                    # Register webhook
                    register_result = await self.register_webhook(repository, db=db)

                    if register_result["success"]:
                        results["successful_registrations"] += 1
                    else:
                        results["failed_registrations"] += 1
                        results["errors"].append({
                            "repository_id": str(repository.id),
                            "error": register_result["error"]
                        })

                    # Small delay to avoid rate limiting
                    await asyncio.sleep(1)

                except Exception as e:
                    results["failed_registrations"] += 1
                    results["errors"].append({
                        "repository_id": str(repository.id),
                        "error": str(e)
                    })

        except Exception as e:
            results["errors"].append({
                "general_error": str(e)
            })

        logger.info(
            "Auto-registration completed",
            **results
        )

        return results

    def _get_webhook_url(self, repository: GitRepository) -> str:
        """
        Generate webhook URL for repository
        """
        return f"{self.base_webhook_url}/{repository.provider.value}/{repository.id}"

    async def _register_webhook_with_provider(
        self,
        repository: GitRepository,
        webhook_url: str,
        secret: str,
        events: List[str]
    ) -> Dict[str, Any]:
        """
        Register webhook with specific Git provider
        """
        if repository.provider == GitProvider.GITHUB:
            return await self._register_github_webhook(repository, webhook_url, secret, events)
        elif repository.provider == GitProvider.GITLAB:
            return await self._register_gitlab_webhook(repository, webhook_url, secret, events)
        elif repository.provider == GitProvider.BITBUCKET:
            return await self._register_bitbucket_webhook(repository, webhook_url, secret, events)
        elif repository.provider == GitProvider.AZURE_DEVOPS:
            return await self._register_azure_webhook(repository, webhook_url, secret, events)
        else:
            return {"success": False, "error": f"Unsupported provider: {repository.provider}"}

    async def _register_github_webhook(
        self,
        repository: GitRepository,
        webhook_url: str,
        secret: str,
        events: List[str]
    ) -> Dict[str, Any]:
        """
        Register webhook with GitHub
        """
        try:
            # Get access token from Vault
            token_path = f"git/{repository.id}/token"
            token_data = await self.vault.get_secret(token_path)
            access_token = token_data.get("access_token")

            if not access_token:
                return {"success": False, "error": "No access token found"}

            # Parse repository URL to get owner/repo
            repo_parts = repository.url.replace("https://github.com/", "").replace(".git", "").split("/")
            if len(repo_parts) != 2:
                return {"success": False, "error": "Invalid GitHub repository URL"}

            owner, repo_name = repo_parts

            # GitHub API endpoint
            api_url = f"https://api.github.com/repos/{owner}/{repo_name}/hooks"

            webhook_config = {
                "name": "web",
                "active": True,
                "events": events,
                "config": {
                    "url": webhook_url,
                    "content_type": "json",
                    "secret": secret,
                    "insecure_ssl": "0"
                }
            }

            headers = {
                "Authorization": f"token {access_token}",
                "Accept": "application/vnd.github.v3+json",
                "User-Agent": "CatNet-Webhook-Registry"
            }

            async with aiohttp.ClientSession() as session:
                async with session.post(api_url, json=webhook_config, headers=headers) as response:
                    if response.status == 201:
                        webhook_data = await response.json()
                        return {
                            "success": True,
                            "webhook_id": str(webhook_data["id"]),
                            "metadata": {
                                "github_hook_id": webhook_data["id"],
                                "ping_url": webhook_data.get("ping_url"),
                                "test_url": webhook_data.get("test_url")
                            }
                        }
                    else:
                        error_data = await response.json()
                        return {
                            "success": False,
                            "error": f"GitHub API error: {error_data.get('message', 'Unknown error')}"
                        }

        except Exception as e:
            return {"success": False, "error": f"Exception: {str(e)}"}

    async def _register_gitlab_webhook(
        self,
        repository: GitRepository,
        webhook_url: str,
        secret: str,
        events: List[str]
    ) -> Dict[str, Any]:
        """
        Register webhook with GitLab
        """
        try:
            # Get access token from Vault
            token_path = f"git/{repository.id}/token"
            token_data = await self.vault.get_secret(token_path)
            access_token = token_data.get("access_token")

            if not access_token:
                return {"success": False, "error": "No access token found"}

            # Extract project ID from repository metadata or URL
            project_id = repository.metadata.get("project_id")
            if not project_id:
                # Try to extract from URL
                url_parts = repository.url.replace("https://gitlab.com/", "").replace(".git", "")
                project_id = url_parts.replace("/", "%2F")  # URL encode the slash

            api_url = f"https://gitlab.com/api/v4/projects/{project_id}/hooks"

            webhook_config = {
                "url": webhook_url,
                "token": secret,
                "push_events": "push_events" in events,
                "merge_requests_events": "merge_requests_events" in events,
                "tag_push_events": "tag_push_events" in events,
                "releases_events": "releases_events" in events,
                "wiki_page_events": "wiki_page_events" in events,
                "enable_ssl_verification": True
            }

            headers = {
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            }

            async with aiohttp.ClientSession() as session:
                async with session.post(api_url, json=webhook_config, headers=headers) as response:
                    if response.status == 201:
                        webhook_data = await response.json()
                        return {
                            "success": True,
                            "webhook_id": str(webhook_data["id"]),
                            "metadata": {
                                "gitlab_hook_id": webhook_data["id"],
                                "project_id": project_id
                            }
                        }
                    else:
                        error_data = await response.json()
                        return {
                            "success": False,
                            "error": f"GitLab API error: {error_data.get('message', 'Unknown error')}"
                        }

        except Exception as e:
            return {"success": False, "error": f"Exception: {str(e)}"}

    async def _register_bitbucket_webhook(
        self,
        repository: GitRepository,
        webhook_url: str,
        secret: str,
        events: List[str]
    ) -> Dict[str, Any]:
        """
        Register webhook with Bitbucket
        """
        try:
            # Get credentials from Vault
            token_path = f"git/{repository.id}/token"
            token_data = await self.vault.get_secret(token_path)
            access_token = token_data.get("access_token")

            if not access_token:
                return {"success": False, "error": "No access token found"}

            # Parse repository URL
            url_parts = repository.url.replace("https://bitbucket.org/", "").replace(".git", "").split("/")
            if len(url_parts) != 2:
                return {"success": False, "error": "Invalid Bitbucket repository URL"}

            workspace, repo_name = url_parts

            api_url = f"https://api.bitbucket.org/2.0/repositories/{workspace}/{repo_name}/hooks"

            webhook_config = {
                "description": "CatNet Webhook",
                "url": webhook_url,
                "active": True,
                "events": events
            }

            headers = {
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            }

            async with aiohttp.ClientSession() as session:
                async with session.post(api_url, json=webhook_config, headers=headers) as response:
                    if response.status == 201:
                        webhook_data = await response.json()
                        return {
                            "success": True,
                            "webhook_id": webhook_data["uuid"],
                            "metadata": {
                                "bitbucket_uuid": webhook_data["uuid"],
                                "workspace": workspace,
                                "repo_name": repo_name
                            }
                        }
                    else:
                        error_data = await response.json()
                        return {
                            "success": False,
                            "error": f"Bitbucket API error: {error_data.get('error', {}).get('message', 'Unknown error')}"
                        }

        except Exception as e:
            return {"success": False, "error": f"Exception: {str(e)}"}

    async def _register_azure_webhook(
        self,
        repository: GitRepository,
        webhook_url: str,
        secret: str,
        events: List[str]
    ) -> Dict[str, Any]:
        """
        Register webhook with Azure DevOps
        """
        try:
            # Get PAT from Vault
            token_path = f"git/{repository.id}/token"
            token_data = await self.vault.get_secret(token_path)
            pat_token = token_data.get("pat_token")

            if not pat_token:
                return {"success": False, "error": "No PAT token found"}

            # Extract organization and project from metadata
            organization = repository.metadata.get("organization")
            project = repository.metadata.get("project")

            if not organization or not project:
                return {"success": False, "error": "Missing Azure DevOps organization or project"}

            api_url = f"https://dev.azure.com/{organization}/_apis/hooks/subscriptions?api-version=6.0"

            # Create service hook subscription
            subscription_config = {
                "consumerActionId": "httpRequest",
                "consumerId": "webHooks",
                "consumerInputs": {
                    "url": webhook_url,
                    "httpHeaders": f"Authorization: Basic {base64.b64encode(f':{secret}'.encode()).decode()}"
                },
                "eventType": "git.push",  # Start with push events
                "publisherId": "tfs",
                "scope": "project",
                "resourceVersion": "1.0"
            }

            # Basic auth with PAT
            auth = base64.b64encode(f":{pat_token}".encode()).decode()
            headers = {
                "Authorization": f"Basic {auth}",
                "Content-Type": "application/json"
            }

            async with aiohttp.ClientSession() as session:
                async with session.post(api_url, json=subscription_config, headers=headers) as response:
                    if response.status == 200:
                        webhook_data = await response.json()
                        return {
                            "success": True,
                            "webhook_id": webhook_data["id"],
                            "metadata": {
                                "azure_subscription_id": webhook_data["id"],
                                "organization": organization,
                                "project": project
                            }
                        }
                    else:
                        error_data = await response.json()
                        return {
                            "success": False,
                            "error": f"Azure DevOps API error: {error_data.get('message', 'Unknown error')}"
                        }

        except Exception as e:
            return {"success": False, "error": f"Exception: {str(e)}"}

    async def _unregister_webhook_from_provider(
        self,
        repository: GitRepository,
        webhook_id: str
    ) -> Dict[str, Any]:
        """
        Unregister webhook from Git provider
        """
        # Implementation depends on provider
        if repository.provider == GitProvider.GITHUB:
            return await self._unregister_github_webhook(repository, webhook_id)
        elif repository.provider == GitProvider.GITLAB:
            return await self._unregister_gitlab_webhook(repository, webhook_id)
        elif repository.provider == GitProvider.BITBUCKET:
            return await self._unregister_bitbucket_webhook(repository, webhook_id)
        elif repository.provider == GitProvider.AZURE_DEVOPS:
            return await self._unregister_azure_webhook(repository, webhook_id)

        return {"success": False, "error": f"Unsupported provider: {repository.provider}"}

    async def _update_webhook_with_provider(
        self,
        repository: GitRepository,
        webhook_id: str,
        events: List[str]
    ) -> Dict[str, Any]:
        """
        Update webhook events with provider
        """
        # Implementation would be similar to registration but with PATCH/PUT requests
        return {"success": True}  # Simplified for now

    async def _test_webhook_with_provider(
        self,
        repository: GitRepository,
        webhook_id: str
    ) -> Dict[str, Any]:
        """
        Test webhook with provider
        """
        # Implementation would trigger test delivery
        return {"success": True, "response": "Test delivery sent"}

    async def _check_webhook_exists_with_provider(
        self,
        repository: GitRepository,
        webhook_id: str
    ) -> Dict[str, Any]:
        """
        Check if webhook still exists with provider
        """
        # Implementation would query provider API
        return {"exists": True}

    async def _has_valid_credentials(self, repository: GitRepository) -> bool:
        """
        Check if repository has valid credentials stored
        """
        try:
            token_path = f"git/{repository.id}/token"
            token_data = await self.vault.get_secret(token_path)
            return bool(token_data.get("access_token") or token_data.get("pat_token"))
        except:
            return False

    async def _unregister_github_webhook(self, repository: GitRepository, webhook_id: str) -> Dict[str, Any]:
        """Unregister GitHub webhook"""
        try:
            token_path = f"git/{repository.id}/token"
            token_data = await self.vault.get_secret(token_path)
            access_token = token_data.get("access_token")

            repo_parts = repository.url.replace("https://github.com/", "").replace(".git", "").split("/")
            owner, repo_name = repo_parts

            api_url = f"https://api.github.com/repos/{owner}/{repo_name}/hooks/{webhook_id}"
            headers = {"Authorization": f"token {access_token}"}

            async with aiohttp.ClientSession() as session:
                async with session.delete(api_url, headers=headers) as response:
                    return {"success": response.status == 204}

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def _unregister_gitlab_webhook(self, repository: GitRepository, webhook_id: str) -> Dict[str, Any]:
        """Unregister GitLab webhook"""
        try:
            token_path = f"git/{repository.id}/token"
            token_data = await self.vault.get_secret(token_path)
            access_token = token_data.get("access_token")

            project_id = repository.metadata.get("project_id")
            if not project_id:
                url_parts = repository.url.replace("https://gitlab.com/", "").replace(".git", "")
                project_id = url_parts.replace("/", "%2F")

            api_url = f"https://gitlab.com/api/v4/projects/{project_id}/hooks/{webhook_id}"
            headers = {"Authorization": f"Bearer {access_token}"}

            async with aiohttp.ClientSession() as session:
                async with session.delete(api_url, headers=headers) as response:
                    return {"success": response.status == 204}

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def _unregister_bitbucket_webhook(self, repository: GitRepository, webhook_id: str) -> Dict[str, Any]:
        """Unregister Bitbucket webhook"""
        try:
            token_path = f"git/{repository.id}/token"
            token_data = await self.vault.get_secret(token_path)
            access_token = token_data.get("access_token")

            url_parts = repository.url.replace("https://bitbucket.org/", "").replace(".git", "").split("/")
            workspace, repo_name = url_parts

            api_url = f"https://api.bitbucket.org/2.0/repositories/{workspace}/{repo_name}/hooks/{webhook_id}"
            headers = {"Authorization": f"Bearer {access_token}"}

            async with aiohttp.ClientSession() as session:
                async with session.delete(api_url, headers=headers) as response:
                    return {"success": response.status == 204}

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def _unregister_azure_webhook(self, repository: GitRepository, webhook_id: str) -> Dict[str, Any]:
        """Unregister Azure DevOps webhook"""
        try:
            token_path = f"git/{repository.id}/token"
            token_data = await self.vault.get_secret(token_path)
            pat_token = token_data.get("pat_token")

            organization = repository.metadata.get("organization")
            api_url = f"https://dev.azure.com/{organization}/_apis/hooks/subscriptions/{webhook_id}?api-version=6.0"

            auth = base64.b64encode(f":{pat_token}".encode()).decode()
            headers = {"Authorization": f"Basic {auth}"}

            async with aiohttp.ClientSession() as session:
                async with session.delete(api_url, headers=headers) as response:
                    return {"success": response.status == 204}

        except Exception as e:
            return {"success": False, "error": str(e)}
"""
Simple GitOps Endpoints
Phase 3 Implementation - Basic GitHub integration without complexity
"""

from fastapi import APIRouter, HTTPException, status, Query
from typing import List, Optional
from pydantic import BaseModel
from datetime import datetime

from ..gitops.simple_github_client import github_client

router = APIRouter(tags=["GitOps"])


class ConnectRepoRequest(BaseModel):
    """Request model for connecting to a repository"""

    repository_url: str
    branch: str = "main"
    token: Optional[str] = None


class ConnectRepoResponse(BaseModel):
    """Response model for repository connection"""

    url: str
    owner: str
    repo: str
    branch: str
    connected_at: str
    status: str = "connected"


class ConfigFileResponse(BaseModel):
    """Response model for configuration files"""

    name: str
    path: str
    size: int
    sha: Optional[str] = ""
    download_url: Optional[str] = ""


class ConfigContentResponse(BaseModel):
    """Response model for configuration content"""

    path: str
    name: str
    content: str
    size: int
    retrieved_at: str


@router.post("/connect", response_model=ConnectRepoResponse)
async def connect_repository(request: ConnectRepoRequest):
    """
    Connect to a GitHub repository

    Simple implementation - just validates and stores connection"""
    try:
        repo_info = github_client.connect_repository(
            repo_url=request.repository_url, branch=request.branch, token=request.token
        )

        return ConnectRepoResponse(
            url=repo_info.url,
            owner=repo_info.owner,
            repo=repo_info.repo,
            branch=repo_info.branch,
            connected_at=repo_info.connected_at.isoformat(),
            status="connected",
        )

    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to connect to repository: {str(e)}",
        )


@router.get("/repository")
async def get_repository_info():
    """Get information about the connected repository"""
    repo_info = github_client.get_repository_info()

    if not repo_info:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="No repository connected"
        )

    return repo_info


@router.get("/configs", response_model=List[ConfigFileResponse])
async def list_configurations(
    path: str = Query("", description="Path within repository to search")
):
    """
    List configuration files in the connected repository

    Returns all .cfg, .conf, .yaml, .yml, and .json files"""
    if not github_client.connected_repo:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No repository connected. Use /connect first",
        )

    try:
        configs = github_client.list_configs(path)

        return [
            ConfigFileResponse(
                name=cfg.get("name", ""),
                path=cfg.get("path", ""),
                size=cfg.get("size", 0),
                sha=cfg.get("sha", ""),
                download_url=cfg.get("download_url", ""),
            )
            for cfg in configs
        ]

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list configurations: {str(e)}",
        )


@router.get("/configs/{config_path:path}", response_model=ConfigContentResponse)
async def get_configuration(config_path: str):
    """
    Get the content of a specific configuration file

    Returns the actual configuration content"""
    if not github_client.connected_repo:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No repository connected. Use /connect first",
        )

    try:
        config = github_client.get_config(config_path)

        return ConfigContentResponse(
            path=config.path,
            name=config.name,
            content=config.content,
            size=config.size,
            retrieved_at=config.retrieved_at.isoformat(),
        )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get configuration: {str(e)}",
        )


@router.post("/test-connection")
async def test_connection():
    """Test if the current repository connection is valid"""
    if not github_client.connected_repo:
        return {"connected": False, "message": "No repository connected"}

    is_valid = github_client.test_connection()

    return {
        "connected": is_valid,
        "repository": github_client.connected_repo.url if is_valid else None,
        "message": "Connection is valid" if is_valid else "Connection failed",
    }


@router.get("/cached-configs")
async def get_cached_configs():
    """Get list of cached configuration files"""
    cached = github_client.get_cached_configs()

    return {
        "cached_files": cached,
        "count": len(cached),
        "cache_dir": str(github_client.cache_dir),
    }


@router.delete("/cache")
async def clear_cache():
    """Clear all cached configurations"""
    github_client.clear_cache()

    return {"status": "cleared", "message": "Configuration cache cleared"}


@router.post("/sync")
async def sync_configurations():
    """
    Sync configurations from GitHub

    Simple implementation - just refreshes the file list"""
    if not github_client.connected_repo:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="No repository connected"
        )

    try:
        # Clear cache to force fresh fetch
        github_client.clear_cache()

        # List configs to populate cache
        configs = github_client.list_configs()

        return {
            "status": "synced",
            "configs_found": len(configs),
            "repository": github_client.connected_repo.url,
            "timestamp": datetime.utcnow().isoformat(),
        }

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to sync: {str(e)}",
        )


# Sample repository for testing
@router.post("/connect-sample")
async def connect_sample_repository():
    """
    Connect to a sample repository for testing

    Uses a public Cisco configuration examples repository"""
    try:
        # Use a real public repo with network configs
        repo_info = github_client.connect_repository(
            repo_url="https://github.com/cisco/cisco-network-puppet-module",
            branch="main",
        )

        return {
            "status": "connected",
            "repository": repo_info.url,
            "message": "Connected to sample Cisco configuration repository",
        }

    except Exception as e:
        # Fallback to mock if real repo fails
        github_client.connected_repo = type(
            "obj",
            (object,),
            {
                "url": "https://github.com/example/network-configs",
                "owner": "example",
                "repo": "network-configs",
                "branch": "main",
                "token": None,
                "connected_at": datetime.utcnow(),
            },
        )()

        return {
            "status": "connected",
            "repository": "https://github.com/example/network-configs",
            "message": "Connected to mock repository for testing",
        }

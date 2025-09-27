"""
API Routes Package

Contains all FastAPI route definitions for the CatNet API.
"""

from . import auth, devices, deployments, gitops, health, inventory, monitoring, admin

__all__ = [
    "auth",
    "devices",
    "deployments",
    "gitops",
    "health",
    "inventory",
    "monitoring",
    "admin"
]
"""
CatNet - Security-first, GitOps-enabled network configuration deployment system
"""

__version__ = "1.0.0"
__author__ = "CatNet Team"
__description__ = "Automated, secure network configuration deployment for Cisco and Juniper devices"

from typing import Final

# Service names
AUTH_SERVICE: Final[str] = "catnet-auth"
GITOPS_SERVICE: Final[str] = "catnet-gitops"
DEPLOYMENT_SERVICE: Final[str] = "catnet-deployment"
DEVICE_SERVICE: Final[str] = "catnet-device"

# Supported vendors
SUPPORTED_VENDORS: Final[list[str]] = ["cisco", "juniper", "cisco-nxos", "cisco-iosxe"]

# Deployment strategies
DEPLOYMENT_STRATEGIES: Final[list[str]] = ["canary", "rolling", "blue-green", "immediate"]
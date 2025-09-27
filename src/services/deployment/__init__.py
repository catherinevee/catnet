"""
CatNet Deployment Microservice.

Handles configuration deployment, rollback, and validation for network devices.
Runs on port 8083.
"""

from .app import create_app
from .models import (
    Deployment,
    DeploymentRequest,
    DeploymentResponse,
    DeploymentStatus,
    DeploymentStrategy,
    RollbackRequest,
    ApprovalRequest,
    ValidationResult
)
from .strategies import (
    CanaryStrategy,
    RollingStrategy,
    BlueGreenStrategy,
    AllAtOnceStrategy
)
from .validators import (
    ConfigValidator,
    PreDeploymentValidator,
    PostDeploymentValidator
)
from .rollback import RollbackManager

__all__ = [
    'create_app',
    'Deployment',
    'DeploymentRequest',
    'DeploymentResponse',
    'DeploymentStatus',
    'DeploymentStrategy',
    'RollbackRequest',
    'ApprovalRequest',
    'ValidationResult',
    'CanaryStrategy',
    'RollingStrategy',
    'BlueGreenStrategy',
    'AllAtOnceStrategy',
    'ConfigValidator',
    'PreDeploymentValidator',
    'PostDeploymentValidator',
    'RollbackManager',
]

__version__ = '1.0.0'
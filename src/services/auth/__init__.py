"""
CatNet Authentication Microservice.

Handles OAuth2, SAML, MFA, JWT tokens, and user management.
Runs on port 8081.
"""

from .app import create_app
from .models import User, Session, MFAToken
from .handlers import (
    LoginHandler,
    MFAHandler,
    TokenHandler,
    LogoutHandler,
    UserManagementHandler,
)
from .validators import (
    LoginValidator,
    MFAValidator,
    TokenValidator,
)

__all__ = [
    'create_app',
    'User',
    'Session',
    'MFAToken',
    'LoginHandler',
    'MFAHandler',
    'TokenHandler',
    'LogoutHandler',
    'UserManagementHandler',
    'LoginValidator',
    'MFAValidator',
    'TokenValidator',
]

__version__ = '1.0.0'
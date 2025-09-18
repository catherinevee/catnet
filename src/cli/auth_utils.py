"""Authentication utilities for CLI commands."""

import json

import os
from pathlib import Path
from typing import Optional, Dict
from functools import wraps
import click


def get_auth_token() -> Optional[str]:
    """Get authentication token from secure storage."""
    # Check environment variable first
    env_token = os.environ.get("CATNET_AUTH_TOKEN")
    if env_token:
        return env_token

    token_file = Path.home() / ".catnet" / "tokens.json"
    if not token_file.exists():
        return None

    try:
        tokens = json.loads(token_file.read_text())
        return tokens.get("access_token")
    except Exception:
        return None


def require_auth(func):
    """Decorator to require authentication for commands."""

    @wraps(func)
    def wrapper(*args, **kwargs):
        if not get_auth_token():
            click.echo(
                click.style(
                    "✗ Authentication required. Please run 'catnet auth login' first.",
                    fg="red",
                )
            )
            raise click.Abort()
        return func(*args, **kwargs)

    return wrapper


def get_headers() -> Dict[str, str]:
    """Get headers with authentication token."""
    token = get_auth_token()
    if not token:
        return {}

    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }


def secure_prompt(prompt_text: str, password: bool = False) -> str:
    """Secure prompt for sensitive information."""
    return click.prompt(prompt_text, hide_input=password)

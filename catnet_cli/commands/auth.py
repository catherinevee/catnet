"""
Authentication commands for CatNet CLI
"""
import click
import asyncio
import getpass
from typing import Optional
from pathlib import Path
import sys

from catnet_cli.client import CatNetAPIClient, AuthenticationError
from catnet_cli.utils import (
    print_success,
    print_error,
    print_info,
    handle_error,
)


@click.group()
def auth():
    """Authentication commands"""
    pass


@auth.command()
@click.option(
    '--username',
    '-u',
    prompt=True,
    help='Username for authentication'
)
@click.option(
    '--password',
    '-p',
    help='Password (will prompt if not provided)'
)
@click.option(
    '--mfa-token',
    '-m',
    help='MFA token for two-factor authentication'
)
@click.pass_context
def login(
    ctx: click.Context,
    username: str,
    password: Optional[str],
    mfa_token: Optional[str]
):
    """Login to CatNet system with MFA support

    Examples:
        catnet auth login
        catnet auth login --username admin --mfa-token 123456
    """
    config = ctx.obj.get('config', {})
    debug = ctx.obj.get('debug', False)

    # Prompt for password if not provided
    if not password:
        password = getpass.getpass('Password: ')

    # Prompt for MFA if required and not provided
    if config.get('security', {}).get('mfa_required', True) and not mfa_token:
        mfa_token = click.prompt('MFA Token', hide_input=False)

    async def do_login():
        async with CatNetAPIClient(config) as client:
            try:
                result = await client.login(username, password, mfa_token)

                # Save token is handled by client
                print_success(f"Successfully logged in as {username}")

                if 'expires_at' in result:
                    print_info(f"Token expires at: {result['expires_at']}")

                if 'roles' in result:
                    print_info(f"Roles: {', '.join(result['roles'])}")

                return result

            except AuthenticationError as e:
                print_error(str(e))
                if 'MFA' in str(e) or 'token' in str(e).lower():
                    print_info("MFA token may be incorrect or expired")
                sys.exit(2)
            except Exception as e:
                handle_error(e, debug)
                sys.exit(1)

    # Run async function
    loop = asyncio.get_event_loop()
    loop.run_until_complete(do_login())


@auth.command()
@click.pass_context
def logout(ctx: click.Context):
    """Logout from CatNet and clear stored credentials

    This will:
    - Revoke the current access token on the server
    - Clear locally stored credentials
    - Require re-authentication for future commands
    """
    config = ctx.obj.get('config', {})
    debug = ctx.obj.get('debug', False)

    async def do_logout():
        async with CatNetAPIClient(config) as client:
            try:
                result = await client.logout()
                print_success("Successfully logged out")
                return result
            except Exception as e:
                # Even if server logout fails, clear local token
                token_file = Path.home() / '.catnet' / 'tokens.json'
                if token_file.exists():
                    token_file.unlink()
                print_success("Logged out (local)")
                if debug:
                    print_info(f"Server logout failed: {e}")

    loop = asyncio.get_event_loop()
    loop.run_until_complete(do_logout())


@auth.command()
@click.pass_context
def refresh(ctx: click.Context):
    """Refresh authentication token before expiration

    Use this to extend your session without re-entering credentials.
    The refresh token must still be valid for this to work.
    """
    config = ctx.obj.get('config', {})
    debug = ctx.obj.get('debug', False)

    async def do_refresh():
        async with CatNetAPIClient(config) as client:
            try:
                if not client.token:
                    print_error("Not logged in. Please login first.")
                    sys.exit(2)

                result = await client.refresh_token()
                print_success("Token refreshed successfully")

                if 'expires_at' in result:
                    print_info(f"New token expires at: {result['expires_at']}")

                return result

            except AuthenticationError as e:
                print_error(str(e))
                print_info("Please login again")
                sys.exit(2)
            except Exception as e:
                handle_error(e, debug)
                sys.exit(1)

    loop = asyncio.get_event_loop()
    loop.run_until_complete(do_refresh())


@auth.command()
@click.pass_context
def whoami(ctx: click.Context):
    """Display current user information

    Shows:
    - Username
    - Roles and permissions
    - Token expiration
    - Session information
    """
    config = ctx.obj.get('config', {})
    debug = ctx.obj.get('debug', False)

    async def get_user_info():
        async with CatNetAPIClient(config) as client:
            try:
                if not client.token:
                    print_error("Not logged in")
                    sys.exit(2)

                # Get user info from API
                                result = await client.request(
                    'GET',
                    '/auth/me',
                    service='auth'
                )

                # Display user information
                click.echo("\n=== Current User ===")
                click.echo(f"Username: {result.get('username', 'Unknown')}")
                click.echo(f"Email: {result.get('email', 'N/A')}")
                click.echo(f"Roles: {', '.join(result.get('roles', []))}")

                if 'permissions' in result:
                                        click.echo(
                        f"Permissions: {',
                        '.join(result['permissions'])}"
                    )

                if 'last_login' in result:
                    click.echo(f"Last Login: {result['last_login']}")

                if 'mfa_enabled' in result:
                    mfa_status = "Enabled" if result['mfa_enabled'] else \
                        "Disabled"
                    click.echo(f"MFA: {mfa_status}")

                click.echo("")
                return result

            except AuthenticationError:
                print_error("Authentication expired. Please login again.")
                sys.exit(2)
            except Exception as e:
                handle_error(e, debug)
                sys.exit(1)

    loop = asyncio.get_event_loop()
    loop.run_until_complete(get_user_info())


@auth.command()
@click.option('--enable/--disable', default=True, help='Enable or disable MFA')
@click.pass_context

def mfa(ctx: click.Context, enable: bool):
    """Configure multi-factor authentication

    Enable or disable MFA for your account.
    When enabling, you'll receive a QR code to scan with your authenticator \
        app.
    """
    config = ctx.obj.get('config', {})
    debug = ctx.obj.get('debug', False)

    async def configure_mfa():
        async with CatNetAPIClient(config) as client:
            try:
                if not client.token:
                    print_error("Not logged in. Please login first.")
                    sys.exit(2)

                endpoint = '/auth/mfa/enable' if enable else \
                    '/auth/mfa/disable'
                result = await client.request('POST', endpoint, service='auth')

                if enable:
                    print_success("MFA enabled successfully")
                    if 'qr_code' in result:
                        click.echo("\nScan this QR code with your \
                            authenticator app:")
                        click.echo(result['qr_code'])
                    if 'secret' in result:
                        click.echo(f"\nManual entry code: {result['secret']}")
                    print_info("\nSave backup codes in a secure location:")
                    for code in result.get('backup_codes', []):
                        click.echo(f"  - {code}")
                else:
                    print_success("MFA disabled successfully")
                    print_info("Your account is now less secure. Consider \
                        re-enabling MFA.")

                return result

            except AuthenticationError as e:
                print_error(str(e))
                sys.exit(2)
            except Exception as e:
                handle_error(e, debug)
                sys.exit(1)

    loop = asyncio.get_event_loop()
    loop.run_until_complete(configure_mfa())

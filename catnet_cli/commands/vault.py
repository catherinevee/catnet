"""
Vault/secrets management commands for CatNet CLI
"""
import click
import asyncio
import sys
import json
from typing import Optional, List
from pathlib import Path

from catnet_cli.client import CatNetAPIClient, AuthenticationError
from catnet_cli.utils import (
    print_success, print_error, print_info, print_warning,
    handle_error, format_table, confirm_action
)


@click.group()
def vault():
    """Secrets and credentials management via HashiCorp Vault"""
    pass


@vault.command('store')
@click.option('--path', '-p', required=True, help='Vault path for the secret')
@click.option('--key', '-k', required=True, help='Secret key name')
@click.option('--value', '-v', help='Secret value (will prompt if not provided)')
@click.option('--file', '-f', type=click.Path(exists=True), help='Read value from file')
@click.option('--ttl', type=int, help='TTL for temporary credentials (seconds)')
@click.pass_context
def store_secret(
    ctx: click.Context,
    path: str,
    key: str,
    value: Optional[str],
    file: Optional[str],
    ttl: Optional[int]
):
    """Store a secret in Vault

    Examples:
        catnet vault store --path devices/router1 --key password
        catnet vault store -p api/keys -k api_key --file api_key.txt
        catnet vault store -p temp/creds -k token --value abc123 --ttl 3600
    """
    config = ctx.obj.get('config', {})
    debug = ctx.obj.get('debug', False)

    # Get value from file or prompt
    if file:
        with open(file, 'r') as f:
            value = f.read().strip()
    elif not value:
        value = click.prompt('Secret value', hide_input=True)

    async def store():
        async with CatNetAPIClient(config) as client:
            try:
                secret_data = {
                    'path': path,
                    'key': key,
                    'value': value
                }

                if ttl:
                    secret_data['ttl'] = ttl

                result = await client.store_secret(secret_data)

                print_success(f"Secret stored successfully at {path}/{key}")

                if 'version' in result:
                    print_info(f"Version: {result['version']}")

                if ttl:
                    print_info(f"TTL: {ttl} seconds")

                return result

            except AuthenticationError:
                print_error("Authentication required. Please login first.")
                sys.exit(2)
            except Exception as e:
                handle_error(e, debug)
                sys.exit(1)

    loop = asyncio.get_event_loop()
    loop.run_until_complete(store())


@vault.command('get')
@click.argument('path')
@click.option('--key', '-k', help='Specific key to retrieve')
@click.option('--version', '-v', type=int, help='Specific version to retrieve')
@click.option('--output', '-o', type=click.Path(), help='Save to file')
@click.pass_context
def get_secret(
    ctx: click.Context,
    path: str,
    key: Optional[str],
    version: Optional[int],
    output: Optional[str]
):
    """Retrieve a secret from Vault

    Examples:
        catnet vault get devices/router1
        catnet vault get devices/router1 --key password
        catnet vault get api/keys -k api_key --output api_key.txt
        catnet vault get devices/router1 --version 2
    """
    config = ctx.obj.get('config', {})
    debug = ctx.obj.get('debug', False)

    async def retrieve():
        async with CatNetAPIClient(config) as client:
            try:
                result = await client.get_secret(path, key=key, version=version)

                if key:
                    # Show specific key
                    value = result.get(key, '')
                    if output:
                        with open(output, 'w') as f:
                            f.write(value)
                        print_success(f"Secret saved to {output}")
                    else:
                        click.echo(value)
                else:
                    # Show all keys
                    click.echo("\n=== Secret Data ===")
                    for k, v in result.items():
                        if k not in ['metadata', 'lease_duration']:
                            # Mask sensitive values in display
                            masked_value = v[:3] + '*' * (len(v) - 3) if len(v) > 3 else '*' * len(v)
                            click.echo(f"{k}: {masked_value}")

                    if output:
                        with open(output, 'w') as f:
                            json.dump(result, f, indent=2)
                        print_success(f"Secrets saved to {output}")

                return result

            except AuthenticationError:
                print_error("Authentication required. Please login first.")
                sys.exit(2)
            except Exception as e:
                handle_error(e, debug)
                sys.exit(1)

    loop = asyncio.get_event_loop()
    loop.run_until_complete(retrieve())


@vault.command('rotate')
@click.argument('path')
@click.option('--auto-update/--no-auto-update', default=True, help='Update devices with new credentials')
@click.option('--force', is_flag=True, help='Skip confirmation')
@click.pass_context
def rotate_credentials(ctx: click.Context, path: str, auto_update: bool, force: bool):
    """Rotate credentials stored in Vault

    This will:
    - Generate new credentials
    - Update Vault with new values
    - Optionally update affected devices
    - Keep previous version for rollback

    Examples:
        catnet vault rotate devices/router1
        catnet vault rotate devices/all --no-auto-update
        catnet vault rotate api/keys --force
    """
    config = ctx.obj.get('config', {})
    debug = ctx.obj.get('debug', False)

    if not force:
        if not confirm_action(f"Rotate credentials at '{path}'?"):
            print_info("Rotation cancelled")
            return

    async def rotate():
        async with CatNetAPIClient(config) as client:
            try:
                print_info(f"Rotating credentials at {path}...")

                result = await client.rotate_credentials(
                    path=path,
                    auto_update=auto_update
                )

                print_success("Credentials rotated successfully")

                new_version = result.get('new_version')
                old_version = result.get('old_version')

                print_info(f"New version: {new_version}")
                print_info(f"Previous version: {old_version} (kept for rollback)")

                if auto_update:
                    updated_devices = result.get('updated_devices', [])
                    if updated_devices:
                        click.echo("\n=== Updated Devices ===")
                        for device in updated_devices:
                            print_success(f"  ✓ {device}")

                return result

            except AuthenticationError:
                print_error("Authentication required. Please login first.")
                sys.exit(2)
            except Exception as e:
                handle_error(e, debug)
                sys.exit(1)

    loop = asyncio.get_event_loop()
    loop.run_until_complete(rotate())


@vault.command('list')
@click.option('--path', '-p', default='/', help='Path to list secrets from')
@click.option('--recursive', '-r', is_flag=True, help='List recursively')
@click.pass_context
def list_secrets(ctx: click.Context, path: str, recursive: bool):
    """List secrets stored in Vault

    Examples:
        catnet vault list
        catnet vault list --path devices/
        catnet vault list -p api/ --recursive
    """
    config = ctx.obj.get('config', {})
    debug = ctx.obj.get('debug', False)

    async def list_vault():
        async with CatNetAPIClient(config) as client:
            try:
                secrets = await client.list_secrets(path, recursive=recursive)

                if not secrets:
                    print_info(f"No secrets found at {path}")
                    return

                click.echo(f"\n=== Secrets at {path} ===")

                headers = ['Path', 'Type', 'Version', 'Last Modified']
                rows = []

                for secret in secrets:
                    rows.append([
                        secret.get('path', ''),
                        secret.get('type', 'kv'),
                        str(secret.get('version', 1)),
                        secret.get('modified', 'Unknown')
                    ])

                click.echo(format_table(headers, rows))
                click.echo(f"\nTotal secrets: {len(secrets)}")

                return secrets

            except AuthenticationError:
                print_error("Authentication required. Please login first.")
                sys.exit(2)
            except Exception as e:
                handle_error(e, debug)
                sys.exit(1)

    loop = asyncio.get_event_loop()
    loop.run_until_complete(list_vault())


@vault.command('delete')
@click.argument('path')
@click.option('--version', '-v', type=int, help='Delete specific version only')
@click.option('--force', is_flag=True, help='Skip confirmation')
@click.pass_context
def delete_secret(ctx: click.Context, path: str, version: Optional[int], force: bool):
    """Delete a secret from Vault

    WARNING: This action cannot be undone unless versioning is enabled.

    Examples:
        catnet vault delete devices/old-router
        catnet vault delete api/deprecated-key --force
        catnet vault delete devices/router1 --version 3
    """
    config = ctx.obj.get('config', {})
    debug = ctx.obj.get('debug', False)

    if not force:
        warning_msg = f"Delete secret at '{path}'"
        if version:
            warning_msg += f" (version {version})"
        warning_msg += "? This cannot be undone."

        if not confirm_action(warning_msg):
            print_info("Deletion cancelled")
            return

    async def delete():
        async with CatNetAPIClient(config) as client:
            try:
                result = await client.delete_secret(path, version=version)

                if version:
                    print_success(f"Version {version} of secret at '{path}' deleted")
                else:
                    print_success(f"Secret at '{path}' deleted successfully")

                return result

            except AuthenticationError:
                print_error("Authentication required. Please login first.")
                sys.exit(2)
            except Exception as e:
                handle_error(e, debug)
                sys.exit(1)

    loop = asyncio.get_event_loop()
    loop.run_until_complete(delete())


@vault.command('policy')
@click.option('--action', type=click.Choice(['list', 'show', 'update']), default='list', help='Policy action')
@click.option('--name', '-n', help='Policy name')
@click.option('--file', '-f', type=click.Path(exists=True), help='Policy file for update')
@click.pass_context
def manage_policies(ctx: click.Context, action: str, name: Optional[str], file: Optional[str]):
    """Manage Vault access policies

    Examples:
        catnet vault policy --action list
        catnet vault policy --action show --name deployment-policy
        catnet vault policy --action update --name new-policy --file policy.hcl
    """
    config = ctx.obj.get('config', {})
    debug = ctx.obj.get('debug', False)

    async def manage():
        async with CatNetAPIClient(config) as client:
            try:
                if action == 'list':
                    policies = await client.list_vault_policies()

                    if not policies:
                        print_info("No policies found")
                        return

                    click.echo("\n=== Vault Policies ===")
                    for policy in policies:
                        click.echo(f"  - {policy}")

                elif action == 'show':
                    if not name:
                        print_error("Policy name required for show action")
                        sys.exit(1)

                    policy_content = await client.get_vault_policy(name)
                    click.echo(f"\n=== Policy: {name} ===")
                    click.echo(policy_content)

                elif action == 'update':
                    if not name or not file:
                        print_error("Both policy name and file required for update")
                        sys.exit(1)

                    with open(file, 'r') as f:
                        policy_content = f.read()

                    await client.update_vault_policy(name, policy_content)
                    print_success(f"Policy '{name}' updated successfully")

            except AuthenticationError:
                print_error("Authentication required. Please login first.")
                sys.exit(2)
            except Exception as e:
                handle_error(e, debug)
                sys.exit(1)

    loop = asyncio.get_event_loop()
    loop.run_until_complete(manage())


@vault.command('audit')
@click.option('--path', '-p', help='Filter audit logs by path')
@click.option('--days', '-d', type=int, default=7, help='Number of days to look back')
@click.option('--limit', '-l', type=int, default=50, help='Maximum number of entries')
@click.pass_context
def view_audit_logs(ctx: click.Context, path: Optional[str], days: int, limit: int):
    """View Vault audit logs for secret access

    Examples:
        catnet vault audit
        catnet vault audit --path devices/ --days 30
        catnet vault audit -p api/keys -l 100
    """
    config = ctx.obj.get('config', {})
    debug = ctx.obj.get('debug', False)

    async def get_audit():
        async with CatNetAPIClient(config) as client:
            try:
                logs = await client.get_vault_audit_logs(
                    path=path,
                    days=days,
                    limit=limit
                )

                if not logs:
                    print_info("No audit logs found")
                    return

                click.echo(f"\n=== Vault Audit Logs (Last {days} days) ===")

                headers = ['Timestamp', 'User', 'Action', 'Path', 'Result']
                rows = []

                for log in logs[:limit]:
                    rows.append([
                        log.get('timestamp', ''),
                        log.get('user', 'Unknown'),
                        log.get('action', ''),
                        log.get('path', '')[:30],  # Truncate long paths
                        log.get('result', '')
                    ])

                click.echo(format_table(headers, rows))

                if len(logs) > limit:
                    print_info(f"\nShowing {limit} of {len(logs)} entries")

                return logs

            except AuthenticationError:
                print_error("Authentication required. Please login first.")
                sys.exit(2)
            except Exception as e:
                handle_error(e, debug)
                sys.exit(1)

    loop = asyncio.get_event_loop()
    loop.run_until_complete(get_audit())
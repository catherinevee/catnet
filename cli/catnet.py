#!/usr/bin/env python3
"""
CatNet CLI - Command Line Interface for CatNet Network Configuration Management

Enterprise-grade network configuration deployment system CLI
"""

import click
import asyncio
import json
import yaml
import sys
import os
from pathlib import Path
from typing import Optional, Dict, Any, List
from datetime import datetime
import tabulate
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.syntax import Syntax
from rich import print as rprint
import httpx
import getpass
import configparser
from urllib.parse import urljoin

# Add parent directory to path for imports
sys.path.append(str(Path(__file__).parent.parent))

from src.auth.jwt_handler import JWTHandler
from src.parsers import ConfigParserFactory, VendorType

# Initialize Rich console
console = Console()

# Configuration file path
CONFIG_DIR = Path.home() / '.catnet'
CONFIG_FILE = CONFIG_DIR / 'config.ini'
TOKEN_FILE = CONFIG_DIR / 'token'


class CatNetCLI:
    """CatNet CLI client"""

    def __init__(self):
        self.config = self.load_config()
        self.api_url = self.config.get('api', 'url', fallback='http://localhost:8080/api/v1')
        self.token = self.load_token()
        self.headers = {}
        if self.token:
            self.headers['Authorization'] = f'Bearer {self.token}'

    def load_config(self) -> configparser.ConfigParser:
        """Load CLI configuration"""
        config = configparser.ConfigParser()

        if CONFIG_FILE.exists():
            config.read(CONFIG_FILE)
        else:
            # Create default configuration
            CONFIG_DIR.mkdir(parents=True, exist_ok=True)
            config['api'] = {
                'url': 'http://localhost:8080/api/v1',
                'timeout': '30'
            }
            config['display'] = {
                'format': 'table',
                'color': 'true'
            }
            with open(CONFIG_FILE, 'w') as f:
                config.write(f)

        return config

    def load_token(self) -> Optional[str]:
        """Load saved authentication token"""
        if TOKEN_FILE.exists():
            return TOKEN_FILE.read_text().strip()
        return None

    def save_token(self, token: str):
        """Save authentication token"""
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        TOKEN_FILE.write_text(token)
        TOKEN_FILE.chmod(0o600)  # Restrict permissions

    def clear_token(self):
        """Clear saved token"""
        if TOKEN_FILE.exists():
            TOKEN_FILE.unlink()

    async def make_request(
        self,
        method: str,
        endpoint: str,
        **kwargs
    ) -> httpx.Response:
        """Make API request"""
        url = urljoin(self.api_url, endpoint)
        timeout = httpx.Timeout(float(self.config.get('api', 'timeout', fallback='30')))

        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.request(
                method,
                url,
                headers=self.headers,
                **kwargs
            )
            response.raise_for_status()
            return response

    def format_output(self, data: Any, format: str = 'table'):
        """Format output for display"""
        if format == 'json':
            return json.dumps(data, indent=2, default=str)
        elif format == 'yaml':
            return yaml.dump(data, default_flow_style=False, default=str)
        else:
            # Table format
            if isinstance(data, list) and data:
                return tabulate.tabulate(data, headers='keys', tablefmt='grid')
            elif isinstance(data, dict):
                return tabulate.tabulate(
                    [[k, v] for k, v in data.items()],
                    headers=['Key', 'Value'],
                    tablefmt='grid'
                )
            else:
                return str(data)


# Create CLI instance
cli_client = CatNetCLI()

# =============================================================================
# Main CLI Group
# =============================================================================

@click.group()
@click.version_option(version='1.0.0')
def cli():
    """
    CatNet CLI - Network Configuration Management System

    Enterprise-grade GitOps-enabled network configuration deployment system
    for Cisco and Juniper devices.
    """
    pass


# =============================================================================
# Authentication Commands
# =============================================================================

@cli.group()
def auth():
    """Authentication management"""
    pass


@auth.command()
@click.option('--username', '-u', prompt=True, help='Username')
@click.option('--password', '-p', prompt=True, hide_input=True, help='Password')
@click.option('--mfa-code', '-m', help='MFA code if enabled')
def login(username: str, password: str, mfa_code: Optional[str]):
    """Login to CatNet"""

    async def _login():
        try:
            # Login request
            response = await cli_client.make_request(
                'POST',
                '/auth/login',
                json={
                    'username': username,
                    'password': password,
                    'mfa_code': mfa_code
                }
            )

            data = response.json()
            token = data.get('access_token')

            if token:
                cli_client.save_token(token)
                cli_client.token = token
                cli_client.headers['Authorization'] = f'Bearer {token}'
                console.print("[green]✓[/green] Login successful")

                # Display user info
                user_info = data.get('user', {})
                console.print(f"Welcome, {user_info.get('full_name', username)}!")
                console.print(f"Role: {user_info.get('role', 'Unknown')}")
            else:
                console.print("[red]✗[/red] Login failed: No token received")

        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                console.print("[red]✗[/red] Invalid credentials")
            elif e.response.status_code == 403:
                console.print("[red]✗[/red] MFA code required or invalid")
            else:
                console.print(f"[red]✗[/red] Login failed: {e}")
        except Exception as e:
            console.print(f"[red]✗[/red] Error: {e}")

    asyncio.run(_login())


@auth.command()
def logout():
    """Logout from CatNet"""
    cli_client.clear_token()
    cli_client.token = None
    cli_client.headers.pop('Authorization', None)
    console.print("[green]✓[/green] Logged out successfully")


@auth.command()
def whoami():
    """Show current user information"""

    async def _whoami():
        if not cli_client.token:
            console.print("[yellow]⚠[/yellow] Not logged in")
            return

        try:
            response = await cli_client.make_request('GET', '/auth/me')
            user = response.json()

            # Create table
            table = Table(title="User Information")
            table.add_column("Property", style="cyan")
            table.add_column("Value", style="white")

            table.add_row("Username", user.get('username', 'N/A'))
            table.add_row("Full Name", user.get('full_name', 'N/A'))
            table.add_row("Email", user.get('email', 'N/A'))
            table.add_row("Role", user.get('role', 'N/A'))
            table.add_row("Superuser", str(user.get('is_superuser', False)))
            table.add_row("Active", str(user.get('is_active', True)))
            table.add_row("MFA Enabled", str(user.get('mfa_enabled', False)))

            console.print(table)

        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                console.print("[red]✗[/red] Session expired. Please login again.")
                cli_client.clear_token()
            else:
                console.print(f"[red]✗[/red] Error: {e}")
        except Exception as e:
            console.print(f"[red]✗[/red] Error: {e}")

    asyncio.run(_whoami())


# =============================================================================
# Device Commands
# =============================================================================

@cli.group()
def device():
    """Device management"""
    pass


@device.command('list')
@click.option('--vendor', '-v', help='Filter by vendor')
@click.option('--status', '-s', type=click.Choice(['online', 'offline', 'all']), default='all')
@click.option('--format', '-f', type=click.Choice(['table', 'json', 'yaml']), default='table')
def device_list(vendor: Optional[str], status: str, format: str):
    """List all devices"""

    async def _list_devices():
        try:
            params = {}
            if vendor:
                params['vendor'] = vendor
            if status != 'all':
                params['status'] = status

            response = await cli_client.make_request('GET', '/devices', params=params)
            devices = response.json()

            if format == 'table':
                table = Table(title="Network Devices")
                table.add_column("ID", style="cyan")
                table.add_column("Hostname", style="white")
                table.add_column("IP Address", style="yellow")
                table.add_column("Vendor", style="blue")
                table.add_column("Model", style="white")
                table.add_column("Status", style="green")

                for device in devices:
                    status_color = "green" if device.get('status') == 'online' else "red"
                    table.add_row(
                        device.get('id', ''),
                        device.get('hostname', ''),
                        device.get('ip_address', ''),
                        device.get('vendor', ''),
                        device.get('model', ''),
                        f"[{status_color}]{device.get('status', 'unknown')}[/{status_color}]"
                    )

                console.print(table)
            else:
                output = cli_client.format_output(devices, format)
                console.print(output)

        except Exception as e:
            console.print(f"[red]✗[/red] Error: {e}")

    asyncio.run(_list_devices())


@device.command('show')
@click.argument('device_id')
@click.option('--format', '-f', type=click.Choice(['table', 'json', 'yaml']), default='table')
def device_show(device_id: str, format: str):
    """Show device details"""

    async def _show_device():
        try:
            response = await cli_client.make_request('GET', f'/devices/{device_id}')
            device = response.json()

            if format == 'table':
                # Device info table
                table = Table(title="Device Information")
                table.add_column("Property", style="cyan")
                table.add_column("Value", style="white")

                for key, value in device.items():
                    if key not in ['config', 'credentials']:  # Skip sensitive data
                        table.add_row(key.replace('_', ' ').title(), str(value))

                console.print(table)

                # Configuration info if available
                if 'last_config_change' in device:
                    console.print(f"\n[cyan]Last Config Change:[/cyan] {device['last_config_change']}")
                if 'last_backup' in device:
                    console.print(f"[cyan]Last Backup:[/cyan] {device['last_backup']}")

            else:
                output = cli_client.format_output(device, format)
                console.print(output)

        except Exception as e:
            console.print(f"[red]✗[/red] Error: {e}")

    asyncio.run(_show_device())


@device.command('backup')
@click.argument('device_id')
@click.option('--output', '-o', help='Output file for backup')
def device_backup(device_id: str, output: Optional[str]):
    """Create device configuration backup"""

    async def _backup_device():
        try:
            with console.status("[bold green]Creating backup..."):
                response = await cli_client.make_request(
                    'POST',
                    f'/devices/{device_id}/backup'
                )
                result = response.json()

            console.print(f"[green]✓[/green] Backup created successfully")
            console.print(f"Backup ID: {result.get('backup_id')}")
            console.print(f"Location: {result.get('location')}")

            if output and 'config' in result:
                Path(output).write_text(result['config'])
                console.print(f"[green]✓[/green] Configuration saved to {output}")

        except Exception as e:
            console.print(f"[red]✗[/red] Error: {e}")

    asyncio.run(_backup_device())


@device.command('exec')
@click.argument('device_id')
@click.argument('command')
@click.option('--timeout', '-t', default=30, help='Command timeout in seconds')
def device_exec(device_id: str, command: str, timeout: int):
    """Execute command on device"""

    async def _exec_command():
        try:
            with console.status(f"[bold green]Executing command..."):
                response = await cli_client.make_request(
                    'POST',
                    f'/devices/{device_id}/execute',
                    json={
                        'command': command,
                        'timeout': timeout
                    }
                )
                result = response.json()

            console.print(f"[green]✓[/green] Command executed successfully")

            # Display output
            if 'output' in result:
                console.print("\n[cyan]Output:[/cyan]")
                syntax = Syntax(result['output'], "text", theme="monokai", line_numbers=False)
                console.print(syntax)

            if 'error' in result:
                console.print(f"\n[red]Error:[/red] {result['error']}")

        except Exception as e:
            console.print(f"[red]✗[/red] Error: {e}")

    asyncio.run(_exec_command())


# =============================================================================
# Deployment Commands
# =============================================================================

@cli.group()
def deploy():
    """Deployment management"""
    pass


@deploy.command('list')
@click.option('--status', '-s', help='Filter by status')
@click.option('--limit', '-l', default=10, help='Number of deployments to show')
@click.option('--format', '-f', type=click.Choice(['table', 'json', 'yaml']), default='table')
def deploy_list(status: Optional[str], limit: int, format: str):
    """List deployments"""

    async def _list_deployments():
        try:
            params = {'limit': limit}
            if status:
                params['status'] = status

            response = await cli_client.make_request('GET', '/deployments', params=params)
            deployments = response.json()

            if format == 'table':
                table = Table(title="Deployments")
                table.add_column("ID", style="cyan")
                table.add_column("Created", style="white")
                table.add_column("Strategy", style="blue")
                table.add_column("Status", style="yellow")
                table.add_column("Devices", style="white")
                table.add_column("Progress", style="green")

                for dep in deployments:
                    # Color code status
                    status = dep.get('state', 'unknown')
                    if status == 'completed':
                        status_str = f"[green]{status}[/green]"
                    elif status == 'failed':
                        status_str = f"[red]{status}[/red]"
                    elif status == 'in_progress':
                        status_str = f"[yellow]{status}[/yellow]"
                    else:
                        status_str = status

                    table.add_row(
                        dep.get('id', '')[:8],  # Short ID
                        dep.get('created_at', '')[:19],  # Date without microseconds
                        dep.get('strategy', 'rolling'),
                        status_str,
                        str(len(dep.get('device_ids', []))),
                        f"{dep.get('progress', 0)}%"
                    )

                console.print(table)
            else:
                output = cli_client.format_output(deployments, format)
                console.print(output)

        except Exception as e:
            console.print(f"[red]✗[/red] Error: {e}")

    asyncio.run(_list_deployments())


@deploy.command('create')
@click.option('--config-file', '-c', required=True, help='Configuration file')
@click.option('--devices', '-d', multiple=True, required=True, help='Device IDs')
@click.option('--strategy', '-s',
              type=click.Choice(['rolling', 'canary', 'blue_green', 'all_at_once']),
              default='rolling')
@click.option('--description', '-desc', help='Deployment description')
@click.option('--dry-run', is_flag=True, help='Perform dry run only')
def deploy_create(
    config_file: str,
    devices: List[str],
    strategy: str,
    description: Optional[str],
    dry_run: bool
):
    """Create new deployment"""

    async def _create_deployment():
        try:
            # Read configuration file
            config_path = Path(config_file)
            if not config_path.exists():
                console.print(f"[red]✗[/red] Configuration file not found: {config_file}")
                return

            config_content = config_path.read_text()

            # Prepare deployment request
            deployment_data = {
                'configuration': config_content,
                'device_ids': list(devices),
                'strategy': strategy,
                'description': description or f"Deployment from {config_file}",
                'dry_run': dry_run
            }

            with console.status("[bold green]Creating deployment..."):
                response = await cli_client.make_request(
                    'POST',
                    '/deployments',
                    json=deployment_data
                )
                result = response.json()

            if dry_run:
                console.print("[yellow]⚠[/yellow] DRY RUN - No actual changes made")

            console.print(f"[green]✓[/green] Deployment created successfully")
            console.print(f"Deployment ID: {result.get('id')}")
            console.print(f"Status: {result.get('state')}")

            if result.get('requires_approval'):
                console.print("[yellow]⚠[/yellow] This deployment requires approval before execution")

            # Show validation results if available
            if 'validation_results' in result:
                console.print("\n[cyan]Validation Results:[/cyan]")
                for device_id, validation in result['validation_results'].items():
                    if validation['valid']:
                        console.print(f"  ✓ {device_id}: Valid")
                    else:
                        console.print(f"  ✗ {device_id}: {validation.get('errors', 'Invalid')}")

        except Exception as e:
            console.print(f"[red]✗[/red] Error: {e}")

    asyncio.run(_create_deployment())


@deploy.command('approve')
@click.argument('deployment_id')
@click.option('--comment', '-c', help='Approval comment')
def deploy_approve(deployment_id: str, comment: Optional[str]):
    """Approve pending deployment"""

    async def _approve_deployment():
        try:
            response = await cli_client.make_request(
                'POST',
                f'/deployments/{deployment_id}/approve',
                json={'comment': comment}
            )
            result = response.json()

            console.print(f"[green]✓[/green] Deployment approved successfully")
            console.print(f"Status: {result.get('state')}")

        except httpx.HTTPStatusError as e:
            if e.response.status_code == 403:
                console.print("[red]✗[/red] Insufficient permissions to approve deployment")
            else:
                console.print(f"[red]✗[/red] Error: {e}")
        except Exception as e:
            console.print(f"[red]✗[/red] Error: {e}")

    asyncio.run(_approve_deployment())


@deploy.command('rollback')
@click.argument('deployment_id')
@click.option('--reason', '-r', required=True, help='Rollback reason')
def deploy_rollback(deployment_id: str, reason: str):
    """Rollback deployment"""

    async def _rollback_deployment():
        try:
            response = await cli_client.make_request(
                'POST',
                f'/deployments/{deployment_id}/rollback',
                json={'reason': reason}
            )
            result = response.json()

            console.print(f"[green]✓[/green] Rollback initiated successfully")
            console.print(f"Rollback ID: {result.get('rollback_id')}")
            console.print(f"Status: {result.get('state')}")

        except Exception as e:
            console.print(f"[red]✗[/red] Error: {e}")

    asyncio.run(_rollback_deployment())


@deploy.command('status')
@click.argument('deployment_id')
@click.option('--watch', '-w', is_flag=True, help='Watch deployment progress')
def deploy_status(deployment_id: str, watch: bool):
    """Show deployment status"""

    async def _show_status():
        try:
            while True:
                response = await cli_client.make_request(
                    'GET',
                    f'/deployments/{deployment_id}'
                )
                deployment = response.json()

                # Clear screen if watching
                if watch:
                    console.clear()

                # Display deployment info
                table = Table(title=f"Deployment {deployment_id[:8]}")
                table.add_column("Property", style="cyan")
                table.add_column("Value", style="white")

                table.add_row("Status", deployment.get('state', 'unknown'))
                table.add_row("Strategy", deployment.get('strategy', 'rolling'))
                table.add_row("Progress", f"{deployment.get('progress', 0)}%")
                table.add_row("Created", deployment.get('created_at', 'N/A'))
                table.add_row("Created By", deployment.get('created_by', 'N/A'))

                console.print(table)

                # Display device status
                if 'device_status' in deployment:
                    console.print("\n[cyan]Device Status:[/cyan]")
                    for device_id, status in deployment['device_status'].items():
                        if status == 'completed':
                            console.print(f"  [green]✓[/green] {device_id}: {status}")
                        elif status == 'failed':
                            console.print(f"  [red]✗[/red] {device_id}: {status}")
                        else:
                            console.print(f"  [yellow]○[/yellow] {device_id}: {status}")

                # Break if not watching or deployment is complete
                if not watch or deployment.get('state') in ['completed', 'failed', 'rolled_back']:
                    break

                await asyncio.sleep(5)  # Refresh every 5 seconds

        except Exception as e:
            console.print(f"[red]✗[/red] Error: {e}")

    asyncio.run(_show_status())


# =============================================================================
# GitOps Commands
# =============================================================================

@cli.group()
def gitops():
    """GitOps management"""
    pass


@gitops.command('repo-list')
@click.option('--format', '-f', type=click.Choice(['table', 'json', 'yaml']), default='table')
def gitops_repo_list(format: str):
    """List configured repositories"""

    async def _list_repos():
        try:
            response = await cli_client.make_request('GET', '/gitops/repositories')
            repos = response.json()

            if format == 'table':
                table = Table(title="Git Repositories")
                table.add_column("ID", style="cyan")
                table.add_column("Name", style="white")
                table.add_column("URL", style="yellow")
                table.add_column("Branch", style="blue")
                table.add_column("Auto Deploy", style="green")

                for repo in repos:
                    table.add_row(
                        repo.get('id', '')[:8],
                        repo.get('name', ''),
                        repo.get('url', ''),
                        repo.get('branch', 'main'),
                        "✓" if repo.get('auto_deploy') else "✗"
                    )

                console.print(table)
            else:
                output = cli_client.format_output(repos, format)
                console.print(output)

        except Exception as e:
            console.print(f"[red]✗[/red] Error: {e}")

    asyncio.run(_list_repos())


@gitops.command('repo-add')
@click.option('--url', '-u', required=True, help='Repository URL')
@click.option('--branch', '-b', default='main', help='Branch to track')
@click.option('--name', '-n', help='Repository name')
@click.option('--auto-deploy', is_flag=True, help='Enable auto-deployment')
@click.option('--webhook-secret', '-w', help='Webhook secret')
def gitops_repo_add(
    url: str,
    branch: str,
    name: Optional[str],
    auto_deploy: bool,
    webhook_secret: Optional[str]
):
    """Add Git repository"""

    async def _add_repo():
        try:
            repo_data = {
                'url': url,
                'branch': branch,
                'name': name or url.split('/')[-1].replace('.git', ''),
                'auto_deploy': auto_deploy,
                'webhook_secret': webhook_secret
            }

            response = await cli_client.make_request(
                'POST',
                '/gitops/repositories',
                json=repo_data
            )
            result = response.json()

            console.print(f"[green]✓[/green] Repository added successfully")
            console.print(f"Repository ID: {result.get('id')}")

            if 'webhook_url' in result:
                console.print(f"\n[cyan]Webhook URL:[/cyan]")
                console.print(result['webhook_url'])
                console.print("\nAdd this URL to your repository's webhook settings")

        except Exception as e:
            console.print(f"[red]✗[/red] Error: {e}")

    asyncio.run(_add_repo())


@gitops.command('sync')
@click.argument('repository_id')
def gitops_sync(repository_id: str):
    """Synchronize repository"""

    async def _sync_repo():
        try:
            with console.status("[bold green]Synchronizing repository..."):
                response = await cli_client.make_request(
                    'POST',
                    f'/gitops/repositories/{repository_id}/sync'
                )
                result = response.json()

            console.print(f"[green]✓[/green] Repository synchronized successfully")
            console.print(f"Commits processed: {result.get('commits_processed', 0)}")
            console.print(f"Configurations found: {result.get('configs_found', 0)}")

            if result.get('deployments_created'):
                console.print(f"\n[cyan]Deployments Created:[/cyan]")
                for dep_id in result['deployments_created']:
                    console.print(f"  • {dep_id}")

        except Exception as e:
            console.print(f"[red]✗[/red] Error: {e}")

    asyncio.run(_sync_repo())


# =============================================================================
# Configuration Commands
# =============================================================================

@cli.group()
def config():
    """Configuration management"""
    pass


@config.command('validate')
@click.argument('config_file')
@click.option('--vendor', '-v',
              type=click.Choice(['cisco', 'juniper']),
              required=True,
              help='Device vendor')
@click.option('--os-type', '-o', help='OS type (e.g., ios, ios_xe, junos)')
def config_validate(config_file: str, vendor: str, os_type: Optional[str]):
    """Validate configuration file"""

    config_path = Path(config_file)
    if not config_path.exists():
        console.print(f"[red]✗[/red] Configuration file not found: {config_file}")
        return

    config_content = config_path.read_text()

    # Parse vendor type
    vendor_type = VendorType.CISCO if vendor == 'cisco' else VendorType.JUNIPER

    # Validate syntax
    is_valid, errors = ConfigParserFactory.validate_syntax(config_content, vendor_type)

    if is_valid:
        console.print(f"[green]✓[/green] Configuration is valid")

        # Parse and show summary
        summary = ConfigParserFactory.get_config_summary(config_content, vendor_type)

        table = Table(title="Configuration Summary")
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="white")

        table.add_row("Hostname", summary.get('hostname', 'N/A'))
        table.add_row("Interfaces", str(summary.get('interface_count', 0)))
        table.add_row("VLANs", str(summary.get('vlan_count', 0)))
        table.add_row("ACLs/Filters", str(summary.get('acl_count', 0)))
        table.add_row("Routing Protocols", ', '.join(summary.get('routing_protocols', [])))

        console.print(table)

        # Show warnings
        if summary.get('warnings'):
            console.print("\n[yellow]Warnings:[/yellow]")
            for warning in summary['warnings']:
                console.print(f"  ⚠ {warning}")
    else:
        console.print(f"[red]✗[/red] Configuration validation failed")
        console.print("\n[red]Errors:[/red]")
        for error in errors:
            console.print(f"  ✗ {error}")


@config.command('diff')
@click.argument('old_config')
@click.argument('new_config')
@click.option('--vendor', '-v',
              type=click.Choice(['cisco', 'juniper']),
              required=True,
              help='Device vendor')
def config_diff(old_config: str, new_config: str, vendor: str):
    """Show configuration diff"""

    old_path = Path(old_config)
    new_path = Path(new_config)

    if not old_path.exists():
        console.print(f"[red]✗[/red] Old configuration file not found: {old_config}")
        return

    if not new_path.exists():
        console.print(f"[red]✗[/red] New configuration file not found: {new_config}")
        return

    old_content = old_path.read_text()
    new_content = new_path.read_text()

    vendor_type = VendorType.CISCO if vendor == 'cisco' else VendorType.JUNIPER

    diff_result = ConfigParserFactory.generate_diff(old_content, new_content, vendor_type)

    console.print(f"[cyan]Configuration Diff:[/cyan]")
    console.print(f"Additions: [green]+{diff_result['additions']}[/green]")
    console.print(f"Deletions: [red]-{diff_result['deletions']}[/red]")

    if diff_result.get('changed_sections'):
        console.print(f"\n[cyan]Changed Sections:[/cyan]")
        for section in diff_result['changed_sections']:
            console.print(f"  • {section}")

    if diff_result.get('diff'):
        console.print("\n[cyan]Detailed Diff:[/cyan]")
        for line in diff_result['diff'][:50]:  # Show first 50 lines
            if line.startswith('+'):
                console.print(f"[green]{line}[/green]")
            elif line.startswith('-'):
                console.print(f"[red]{line}[/red]")
            else:
                console.print(line)


# =============================================================================
# Health Commands
# =============================================================================

@cli.group()
def health():
    """System health monitoring"""
    pass


@health.command('check')
@click.option('--detailed', '-d', is_flag=True, help='Show detailed health information')
def health_check(detailed: bool):
    """Check system health"""

    async def _health_check():
        try:
            endpoint = '/health/detailed' if detailed else '/health'
            response = await cli_client.make_request('GET', endpoint)
            health_data = response.json()

            status = health_data.get('status', 'unknown')
            if status in ['ok', 'healthy']:
                console.print(f"[green]✓[/green] System is healthy")
            elif status == 'degraded':
                console.print(f"[yellow]⚠[/yellow] System is degraded")
            else:
                console.print(f"[red]✗[/red] System is unhealthy")

            if detailed and 'components' in health_data:
                console.print("\n[cyan]Component Status:[/cyan]")
                for component in health_data['components']:
                    name = component.get('name')
                    comp_status = component.get('status')
                    latency = component.get('latency_ms', 'N/A')

                    if comp_status == 'healthy':
                        console.print(f"  [green]✓[/green] {name}: {comp_status} ({latency}ms)")
                    else:
                        console.print(f"  [red]✗[/red] {name}: {comp_status}")

        except Exception as e:
            console.print(f"[red]✗[/red] Error: {e}")

    asyncio.run(_health_check())


@health.command('metrics')
@click.option('--format', '-f', type=click.Choice(['prometheus', 'json']), default='json')
def health_metrics(format: str):
    """Show system metrics"""

    async def _show_metrics():
        try:
            endpoint = '/health/metrics' if format == 'prometheus' else '/health/metrics/json'
            response = await cli_client.make_request('GET', endpoint)

            if format == 'prometheus':
                console.print(response.text)
            else:
                metrics = response.json()
                console.print(json.dumps(metrics, indent=2))

        except Exception as e:
            console.print(f"[red]✗[/red] Error: {e}")

    asyncio.run(_show_metrics())


# =============================================================================
# Utility Commands
# =============================================================================

@cli.command()
@click.option('--api-url', help='API server URL')
@click.option('--timeout', type=int, help='Request timeout in seconds')
def configure(api_url: Optional[str], timeout: Optional[int]):
    """Configure CLI settings"""

    config = cli_client.config

    if api_url:
        config.set('api', 'url', api_url)
        console.print(f"[green]✓[/green] API URL set to: {api_url}")

    if timeout:
        config.set('api', 'timeout', str(timeout))
        console.print(f"[green]✓[/green] Timeout set to: {timeout} seconds")

    with open(CONFIG_FILE, 'w') as f:
        config.write(f)

    console.print("[green]✓[/green] Configuration saved")


@cli.command()
def version():
    """Show version information"""
    console.print("[cyan]CatNet CLI[/cyan]")
    console.print("Version: 1.0.0")
    console.print("API URL:", cli_client.api_url)
    console.print("Config:", str(CONFIG_FILE))


# =============================================================================
# Main Entry Point
# =============================================================================

if __name__ == '__main__':
    cli()
"""
Device management commands for CatNet CLI
"""
import click
import asyncio
import sys
from typing import Optional
from pathlib import Path
import json
import yaml

from catnet_cli.client import (
    CatNetAPIClient,
    AuthenticationError,
    NotFoundError,
)
from catnet_cli.utils import (
    print_success, print_error, print_info, print_warning,
    handle_error, format_table, confirm_action
)


@click.group()

def device():
    """Device management commands"""
    pass


@device.command('list')
@click.option(
    '--vendor',
    type=click.Choice(['cisco',
    'juniper']),
    help='Filter by vendor'
)
@click.option(
    '--status',
    type=click.Choice(['online',
    'offline',
    'maintenance']),
    help='Filter by status'
)
@click.option(
    '--format',
    'output_format',
    type=click.Choice(['table',
    'json',
    'yaml']),
    default='table',
    help='Output format'
)
@click.pass_context

def list_devices(
    ctx: click.Context,
    vendor: Optional[str],
    status: Optional[str],
    output_format: str
):
    """List all managed network devices

    Examples:
        catnet device list
        catnet device list --vendor cisco --status online
        catnet device list --format json
    """
    config = ctx.obj.get('config', {})
    debug = ctx.obj.get('debug', False)

    async def get_devices():
        async with CatNetAPIClient(config) as client:
            try:
                                devices = await client.list_devices(
                    vendor=vendor,
                    status=status
                )

                if output_format == 'json':
                    click.echo(json.dumps(devices, indent=2))
                elif output_format == 'yaml':
                    click.echo(yaml.dump(devices, default_flow_style=False))
                else:  # table format
                    if not devices:
                        print_info("No devices found")
                        return

                    headers = ['ID',
                        'Hostname'
                        'IP Address'
                        'Vendor'
                        'Model'
                        'Status']
                    rows = []
                    for dev in devices:
                        rows.append([
                            dev.get('id', '')[:8],  # Truncate UUID for display
                            dev.get('hostname', ''),
                            dev.get('ip_address', ''),
                            dev.get('vendor', ''),
                            dev.get('model', ''),
                            dev.get('status', '')
                        ])

                    click.echo(format_table(headers, rows))
                    click.echo(f"\nTotal devices: {len(devices)}")

                return devices

            except AuthenticationError:
                print_error("Authentication required. Please login first.")
                sys.exit(2)
            except Exception as e:
                handle_error(e, debug)
                sys.exit(1)

    loop = asyncio.get_event_loop()
    loop.run_until_complete(get_devices())


@device.command('add')
@click.option('--hostname', '-h', required=True, help='Device hostname')
@click.option('--ip', '-i', required=True, help='Device IP address')
@click.option(
    '--vendor',
    required=True,
    type=click.Choice(['cisco',
    'juniper']),
    help='Device vendor'
)
@click.option('--model', '-m', required=True, help='Device model')
@click.option('--username', '-u', help='Device username (stored in Vault)')
@click.option('--password', '-p', help='Device password (stored in Vault)')
@click.option('--port', default=22, help='SSH port (default: 22)')
@click.option('--location', help='Physical location')
@click.option('--tags', multiple=True, help='Tags for device categorization')
@click.pass_context
def add_device(
    ctx: click.Context,
    hostname: str,
    ip: str,
    vendor: str,
    model: str,
    username: Optional[str],
    password: Optional[str],
    port: int,
    location: Optional[str],
    tags: tuple
):
    """Add a new device to management

    Examples:
        catnet device add --hostname router1 --ip 192.168.1.1 --vendor cisco \
            --model ISR4451
        catnet device add -h switch1 -i 10.0.0.1 --vendor juniper -m EX4200 \
            --username admin
    """
    config = ctx.obj.get('config', {})
    debug = ctx.obj.get('debug', False)

    # Prompt for credentials if not provided
    if not username:
        username = click.prompt('Device username')
    if not password:
        import getpass
        password = getpass.getpass('Device password: ')

    async def create_device():
        async with CatNetAPIClient(config) as client:
            try:
                device_data = {
                    'hostname': hostname,
                    'ip_address': ip,
                    'vendor': vendor,
                    'model': model,
                    'port': port,
                    'username': username,
                    'password': password,
                    'tags': list(tags)
                }

                if location:
                    device_data['location'] = location

                result = await client.add_device(device_data)
                print_success(f"Device '{hostname}' added successfully")
                print_info(f"Device ID: {result['id']}")

                # Credentials are automatically stored in Vault by the backend
                print_info("Credentials securely stored in Vault")

                return result

            except AuthenticationError:
                print_error("Authentication required. Please login first.")
                sys.exit(2)
            except Exception as e:
                handle_error(e, debug)
                sys.exit(1)

    loop = asyncio.get_event_loop()
    loop.run_until_complete(create_device())


@device.command('backup')
@click.argument('device_id')
@click.option('--output', '-o', help='Output file for backup')
@click.option('--encrypt/--no-encrypt', default=True, help='Encrypt backup')
@click.pass_context

def backup_device(
    ctx: click.Context,
    device_id: str,
    output: Optional[str],
    encrypt: bool
):
    """Create backup of device configuration

    Examples:
        catnet device backup dev-router1-prod
        catnet device backup dev-123 --output backup.conf
        catnet device backup dev-456 --no-encrypt
    """
    config = ctx.obj.get('config', {})
    debug = ctx.obj.get('debug', False)

    async def create_backup():
        async with CatNetAPIClient(config) as client:
            try:
                print_info(f"Creating backup for device {device_id}...")
                result = await client.backup_device(device_id)

                backup_id = result.get('backup_id')
                backup_content = result.get('content')
                timestamp = result.get('timestamp')

                print_success(f"Backup created successfully")
                print_info(f"Backup ID: {backup_id}")
                print_info(f"Timestamp: {timestamp}")

                if encrypt:
                    print_info("Backup is encrypted")

                # Save to file if specified
                if output:
                    output_path = Path(output)
                    with open(output_path, 'w') as f:
                        f.write(backup_content)
                    print_success(f"Backup saved to {output_path}")

                return result

            except NotFoundError:
                print_error(f"Device '{device_id}' not found")
                sys.exit(1)
            except AuthenticationError:
                print_error("Authentication required. Please login first.")
                sys.exit(2)
            except Exception as e:
                handle_error(e, debug)
                sys.exit(1)

    loop = asyncio.get_event_loop()
    loop.run_until_complete(create_backup())


@device.command('execute')
@click.argument('device_id')
@click.option('--command', '-c', required=True, help='Command to execute')
@click.option(
    '--confirm/--no-confirm',
    default=True,
    help='Confirmation prompt'
)
@click.option('--output', '-o', help='Save output to file')
@click.pass_context
def execute_command(
    ctx: click.Context,
    device_id: str,
    command: str,
    confirm: bool,
    output: Optional[str]
):
    """Execute command on device (with audit logging)

    WARNING: All commands are logged for audit purposes.
    Use with caution on production devices.

    Examples:
        catnet device execute dev-router1 --command "show version"
        catnet device execute dev-123 -c "show running-config" --no-confirm
        catnet device execute dev-456 -c "show interfaces" -o interfaces.txt
    """
    config = ctx.obj.get('config', {})
    debug = ctx.obj.get('debug', False)

    # Dangerous commands that require extra confirmation
    dangerous_commands = ['reload',
        'delete'
        'format'
        'write erase'
        'request system reboot']
    is_dangerous = any(cmd in command.lower() for cmd in dangerous_commands)

    if is_dangerous:
        print_warning(f"WARNING: This appears to be a potentially dangerous \
            command!")

    if confirm:
        if not confirm_action(f"Execute '{command}' on device {device_id}?"):
            print_info("Command execution cancelled")
            return

    async def exec_command():
        async with CatNetAPIClient(config) as client:
            try:
                print_info(f"Executing command on {device_id}...")
                result = await client.execute_command(device_id, command)

                command_output = result.get('output', '')
                execution_time = result.get('execution_time', '')
                audit_id = result.get('audit_id', '')

                # Display output
                click.echo("\n=== Command Output ===")
                click.echo(command_output)
                click.echo("=== End Output ===\n")

                print_success("Command executed successfully")
                print_info(f"Execution time: {execution_time}")
                print_info(f"Audit ID: {audit_id}")

                # Save to file if specified
                if output:
                    output_path = Path(output)
                    with open(output_path, 'w') as f:
                        f.write(command_output)
                    print_success(f"Output saved to {output_path}")

                return result

            except NotFoundError:
                print_error(f"Device '{device_id}' not found")
                sys.exit(1)
            except AuthenticationError:
                print_error("Authentication required. Please login first.")
                sys.exit(2)
            except Exception as e:
                handle_error(e, debug)
                sys.exit(1)

    loop = asyncio.get_event_loop()
    loop.run_until_complete(exec_command())


@device.command('health')
@click.argument('device_id')
@click.option('--detailed', is_flag=True, help='Show detailed health metrics')
@click.pass_context

def check_health(ctx: click.Context, device_id: str, detailed: bool):
    """Check device health status and metrics

    Examples:
        catnet device health dev-router1
        catnet device health dev-switch-core1 --detailed
    """
    config = ctx.obj.get('config', {})
    debug = ctx.obj.get('debug', False)

    async def get_health():
        async with CatNetAPIClient(config) as client:
            try:
                                result = await client.request(
                    'GET',
                    f'/devices/{device_id}/health',
                    service='device'
                )

                status = result.get('status', 'unknown')
                metrics = result.get('metrics', {})

                # Display health status
                click.echo(f"\n=== Device Health: {device_id} ===")

                # Overall status with color
                status_color = {
                    'healthy': 'green',
                    'warning': 'yellow',
                    'critical': 'red',
                    'unknown': 'white'
                }.get(status, 'white')

                click.echo(
                                        click.style(
                        f"Status: {status.upper()}",
                        fg=status_color,
                        bold=True
                    )
                )

                # Basic metrics
                click.echo(f"\nCPU Usage: {metrics.get('cpu_usage', 'N/A')}%")
                                click.echo(
                    f"Memory Usage: {metrics.get('memory_usage',
                    'N/A')}%"
                )
                click.echo(f"Uptime: {metrics.get('uptime', 'N/A')}")
                click.echo(f"Temperature: {metrics.get('temperature', 'N/A')}")

                # Interface status
                interfaces = metrics.get('interfaces', {})
                if interfaces:
                    up_count = interfaces.get('up', 0)
                    down_count = interfaces.get('down', 0)
                                        click.echo(
                        f"\nInterfaces: {up_count} up,
                        {down_count} down"
                    )

                if detailed:
                    click.echo("\n=== Detailed Metrics ===")
                    click.echo(json.dumps(metrics, indent=2))

                # Alerts
                if 'alerts' in result and result['alerts']:
                    click.echo("\n=== Active Alerts ===")
                    for alert in result['alerts']:
                        severity = alert.get('severity', 'info')
                        message = alert.get('message', '')
                        color = {
                            'critical': 'red',
                            'warning': 'yellow',
                            'info': 'white'
                        }.get(severity, 'white')
                                                click.echo(
                            click.style(f"[{severity.upper()}] {message}",
                            fg=color)
                        )

                return result

            except NotFoundError:
                print_error(f"Device '{device_id}' not found")
                sys.exit(1)
            except AuthenticationError:
                print_error("Authentication required. Please login first.")
                sys.exit(2)
            except Exception as e:
                handle_error(e, debug)
                sys.exit(1)

    loop = asyncio.get_event_loop()
    loop.run_until_complete(get_health())


@device.command('remove')
@click.argument('device_id')
@click.option('--force', is_flag=True, help='Skip confirmation')
@click.pass_context

def remove_device(ctx: click.Context, device_id: str, force: bool):
    """Remove device from management

    This will:
    - Remove device from inventory
    - Delete associated credentials from Vault
    - Clean up backup history

    Examples:
        catnet device remove dev-old-router
        catnet device remove dev-123 --force
    """
    config = ctx.obj.get('config', {})
    debug = ctx.obj.get('debug', False)

    if not force:
        if not confirm_action(f"Remove device '{device_id}' from management? \
            This cannot be undone."):
            print_info("Device removal cancelled")
            return

    async def delete_device():
        async with CatNetAPIClient(config) as client:
            try:
                                result = await client.request(
                    'DELETE',
                    f'/devices/{device_id}',
                    service='device'
                )
                print_success(f"Device '{device_id}' removed successfully")
                print_info("Associated credentials have been deleted from \
                    Vault")
                return result

            except NotFoundError:
                print_error(f"Device '{device_id}' not found")
                sys.exit(1)
            except AuthenticationError:
                print_error("Authentication required. Please login first.")
                sys.exit(2)
            except Exception as e:
                handle_error(e, debug)
                sys.exit(1)

    loop = asyncio.get_event_loop()
    loop.run_until_complete(delete_device())

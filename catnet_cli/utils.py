"""
Utility functions for CatNet CLI
"""
import logging
import sys
import click
import asyncio
import aiohttp
from typing import Dict, Any
from datetime import datetime
import json

from catnet_cli import __version__

logger = logging.getLogger(__name__)


def setup_logging(debug: bool = False):
    """Configure logging for CLI"""
    level = logging.DEBUG if debug else logging.INFO

    # Configure root logger
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    # Reduce noise from third-party libraries
    if not debug:
        logging.getLogger('urllib3').setLevel(logging.WARNING)
        logging.getLogger('aiohttp').setLevel(logging.WARNING)


def print_version():
    """Display version information"""
    click.echo(f"CatNet CLI v{__version__}")
    click.echo("Network Configuration Management System")
    click.echo("Copyright (c) 2024 CatNet Team")


async def check_service_health(url: str, service_name: str, timeout: int = 5) -> Dict[str, Any]:
    """Check health of a single service"""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{url}/health", timeout=timeout) as response:
                if response.status == 200:
                    data = await response.json()
                    return {
                        'healthy': True,
                        'message': f"{service_name} is operational",
                        'details': data
                    }
                else:
                    return {
                        'healthy': False,
                        'message': f"{service_name} returned status {response.status}",
                        'details': None
                    }
    except asyncio.TimeoutError:
        return {
            'healthy': False,
            'message': f"{service_name} connection timeout",
            'details': None
        }
    except Exception as e:
        return {
            'healthy': False,
            'message': f"{service_name} connection failed: {str(e)}",
            'details': None
        }


async def check_system_status(config: Dict[str, Any], debug: bool = False) -> Dict[str, Dict[str, Any]]:
    """Check status of all CatNet services"""
    services = {
        'API Gateway': config['api']['base_url'],
        'Authentication Service': config['api']['auth_url'],
        'GitOps Service': config['api']['gitops_url'],
        'Deployment Service': config['api']['deploy_url'],
        'Device Service': config['api']['device_url'],
    }

    # Add Vault if configured
    if vault_url := config.get('vault', {}).get('url'):
        services['Vault'] = vault_url

    # Check all services concurrently
    tasks = [
        check_service_health(url, name)
        for name, url in services.items()
    ]

    results = await asyncio.gather(*tasks, return_exceptions=True)

    # Build status dict
    status = {}
    for (name, _), result in zip(services.items(), results):
        if isinstance(result, Exception):
            status[name] = {
                'healthy': False,
                'message': f"Error: {str(result)}",
                'details': None
            }
        else:
            status[name] = result

    return status


def format_table(headers: list, rows: list) -> str:
    """Format data as ASCII table"""
    if not rows:
        return "No data available"

    # Calculate column widths
    widths = []
    for i, header in enumerate(headers):
        max_width = len(header)
        for row in rows:
            if i < len(row):
                max_width = max(max_width, len(str(row[i])))
        widths.append(max_width)

    # Build separator
    separator = "+" + "+".join(["-" * (w + 2) for w in widths]) + "+"

    # Build header
    header_row = "|"
    for header, width in zip(headers, widths):
        header_row += f" {header:<{width}} |"

    # Build data rows
    data_rows = []
    for row in rows:
        data_row = "|"
        for i, (cell, width) in enumerate(zip(row, widths)):
            data_row += f" {str(cell):<{width}} |"
        data_rows.append(data_row)

    # Combine all parts
    table = [separator, header_row, separator] + data_rows + [separator]
    return "\n".join(table)


def format_json(data: Any, pretty: bool = True) -> str:
    """Format data as JSON"""
    if pretty:
        return json.dumps(data, indent=2, sort_keys=True)
    else:
        return json.dumps(data)


def format_timestamp(timestamp: str) -> str:
    """Format timestamp for display"""
    try:
        dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    except:
        return timestamp


def confirm_action(message: str, default: bool = False) -> bool:
    """Prompt user for confirmation"""
    suffix = " [Y/n]" if default else " [y/N]"
    prompt = message + suffix + ": "

    while True:
        response = click.prompt(prompt, default="", show_default=False).lower()

        if not response:
            return default
        elif response in ['y', 'yes']:
            return True
        elif response in ['n', 'no']:
            return False
        else:
            click.echo("Please respond with 'y' or 'n'")


def handle_error(error: Exception, debug: bool = False):
    """Handle and display errors appropriately"""
    if debug:
        # Show full traceback in debug mode
        import traceback
        click.echo(click.style("Error Details:", fg='red', bold=True), err=True)
        click.echo(traceback.format_exc(), err=True)
    else:
        # Show user-friendly message
        error_msg = str(error)
        if hasattr(error, '__class__'):
            error_type = error.__class__.__name__
            click.echo(
                click.style(f"Error ({error_type}): ", fg='red', bold=True) +
                error_msg,
                err=True
            )
        else:
            click.echo(
                click.style("Error: ", fg='red', bold=True) + error_msg,
                err=True
            )


def print_success(message: str):
    """Print success message"""
    click.echo(click.style("✓ ", fg='green', bold=True) + message)


def print_warning(message: str):
    """Print warning message"""
    click.echo(click.style("⚠ ", fg='yellow', bold=True) + message)


def print_error(message: str):
    """Print error message"""
    click.echo(click.style("✗ ", fg='red', bold=True) + message, err=True)


def print_info(message: str):
    """Print info message"""
    click.echo(click.style("ℹ ", fg='blue', bold=True) + message)
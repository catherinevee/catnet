"""
Main CLI entry point for CatNet
"""
import click
import asyncio
import sys
import os
from pathlib import Path
from typing import Optional
import json

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from catnet_cli.commands import auth, gitops, deploy, device, vault
from catnet_cli.config import ConfigManager
from catnet_cli.utils import setup_logging, print_version


@click.group(context_settings=dict(help_option_names=["-h", "--help"]))
@click.option("--config", "-c", type=click.Path(), help="Path to configuration file")
@click.option("--debug/--no-debug", default=False, help="Enable debug mode")
@click.pass_context
def cli(ctx: click.Context, config: Optional[str], debug: bool):
    """CatNet CLI - Network Configuration Management System

    Manage network device configurations with GitOps integration,
    automatic rollback, and enterprise-grade security.
    """
    # Ensure context object exists
    ctx.ensure_object(dict)

    # Load configuration
    config_manager = ConfigManager(config_path=config)
    ctx.obj["config"] = config_manager.load()
    ctx.obj["debug"] = debug

    # Setup logging
    setup_logging(debug)

    # Store config manager for other commands
    ctx.obj["config_manager"] = config_manager


@cli.command()
def version():
    """Display CatNet version information"""
    print_version()


@cli.command()
@click.pass_context
def status(ctx: click.Context):
    """Check overall system and service status"""
    from catnet_cli.utils import check_system_status

    debug = ctx.obj.get("debug", False)
    config = ctx.obj.get("config", {})

    # Run async status check
    loop = asyncio.get_event_loop()
    try:
        result = loop.run_until_complete(check_system_status(config, debug))

        # Display status
        click.echo("\n=== CatNet System Status ===\n")

        for service, status in result.items():
            status_symbol = "✓" if status["healthy"] else "✗"
            status_color = "green" if status["healthy"] else "red"

            click.echo(
                click.style(f"{status_symbol} {service}: ", fg=status_color)
                + status.get("message", "Unknown")
            )

            if debug and "details" in status:
                click.echo(f"  Details: {status['details']}")

        click.echo("")

        # Exit with error if any service unhealthy
        if not all(s["healthy"] for s in result.values()):
            sys.exit(1)

    except Exception as e:
        if debug:
            raise
        click.echo(f"Error checking status: {e}", err=True)
        sys.exit(1)


# Add command groups
cli.add_command(auth.auth)
cli.add_command(gitops.gitops)
cli.add_command(deploy.deploy)
cli.add_command(device.device)
cli.add_command(vault.vault)


def main():
    """Main entry point"""
    try:
        cli(obj={})
    except KeyboardInterrupt:
        click.echo("\nOperation cancelled by user", err=True)
        sys.exit(130)
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


if __name__ == "__main__":
    main()

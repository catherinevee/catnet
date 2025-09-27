#!/usr/bin/env python3

import click
import asyncio
import json
import sys
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.progress import track
import os

from src.db.database import Database
from src.db.session import SessionLocal
from src.db.models import User, Device, Deployment
from src.auth.authentication import AuthenticationService
from src.core.deployment import DeploymentService
from src.gitops.git_service import GitOpsService

console = Console()

@click.group()
@click.version_option(version="1.0.0", prog_name="CatNet")
def cli():
    """CatNet - Secure Network Configuration Deployment System"""
    pass

@cli.command()
def init():
    """Initialize CatNet database and configuration"""
    console.print("[bold blue]Initializing CatNet...[/bold blue]")

    db = Database()

    with console.status("[bold green]Creating database tables..."):
        db.create_tables()
        console.print("✓ Database tables created")

    with console.status("[bold green]Setting up initial configuration..."):
        Path("configs").mkdir(exist_ok=True)
        Path("logs").mkdir(exist_ok=True)
        Path("backups").mkdir(exist_ok=True)
        console.print("✓ Directories created")

    console.print("[bold green]CatNet initialized successfully![/bold green]")

@cli.group()
def user():
    """Manage users"""
    pass

@user.command()
@click.option('--username', prompt=True, help='Username')
@click.option('--email', prompt=True, help='Email address')
@click.option('--password', prompt=True, hide_input=True, help='Password')
@click.option('--admin', is_flag=True, help='Create as admin user')
def create(username, email, password, admin):
    """Create a new user"""
    async def create_user():
        db = SessionLocal()
        auth_service = AuthenticationService(db)

        try:
            from src.db.models import UserRole
            role = UserRole.ADMIN if admin else UserRole.OPERATOR

            user = await auth_service.create_user(
                username=username,
                email=email,
                password=password,
                full_name=username,
                role=role
            )

            console.print(f"[bold green]User {username} created successfully![/bold green]")
            console.print(f"ID: {user.id}")
            console.print(f"Role: {role.value}")

        except Exception as e:
            console.print(f"[bold red]Error: {e}[/bold red]")
        finally:
            db.close()

    asyncio.run(create_user())

@cli.group()
def device():
    """Manage network devices"""
    pass

@device.command('list')
def list_devices():
    """List all devices"""
    db = SessionLocal()

    devices = db.query(Device).all()

    if not devices:
        console.print("No devices found")
        return

    table = Table(title="Network Devices")
    table.add_column("ID", style="cyan")
    table.add_column("Hostname", style="magenta")
    table.add_column("IP Address")
    table.add_column("Vendor", style="green")
    table.add_column("Site")
    table.add_column("Status")

    for d in devices:
        status = "🟢 Active" if d.is_active else "🔴 Inactive"
        table.add_row(
            str(d.id)[:8],
            d.hostname,
            d.ip_address,
            d.vendor.value if d.vendor else "Unknown",
            d.site or "N/A",
            status
        )

    console.print(table)
    db.close()

@device.command()
@click.option('--hostname', prompt=True, help='Device hostname')
@click.option('--ip', prompt=True, help='IP address')
@click.option('--vendor', prompt=True, type=click.Choice(['cisco_ios', 'cisco_iosxe', 'cisco_nxos', 'juniper_junos']))
@click.option('--site', help='Site location')
def add(hostname, ip, vendor, site):
    """Add a new device"""
    db = SessionLocal()

    from src.db.models import DeviceVendor
    vendor_map = {
        'cisco_ios': DeviceVendor.CISCO_IOS,
        'cisco_iosxe': DeviceVendor.CISCO_IOSXE,
        'cisco_nxos': DeviceVendor.CISCO_NXOS,
        'juniper_junos': DeviceVendor.JUNIPER_JUNOS
    }

    device = Device(
        hostname=hostname,
        ip_address=ip,
        vendor=vendor_map[vendor],
        site=site,
        credentials_ref=f"devices/{hostname}/credentials",
        is_active=True
    )

    db.add(device)
    db.commit()

    console.print(f"[bold green]Device {hostname} added successfully![/bold green]")
    console.print(f"ID: {device.id}")
    db.close()

@cli.group()
def deploy():
    """Manage deployments"""
    pass

@deploy.command('create')
@click.argument('config_file', type=click.Path(exists=True))
@click.option('--name', prompt=True, help='Deployment name')
@click.option('--strategy', default='rolling', type=click.Choice(['rolling', 'canary', 'blue_green']))
@click.option('--dry-run', is_flag=True, help='Validate only, do not deploy')
def create_deployment(config_file, name, strategy, dry_run):
    """Create a new deployment from configuration file"""
    async def create():
        db = SessionLocal()

        with open(config_file, 'r') as f:
            if config_file.endswith('.json'):
                configs = json.load(f)
            else:
                import yaml
                configs = yaml.safe_load(f)

        if not isinstance(configs, list):
            configs = [configs]

        if dry_run:
            console.print("[bold yellow]Dry run mode - validating configurations...[/bold yellow]")

            from src.core.validators import ConfigValidator
            validator = ConfigValidator()

            for config in configs:
                result = await validator.validate_configuration(config)
                if result.is_valid:
                    console.print(f"✓ Config for {config.get('hostname', 'Unknown')} is valid")
                else:
                    console.print(f"✗ Config for {config.get('hostname', 'Unknown')} has errors:")
                    for error in result.errors:
                        console.print(f"  - {error}", style="red")

            return

        deployment_service = DeploymentService(db)
        deployment = await deployment_service.create_deployment(
            name=name,
            configs=configs,
            user_id="cli-user",
            strategy=strategy
        )

        console.print(f"[bold green]Deployment created successfully![/bold green]")
        console.print(f"ID: {deployment['id']}")
        console.print(f"Strategy: {strategy}")
        console.print(f"Status: {deployment['state']}")

        db.close()

    asyncio.run(create())

@deploy.command('list')
@click.option('--limit', default=10, help='Number of deployments to show')
def list_deployments(limit):
    """List recent deployments"""
    db = SessionLocal()

    deployments = db.query(Deployment).order_by(
        Deployment.created_at.desc()
    ).limit(limit).all()

    if not deployments:
        console.print("No deployments found")
        return

    table = Table(title="Recent Deployments")
    table.add_column("ID", style="cyan")
    table.add_column("Name", style="magenta")
    table.add_column("State")
    table.add_column("Strategy")
    table.add_column("Created At")
    table.add_column("Devices")

    for d in deployments:
        state_color = {
            "PENDING": "yellow",
            "APPROVED": "blue",
            "IN_PROGRESS": "cyan",
            "COMPLETED": "green",
            "FAILED": "red",
            "ROLLED_BACK": "magenta"
        }.get(d.state.value if d.state else "PENDING", "white")

        table.add_row(
            str(d.id)[:8],
            d.name,
            f"[{state_color}]{d.state.value if d.state else 'PENDING'}[/{state_color}]",
            d.strategy,
            d.created_at.strftime("%Y-%m-%d %H:%M"),
            str(len(d.devices))
        )

    console.print(table)
    db.close()

@cli.group()
def gitops():
    """GitOps management"""
    pass

@gitops.command('connect')
@click.option('--name', prompt=True, help='Repository name')
@click.option('--url', prompt=True, help='Repository URL')
@click.option('--branch', default='main', help='Branch to track')
def connect_repo(name, url, branch):
    """Connect a Git repository"""
    async def connect():
        db = SessionLocal()
        git_service = GitOpsService(db)

        try:
            repo = await git_service.connect_repository(
                name=name,
                url=url,
                branch=branch
            )

            console.print(f"[bold green]Repository connected successfully![/bold green]")
            console.print(f"ID: {repo.id}")
            console.print(f"Webhook secret stored in Vault")

        except Exception as e:
            console.print(f"[bold red]Error: {e}[/bold red]")
        finally:
            db.close()

    asyncio.run(connect())

@cli.command()
def serve():
    """Start the CatNet API server"""
    console.print("[bold blue]Starting CatNet API server...[/bold blue]")

    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )

@cli.command()
def status():
    """Check system status"""
    console.print("[bold]CatNet System Status[/bold]\n")

    db = Database()
    db_status = db.check_connection()
    console.print(f"Database: {'🟢 Connected' if db_status else '🔴 Disconnected'}")

    try:
        from src.security.vault_client import VaultClient
        vault = VaultClient()
        vault_health = vault.check_health()
        vault_status = not vault_health.get("sealed", True)
        console.print(f"Vault: {'🟢 Unsealed' if vault_status else '🔴 Sealed'}")
    except:
        console.print("Vault: 🔴 Unavailable")

    db_session = SessionLocal()
    user_count = db_session.query(User).count()
    device_count = db_session.query(Device).count()
    deployment_count = db_session.query(Deployment).count()

    console.print(f"\nStatistics:")
    console.print(f"  Users: {user_count}")
    console.print(f"  Devices: {device_count}")
    console.print(f"  Deployments: {deployment_count}")

    db_session.close()

if __name__ == '__main__':
    cli()
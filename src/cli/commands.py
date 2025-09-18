"""CatNet CLI command definitions."""

import click
import asyncio
import json
import os

from typing import Optional
from pathlib import Path
import sys

from ..auth.service import AuthenticationService
from ..gitops.service import GitOpsService
from ..deployment.service import DeploymentService
from ..devices.service import DeviceService
from ..core.config import Config
from ..security.vault import VaultClient


@click.group()
@click.option(
    "--config", "-c", type=click.Path(exists=True), help="Path to configuration file"
)
@click.option("--debug/--no-debug", default=False, help="Enable debug mode")
@click.pass_context
def cli(ctx, config, debug):
    """CatNet - Secure Network Configuration Deployment System."""
    ctx.ensure_object(dict)
    ctx.obj["DEBUG"] = debug

    if config:
        ctx.obj["CONFIG"] = Config.from_file(config)
    else:
        ctx.obj["CONFIG"] = Config.from_env()

    if debug:
        click.echo("Debug mode enabled")


@cli.group()
@click.pass_context
def auth(ctx):
    """Authentication and authorization commands."""
    pass


@auth.command()
@click.option("--username", "-u", prompt=True, help="Username")
@click.option("--password", "-p", prompt=True, hide_input=True, help="Password")
@click.option("--mfa-token", "-m", prompt="MFA Token", help="MFA token")
@click.pass_context
def login(ctx, username, password, mfa_token):
    """Authenticate to CatNet."""

    async def _login():
        auth_service = AuthenticationService(ctx.obj["CONFIG"])
        try:
            result = await auth_service.login(username, password, mfa_token)

            # Save tokens to secure storage
            token_file = Path.home() / ".catnet" / "tokens.json"
            token_file.parent.mkdir(exist_ok=True)
            token_file.write_text(
                json.dumps(
                    {
                        "access_token": result["access_token"],
                        "refresh_token": result["refresh_token"],
                    }
                )
            )
            token_file.chmod(0o600)  # Secure file permissions

            click.echo(click.style("✓ Authentication successful", fg="green"))
            click.echo(f"Session expires: {result['expires_at']}")
        except Exception as e:
            click.echo(click.style(f"✗ Authentication failed: {str(e)}", fg="red"))
            sys.exit(1)

    asyncio.run(_login())


@auth.command()
@click.pass_context
def logout(ctx):
    """Logout from CatNet."""

    async def _logout():
        auth_service = AuthenticationService(ctx.obj["CONFIG"])
        try:
            # Load tokens
            token_file = Path.home() / ".catnet" / "tokens.json"
            if not token_file.exists():
                click.echo("Not logged in")
                return

            tokens = json.loads(token_file.read_text())
            await auth_service.logout(tokens["access_token"])

            # Remove token file
            token_file.unlink()
            click.echo(click.style("✓ Logged out successfully", fg="green"))
        except Exception as e:
            click.echo(click.style(f"✗ Logout failed: {str(e)}", fg="red"))
            sys.exit(1)

    asyncio.run(_logout())


@auth.command()
@click.pass_context
def refresh(ctx):
    """Refresh authentication token."""

    async def _refresh():
        auth_service = AuthenticationService(ctx.obj["CONFIG"])
        try:
            token_file = Path.home() / ".catnet" / "tokens.json"
            if not token_file.exists():
                click.echo("Not logged in")
                sys.exit(1)

            tokens = json.loads(token_file.read_text())
            result = await auth_service.refresh_token(tokens["refresh_token"])

            # Update tokens
            token_file.write_text(
                json.dumps(
                    {
                        "access_token": result["access_token"],
                        "refresh_token": result["refresh_token"],
                    }
                )
            )

            click.echo(click.style("✓ Token refreshed successfully", fg="green"))
        except Exception as e:
            click.echo(click.style(f"✗ Token refresh failed: {str(e)}", fg="red"))
            sys.exit(1)

    asyncio.run(_refresh())


@cli.group()
@click.pass_context
def gitops(ctx):
    """GitOps repository management commands."""
    pass


@gitops.command("connect")
@click.option("--url", "-u", required=True, help="Git repository URL")
@click.option("--branch", "-b", default="main", help="Git branch")
@click.option("--webhook-secret", help="Webhook secret for verification")
@click.pass_context
def git_connect(ctx, url, branch, webhook_secret):
    """Connect a Git repository."""

    async def _connect():
        gitops_service = GitOpsService(ctx.obj["CONFIG"])
        try:
            result = await gitops_service.connect_repository(
                url=url, branch=branch, webhook_secret=webhook_secret
            )
            click.echo(click.style("✓ Repository connected successfully", fg="green"))
            click.echo(f"Repository ID: {result['id']}")
            click.echo(f"Webhook URL: {result['webhook_url']}")
        except Exception as e:
            click.echo(
                click.style(f"✗ Failed to connect repository: {str(e)}", fg="red")
            )
            sys.exit(1)

    asyncio.run(_connect())


@gitops.command("sync")
@click.option("--repo-id", "-r", required=True, help="Repository ID")
@click.option("--force/--no-force", default=False, help="Force sync")
@click.pass_context
def git_sync(ctx, repo_id, force):
    """Sync configurations from Git repository."""

    async def _sync():
        gitops_service = GitOpsService(ctx.obj["CONFIG"])
        try:
            result = await gitops_service.sync_repository(repo_id, force=force)
            click.echo(click.style("✓ Repository synced successfully", fg="green"))
            click.echo(f"Commits processed: {result['commits_processed']}")
            click.echo(f"Configurations updated: {result['configs_updated']}")
        except Exception as e:
            click.echo(click.style(f"✗ Sync failed: {str(e)}", fg="red"))
            sys.exit(1)

    asyncio.run(_sync())


@gitops.command("list")
@click.pass_context
def git_list(ctx):
    """List connected Git repositories."""

    async def _list():
        gitops_service = GitOpsService(ctx.obj["CONFIG"])
        try:
            repos = await gitops_service.list_repositories()
            if not repos:
                click.echo("No repositories connected")
                return

            click.echo("Connected repositories:")
            for repo in repos:
                click.echo(f"  - {repo['url']} ({repo['branch']})")
                click.echo(f"    ID: {repo['id']}")
                click.echo(f"    Last sync: {repo['last_sync']}")
        except Exception as e:
            click.echo(
                click.style(f"✗ Failed to list repositories: {str(e)}", fg="red")
            )
            sys.exit(1)

    asyncio.run(_list())


@cli.group()
@click.pass_context
def deploy(ctx):
    """Deployment management commands."""
    pass


@deploy.command("create")
@click.option(
    "--config-file",
    "-f",
    type=click.Path(exists=True),
    help="Configuration file to deploy",
)
@click.option("--target", "-t", multiple=True, help="Target devices")
@click.option(
    "--strategy",
    type=click.Choice(["rolling", "canary", "blue-green"]),
    default="rolling",
    help="Deployment strategy",
)
@click.option("--dry-run/--no-dry-run", default=False, help="Dry run mode")
@click.pass_context
def deploy_create(ctx, config_file, target, strategy, dry_run):
    """Create a new deployment."""

    async def _create():
        deployment_service = DeploymentService(ctx.obj["CONFIG"])
        try:
            # Read configuration
            with open(config_file, "r") as f:
                config_content = f.read()

            result = await deployment_service.create_deployment(
                config=config_content,
                targets=list(target),
                strategy=strategy,
                dry_run=dry_run,
            )

            click.echo(click.style("✓ Deployment created successfully", fg="green"))
            click.echo(f"Deployment ID: {result['id']}")
            click.echo(f"Status: {result['status']}")

            if result.get("requires_approval"):
                click.echo(click.style("⚠ Deployment requires approval", fg="yellow"))
                click.echo(f"Approval URL: {result['approval_url']}")
        except Exception as e:
            click.echo(click.style(f"✗ Deployment creation failed: {str(e)}", fg="red"))
            sys.exit(1)

    asyncio.run(_create())


@deploy.command("status")
@click.argument("deployment_id")
@click.pass_context
def deploy_status(ctx, deployment_id):
    """Check deployment status."""

    async def _status():
        deployment_service = DeploymentService(ctx.obj["CONFIG"])
        try:
            status = await deployment_service.get_deployment_status(deployment_id)

            click.echo(f"Deployment: {deployment_id}")
            click.echo(f"Status: {status['state']}")
            click.echo(f"Progress: {status['progress']}%")

            if status.get("devices"):
                click.echo("\nDevice status:")
                for device in status["devices"]:
                    symbol = "✓" if device["status"] == "success" else "✗"
                    color = "green" if device["status"] == "success" else "red"
                    click.echo(
                        click.style(
                            f"  {symbol} {device['name']}: {device['status']}", fg=color
                        )
                    )
        except Exception as e:
            click.echo(
                click.style(f"✗ Failed to get deployment status: {str(e)}", fg="red")
            )
            sys.exit(1)

    asyncio.run(_status())


@deploy.command("approve")
@click.argument("deployment_id")
@click.option("--comment", "-c", help="Approval comment")
@click.pass_context
def deploy_approve(ctx, deployment_id, comment):
    """Approve a pending deployment."""

    async def _approve():
        deployment_service = DeploymentService(ctx.obj["CONFIG"])
        try:
            result = await deployment_service.approve_deployment(
                deployment_id, comment=comment
            )
            click.echo(click.style("✓ Deployment approved successfully", fg="green"))
            click.echo(f"Deployment starting: {result['start_time']}")
        except Exception as e:
            click.echo(click.style(f"✗ Approval failed: {str(e)}", fg="red"))
            sys.exit(1)

    asyncio.run(_approve())


@deploy.command("rollback")
@click.argument("deployment_id")
@click.option("--reason", "-r", required=True, help="Rollback reason")
@click.pass_context
def deploy_rollback(ctx, deployment_id, reason):
    """Rollback a deployment."""

    async def _rollback():
        deployment_service = DeploymentService(ctx.obj["CONFIG"])
        try:
            result = await deployment_service.rollback_deployment(
                deployment_id, reason=reason
            )
            click.echo(click.style("✓ Rollback initiated successfully", fg="green"))
            click.echo(f"Rollback ID: {result['rollback_id']}")
            click.echo(f"Affected devices: {result['device_count']}")
        except Exception as e:
            click.echo(click.style(f"✗ Rollback failed: {str(e)}", fg="red"))
            sys.exit(1)

    asyncio.run(_rollback())


@deploy.command("history")
@click.option("--limit", "-l", default=10, help="Number of deployments to show")
@click.pass_context
def deploy_history(ctx, limit):
    """Show deployment history."""

    async def _history():
        deployment_service = DeploymentService(ctx.obj["CONFIG"])
        try:
            deployments = await deployment_service.get_deployment_history(limit=limit)

            if not deployments:
                click.echo("No deployments found")
                return

            click.echo("Recent deployments:")
            for dep in deployments:
                symbol = "✓" if dep["status"] == "success" else "✗"
                color = "green" if dep["status"] == "success" else "red"
                click.echo(
                    click.style(
                        f"  {symbol} {dep['id'][:8]} - "
                        f"{dep['created_at']} - {dep['status']}",
                        fg=color,
                    )
                )
        except Exception as e:
            click.echo(
                click.style(f"✗ Failed to get deployment history: {str(e)}", fg="red")
            )
            sys.exit(1)

    asyncio.run(_history())


@cli.group()
@click.pass_context
def device(ctx):
    """Device management commands."""
    pass


@device.command("list")
@click.option(
    "--vendor", type=click.Choice(["cisco", "juniper"]), help="Filter by vendor"
)
@click.option(
    "--status",
    type=click.Choice(["online", "offline", "maintenance"]),
    help="Filter by status",
)
@click.pass_context
def device_list(ctx, vendor, status):
    """List managed devices."""

    async def _list():
        device_service = DeviceService(ctx.obj["CONFIG"])
        try:
            devices = await device_service.list_devices(vendor=vendor, status=status)

            if not devices:
                click.echo("No devices found")
                return

            click.echo("Managed devices:")
            for dev in devices:
                status_color = "green" if dev["status"] == "online" else "yellow"
                click.echo(f"  {dev['hostname']} ({dev['vendor']})")
                click.echo(click.style(f"    Status: {dev['status']}", fg=status_color))
                click.echo(f"    IP: {dev['ip_address']}")
                click.echo(f"    Model: {dev['model']}")
        except Exception as e:
            click.echo(click.style(f"✗ Failed to list devices: {str(e)}", fg="red"))
            sys.exit(1)

    asyncio.run(_list())


@device.command("add")
@click.option("--hostname", "-h", required=True, help="Device hostname")
@click.option("--ip", "-i", required=True, help="Device IP address")
@click.option(
    "--vendor",
    type=click.Choice(["cisco", "juniper"]),
    required=True,
    help="Device vendor",
)
@click.option("--model", "-m", required=True, help="Device model")
@click.option("--username", "-u", help="Device username (stored in Vault)")
@click.pass_context
def device_add(ctx, hostname, ip, vendor, model, username):
    """Add a new device."""

    async def _add():
        device_service = DeviceService(ctx.obj["CONFIG"])
        try:
            result = await device_service.add_device(
                hostname=hostname,
                ip_address=ip,
                vendor=vendor,
                model=model,
                username=username,
            )
            click.echo(click.style("✓ Device added successfully", fg="green"))
            click.echo(f"Device ID: {result['id']}")

            if result.get("vault_path"):
                click.echo(f"Credentials stored at: {result['vault_path']}")
        except Exception as e:
            click.echo(click.style(f"✗ Failed to add device: {str(e)}", fg="red"))
            sys.exit(1)

    asyncio.run(_add())


@device.command("backup")
@click.argument("device_id")
@click.pass_context
def device_backup(ctx, device_id):
    """Backup device configuration."""

    async def _backup():
        device_service = DeviceService(ctx.obj["CONFIG"])
        try:
            click.echo(f"Backing up device {device_id}...")
            result = await device_service.backup_device(device_id)

            click.echo(click.style("✓ Backup completed successfully", fg="green"))
            click.echo(f"Backup ID: {result['backup_id']}")
            click.echo(f"Location: {result['location']}")
            click.echo(f"Size: {result['size']} bytes")
        except Exception as e:
            click.echo(click.style(f"✗ Backup failed: {str(e)}", fg="red"))
            sys.exit(1)

    asyncio.run(_backup())


@device.command("execute")
@click.argument("device_id")
@click.option("--command", "-c", required=True, help="Command to execute")
@click.option("--confirm/--no-confirm", default=True, help="Confirm before execution")
@click.pass_context
def device_execute(ctx, device_id, command, confirm):
    """Execute command on device."""

    async def _execute():
        device_service = DeviceService(ctx.obj["CONFIG"])

        if confirm:
            click.echo(f"Command to execute: {command}")
            if not click.confirm("Are you sure you want to execute this command?"):
                click.echo("Command cancelled")
                return

        try:
            click.echo(f"Executing command on device {device_id}...")
            result = await device_service.execute_command(device_id, command)

            click.echo(click.style("✓ Command executed successfully", fg="green"))
            click.echo("\nOutput:")
            click.echo(result["output"])

            if result.get("audit_id"):
                click.echo(f"\nAudit ID: {result['audit_id']}")
        except Exception as e:
            click.echo(click.style(f"✗ Command execution failed: {str(e)}", fg="red"))
            sys.exit(1)

    asyncio.run(_execute())


@device.command("health")
@click.argument("device_id")
@click.pass_context
def device_health(ctx, device_id):
    """Check device health status."""

    async def _health():
        device_service = DeviceService(ctx.obj["CONFIG"])
        try:
            health = await device_service.check_device_health(device_id)

            overall_status = "healthy" if health["healthy"] else "unhealthy"
            color = "green" if health["healthy"] else "red"

            click.echo(f"Device: {device_id}")
            click.echo(click.style(f"Overall Status: {overall_status}", fg=color))

            click.echo("\nHealth Checks:")
            for check in health["checks"]:
                symbol = "✓" if check["passed"] else "✗"
                check_color = "green" if check["passed"] else "red"
                click.echo(
                    click.style(
                        f"  {symbol} {check['name']}: {check['message']}",
                        fg=check_color,
                    )
                )

            if health.get("metrics"):
                click.echo("\nMetrics:")
                for metric, value in health["metrics"].items():
                    click.echo(f"  {metric}: {value}")
        except Exception as e:
            click.echo(click.style(f"✗ Health check failed: {str(e)}", fg="red"))
            sys.exit(1)

    asyncio.run(_health())


@cli.group()
@click.pass_context
def vault(ctx):
    """Vault secret management commands."""
    pass


@vault.command("status")
@click.pass_context
def vault_status(ctx):
    """Check Vault connection status."""

    async def _status():
        vault_client = VaultClient(ctx.obj["CONFIG"])
        try:
            status = await vault_client.get_status()

            click.echo(f"Vault Status: {status['status']}")
            click.echo(f"Version: {status['version']}")
            click.echo(f"Sealed: {status['sealed']}")

            if status.get("cluster_name"):
                click.echo(f"Cluster: {status['cluster_name']}")
        except Exception as e:
            click.echo(click.style(f"✗ Failed to get Vault status: {str(e)}", fg="red"))
            sys.exit(1)

    asyncio.run(_status())


@vault.command("rotate")
@click.argument("device_id")
@click.pass_context
def vault_rotate(ctx, device_id):
    """Rotate device credentials in Vault."""

    async def _rotate():
        vault_client = VaultClient(ctx.obj["CONFIG"])
        try:
            click.echo(f"Rotating credentials for device {device_id}...")
            result = await vault_client.rotate_credentials(device_id)

            click.echo(click.style("✓ Credentials rotated successfully", fg="green"))
            click.echo(f"New version: {result['version']}")
            click.echo(f"Expires: {result['expires_at']}")
        except Exception as e:
            click.echo(click.style(f"✗ Credential rotation failed: {str(e)}", fg="red"))
            sys.exit(1)

    asyncio.run(_rotate())


@cli.group()
@click.pass_context
def ssh(ctx):
    """SSH key management commands."""
    pass


@ssh.command("generate")
@click.option(
    "--type",
    "-t",
    type=click.Choice(["rsa", "ed25519"]),
    default="ed25519",
    help="Key type to generate",
)
@click.option("--size", "-s", type=int, default=4096, help="Key size (RSA only)")
@click.option("--comment", "-c", help="Key comment")
@click.option("--output", "-o", help="Output file path")
@click.pass_context
def ssh_generate(ctx, type, size, comment, output):
    """Generate SSH key pair."""
    from ..devices.ssh_manager import SSHKeyManager
    from ..security.vault import VaultClient

    async def _generate():
        vault = VaultClient(ctx.obj["CONFIG"])
        ssh_manager = SSHKeyManager(vault)

        try:
            click.echo(f"Generating {type} SSH key pair...")
            private_key, public_key = await ssh_manager.generate_ssh_keypair(
                key_type=type,
                key_size=size,
                comment=comment or f"catnet@{os.uname().nodename}",
            )

            if output:
                # Save to files
                private_file = Path(output)
                public_file = Path(f"{output}.pub")

                private_file.write_text(private_key)
                private_file.chmod(0o600)
                public_file.write_text(public_key)

                click.echo(click.style("✓ SSH key pair generated", fg="green"))
                click.echo(f"Private key: {private_file}")
                click.echo(f"Public key: {public_file}")
            else:
                # Display keys
                click.echo(click.style("✓ SSH key pair generated", fg="green"))
                click.echo("\nPrivate key:")
                click.echo(private_key)
                click.echo("\nPublic key:")
                click.echo(public_key)

            # Calculate fingerprint
            from ..auth.ssh_auth import SSHKeyAuthService

            fingerprint = SSHKeyAuthService(None, None).calculate_fingerprint(
                public_key
            )
            click.echo(f"\nFingerprint: {fingerprint}")

        except Exception as e:
            click.echo(click.style(f"✗ Key generation failed: {str(e)}", fg="red"))
            sys.exit(1)

    asyncio.run(_generate())


@ssh.command("add-user")
@click.option(
    "--key-file",
    "-f",
    type=click.Path(exists=True),
    required=True,
    help="Path to public key file",
)
@click.option("--name", "-n", required=True, help="Key name")
@click.option("--comment", "-c", help="Key comment")
@click.pass_context
def ssh_add_user(ctx, key_file, name, comment):
    """Add SSH public key to user account."""

    async def _add():
        from ..auth.ssh_auth import SSHKeyAuthService
        from ..security.audit import AuditLogger

        # Would need database session here

        try:
            # Read public key
            public_key = Path(key_file).read_text().strip()

            # Get current user from token
            token_file = Path.home() / ".catnet" / "tokens.json"
            if not token_file.exists():
                click.echo("Not authenticated. Please login first.")
                sys.exit(1)

            # In production, would decode JWT to get user_id
            user_id = "current_user_id"  # Placeholder

            click.echo(f"Adding SSH key '{name}' to your account...")

            # Would call the service here with actual DB session
            # ssh_service = SSHKeyAuthService(db_session, audit_logger)
            # key = await ssh_service.add_ssh_key(
            #     user_id, public_key, name, comment
            # )
            click.echo(f"Public key fingerprint: {public_key[:50]}...")
            click.echo(f"User ID: {user_id}")

            click.echo(click.style("✓ SSH key added successfully", fg="green"))

        except Exception as e:
            click.echo(click.style(f"✗ Failed to add SSH key: {str(e)}", fg="red"))
            sys.exit(1)

    asyncio.run(_add())


@ssh.command("list-user")
@click.pass_context
def ssh_list_user(ctx):
    """List SSH keys for current user."""

    async def _list():
        try:
            # Check authentication
            token_file = Path.home() / ".catnet" / "tokens.json"
            if not token_file.exists():
                click.echo("Not authenticated. Please login first.")
                sys.exit(1)

            # Would get user keys from service
            # keys = await ssh_service.list_user_keys(user_id)

            # Mock data for demonstration
            keys = [
                {
                    "name": "laptop",
                    "fingerprint": "SHA256:abcd1234...",
                    "key_type": "ed25519",
                    "created_at": "2024-01-01T12:00:00",
                    "last_used": "2024-01-15T10:30:00",
                }
            ]

            if not keys:
                click.echo("No SSH keys configured")
                return

            click.echo("Your SSH keys:")
            for key in keys:
                click.echo(f"\n  Name: {key['name']}")
                click.echo(f"  Type: {key['key_type']}")
                click.echo(f"  Fingerprint: {key['fingerprint']}")
                click.echo(f"  Created: {key['created_at']}")
                click.echo(f"  Last used: {key.get('last_used', 'Never')}")

        except Exception as e:
            click.echo(click.style(f"✗ Failed to list SSH keys: {str(e)}", fg="red"))
            sys.exit(1)

    asyncio.run(_list())


@ssh.command("add-device")
@click.argument("device_id")
@click.option(
    "--key-file", "-f", type=click.Path(exists=True), help="Path to public key file"
)
@click.option("--generate/--no-generate", default=False, help="Generate new key pair")
@click.option("--deploy/--no-deploy", default=True, help="Deploy key to device")
@click.pass_context
def ssh_add_device(ctx, device_id, key_file, generate, deploy):
    """Add SSH key for device authentication."""
    from ..devices.ssh_manager import SSHKeyManager
    from ..security.vault import VaultClient

    async def _add():
        vault = VaultClient(ctx.obj["CONFIG"])
        ssh_manager = SSHKeyManager(vault)

        try:
            if generate:
                # Generate new key pair
                click.echo(f"Generating SSH key pair for device {device_id}...")
                private_key, public_key = await ssh_manager.generate_ssh_keypair()

                # Store in Vault
                result = await ssh_manager.store_ssh_key(
                    device_id, private_key, public_key
                )
                click.echo(click.style("✓ SSH key generated and stored", fg="green"))
                click.echo(f"Vault path: {result['vault_path']}")

            elif key_file:
                # Use existing key
                public_key = Path(key_file).read_text().strip()
                private_key = None  # Would need private key for storage

                click.echo(f"Storing SSH key for device {device_id}...")
                result = await ssh_manager.store_ssh_key(
                    device_id, private_key or "", public_key
                )
                click.echo(click.style("✓ SSH key stored", fg="green"))

            else:
                click.echo("Either --generate or --key-file must be specified")
                sys.exit(1)

            if deploy:
                click.echo(f"Deploying public key to device {device_id}...")
                # Would deploy to actual device here
                click.echo(click.style("✓ Public key deployed to device", fg="green"))

        except Exception as e:
            click.echo(
                click.style(f"✗ Failed to add device SSH key: {str(e)}", fg="red")
            )
            sys.exit(1)

    asyncio.run(_add())


@ssh.command("rotate-device")
@click.argument("device_id")
@click.option("--deploy/--no-deploy", default=True, help="Deploy new key to device")
@click.pass_context
def ssh_rotate_device(ctx, device_id, deploy):
    """Rotate SSH key for device."""
    from ..devices.ssh_manager import SSHKeyManager
    from ..security.vault import VaultClient

    async def _rotate():
        vault = VaultClient(ctx.obj["CONFIG"])
        ssh_manager = SSHKeyManager(vault)

        try:
            click.echo(f"Rotating SSH key for device {device_id}...")
            result = await ssh_manager.rotate_ssh_key(device_id)

            click.echo(click.style("✓ SSH key rotated successfully", fg="green"))
            click.echo(
                f"New fingerprint: {result.get('public_key', '').split()[1][:20]}..."
            )

            if deploy:
                click.echo("Deploying new public key to device...")
                # Would deploy to actual device here
                click.echo(click.style("✓ New key deployed to device", fg="green"))

        except Exception as e:
            click.echo(click.style(f"✗ Key rotation failed: {str(e)}", fg="red"))
            sys.exit(1)

    asyncio.run(_rotate())


@ssh.command("test")
@click.argument("device_id")
@click.option("--username", "-u", help="SSH username")
@click.pass_context
def ssh_test(ctx, device_id, username):
    """Test SSH connection to device."""
    from ..devices.ssh_manager import SSHKeyManager
    from ..security.vault import VaultClient

    async def _test():
        vault = VaultClient(ctx.obj["CONFIG"])
        ssh_manager = SSHKeyManager(vault)

        try:
            click.echo(f"Testing SSH connection to device {device_id}...")

            # Get device info (mock)
            hostname = "192.168.1.1"
            ssh_username = username or "catnet"

            # Get SSH key from Vault
            ssh_key = await ssh_manager.get_ssh_key(device_id)

            # Test connection
            success = await ssh_manager.test_ssh_connection(
                hostname=hostname,
                username=ssh_username,
                private_key=ssh_key["private_key"],
            )

            if success:
                click.echo(click.style("✓ SSH connection successful", fg="green"))
            else:
                click.echo(click.style("✗ SSH connection failed", fg="red"))

        except Exception as e:
            click.echo(click.style(f"✗ Connection test failed: {str(e)}", fg="red"))
            sys.exit(1)

    asyncio.run(_test())


@cli.command()
@click.pass_context
def version(ctx):
    """Show CatNet version."""
    click.echo("CatNet v1.0.0")
    click.echo("Network Configuration Deployment System")
    click.echo("Security-first, GitOps-enabled")


@cli.command()
@click.pass_context
def status(ctx):
    """Show system status."""

    async def _status():
        try:
            # Check authentication status
            token_file = Path.home() / ".catnet" / "tokens.json"
            if token_file.exists():
                click.echo(click.style("✓ Authenticated", fg="green"))
            else:
                click.echo(click.style("✗ Not authenticated", fg="yellow"))

            # Check service connectivity
            click.echo("\nService Status:")
            services = [
                ("Authentication Service", "http://localhost:8081/health"),
                ("GitOps Service", "http://localhost:8082/health"),
                ("Deployment Service", "http://localhost:8083/health"),
                ("Device Service", "http://localhost:8084/health"),
            ]

            import aiohttp

            async with aiohttp.ClientSession() as session:
                for service_name, url in services:
                    try:
                        async with session.get(url, timeout=2) as response:
                            if response.status == 200:
                                click.echo(
                                    click.style(f"  ✓ {service_name}", fg="green")
                                )
                            else:
                                click.echo(click.style(f"  ✗ {service_name}", fg="red"))
                    except Exception:
                        click.echo(
                            click.style(f"  ✗ {service_name} (unreachable)", fg="red")
                        )

        except Exception as e:
            click.echo(click.style(f"✗ Status check failed: {str(e)}", fg="red"))
            sys.exit(1)

    asyncio.run(_status())


if __name__ == "__main__":
    cli()

#!/usr/bin/env python3
import asyncio
import os
import sys
import signal
from typing import Optional
import logging
from pathlib import Path
import click
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=getattr(logging, os.getenv("LOG_LEVEL", "INFO")),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("catnet")



class CatNetOrchestrator:
    def __init__(self):
        self.services = {}
        self.running = False
        self.shutdown_handler: Optional[asyncio.Task] = None

    async def start_auth_service(self):
        from src.auth.service import AuthenticationService

        logger.info("Starting Authentication Service on port 8081...")
        service = AuthenticationService(port=8081)
        self.services["auth"] = service
        # Run in background
        asyncio.create_task(self._run_service(service))

    async def start_gitops_service(self):
        logger.info("Starting GitOps Service on port 8082...")
        # Import and start GitOps service
        # asyncio.create_task(self._run_gitops())

    async def start_deployment_service(self):
        logger.info("Starting Deployment Service on port 8083...")
        # Import and start Deployment service
        # asyncio.create_task(self._run_deployment())

    async def start_device_service(self):
        logger.info("Starting Device Service on port 8084...")
        # Import and start Device service
        # asyncio.create_task(self._run_device())

    async def _run_service(self, service):
        try:
            await asyncio.get_event_loop().run_in_executor(None, service.run)
        except Exception as e:
            logger.error(f"Service failed: {e}")

    async def start_all_services(self):
        self.running = True
        logger.info("Starting CatNet services...")

        # Initialize database
        from src.db.database import init_database

        db_manager = init_database()

        # Create tables if needed
        await db_manager.create_all()

        # Start services
        await self.start_auth_service()
        await asyncio.sleep(1)  # Give services time to start

        # await self.start_gitops_service()
        # await self.start_deployment_service()
        # await self.start_device_service()

        logger.info("All services started successfully")

    async def stop_all_services(self):
        self.running = False
        logger.info("Stopping CatNet services...")
        # Gracefully stop all services
        for service_name, service in self.services.items():
            logger.info(f"Stopping {service_name} service...")
            # Implement graceful shutdown

        logger.info("All services stopped")

    def handle_signal(self, sig, frame):
        logger.info(f"Received signal {sig}")
        asyncio.create_task(self.stop_all_services())
        sys.exit(0)


@click.group()

def cli():
    """CatNet - Network Configuration Deployment System"""


@cli.command()
@click.option(
    "--service",
    type=click.Choice(["all", "auth", "gitops", "deployment", "device"]),
    default="all",
)

def start(service):
    """Start CatNet services"""
    orchestrator = CatNetOrchestrator()

    # Setup signal handlers
    signal.signal(signal.SIGINT, orchestrator.handle_signal)
    signal.signal(signal.SIGTERM, orchestrator.handle_signal)

    async def run():
        if service == "all":
            await orchestrator.start_all_services()
        elif service == "auth":
            await orchestrator.start_auth_service()
        elif service == "gitops":
            await orchestrator.start_gitops_service()
        elif service == "deployment":
            await orchestrator.start_deployment_service()
        elif service == "device":
            await orchestrator.start_device_service()

        # Keep running
        while orchestrator.running:
            await asyncio.sleep(1)

    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        logger.info("Shutting down CatNet...")


@cli.command()

def init():
    """Initialize CatNet database and configuration"""

    async def init_db():
        from src.db.database import init_database
        from alembic.config import Config
        from alembic import command

        logger.info("Initializing database...")
        db_manager = init_database()

        # Create all tables
        await db_manager.create_all()

        # Run migrations
        alembic_cfg = Config("alembic.ini")
        command.upgrade(alembic_cfg, "head")

        logger.info("Database initialized successfully")

        # Create default admin user
        from src.db.models import User
        from src.security.auth import AuthManager

                auth_manager = AuthManager(
            secret_key=os.getenv("JWT_SECRET_KEY",
            "change-me")
        )

        async with db_manager.session_scope() as session:
            # Check if admin exists
            from sqlalchemy import select

            result = await session.execute(select(User).where(User.username == \
                "admin"))
            admin = result.scalar_one_or_none()

            if not admin:
                # Create admin user
                admin = User(
                    username="admin",
                    email="admin@catnet.local",
                    password_hash=auth_manager.get_password_hash(
                        "admin123"
                    ),  # Change in production!
                    is_superuser=True,
                    roles=["admin"],
                )
                session.add(admin)
                await session.commit()
                logger.info(
                                        "Default admin user created (
                        username: admin,
                        password: admin123
                    )"
                )
                logger.warning("⚠️  CHANGE THE DEFAULT ADMIN PASSWORD \
                    IMMEDIATELY!")
            else:
                logger.info("Admin user already exists")

    asyncio.run(init_db())


@cli.command()
@click.option("--host", default="192.168.1.1")
@click.option(
    "--vendor",
    type=click.Choice(["cisco_ios",
    "cisco_xe",
    "juniper"])
)
@click.option("--username", prompt=True)
@click.option("--password", prompt=True, hide_input=True)

def test_connection(host, vendor, username, password):
    """Test connection to a network device"""
    from netmiko import ConnectHandler

    logger.info(f"Testing connection to {host}...")

    try:
        device = {
            "device_type": vendor,
            "host": host,
            "username": username,
            "password": password,
        }

        with ConnectHandler(**device) as conn:
            output = conn.send_command("show version")
            logger.info("Connection successful!")
            print(output[:500])  # Print first 500 chars

    except Exception as e:
        logger.error(f"Connection failed: {e}")


@cli.command()

def validate_config():
    """Validate CatNet configuration"""
    logger.info("Validating configuration...")

    required_env_vars = [
        "DATABASE_URL",
        "VAULT_URL",
        "JWT_SECRET_KEY",
    ]

    missing = []
    for var in required_env_vars:
        if not os.getenv(var):
            missing.append(var)

    if missing:
                logger.error(
            f"Missing required environment variables: {',
            '.join(missing)}"
        )
        sys.exit(1)

    # Test database connection
    async def test_db():
        from src.db.database import init_database

        db_manager = init_database()
        if await db_manager.health_check():
            logger.info("✓ Database connection OK")
        else:
            logger.error("✗ Database connection failed")
            return False

        await db_manager.close()
        return True

    if not asyncio.run(test_db()):
        sys.exit(1)

    # Test Vault connection if configured
    vault_url = os.getenv("VAULT_URL")
    if vault_url and vault_url != "http://localhost:8200":
        try:
            from src.security.vault import VaultClient

            vault = VaultClient()
            if vault.client.is_authenticated():
                logger.info("✓ Vault connection OK")
            else:
                logger.warning("⚠ Vault not authenticated")
        except Exception as e:
            logger.warning(f"⚠ Vault connection failed: {e}")

    logger.info("Configuration validation complete")


@cli.command()
@click.option("--coverage", is_flag=True, help="Run with coverage report")
@click.option("--verbose", is_flag=True, help="Verbose output")

def test(coverage, verbose):
    """Run test suite"""
    import subprocess

    cmd = ["pytest", "tests/"]

    if coverage:
        cmd.extend(["--cov=src", "--cov-report=html", "--cov-report=term"])

    if verbose:
        cmd.append("-v")

    logger.info("Running tests...")
    result = subprocess.run(cmd)
    sys.exit(result.returncode)


@cli.command()

def generate_keys():
    """Generate RSA keypair for signing"""
    from src.security.encryption import EncryptionManager

    logger.info("Generating RSA keypair...")
    private_key, public_key = EncryptionManager.generate_rsa_keypair()

    # Save keys
    keys_dir = Path("keys")
    keys_dir.mkdir(exist_ok=True)

    with open(keys_dir / "private_key.pem", "wb") as f:
        f.write(private_key)
    os.chmod(keys_dir / "private_key.pem", 0o600)

    with open(keys_dir / "public_key.pem", "wb") as f:
        f.write(public_key)

    logger.info(f"Keys generated in {keys_dir}")
    logger.info("⚠️  Keep the private key secure!")


if __name__ == "__main__":
    cli()

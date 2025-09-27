"""
Database initialization for CatNet.
Creates tables, indexes, and initial data.
"""

import asyncio
import sys
from pathlib import Path
from typing import Optional
import asyncpg
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from alembic import command
from alembic.config import Config
import logging

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent.parent))

from src.db.models import Base, User, Role, Permission
from src.core.config import get_settings
from src.security.encryption import EncryptionManager
from src.security.vault import VaultClient
from src.security.audit import AuditLogger

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class DatabaseInitializer:
    """
    Database initialization and setup.
    """

    def __init__(self):
        """Initialize database initializer."""
        self.settings = get_settings()
        self.encryption = EncryptionManager()
        self.vault = VaultClient()
        self.audit = AuditLogger()

        # Database connection
        self.engine = None
        self.async_session = None

    async def init_database(self, drop_existing: bool = False):
        """
        Initialize database with tables and initial data.

        Args:
            drop_existing: Whether to drop existing tables
        """
        try:
            logger.info("Starting database initialization...")

            # Create engine
            self.engine = create_async_engine(
                self.settings.DATABASE_URL,
                echo=self.settings.DEBUG,
                pool_size=20,
                max_overflow=10,
                pool_pre_ping=True
            )

            # Create session factory
            self.async_session = sessionmaker(
                self.engine,
                class_=AsyncSession,
                expire_on_commit=False
            )

            # Create database if it doesn't exist
            await self._create_database_if_not_exists()

            # Drop existing tables if requested
            if drop_existing:
                logger.warning("Dropping existing tables...")
                async with self.engine.begin() as conn:
                    await conn.run_sync(Base.metadata.drop_all)

            # Create all tables
            logger.info("Creating database tables...")
            async with self.engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)

            # Create indexes
            await self._create_indexes()

            # Create initial data
            await self._create_initial_data()

            # Create stored procedures
            await self._create_stored_procedures()

            # Create triggers
            await self._create_triggers()

            # Setup partitioning
            await self._setup_partitioning()

            # Verify installation
            await self._verify_installation()

            logger.info("Database initialization completed successfully!")

        except Exception as e:
            logger.error(f"Database initialization failed: {e}")
            raise

        finally:
            if self.engine:
                await self.engine.dispose()

    async def _create_database_if_not_exists(self):
        """Create database if it doesn't exist."""
        # Parse database name from URL
        db_url_parts = self.settings.DATABASE_URL.split('/')
        db_name = db_url_parts[-1].split('?')[0]
        server_url = '/'.join(db_url_parts[:-1]) + '/postgres'

        try:
            # Connect to postgres database
            conn = await asyncpg.connect(server_url)

            # Check if database exists
            exists = await conn.fetchval(
                "SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname = $1)",
                db_name
            )

            if not exists:
                logger.info(f"Creating database {db_name}...")
                await conn.execute(f'CREATE DATABASE "{db_name}"')

            await conn.close()

        except Exception as e:
            logger.error(f"Failed to create database: {e}")
            raise

    async def _create_indexes(self):
        """Create database indexes for performance."""
        logger.info("Creating indexes...")

        indexes = [
            # User indexes
            "CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)",
            "CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)",
            "CREATE INDEX IF NOT EXISTS idx_users_is_active ON users(is_active)",

            # Device indexes
            "CREATE INDEX IF NOT EXISTS idx_devices_hostname ON devices(hostname)",
            "CREATE INDEX IF NOT EXISTS idx_devices_ip_address ON devices(ip_address)",
            "CREATE INDEX IF NOT EXISTS idx_devices_vendor ON devices(vendor)",
            "CREATE INDEX IF NOT EXISTS idx_devices_is_active ON devices(is_active)",
            "CREATE INDEX IF NOT EXISTS idx_devices_health_status ON devices(health_status)",

            # Deployment indexes
            "CREATE INDEX IF NOT EXISTS idx_deployments_state ON deployments(state)",
            "CREATE INDEX IF NOT EXISTS idx_deployments_created_at ON deployments(created_at)",
            "CREATE INDEX IF NOT EXISTS idx_deployments_created_by ON deployments(created_by)",

            # Session indexes
            "CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token)",
            "CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id)",
            "CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at)",

            # Audit log indexes
            "CREATE INDEX IF NOT EXISTS idx_audit_logs_event_type ON audit_logs(event_type)",
            "CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id)",
            "CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at)",

            # Configuration indexes
            "CREATE INDEX IF NOT EXISTS idx_configurations_device_id ON configurations(device_id)",
            "CREATE INDEX IF NOT EXISTS idx_configurations_repository_id ON configurations(repository_id)",
            "CREATE INDEX IF NOT EXISTS idx_configurations_created_at ON configurations(created_at)",

            # Health check indexes
            "CREATE INDEX IF NOT EXISTS idx_health_checks_device_id ON health_checks(device_id)",
            "CREATE INDEX IF NOT EXISTS idx_health_checks_checked_at ON health_checks(checked_at)",
            "CREATE INDEX IF NOT EXISTS idx_health_checks_status ON health_checks(status)",

            # Notification indexes
            "CREATE INDEX IF NOT EXISTS idx_notifications_recipient_id ON notifications(recipient_id)",
            "CREATE INDEX IF NOT EXISTS idx_notifications_created_at ON notifications(created_at)",
            "CREATE INDEX IF NOT EXISTS idx_notifications_status ON notifications(status)",

            # Request log indexes
            "CREATE INDEX IF NOT EXISTS idx_request_logs_path ON request_logs(path)",
            "CREATE INDEX IF NOT EXISTS idx_request_logs_method ON request_logs(method)",
            "CREATE INDEX IF NOT EXISTS idx_request_logs_status_code ON request_logs(status_code)",
            "CREATE INDEX IF NOT EXISTS idx_request_logs_created_at ON request_logs(created_at)",
        ]

        async with self.engine.begin() as conn:
            for index_sql in indexes:
                await conn.execute(index_sql)

    async def _create_initial_data(self):
        """Create initial data for the database."""
        logger.info("Creating initial data...")

        async with self.async_session() as session:
            try:
                # Create default roles
                roles = [
                    {
                        'name': 'admin',
                        'description': 'Administrator role with full access',
                        'permissions': [
                            'admin.all',
                            'deployment.create', 'deployment.approve', 'deployment.rollback',
                            'device.create', 'device.update', 'device.delete', 'device.execute',
                            'user.create', 'user.update', 'user.delete',
                            'git.manage', 'git.sync',
                            'security.manage'
                        ]
                    },
                    {
                        'name': 'operator',
                        'description': 'Network operator role',
                        'permissions': [
                            'deployment.create', 'deployment.view',
                            'device.view', 'device.execute',
                            'git.sync'
                        ]
                    },
                    {
                        'name': 'viewer',
                        'description': 'Read-only viewer role',
                        'permissions': [
                            'deployment.view',
                            'device.view'
                        ]
                    },
                    {
                        'name': 'security',
                        'description': 'Security team role',
                        'permissions': [
                            'security.manage',
                            'audit.view',
                            'user.view'
                        ]
                    }
                ]

                for role_data in roles:
                    # Check if role exists
                    existing = await session.execute(
                        select(Role).where(Role.name == role_data['name'])
                    )
                    if not existing.scalar_one_or_none():
                        role = Role(
                            name=role_data['name'],
                            description=role_data['description'],
                            permissions=role_data['permissions'],
                            is_active=True
                        )
                        session.add(role)

                # Create admin user
                admin_exists = await session.execute(
                    select(User).where(User.username == 'admin')
                )

                if not admin_exists.scalar_one_or_none():
                    # Get admin role
                    admin_role = await session.execute(
                        select(Role).where(Role.name == 'admin')
                    )
                    admin_role = admin_role.scalar_one()

                    # Hash default password
                    default_password = "CatNet@Admin123!"
                    hashed_password = self.encryption.hash_password(default_password)

                    admin_user = User(
                        username='admin',
                        email='admin@catnet.local',
                        full_name='System Administrator',
                        password_hash=hashed_password,
                        role_id=admin_role.id,
                        is_active=True,
                        is_superuser=True,
                        mfa_enabled=False,  # Enable after first login
                        must_change_password=True
                    )
                    session.add(admin_user)

                    logger.info(f"Created admin user with default password: {default_password}")
                    logger.warning("IMPORTANT: Change the admin password immediately after first login!")

                await session.commit()

            except Exception as e:
                await session.rollback()
                logger.error(f"Failed to create initial data: {e}")
                raise

    async def _create_stored_procedures(self):
        """Create stored procedures for complex operations."""
        logger.info("Creating stored procedures...")

        procedures = [
            # Cleanup old sessions
            """
            CREATE OR REPLACE FUNCTION cleanup_expired_sessions()
            RETURNS INTEGER AS $$
            DECLARE
                deleted_count INTEGER;
            BEGIN
                DELETE FROM sessions WHERE expires_at < NOW();
                GET DIAGNOSTICS deleted_count = ROW_COUNT;
                RETURN deleted_count;
            END;
            $$ LANGUAGE plpgsql;
            """,

            # Get device health statistics
            """
            CREATE OR REPLACE FUNCTION get_device_health_stats()
            RETURNS TABLE(
                health_status VARCHAR,
                device_count BIGINT,
                percentage NUMERIC
            ) AS $$
            DECLARE
                total_devices BIGINT;
            BEGIN
                SELECT COUNT(*) INTO total_devices FROM devices WHERE is_active = true;

                RETURN QUERY
                SELECT
                    d.health_status,
                    COUNT(*) as device_count,
                    CASE
                        WHEN total_devices > 0 THEN
                            ROUND((COUNT(*) * 100.0 / total_devices), 2)
                        ELSE 0
                    END as percentage
                FROM devices d
                WHERE d.is_active = true
                GROUP BY d.health_status;
            END;
            $$ LANGUAGE plpgsql;
            """,

            # Calculate deployment success rate
            """
            CREATE OR REPLACE FUNCTION get_deployment_success_rate(
                time_window INTERVAL DEFAULT '24 hours'
            )
            RETURNS NUMERIC AS $$
            DECLARE
                total_deployments BIGINT;
                successful_deployments BIGINT;
            BEGIN
                SELECT COUNT(*) INTO total_deployments
                FROM deployments
                WHERE created_at > NOW() - time_window;

                SELECT COUNT(*) INTO successful_deployments
                FROM deployments
                WHERE created_at > NOW() - time_window
                AND state = 'completed';

                IF total_deployments > 0 THEN
                    RETURN ROUND((successful_deployments * 100.0 / total_deployments), 2);
                ELSE
                    RETURN 100.0;
                END IF;
            END;
            $$ LANGUAGE plpgsql;
            """,

            # Archive old audit logs
            """
            CREATE OR REPLACE FUNCTION archive_audit_logs(
                days_to_keep INTEGER DEFAULT 365
            )
            RETURNS INTEGER AS $$
            DECLARE
                archived_count INTEGER;
            BEGIN
                -- Create archive table if not exists
                CREATE TABLE IF NOT EXISTS audit_logs_archive (LIKE audit_logs INCLUDING ALL);

                -- Move old records to archive
                WITH moved AS (
                    DELETE FROM audit_logs
                    WHERE created_at < NOW() - (days_to_keep || ' days')::INTERVAL
                    RETURNING *
                )
                INSERT INTO audit_logs_archive SELECT * FROM moved;

                GET DIAGNOSTICS archived_count = ROW_COUNT;
                RETURN archived_count;
            END;
            $$ LANGUAGE plpgsql;
            """
        ]

        async with self.engine.begin() as conn:
            for procedure in procedures:
                await conn.execute(procedure)

    async def _create_triggers(self):
        """Create database triggers."""
        logger.info("Creating triggers...")

        triggers = [
            # Update device last_updated timestamp
            """
            CREATE OR REPLACE FUNCTION update_device_timestamp()
            RETURNS TRIGGER AS $$
            BEGIN
                NEW.last_updated = NOW();
                RETURN NEW;
            END;
            $$ LANGUAGE plpgsql;

            DROP TRIGGER IF EXISTS update_device_timestamp_trigger ON devices;

            CREATE TRIGGER update_device_timestamp_trigger
            BEFORE UPDATE ON devices
            FOR EACH ROW
            EXECUTE FUNCTION update_device_timestamp();
            """,

            # Audit user modifications
            """
            CREATE OR REPLACE FUNCTION audit_user_changes()
            RETURNS TRIGGER AS $$
            BEGIN
                INSERT INTO audit_logs (
                    event_type,
                    user_id,
                    details,
                    created_at
                ) VALUES (
                    CASE
                        WHEN TG_OP = 'INSERT' THEN 'USER_CREATED'
                        WHEN TG_OP = 'UPDATE' THEN 'USER_UPDATED'
                        WHEN TG_OP = 'DELETE' THEN 'USER_DELETED'
                    END,
                    COALESCE(NEW.id, OLD.id),
                    jsonb_build_object(
                        'operation', TG_OP,
                        'table', TG_TABLE_NAME,
                        'old_data', to_jsonb(OLD),
                        'new_data', to_jsonb(NEW)
                    ),
                    NOW()
                );
                RETURN COALESCE(NEW, OLD);
            END;
            $$ LANGUAGE plpgsql;

            DROP TRIGGER IF EXISTS audit_user_changes_trigger ON users;

            CREATE TRIGGER audit_user_changes_trigger
            AFTER INSERT OR UPDATE OR DELETE ON users
            FOR EACH ROW
            EXECUTE FUNCTION audit_user_changes();
            """,

            # Prevent deployment state regression
            """
            CREATE OR REPLACE FUNCTION prevent_deployment_state_regression()
            RETURNS TRIGGER AS $$
            BEGIN
                -- Define valid state transitions
                IF OLD.state = 'completed' AND NEW.state != 'rolled_back' THEN
                    RAISE EXCEPTION 'Cannot change state from completed to %', NEW.state;
                END IF;

                IF OLD.state = 'failed' AND NEW.state NOT IN ('pending', 'rolled_back') THEN
                    RAISE EXCEPTION 'Cannot change state from failed to %', NEW.state;
                END IF;

                IF OLD.state = 'rolled_back' THEN
                    RAISE EXCEPTION 'Cannot change state from rolled_back';
                END IF;

                RETURN NEW;
            END;
            $$ LANGUAGE plpgsql;

            DROP TRIGGER IF EXISTS prevent_deployment_state_regression_trigger ON deployments;

            CREATE TRIGGER prevent_deployment_state_regression_trigger
            BEFORE UPDATE OF state ON deployments
            FOR EACH ROW
            EXECUTE FUNCTION prevent_deployment_state_regression();
            """
        ]

        async with self.engine.begin() as conn:
            for trigger in triggers:
                await conn.execute(trigger)

    async def _setup_partitioning(self):
        """Setup table partitioning for large tables."""
        logger.info("Setting up partitioning...")

        # Partition audit logs by month
        partition_sql = """
        -- Create partitioned audit logs table
        CREATE TABLE IF NOT EXISTS audit_logs_partitioned (
            LIKE audit_logs INCLUDING ALL
        ) PARTITION BY RANGE (created_at);

        -- Create partitions for the next 12 months
        DO $$
        DECLARE
            start_date DATE;
            end_date DATE;
            partition_name TEXT;
        BEGIN
            FOR i IN 0..11 LOOP
                start_date := DATE_TRUNC('month', CURRENT_DATE + (i || ' months')::INTERVAL);
                end_date := start_date + INTERVAL '1 month';
                partition_name := 'audit_logs_' || TO_CHAR(start_date, 'YYYY_MM');

                -- Check if partition exists
                IF NOT EXISTS (
                    SELECT 1 FROM pg_class
                    WHERE relname = partition_name
                ) THEN
                    EXECUTE format(
                        'CREATE TABLE %I PARTITION OF audit_logs_partitioned
                        FOR VALUES FROM (%L) TO (%L)',
                        partition_name, start_date, end_date
                    );
                END IF;
            END LOOP;
        END $$;

        -- Create function to automatically create new partitions
        CREATE OR REPLACE FUNCTION create_monthly_partition()
        RETURNS VOID AS $$
        DECLARE
            start_date DATE;
            end_date DATE;
            partition_name TEXT;
        BEGIN
            start_date := DATE_TRUNC('month', CURRENT_DATE + INTERVAL '1 month');
            end_date := start_date + INTERVAL '1 month';
            partition_name := 'audit_logs_' || TO_CHAR(start_date, 'YYYY_MM');

            IF NOT EXISTS (
                SELECT 1 FROM pg_class
                WHERE relname = partition_name
            ) THEN
                EXECUTE format(
                    'CREATE TABLE %I PARTITION OF audit_logs_partitioned
                    FOR VALUES FROM (%L) TO (%L)',
                    partition_name, start_date, end_date
                );
            END IF;
        END;
        $$ LANGUAGE plpgsql;
        """

        async with self.engine.begin() as conn:
            await conn.execute(partition_sql)

    async def _verify_installation(self):
        """Verify database installation."""
        logger.info("Verifying installation...")

        async with self.async_session() as session:
            # Check tables exist
            tables_query = """
            SELECT table_name
            FROM information_schema.tables
            WHERE table_schema = 'public'
            ORDER BY table_name
            """
            result = await session.execute(tables_query)
            tables = [row[0] for row in result]

            required_tables = [
                'users', 'roles', 'sessions', 'devices', 'deployments',
                'configurations', 'audit_logs', 'health_checks',
                'git_repositories', 'notifications'
            ]

            missing_tables = set(required_tables) - set(tables)
            if missing_tables:
                raise Exception(f"Missing tables: {missing_tables}")

            logger.info(f"Found {len(tables)} tables")

            # Check admin user exists
            admin_result = await session.execute(
                select(User).where(User.username == 'admin')
            )
            admin = admin_result.scalar_one_or_none()
            if not admin:
                raise Exception("Admin user not created")

            # Check roles exist
            roles_result = await session.execute(select(Role))
            roles = roles_result.scalars().all()
            if len(roles) < 4:
                raise Exception(f"Expected at least 4 roles, found {len(roles)}")

            logger.info("Database verification completed successfully!")

    async def run_migrations(self):
        """Run database migrations using Alembic."""
        logger.info("Running database migrations...")

        # Configure Alembic
        alembic_cfg = Config("alembic.ini")
        alembic_cfg.set_main_option("sqlalchemy.url", self.settings.DATABASE_URL)

        # Run migrations
        command.upgrade(alembic_cfg, "head")

        logger.info("Migrations completed successfully!")

    async def create_backup(self, backup_path: str = None):
        """
        Create database backup.

        Args:
            backup_path: Path to save backup file
        """
        import subprocess
        from datetime import datetime

        if not backup_path:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = f"catnet_backup_{timestamp}.sql"

        logger.info(f"Creating database backup to {backup_path}...")

        # Parse connection details from DATABASE_URL
        db_url_parts = self.settings.DATABASE_URL.split('/')
        db_name = db_url_parts[-1].split('?')[0]

        # Run pg_dump
        try:
            subprocess.run([
                'pg_dump',
                '-d', db_name,
                '-f', backup_path,
                '--verbose',
                '--no-owner',
                '--no-acl'
            ], check=True)

            logger.info(f"Backup created successfully: {backup_path}")
            return backup_path

        except subprocess.CalledProcessError as e:
            logger.error(f"Backup failed: {e}")
            raise

    async def restore_backup(self, backup_path: str):
        """
        Restore database from backup.

        Args:
            backup_path: Path to backup file
        """
        import subprocess

        logger.info(f"Restoring database from {backup_path}...")

        # Parse connection details from DATABASE_URL
        db_url_parts = self.settings.DATABASE_URL.split('/')
        db_name = db_url_parts[-1].split('?')[0]

        # Run psql
        try:
            subprocess.run([
                'psql',
                '-d', db_name,
                '-f', backup_path,
                '--verbose'
            ], check=True)

            logger.info("Database restored successfully!")

        except subprocess.CalledProcessError as e:
            logger.error(f"Restore failed: {e}")
            raise


async def main():
    """Main initialization function."""
    import argparse

    parser = argparse.ArgumentParser(description='CatNet Database Initialization')
    parser.add_argument('--drop', action='store_true', help='Drop existing tables')
    parser.add_argument('--migrate', action='store_true', help='Run migrations')
    parser.add_argument('--backup', type=str, help='Create backup to specified file')
    parser.add_argument('--restore', type=str, help='Restore from specified file')

    args = parser.parse_args()

    initializer = DatabaseInitializer()

    try:
        if args.backup:
            await initializer.create_backup(args.backup)
        elif args.restore:
            await initializer.restore_backup(args.restore)
        elif args.migrate:
            await initializer.run_migrations()
        else:
            await initializer.init_database(drop_existing=args.drop)

    except Exception as e:
        logger.error(f"Operation failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())


# Export main components
__all__ = ['DatabaseInitializer']
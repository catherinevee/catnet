"""
Database migrations management module for CatNet
"""
import asyncio
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from pathlib import Path
import hashlib
import json

from sqlalchemy import text, MetaData, Table, Column, String, DateTime, Integer, Boolean
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.operations import Operations

from ..core.config import settings
from ..core.exceptions import DatabaseError

logger = logging.getLogger(__name__)


class MigrationManager:
    """Manages database migrations and schema versioning"""

    def __init__(self):
        self.alembic_cfg = Config("alembic.ini")
        self.engine = None
        self.metadata = MetaData()
        self._initialize_migrations_table()

    def _initialize_migrations_table(self):
        """Create migrations tracking table if not exists"""
        self.migrations_table = Table(
            'catnet_migrations',
            self.metadata,
            Column('id', Integer, primary_key=True),
            Column('migration_id', String(255), unique=True, nullable=False),
            Column('description', String(500)),
            Column('applied_at', DateTime, default=datetime.utcnow),
            Column('checksum', String(64), nullable=False),
            Column('success', Boolean, default=True),
            Column('error_message', String(1000)),
            Column('rollback_available', Boolean, default=True),
            Column('applied_by', String(100))
        )

    async def initialize(self):
        """Initialize the migration manager"""
        self.engine = create_async_engine(
            settings.database_url,
            echo=settings.debug,
            pool_pre_ping=True
        )

        # Create migrations table if not exists
        async with self.engine.begin() as conn:
            await conn.run_sync(self.metadata.create_all)

    async def get_current_version(self) -> Optional[str]:
        """Get current database schema version"""
        try:
            async with self.engine.begin() as conn:
                result = await conn.execute(
                    text("SELECT version_num FROM alembic_version LIMIT 1")
                )
                row = result.first()
                return row[0] if row else None
        except Exception as e:
            logger.error(f"Error getting current version: {e}")
            return None

    async def get_pending_migrations(self) -> List[Dict[str, Any]]:
        """Get list of pending migrations"""
        try:
            current_version = await self.get_current_version()

            # Get all migration files
            migrations_dir = Path("alembic/versions")
            migration_files = sorted(migrations_dir.glob("*.py"))

            pending = []
            for file in migration_files:
                # Parse migration file
                migration_info = self._parse_migration_file(file)

                # Check if already applied
                if not await self._is_migration_applied(migration_info['revision']):
                    pending.append(migration_info)

            return pending

        except Exception as e:
            logger.error(f"Error getting pending migrations: {e}")
            return []

    def _parse_migration_file(self, file_path: Path) -> Dict[str, Any]:
        """Parse migration file to extract metadata"""
        content = file_path.read_text()

        # Extract revision
        revision = None
        down_revision = None
        branch_labels = None
        depends_on = None
        message = ""

        for line in content.split('\n'):
            if line.startswith('revision ='):
                revision = eval(line.split('=')[1].strip())
            elif line.startswith('down_revision ='):
                down_revision = eval(line.split('=')[1].strip())
            elif line.startswith('branch_labels ='):
                branch_labels = eval(line.split('=')[1].strip())
            elif line.startswith('depends_on ='):
                depends_on = eval(line.split('=')[1].strip())
            elif '"""' in line and message == "":
                # Extract message from docstring
                start = content.find('"""')
                end = content.find('"""', start + 3)
                if start != -1 and end != -1:
                    message = content[start + 3:end].strip()

        return {
            'revision': revision,
            'down_revision': down_revision,
            'branch_labels': branch_labels,
            'depends_on': depends_on,
            'message': message,
            'file_path': str(file_path),
            'checksum': hashlib.sha256(content.encode()).hexdigest()
        }

    async def _is_migration_applied(self, migration_id: str) -> bool:
        """Check if a migration has been applied"""
        try:
            async with self.engine.begin() as conn:
                result = await conn.execute(
                    text("SELECT 1 FROM catnet_migrations WHERE migration_id = :migration_id"),
                    {"migration_id": migration_id}
                )
                return result.first() is not None
        except Exception:
            return False

    async def apply_migration(self, migration_id: str, user: Optional[str] = None) -> bool:
        """Apply a specific migration"""
        try:
            logger.info(f"Applying migration: {migration_id}")

            # Record migration start
            async with self.engine.begin() as conn:
                await conn.execute(
                    text("""
                        INSERT INTO catnet_migrations
                        (migration_id, description, applied_at, checksum, success, applied_by)
                        VALUES (:migration_id, :description, :applied_at, :checksum, :success, :applied_by)
                    """),
                    {
                        "migration_id": migration_id,
                        "description": f"Applying migration {migration_id}",
                        "applied_at": datetime.utcnow(),
                        "checksum": "",
                        "success": False,
                        "applied_by": user or "system"
                    }
                )

            # Run Alembic migration
            command.upgrade(self.alembic_cfg, migration_id)

            # Update migration status
            async with self.engine.begin() as conn:
                await conn.execute(
                    text("""
                        UPDATE catnet_migrations
                        SET success = true
                        WHERE migration_id = :migration_id
                    """),
                    {"migration_id": migration_id}
                )

            logger.info(f"Migration {migration_id} applied successfully")
            return True

        except Exception as e:
            logger.error(f"Failed to apply migration {migration_id}: {e}")

            # Record failure
            async with self.engine.begin() as conn:
                await conn.execute(
                    text("""
                        UPDATE catnet_migrations
                        SET success = false, error_message = :error
                        WHERE migration_id = :migration_id
                    """),
                    {
                        "migration_id": migration_id,
                        "error": str(e)
                    }
                )

            return False

    async def rollback_migration(self, migration_id: str, user: Optional[str] = None) -> bool:
        """Rollback a specific migration"""
        try:
            logger.info(f"Rolling back migration: {migration_id}")

            # Check if rollback is available
            async with self.engine.begin() as conn:
                result = await conn.execute(
                    text("""
                        SELECT rollback_available
                        FROM catnet_migrations
                        WHERE migration_id = :migration_id
                    """),
                    {"migration_id": migration_id}
                )
                row = result.first()
                if not row or not row[0]:
                    logger.error(f"Rollback not available for migration {migration_id}")
                    return False

            # Run Alembic downgrade
            command.downgrade(self.alembic_cfg, "-1")

            # Update migration status
            async with self.engine.begin() as conn:
                await conn.execute(
                    text("""
                        DELETE FROM catnet_migrations
                        WHERE migration_id = :migration_id
                    """),
                    {"migration_id": migration_id}
                )

            logger.info(f"Migration {migration_id} rolled back successfully")
            return True

        except Exception as e:
            logger.error(f"Failed to rollback migration {migration_id}: {e}")
            return False

    async def apply_all_pending(self, user: Optional[str] = None) -> Dict[str, Any]:
        """Apply all pending migrations"""
        results = {
            'total': 0,
            'success': 0,
            'failed': 0,
            'migrations': []
        }

        pending = await self.get_pending_migrations()
        results['total'] = len(pending)

        for migration in pending:
            success = await self.apply_migration(migration['revision'], user)

            if success:
                results['success'] += 1
            else:
                results['failed'] += 1
                # Stop on first failure
                break

            results['migrations'].append({
                'id': migration['revision'],
                'success': success,
                'message': migration.get('message', '')
            })

        return results

    async def create_migration(self, message: str) -> str:
        """Create a new migration"""
        try:
            # Generate migration using Alembic
            command.revision(self.alembic_cfg, message=message, autogenerate=True)

            # Get the newly created migration
            migrations_dir = Path("alembic/versions")
            latest_file = max(migrations_dir.glob("*.py"), key=lambda f: f.stat().st_mtime)

            migration_info = self._parse_migration_file(latest_file)

            logger.info(f"Created migration: {migration_info['revision']} - {message}")
            return migration_info['revision']

        except Exception as e:
            logger.error(f"Failed to create migration: {e}")
            raise DatabaseError(f"Failed to create migration: {str(e)}")

    async def validate_schema(self) -> Dict[str, Any]:
        """Validate database schema integrity"""
        validation_results = {
            'valid': True,
            'errors': [],
            'warnings': [],
            'tables': {},
            'version': await self.get_current_version()
        }

        try:
            async with self.engine.begin() as conn:
                # Get all tables
                result = await conn.execute(
                    text("""
                        SELECT table_name
                        FROM information_schema.tables
                        WHERE table_schema = 'public'
                    """)
                )
                tables = [row[0] for row in result]

                # Expected tables from models
                expected_tables = [
                    'users', 'roles', 'user_roles', 'sessions',
                    'devices', 'device_configs', 'device_groups',
                    'deployments', 'deployment_devices', 'deployment_approvers',
                    'git_repositories', 'tasks', 'audit_logs',
                    'compliance_rules', 'catnet_migrations', 'alembic_version'
                ]

                # Check for missing tables
                missing_tables = set(expected_tables) - set(tables)
                if missing_tables:
                    validation_results['valid'] = False
                    validation_results['errors'].append(
                        f"Missing tables: {', '.join(missing_tables)}"
                    )

                # Check for unexpected tables
                unexpected_tables = set(tables) - set(expected_tables)
                if unexpected_tables:
                    validation_results['warnings'].append(
                        f"Unexpected tables: {', '.join(unexpected_tables)}"
                    )

                # Validate each table structure
                for table in tables:
                    if table in expected_tables:
                        table_valid = await self._validate_table_structure(conn, table)
                        validation_results['tables'][table] = table_valid

        except Exception as e:
            validation_results['valid'] = False
            validation_results['errors'].append(f"Schema validation failed: {str(e)}")

        return validation_results

    async def _validate_table_structure(self, conn, table_name: str) -> Dict[str, Any]:
        """Validate individual table structure"""
        table_info = {
            'valid': True,
            'columns': {},
            'indexes': [],
            'constraints': []
        }

        try:
            # Get columns
            result = await conn.execute(
                text("""
                    SELECT column_name, data_type, is_nullable, column_default
                    FROM information_schema.columns
                    WHERE table_name = :table_name
                """),
                {"table_name": table_name}
            )

            for row in result:
                table_info['columns'][row[0]] = {
                    'type': row[1],
                    'nullable': row[2] == 'YES',
                    'default': row[3]
                }

            # Get indexes
            result = await conn.execute(
                text("""
                    SELECT indexname, indexdef
                    FROM pg_indexes
                    WHERE tablename = :table_name
                """),
                {"table_name": table_name}
            )

            for row in result:
                table_info['indexes'].append({
                    'name': row[0],
                    'definition': row[1]
                })

            # Get constraints
            result = await conn.execute(
                text("""
                    SELECT conname, contype
                    FROM pg_constraint
                    JOIN pg_class ON pg_constraint.conrelid = pg_class.oid
                    WHERE relname = :table_name
                """),
                {"table_name": table_name}
            )

            for row in result:
                constraint_type = {
                    'p': 'PRIMARY KEY',
                    'f': 'FOREIGN KEY',
                    'u': 'UNIQUE',
                    'c': 'CHECK'
                }.get(row[1], row[1])

                table_info['constraints'].append({
                    'name': row[0],
                    'type': constraint_type
                })

        except Exception as e:
            table_info['valid'] = False
            table_info['error'] = str(e)

        return table_info

    async def backup_schema(self, backup_path: Path) -> bool:
        """Backup database schema"""
        try:
            schema_data = {
                'timestamp': datetime.utcnow().isoformat(),
                'version': await self.get_current_version(),
                'schema': {}
            }

            async with self.engine.begin() as conn:
                # Get all table definitions
                result = await conn.execute(
                    text("""
                        SELECT table_name
                        FROM information_schema.tables
                        WHERE table_schema = 'public'
                    """)
                )

                for row in result:
                    table_name = row[0]
                    table_info = await self._validate_table_structure(conn, table_name)
                    schema_data['schema'][table_name] = table_info

            # Write to file
            backup_path.parent.mkdir(parents=True, exist_ok=True)
            with open(backup_path, 'w') as f:
                json.dump(schema_data, f, indent=2, default=str)

            logger.info(f"Schema backed up to {backup_path}")
            return True

        except Exception as e:
            logger.error(f"Failed to backup schema: {e}")
            return False

    async def get_migration_history(self) -> List[Dict[str, Any]]:
        """Get migration history"""
        try:
            async with self.engine.begin() as conn:
                result = await conn.execute(
                    text("""
                        SELECT migration_id, description, applied_at, success, error_message, applied_by
                        FROM catnet_migrations
                        ORDER BY applied_at DESC
                    """)
                )

                history = []
                for row in result:
                    history.append({
                        'migration_id': row[0],
                        'description': row[1],
                        'applied_at': row[2].isoformat() if row[2] else None,
                        'success': row[3],
                        'error_message': row[4],
                        'applied_by': row[5]
                    })

                return history

        except Exception as e:
            logger.error(f"Failed to get migration history: {e}")
            return []

    async def cleanup_old_migrations(self, days: int = 90) -> int:
        """Clean up old successful migration records"""
        try:
            cutoff_date = datetime.utcnow() - timedelta(days=days)

            async with self.engine.begin() as conn:
                result = await conn.execute(
                    text("""
                        DELETE FROM catnet_migrations
                        WHERE success = true
                        AND applied_at < :cutoff_date
                        AND migration_id NOT IN (
                            SELECT version_num FROM alembic_version
                        )
                    """),
                    {"cutoff_date": cutoff_date}
                )

                deleted_count = result.rowcount
                logger.info(f"Cleaned up {deleted_count} old migration records")
                return deleted_count

        except Exception as e:
            logger.error(f"Failed to cleanup old migrations: {e}")
            return 0


# Global migration manager instance
migration_manager = MigrationManager()


# Convenience functions
async def apply_migrations(user: Optional[str] = None) -> Dict[str, Any]:
    """Apply all pending migrations"""
    await migration_manager.initialize()
    return await migration_manager.apply_all_pending(user)


async def create_migration(message: str) -> str:
    """Create a new migration"""
    await migration_manager.initialize()
    return await migration_manager.create_migration(message)


async def validate_database_schema() -> Dict[str, Any]:
    """Validate database schema"""
    await migration_manager.initialize()
    return await migration_manager.validate_schema()


async def get_migration_status() -> Dict[str, Any]:
    """Get current migration status"""
    await migration_manager.initialize()

    current_version = await migration_manager.get_current_version()
    pending = await migration_manager.get_pending_migrations()
    history = await migration_manager.get_migration_history()

    return {
        'current_version': current_version,
        'pending_count': len(pending),
        'pending_migrations': pending,
        'recent_history': history[:10]
    }
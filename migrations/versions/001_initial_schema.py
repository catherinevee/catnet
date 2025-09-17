"""Initial database schema

Revision ID: 001
Revises:
Create Date: 2024-01-01 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '001'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create users table
    op.create_table('users',
        sa.Column('id', postgresql.UUID(), nullable=False),
        sa.Column('username', sa.String(100), nullable=False),
        sa.Column('email', sa.String(255), nullable=False),
        sa.Column('password_hash', sa.String(255), nullable=False),
        sa.Column('is_active', sa.Boolean(), default=True),
        sa.Column('is_superuser', sa.Boolean(), default=False),
        sa.Column('mfa_secret', sa.String(255), nullable=True),
        sa.Column('roles', postgresql.ARRAY(sa.String), nullable=True),
        sa.Column('failed_login_attempts', sa.Integer(), default=0),
        sa.Column('locked_until', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), onupdate=sa.text('now()'), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('username'),
        sa.UniqueConstraint('email')
    )

    # Create devices table
    op.create_table('devices',
        sa.Column('id', postgresql.UUID(), nullable=False),
        sa.Column('hostname', sa.String(255), nullable=False),
        sa.Column('ip_address', sa.String(45), nullable=False),
        sa.Column('vendor', sa.String(50), nullable=False),
        sa.Column('model', sa.String(100), nullable=True),
        sa.Column('os_version', sa.String(100), nullable=True),
        sa.Column('serial_number', sa.String(100), nullable=True),
        sa.Column('location', sa.String(255), nullable=True),
        sa.Column('status', sa.String(50), default='active'),
        sa.Column('last_backup', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_seen', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), onupdate=sa.text('now()'), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('hostname'),
        sa.UniqueConstraint('ip_address')
    )

    # Create deployments table
    op.create_table('deployments',
        sa.Column('id', postgresql.UUID(), nullable=False),
        sa.Column('created_by', postgresql.UUID(), nullable=False),
        sa.Column('config_hash', sa.String(64), nullable=False),
        sa.Column('signature', sa.Text(), nullable=False),
        sa.Column('encryption_key_id', sa.String(128), nullable=True),
        sa.Column('state', sa.String(50), nullable=False),
        sa.Column('approved_by', postgresql.ARRAY(postgresql.UUID), default='{}'),
        sa.Column('audit_log', postgresql.JSONB(), nullable=False, default='{}'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['created_by'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id')
    )

    # Create git_repositories table
    op.create_table('git_repositories',
        sa.Column('id', postgresql.UUID(), nullable=False),
        sa.Column('url', sa.Text(), nullable=False),
        sa.Column('branch', sa.String(100), default='main'),
        sa.Column('webhook_secret_ref', sa.String(256), nullable=True),
        sa.Column('last_commit_hash', sa.String(40), nullable=True),
        sa.Column('gpg_verification', sa.Boolean(), default=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )

    # Create device_configs table
    op.create_table('device_configs',
        sa.Column('id', postgresql.UUID(), nullable=False),
        sa.Column('device_id', postgresql.UUID(), nullable=False),
        sa.Column('config_encrypted', sa.Text(), nullable=False),
        sa.Column('backup_location', sa.Text(), nullable=False),
        sa.Column('version', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['device_id'], ['devices.id'], ),
        sa.PrimaryKeyConstraint('id')
    )

    # Create audit_logs table
    op.create_table('audit_logs',
        sa.Column('id', postgresql.UUID(), nullable=False),
        sa.Column('user_id', postgresql.UUID(), nullable=True),
        sa.Column('action', sa.String(100), nullable=False),
        sa.Column('resource_type', sa.String(50), nullable=True),
        sa.Column('resource_id', sa.String(100), nullable=True),
        sa.Column('details', postgresql.JSONB(), nullable=True),
        sa.Column('ip_address', sa.String(45), nullable=True),
        sa.Column('user_agent', sa.String(255), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id')
    )

    # Create indexes
    op.create_index('idx_audit_logs_created_at', 'audit_logs', ['created_at'])
    op.create_index('idx_audit_logs_user_id', 'audit_logs', ['user_id'])
    op.create_index('idx_deployments_state', 'deployments', ['state'])
    op.create_index('idx_devices_status', 'devices', ['status'])


def downgrade() -> None:
    op.drop_index('idx_devices_status', 'devices')
    op.drop_index('idx_deployments_state', 'deployments')
    op.drop_index('idx_audit_logs_user_id', 'audit_logs')
    op.drop_index('idx_audit_logs_created_at', 'audit_logs')
    op.drop_table('audit_logs')
    op.drop_table('device_configs')
    op.drop_table('git_repositories')
    op.drop_table('deployments')
    op.drop_table('devices')
    op.drop_table('users')
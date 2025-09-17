"""Add certificate fields to devices table

Revision ID: 002
Revises: 001
Create Date: 2025-09-17
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers
revision = '002'
down_revision = '001'
branch_labels = None
depends_on = None


def upgrade():
    """Add certificate-related fields to devices table"""

    # Add certificate fields to devices table
    op.add_column('devices', sa.Column('certificate_serial', sa.String(255), nullable=True))
    op.add_column('devices', sa.Column('certificate_expires_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('devices', sa.Column('certificate_fingerprint', sa.String(128), nullable=True))
    op.add_column('devices', sa.Column('certificate_status', sa.String(50), nullable=True, server_default='pending'))
    op.add_column('devices', sa.Column('certificate_issued_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('devices', sa.Column('certificate_revoked_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('devices', sa.Column('certificate_revocation_reason', sa.String(255), nullable=True))

    # Add indexes for certificate lookups
    op.create_index('ix_devices_certificate_serial', 'devices', ['certificate_serial'])
    op.create_index('ix_devices_certificate_fingerprint', 'devices', ['certificate_fingerprint'])
    op.create_index('ix_devices_certificate_status', 'devices', ['certificate_status'])

    # Add certificate fields to users table for GPG/signing certificates
    op.add_column('users', sa.Column('signing_key_id', sa.String(255), nullable=True))
    op.add_column('users', sa.Column('signing_key_fingerprint', sa.String(128), nullable=True))
    op.add_column('users', sa.Column('signing_key_created_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('users', sa.Column('signing_key_expires_at', sa.DateTime(timezone=True), nullable=True))

    # Add signature fields to deployments table
    op.add_column('deployments', sa.Column('config_signature', sa.Text(), nullable=True))
    op.add_column('deployments', sa.Column('signed_by', postgresql.UUID(as_uuid=True), nullable=True))
    op.add_column('deployments', sa.Column('signature_verified', sa.Boolean(), nullable=True, server_default='false'))
    op.add_column('deployments', sa.Column('signature_timestamp', sa.DateTime(timezone=True), nullable=True))

    # Add foreign key for signed_by
    op.create_foreign_key(
        'fk_deployments_signed_by_user',
        'deployments', 'users',
        ['signed_by'], ['id'],
        ondelete='SET NULL'
    )


def downgrade():
    """Remove certificate-related fields"""

    # Drop foreign key
    op.drop_constraint('fk_deployments_signed_by_user', 'deployments', type_='foreignkey')

    # Drop indexes
    op.drop_index('ix_devices_certificate_status', 'devices')
    op.drop_index('ix_devices_certificate_fingerprint', 'devices')
    op.drop_index('ix_devices_certificate_serial', 'devices')

    # Remove columns from deployments
    op.drop_column('deployments', 'signature_timestamp')
    op.drop_column('deployments', 'signature_verified')
    op.drop_column('deployments', 'signed_by')
    op.drop_column('deployments', 'config_signature')

    # Remove columns from users
    op.drop_column('users', 'signing_key_expires_at')
    op.drop_column('users', 'signing_key_created_at')
    op.drop_column('users', 'signing_key_fingerprint')
    op.drop_column('users', 'signing_key_id')

    # Remove columns from devices
    op.drop_column('devices', 'certificate_revocation_reason')
    op.drop_column('devices', 'certificate_revoked_at')
    op.drop_column('devices', 'certificate_issued_at')
    op.drop_column('devices', 'certificate_status')
    op.drop_column('devices', 'certificate_fingerprint')
    op.drop_column('devices', 'certificate_expires_at')
    op.drop_column('devices', 'certificate_serial')
-- CatNet Database Initialization Script
-- Creates necessary extensions and initial schema

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "pg_stat_statements";

-- Create audit schema for separation
CREATE SCHEMA IF NOT EXISTS audit;

-- Create enum types
CREATE TYPE deployment_status AS ENUM (
    'pending',
    'approved',
    'running',
    'completed',
    'failed',
    'rolled_back',
    'cancelled'
);

CREATE TYPE deployment_strategy AS ENUM (
    'rolling',
    'canary',
    'blue_green',
    'immediate'
);

CREATE TYPE device_vendor AS ENUM (
    'cisco',
    'juniper',
    'arista',
    'unknown'
);

CREATE TYPE device_platform AS ENUM (
    'ios',
    'ios_xe',
    'nxos',
    'junos',
    'eos',
    'unknown'
);

CREATE TYPE device_status AS ENUM (
    'active',
    'inactive',
    'maintenance',
    'unreachable',
    'unknown'
);

CREATE TYPE audit_event_type AS ENUM (
    'authentication',
    'authorization',
    'device_access',
    'configuration_change',
    'deployment',
    'security_violation',
    'system_event'
);

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    is_active BOOLEAN DEFAULT true,
    is_superuser BOOLEAN DEFAULT false,
    mfa_enabled BOOLEAN DEFAULT false,
    mfa_secret VARCHAR(32),
    last_login TIMESTAMPTZ,
    failed_login_attempts INTEGER DEFAULT 0,
    locked_until TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- User sessions table
CREATE TABLE IF NOT EXISTS user_sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_token VARCHAR(255) UNIQUE NOT NULL,
    refresh_token VARCHAR(255) UNIQUE,
    ip_address INET,
    user_agent TEXT,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    last_activity TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- Devices table
CREATE TABLE IF NOT EXISTS devices (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(100) NOT NULL,
    hostname VARCHAR(255) UNIQUE NOT NULL,
    ip_address INET NOT NULL,
    vendor device_vendor NOT NULL DEFAULT 'unknown',
    platform device_platform NOT NULL DEFAULT 'unknown',
    os_version VARCHAR(100),
    model VARCHAR(100),
    serial_number VARCHAR(100),
    location VARCHAR(255),
    rack_position VARCHAR(50),
    management_ip INET,
    ssh_port INTEGER DEFAULT 22,
    snmp_community_ref VARCHAR(255), -- Vault reference
    ssh_key_ref VARCHAR(255),        -- Vault reference
    status device_status DEFAULT 'unknown',
    last_backup TIMESTAMPTZ,
    last_health_check TIMESTAMPTZ,
    health_score FLOAT DEFAULT 0,
    tags JSONB DEFAULT '{}',
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- Git repositories table
CREATE TABLE IF NOT EXISTS git_repositories (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(100) NOT NULL,
    url TEXT NOT NULL,
    branch VARCHAR(100) DEFAULT 'main',
    webhook_secret_ref VARCHAR(255), -- Vault reference
    deploy_key_ref VARCHAR(255),     -- Vault reference
    last_commit_hash VARCHAR(40),
    last_sync TIMESTAMPTZ,
    auto_deploy BOOLEAN DEFAULT false,
    require_approval BOOLEAN DEFAULT true,
    gpg_verification BOOLEAN DEFAULT true,
    scan_secrets BOOLEAN DEFAULT true,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- Device configurations table
CREATE TABLE IF NOT EXISTS device_configs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    config_type VARCHAR(50) NOT NULL DEFAULT 'running',
    config_hash VARCHAR(64) NOT NULL, -- SHA-256
    config_encrypted TEXT NOT NULL,   -- Encrypted content
    encryption_key_ref VARCHAR(255),  -- Vault key reference
    backup_location TEXT,
    size_bytes BIGINT,
    version INTEGER NOT NULL DEFAULT 1,
    is_current BOOLEAN DEFAULT false,
    checksum VARCHAR(64),
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- Deployments table
CREATE TABLE IF NOT EXISTS deployments (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(100) NOT NULL,
    description TEXT,
    git_repository_id UUID REFERENCES git_repositories(id),
    commit_hash VARCHAR(40),
    strategy deployment_strategy DEFAULT 'rolling',
    status deployment_status DEFAULT 'pending',
    device_filter JSONB,  -- Device selection criteria
    config_files JSONB,   -- List of configuration files
    rollback_plan JSONB,  -- Rollback configuration
    approval_required BOOLEAN DEFAULT true,
    approved_by UUID[] DEFAULT '{}',
    auto_rollback BOOLEAN DEFAULT true,
    rollback_threshold FLOAT DEFAULT 0.1, -- 10% failure threshold
    canary_percentage INTEGER DEFAULT 5,
    wait_between_batches INTEGER DEFAULT 300, -- 5 minutes
    total_devices INTEGER DEFAULT 0,
    successful_devices INTEGER DEFAULT 0,
    failed_devices INTEGER DEFAULT 0,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    error_message TEXT,
    created_by UUID NOT NULL REFERENCES users(id),
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- Deployment device status table
CREATE TABLE IF NOT EXISTS deployment_devices (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    deployment_id UUID NOT NULL REFERENCES deployments(id) ON DELETE CASCADE,
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    status deployment_status DEFAULT 'pending',
    batch_number INTEGER DEFAULT 1,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    backup_config_id UUID REFERENCES device_configs(id),
    error_message TEXT,
    retry_count INTEGER DEFAULT 0,
    rollback_completed BOOLEAN DEFAULT false,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(deployment_id, device_id)
);

-- Audit log table
CREATE TABLE audit.audit_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    event_type audit_event_type NOT NULL,
    user_id UUID REFERENCES users(id),
    session_id UUID,
    device_id UUID REFERENCES devices(id),
    deployment_id UUID REFERENCES deployments(id),
    ip_address INET,
    user_agent TEXT,
    resource_type VARCHAR(100),
    resource_id VARCHAR(255),
    action VARCHAR(100) NOT NULL,
    result VARCHAR(50) NOT NULL, -- success, failure, denied
    details JSONB DEFAULT '{}',
    security_classification VARCHAR(20) DEFAULT 'internal',
    retention_period INTEGER DEFAULT 2555, -- days
    hash_chain VARCHAR(64), -- For immutability verification
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL
);

-- Rate limiting table
CREATE TABLE IF NOT EXISTS rate_limits (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    key VARCHAR(255) NOT NULL,
    count INTEGER NOT NULL DEFAULT 1,
    window_start TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(key, window_start)
);

-- API keys table
CREATE TABLE IF NOT EXISTS api_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(100) NOT NULL,
    key_hash VARCHAR(255) UNIQUE NOT NULL,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    permissions JSONB DEFAULT '[]',
    last_used TIMESTAMPTZ,
    usage_count BIGINT DEFAULT 0,
    is_active BOOLEAN DEFAULT true,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_is_active ON users(is_active);

CREATE INDEX IF NOT EXISTS idx_user_sessions_user_id ON user_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_user_sessions_token ON user_sessions(session_token);
CREATE INDEX IF NOT EXISTS idx_user_sessions_expires_at ON user_sessions(expires_at);

CREATE INDEX IF NOT EXISTS idx_devices_hostname ON devices(hostname);
CREATE INDEX IF NOT EXISTS idx_devices_ip_address ON devices(ip_address);
CREATE INDEX IF NOT EXISTS idx_devices_vendor ON devices(vendor);
CREATE INDEX IF NOT EXISTS idx_devices_status ON devices(status);
CREATE INDEX IF NOT EXISTS idx_devices_tags ON devices USING GIN(tags);

CREATE INDEX IF NOT EXISTS idx_device_configs_device_id ON device_configs(device_id);
CREATE INDEX IF NOT EXISTS idx_device_configs_hash ON device_configs(config_hash);
CREATE INDEX IF NOT EXISTS idx_device_configs_current ON device_configs(device_id, is_current);

CREATE INDEX IF NOT EXISTS idx_deployments_status ON deployments(status);
CREATE INDEX IF NOT EXISTS idx_deployments_created_by ON deployments(created_by);
CREATE INDEX IF NOT EXISTS idx_deployments_git_repo ON deployments(git_repository_id);

CREATE INDEX IF NOT EXISTS idx_deployment_devices_deployment ON deployment_devices(deployment_id);
CREATE INDEX IF NOT EXISTS idx_deployment_devices_device ON deployment_devices(device_id);
CREATE INDEX IF NOT EXISTS idx_deployment_devices_status ON deployment_devices(status);

CREATE INDEX IF NOT EXISTS idx_audit_log_user_id ON audit.audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_event_type ON audit.audit_log(event_type);
CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON audit.audit_log(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_log_device_id ON audit.audit_log(device_id);

CREATE INDEX IF NOT EXISTS idx_rate_limits_key ON rate_limits(key);
CREATE INDEX IF NOT EXISTS idx_rate_limits_expires_at ON rate_limits(expires_at);

CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON api_keys(user_id);

-- Create triggers for updated_at
CREATE TRIGGER update_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_devices_updated_at
    BEFORE UPDATE ON devices
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_git_repositories_updated_at
    BEFORE UPDATE ON git_repositories
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_deployments_updated_at
    BEFORE UPDATE ON deployments
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_deployment_devices_updated_at
    BEFORE UPDATE ON deployment_devices
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Create default admin user (password: admin123 - CHANGE IN PRODUCTION!)
INSERT INTO users (
    username,
    email,
    password_hash,
    first_name,
    last_name,
    is_active,
    is_superuser,
    mfa_enabled
) VALUES (
    'admin',
    'admin@catnet.local',
    '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LZ.rBxrGKZbwS/O3C', -- admin123
    'CatNet',
    'Administrator',
    true,
    true,
    false
) ON CONFLICT (username) DO NOTHING;

-- Create cleanup function for old sessions and rate limits
CREATE OR REPLACE FUNCTION cleanup_expired_data()
RETURNS void AS $$
BEGIN
    -- Clean up expired sessions
    DELETE FROM user_sessions WHERE expires_at < CURRENT_TIMESTAMP;

    -- Clean up old rate limit entries
    DELETE FROM rate_limits WHERE expires_at < CURRENT_TIMESTAMP;

    -- Clean up old audit logs based on retention period
    DELETE FROM audit.audit_log
    WHERE created_at < CURRENT_TIMESTAMP - INTERVAL '1 day' * retention_period;
END;
$$ LANGUAGE plpgsql;

-- Grant permissions
GRANT USAGE ON SCHEMA audit TO catnet;
GRANT SELECT, INSERT ON audit.audit_log TO catnet;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO catnet;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO catnet;
#!/bin/bash
# CatNet Production Entrypoint Script
set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Wait for service to be ready
wait_for_service() {
    local host=$1
    local port=$2
    local service=$3
    local max_attempts=30
    local attempt=1

    log_info "Waiting for $service to be ready..."

    while [ $attempt -le $max_attempts ]; do
        if nc -z "$host" "$port" 2>/dev/null; then
            log_info "$service is ready!"
            return 0
        fi

        echo -n "."
        sleep 2
        attempt=$((attempt + 1))
    done

    log_error "$service failed to become ready"
    return 1
}

# Validate required environment variables
validate_environment() {
    log_info "Validating environment configuration..."

    required_vars=(
        "POSTGRES_HOST"
        "POSTGRES_PORT"
        "POSTGRES_DB"
        "POSTGRES_USER"
        "VAULT_URL"
    )

    for var in "${required_vars[@]}"; do
        if [ -z "${!var}" ]; then
            log_error "Required environment variable $var is not set"
            exit 1
        fi
    done

    log_info "Environment validation passed"
}

# Initialize Vault secrets
init_vault() {
    log_info "Initializing Vault connection..."

    if [ -n "$VAULT_TOKEN" ]; then
        export VAULT_TOKEN

        # Check Vault health
        if python -c "from src.security.vault import VaultClient; v = VaultClient(); exit(0 if v.health_check() else 1)"; then
            log_info "Vault connection established"

            # Initialize required secrets if not present
            python <<EOF
from src.security.vault import VaultClient
import secrets

vault = VaultClient()

# Ensure encryption keys exist
try:
    vault.get_encryption_key("catnet-configs")
except:
    # Key doesn't exist, will be created on first use
    pass

try:
    vault.get_encryption_key("catnet-backups")
except:
    # Key doesn't exist, will be created on first use
    pass

print("Vault initialization complete")
EOF
        else
            log_warn "Vault connection failed - running without secret management"
        fi
    else
        log_warn "VAULT_TOKEN not set - running without Vault integration"
    fi
}

# Run database migrations
run_migrations() {
    log_info "Running database migrations..."

    # Wait for database to be ready
    wait_for_service "${POSTGRES_HOST}" "${POSTGRES_PORT}" "PostgreSQL"

    # Run Alembic migrations
    if alembic upgrade head; then
        log_info "Database migrations completed successfully"
    else
        log_error "Database migration failed"
        exit 1
    fi

    # Initialize database with default data if needed
    python <<EOF
import asyncio
from src.db.database import database
from src.db.models import User, UserRole
from sqlalchemy import select

async def init_default_data():
    await database.init()

    async with database.get_session() as session:
        # Check if admin user exists
        result = await session.execute(
            select(User).where(User.username == "admin")
        )
        admin = result.scalar_one_or_none()

        if not admin:
            from src.auth.auth_service import auth_service

            # Create default admin user
            admin = User(
                username="admin",
                email="admin@catnet.local",
                full_name="System Administrator",
                hashed_password=auth_service.get_password_hash("ChangeMeImmediately!"),
                role=UserRole.ADMIN,
                is_superuser=True,
                is_active=True
            )
            session.add(admin)
            await session.commit()
            print("Default admin user created (password: ChangeMeImmediately!)")
            print("WARNING: Change the admin password immediately!")

        print("Database initialization complete")

asyncio.run(init_default_data())
EOF
}

# Create required directories
setup_directories() {
    log_info "Setting up required directories..."

    directories=(
        "/app/logs"
        "/app/backups"
        "/app/tmp"
        "/app/data/vault"
        "/app/data/configs"
    )

    for dir in "${directories[@]}"; do
        if [ ! -d "$dir" ]; then
            mkdir -p "$dir"
            log_info "Created directory: $dir"
        fi
    done

    # Set proper permissions
    chmod 700 /app/data/vault
    chmod 700 /app/backups
    chmod 755 /app/logs
}

# Configure SSH for network device connections
setup_ssh() {
    log_info "Configuring SSH..."

    # Create SSH config if it doesn't exist
    if [ ! -f ~/.ssh/config ]; then
        cat > ~/.ssh/config <<EOF
Host *
    StrictHostKeyChecking accept-new
    UserKnownHostsFile ~/.ssh/known_hosts
    LogLevel ERROR
    ConnectTimeout 30
    ServerAliveInterval 60
    ServerAliveCountMax 3
    Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr
    MACs hmac-sha2-512,hmac-sha2-256
    KexAlgorithms curve25519-sha256,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256
EOF
        chmod 600 ~/.ssh/config
        log_info "SSH configuration created"
    fi
}

# Health check function
health_check() {
    # Check if the application responds to health endpoint
    if curl -f http://localhost:8080/api/v1/health >/dev/null 2>&1; then
        return 0
    else
        return 1
    fi
}

# Graceful shutdown handler
shutdown_handler() {
    log_info "Received shutdown signal, initiating graceful shutdown..."

    # Send SIGTERM to the application
    if [ -n "$APP_PID" ]; then
        kill -TERM "$APP_PID" 2>/dev/null || true

        # Wait for process to terminate
        wait "$APP_PID" 2>/dev/null || true
    fi

    log_info "Shutdown complete"
    exit 0
}

# Set up signal handlers
trap shutdown_handler SIGTERM SIGINT

# Main execution
main() {
    log_info "Starting CatNet application..."

    # Validate environment
    validate_environment

    # Setup directories
    setup_directories

    # Configure SSH
    setup_ssh

    # Initialize Vault
    init_vault

    # Run migrations
    run_migrations

    # Wait for Redis if configured
    if [ -n "$REDIS_HOST" ]; then
        wait_for_service "${REDIS_HOST}" "${REDIS_PORT:-6379}" "Redis"
    fi

    # Start the application
    log_info "Starting CatNet API server..."

    # Determine worker count based on CPU cores
    WORKERS=${WORKERS:-$(nproc --all)}

    # Start application in background to handle signals
    exec uvicorn src.api.app:app \
        --host 0.0.0.0 \
        --port ${PORT:-8080} \
        --workers ${WORKERS} \
        --loop uvloop \
        --log-level ${LOG_LEVEL:-info} \
        --access-log \
        --use-colors \
        --proxy-headers \
        --forwarded-allow-ips='*' &

    APP_PID=$!

    # Wait for application to start
    sleep 5

    # Perform initial health check
    max_health_checks=10
    health_check_count=0

    while [ $health_check_count -lt $max_health_checks ]; do
        if health_check; then
            log_info "Application is healthy and ready to serve requests"
            break
        fi

        health_check_count=$((health_check_count + 1))
        log_info "Waiting for application to become healthy... ($health_check_count/$max_health_checks)"
        sleep 3
    done

    if [ $health_check_count -eq $max_health_checks ]; then
        log_error "Application failed to become healthy"
        exit 1
    fi

    # Wait for the application process
    wait $APP_PID
}

# Run main function
main "$@"
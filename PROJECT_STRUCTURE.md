# CatNet Project Structure

## Root Directory Organization

```
catnet/
├── .github/                  # GitHub specific files
│   └── workflows/           # GitHub Actions CI/CD
├── configs/                 # Configuration files
│   ├── prometheus.yml       # Prometheus monitoring config
│   └── logging.yml         # Logging configuration
├── deployment/              # Deployment configurations
│   ├── ansible/            # Ansible playbooks
│   ├── kubernetes/         # K8s manifests
│   └── terraform/          # Infrastructure as Code
├── docs/                    # Documentation
│   ├── index.md            # Documentation home
│   ├── getting-started.md  # Quick start guide
│   ├── API_DOCUMENTATION.md
│   ├── SECURITY_ARCHITECTURE.md
│   ├── COMPLIANCE.md
│   └── RUNBOOKS.md
├── examples/                # Example configurations
│   ├── configs/            # Sample device configs
│   └── scripts/            # Example scripts
├── migrations/              # Database migrations
│   └── alembic/            # Alembic migration files
├── scripts/                 # Utility scripts
│   ├── create_admin.py     # Create admin user
│   ├── generate_ca.py      # Generate certificates
│   └── validate_pipeline.py
├── src/                     # Source code
│   ├── api/                # API endpoints
│   ├── auth/               # Authentication
│   ├── cli/                # CLI commands
│   ├── core/               # Core business logic
│   ├── db/                 # Database models
│   ├── deployment/         # Deployment logic
│   ├── devices/            # Device communication
│   ├── gitops/             # GitOps integration
│   ├── security/           # Security components
│   └── workers/            # Background workers
├── tests/                   # Test suite
│   ├── unit/               # Unit tests
│   ├── integration/        # Integration tests
│   └── e2e/                # End-to-end tests
├── .editorconfig           # Editor configuration
├── .env.example            # Environment template
├── .gitignore              # Git ignore rules
├── .gitleaks.toml          # Secret scanning config
├── .pre-commit-config.yaml # Pre-commit hooks
├── alembic.ini             # Alembic configuration
├── catnet_cli.py           # CLI entry point
├── CHANGELOG.md            # Version history
├── CLAUDE.md               # Project specification
├── CLAUDE-commandreference.txt
├── CONTRIBUTING.md         # Contribution guide
├── docker-compose.yml      # Docker services
├── Dockerfile              # Container image
├── LICENSE                 # MIT License
├── Makefile               # Build automation
├── PROJECT_STRUCTURE.md   # This file
├── pyproject.toml         # Python project config
├── pytest.ini             # Pytest configuration
├── README.md              # Project overview
├── requirements.txt       # Python dependencies
└── setup.py               # Package setup
```

## Key Directories Explained

### `/src` - Application Source Code

The main application code organized by domain:

- **`api/`**: RESTful API endpoints using FastAPI
- **`auth/`**: Authentication and authorization logic
- **`cli/`**: Command-line interface implementation
- **`core/`**: Core business logic and utilities
- **`db/`**: Database models and migrations
- **`deployment/`**: Deployment strategies and execution
- **`devices/`**: Network device communication layer
- **`gitops/`**: Git integration and webhook processing
- **`security/`**: Security components (encryption, vault, audit)
- **`workers/`**: Async background job processors

### `/tests` - Test Suite

Comprehensive testing structure:

- **`unit/`**: Individual component tests
- **`integration/`**: API and service integration tests
- **`e2e/`**: End-to-end workflow tests

### `/deployment` - Infrastructure Code

Deployment configurations for different platforms:

- **`ansible/`**: Ansible playbooks for deployment
- **`kubernetes/`**: K8s manifests and Helm charts
- **`terraform/`**: Infrastructure as Code definitions

### `/docs` - Documentation

Complete documentation set:

- User guides and tutorials
- API reference documentation
- Security and compliance docs
- Operational runbooks

### `/examples` - Sample Configurations

Ready-to-use examples:

- Device configuration templates
- Deployment strategies
- GitOps workflows

## Configuration Files

### Python Project
- `pyproject.toml` - Modern Python packaging configuration
- `setup.py` - Legacy setup for compatibility
- `requirements.txt` - Direct dependency list

### Development Tools
- `.pre-commit-config.yaml` - Code quality checks
- `.editorconfig` - Editor consistency
- `pytest.ini` - Test configuration
- `.gitignore` - Version control exclusions

### CI/CD
- `.github/workflows/` - GitHub Actions pipelines
- `Makefile` - Build and deployment automation
- `Dockerfile` - Container definition
- `docker-compose.yml` - Local development environment

### Security
- `.gitleaks.toml` - Secret scanning rules
- `.env.example` - Environment variable template

## Import Structure

```python
# External imports
from fastapi import FastAPI, Depends
from sqlalchemy.orm import Session

# Internal imports - absolute
from src.auth.service import AuthenticationService
from src.db.models import User, Device
from src.core.config import Config

# Internal imports - relative (within same package)
from .utils import validate_config
from ..security.vault import VaultClient
```

## Environment Variables

Key environment variables (see `.env.example`):

```bash
# Database
DATABASE_URL=postgresql://user:pass@localhost/catnet

# Redis
REDIS_URL=redis://localhost:6379

# Vault
VAULT_URL=http://localhost:8200
VAULT_TOKEN=your-token

# Security
SECRET_KEY=your-secret-key
JWT_SECRET=your-jwt-secret

# Services
AUTH_SERVICE_URL=http://localhost:8081
GITOPS_SERVICE_URL=http://localhost:8082
DEPLOY_SERVICE_URL=http://localhost:8083
DEVICE_SERVICE_URL=http://localhost:8084
```

## Development Workflow

```bash
# Setup
make dev-install        # Install with dev dependencies
make migrate            # Run database migrations

# Development
make run               # Start application
make test              # Run tests
make lint              # Check code quality
make format            # Format code

# Docker
make docker-build      # Build images
make docker-up         # Start services
make docker-logs       # View logs
```

## Deployment Structure

### Production Deployment
```
/opt/catnet/
├── app/               # Application code
├── config/            # Configuration files
├── logs/              # Application logs
├── data/              # Persistent data
└── certs/             # SSL certificates
```

### Docker Deployment
```
catnet_network/
├── catnet_app
├── catnet_db (PostgreSQL)
├── catnet_redis
├── catnet_vault
└── catnet_nginx
```

## Security Considerations

- Secrets stored in HashiCorp Vault
- Configuration files use environment variables
- Certificates in `/certs` (not in version control)
- Audit logs in separate secure storage
- No hardcoded credentials anywhere

## Best Practices

1. **Code Organization**: Domain-driven design with clear boundaries
2. **Testing**: Comprehensive test coverage at all levels
3. **Documentation**: Keep docs close to code
4. **Configuration**: Environment-specific configs outside code
5. **Security**: Defense in depth, never trust user input
6. **Deployment**: Containerized, scalable, observable

This structure supports:
- Microservices architecture
- Horizontal scaling
- CI/CD automation
- Security best practices
- Easy maintenance and updates
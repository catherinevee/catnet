# CatNet

[![CI/CD Pipeline](https://github.com/catherinevee/catnet/actions/workflows/ci.yml/badge.svg)](https://github.com/catherinevee/catnet/actions/workflows/ci.yml)
[![Python Version](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Enterprise-grade network configuration management system with GitOps integration for Cisco and Juniper devices.

## Overview

CatNet is a zero-trust, GitOps-enabled network configuration deployment system that provides automated, secure configuration management for enterprise network infrastructure. Built with security-first principles, it implements comprehensive audit logging, multi-layer validation, and automated rollback capabilities.

## Features

- **Multi-vendor support** for Cisco (IOS, IOS-XE, NX-OS) and Juniper (Junos)
- **GitOps integration** with GitHub and GitLab webhook support
- **Zero-trust security** with mTLS, certificate-based authentication, and GPG signing
- **Deployment strategies** including canary, rolling, and blue-green deployments
- **Automated rollback** with health monitoring and validation
- **Comprehensive audit trail** with immutable logging and non-repudiation
- **HashiCorp Vault integration** for secrets management
- **Rate limiting** and DDoS protection
- **Multi-factor authentication** with TOTP support

## Installation

### Prerequisites

- Python 3.11 or higher
- Docker and Docker Compose
- PostgreSQL 14+ with TimescaleDB extension
- Redis 7+
- HashiCorp Vault (optional for development)

### Quick Start

Clone the repository and install dependencies:

```bash
git clone https://github.com/catherinevee/catnet.git
cd catnet
pip install -r requirements.txt
```

Configure environment variables:

```bash
cp .env.example .env
# Edit .env with your configuration
```

Initialize the database:

```bash
alembic upgrade head
python scripts/create_test_data.py
```

Generate certificates:

```bash
python scripts/generate_ca.py
```

Start the services:

```bash
# Using Docker Compose
docker-compose up -d

# Or run locally
python -m src.main start --service all
```

## Usage

### Basic Configuration Deployment

```python
from catnet import Client

# Initialize client
client = Client(
    base_url="https://api.catnet.local",
    api_key="your_api_key"
)

# Create a deployment
deployment = client.deployments.create(
    config_ids=["config_1", "config_2"],
    device_ids=["device_1", "device_2"],
    strategy="canary"
)

# Monitor deployment status
status = client.deployments.get_status(deployment.id)
print(f"Deployment {deployment.id}: {status.state}")
```

### Command Line Interface

```bash
# Test device connectivity
catnet test-connection --host 192.168.1.1 --vendor cisco_ios

# Validate configuration
catnet validate-config --file config.yaml

# Create deployment
catnet deploy create --config configs/router.yaml --strategy rolling

# Check deployment status
catnet deploy status --id deployment_123
```

## Architecture

CatNet uses a microservices architecture with four core services:

| Service | Port | Description |
|---------|------|-------------|
| Authentication Service | 8081 | Handles authentication, MFA, and session management |
| GitOps Service | 8082 | Processes Git webhooks and manages configurations |
| Deployment Service | 8083 | Orchestrates configuration deployments |
| Device Service | 8084 | Manages device connections and command execution |

### Data Flow

1. Configurations are stored in Git repositories
2. Webhooks trigger validation and deployment workflows
3. Deployments require approval based on configured policies
4. Configurations are deployed using the selected strategy
5. Automatic rollback occurs on validation failure

## Development

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src --cov-report=html

# Run specific test suite
pytest tests/unit/
pytest tests/integration/
```

### Code Quality

```bash
# Format code
black src/ tests/

# Run linters
flake8 src/
pylint src/
mypy src/ --strict

# Security scanning
bandit -r src/
```

### Building Documentation

```bash
# Generate API documentation
python scripts/generate_docs.py

# Build Sphinx documentation
cd docs && make html
```

## API Documentation

The REST API provides comprehensive endpoints for all operations. See the [API Documentation](docs/API_DOCUMENTATION.md) for complete reference.

### Authentication

All API requests require authentication using JWT tokens or API keys:

```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
     https://api.catnet.local/api/v1/devices
```

### Rate Limiting

API endpoints implement rate limiting:
- Authentication: 5 requests per minute
- Read operations: 100 requests per minute
- Write operations: 50 requests per minute
- Deployment operations: 10 requests per 5 minutes

## Security

CatNet implements defense-in-depth security:

- **Encryption**: AES-256-GCM at rest, TLS 1.3 in transit
- **Authentication**: JWT tokens with refresh, MFA support
- **Authorization**: Role-based access control (RBAC)
- **Audit Logging**: Immutable audit trail with hash verification
- **Certificate Management**: X.509 certificates for device authentication
- **Secrets Management**: HashiCorp Vault integration
- **Security Scanning**: Integrated Trivy, Semgrep, and GitLeaks

## Compliance

CatNet is designed to meet enterprise compliance requirements:

- **NIST 800-53**: 95% control coverage
- **SOC 2 Type II**: Ready for audit
- **PCI DSS**: Network segmentation compliant
- **GDPR**: Data protection compliant

See [Compliance Documentation](docs/COMPLIANCE.md) for detailed mappings.

## Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

1. Fork the repository
2. Create a feature branch
3. Make your changes with tests
4. Submit a pull request

## Support

- **Documentation**: [docs/](docs/)
- **Issues**: [GitHub Issues](https://github.com/catherinevee/catnet/issues)
- **Discussions**: [GitHub Discussions](https://github.com/catherinevee/catnet/discussions)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

CatNet is built with enterprise security best practices and follows the NIST Cybersecurity Framework.

---

**Project Status**: Production Ready (v1.0.0)
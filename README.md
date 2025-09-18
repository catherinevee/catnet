# CatNet

[![CI/CD Pipeline](https://github.com/catherinevee/catnet/workflows/CI/CD%20Pipeline/badge.svg)](https://github.com/catherinevee/catnet/actions/workflows/ci.yml)
[![Tests](https://img.shields.io/badge/tests-24%20passed-success)](https://github.com/catherinevee/catnet/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/badge/coverage-15%25-orange)](https://github.com/catherinevee/catnet)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Dependencies](https://img.shields.io/librariesio/github/catherinevee/catnet)](https://libraries.io/github/catherinevee/catnet)
[![Security: Trivy](https://img.shields.io/badge/security-trivy-blue.svg)](https://github.com/aquasecurity/trivy)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Pre-commit](https://img.shields.io/badge/pre--commit-enabled-brightgreen?logo=pre-commit&logoColor=white)](https://github.com/pre-commit/pre-commit)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat)](https://github.com/catherinevee/catnet/pulls)

Security-first, GitOps-enabled network configuration deployment system for enterprise networks. CatNet automates network device configuration management with built-in safety mechanisms, comprehensive audit logging, and multi-vendor support.

## Features

- **Multi-vendor support** for Cisco (IOS, IOS-XE, NX-OS) and Juniper (Junos) devices
- **GitOps integration** for configuration as code workflows
- **Advanced deployment strategies** including canary, rolling, and blue-green deployments
- **Automatic rollback** on failure detection
- **SSH key and certificate-based** device authentication
- **Multi-factor authentication** (TOTP) for user access
- **HashiCorp Vault integration** for secrets management
- **Comprehensive audit logging** for compliance
- **Real-time health monitoring** and validation

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [Configuration](#configuration)
- [API Documentation](#api-documentation)
- [Development](#development)
- [Testing](#testing)
- [Contributing](#contributing)
- [License](#license)
- [Support](#support)

## Installation

### Prerequisites

- Python 3.11 or higher
- PostgreSQL 14+
- Redis 7+
- HashiCorp Vault
- Docker (optional, for containerized deployment)

### Using Docker (Recommended)

```bash
# Clone the repository
git clone https://github.com/catherinevee/catnet.git
cd catnet

# Copy and configure environment variables
cp .env.example .env
# Edit .env with your settings

# Start all services
docker-compose up -d

# Verify services are running
docker-compose ps
```

### Local Installation

```bash
# Clone the repository
git clone https://github.com/catherinevee/catnet.git
cd catnet

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install CatNet
pip install -e .

# Run database migrations
alembic upgrade head
```

## Quick Start

### 1. Initialize the System

```bash
# Create admin user
python scripts/create_admin.py

# Generate certificates for mTLS
python scripts/generate_ca.py

# Start CatNet services
make run
```

### 2. Authenticate

```bash
catnet auth login
# Enter username, password, and MFA token
```

### 3. Add a Device

```bash
catnet device add \
  --hostname router1 \
  --ip 192.168.1.1 \
  --vendor cisco \
  --model ISR4451
```

### 4. Deploy Configuration

```bash
catnet deploy create \
  --config-file configs/router1.yml \
  --target router1 \
  --strategy canary
```

## Usage

### Command Line Interface

CatNet provides a comprehensive CLI for all operations:

```bash
# Authentication
catnet auth login                     # Login with MFA
catnet auth logout                    # Logout

# Device Management
catnet device list                    # List all devices
catnet device add                     # Add new device
catnet device backup <device_id>      # Backup configuration

# Deployments
catnet deploy create                  # Create deployment
catnet deploy status <id>             # Check status
catnet deploy rollback <id>           # Rollback deployment

# GitOps
catnet gitops connect                 # Connect repository
catnet gitops sync                    # Sync configurations

# SSH Key Management
catnet ssh generate                   # Generate SSH keys
catnet ssh add-device <device_id>     # Add SSH key to device
```

For complete CLI documentation, see [CLI Reference](docs/cli-reference.md).

### API Usage

```python
import requests

# Authenticate
response = requests.post('http://localhost:8081/auth/login', json={
    'username': 'admin',
    'password': 'password',
    'mfa_token': '123456'
})
token = response.json()['access_token']

# Create deployment
headers = {'Authorization': f'Bearer {token}'}
deployment = requests.post(
    'http://localhost:8083/deployments',
    json={
        'config': config_content,
        'targets': ['router1'],
        'strategy': 'rolling'
    },
    headers=headers
)
```

## Configuration

### Environment Variables

Create a `.env` file based on `.env.example`:

```bash
# Database
DATABASE_URL=postgresql://catnet:password@localhost/catnet

# Redis
REDIS_URL=redis://localhost:6379

# Vault
VAULT_URL=http://localhost:8200
VAULT_TOKEN=your-vault-token

# Security
SECRET_KEY=your-secret-key
JWT_SECRET=your-jwt-secret
```

### GitOps Repository Structure

```
network-configs/
├── devices/
│   ├── router1.yml
│   └── switch1.yml
├── templates/
│   └── base.j2
└── catnet.yml
```

### Device Configuration Example

```yaml
device:
  hostname: router1
  vendor: cisco_ios

configuration:
  interfaces:
    - name: GigabitEthernet0/0
      ip_address: 192.168.1.1
      subnet_mask: 255.255.255.0

deployment:
  strategy: canary
  validation:
    pre_checks:
      - ping_test: 8.8.8.8
```

## API Documentation

CatNet exposes RESTful APIs on the following ports:

| Service | Port | Description |
|---------|------|-------------|
| Authentication | 8081 | User authentication and authorization |
| GitOps | 8082 | Repository management and webhooks |
| Deployment | 8083 | Configuration deployment management |
| Device | 8084 | Device inventory and communication |

Full API documentation: [API Reference](docs/API_DOCUMENTATION.md)

Interactive API docs available at: `http://localhost:8000/docs`

## Development

### Setting Up Development Environment

```bash
# Install development dependencies
make dev-install

# Run tests
make test

# Format code
make format

# Run linters
make lint
```

### Project Structure

```
catnet/
├── src/              # Source code
│   ├── api/         # API endpoints
│   ├── auth/        # Authentication
│   ├── devices/     # Device communication
│   └── gitops/      # GitOps integration
├── tests/           # Test suite
├── docs/            # Documentation
└── examples/        # Example configurations
```

See [PROJECT_STRUCTURE.md](PROJECT_STRUCTURE.md) for detailed structure.

### Making Changes

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests (`make test`)
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

## Testing

```bash
# Run all tests
make test

# Run specific test categories
make test-unit          # Unit tests only
make test-integration   # Integration tests
make test-security      # Security tests

# Generate coverage report
pytest --cov=src --cov-report=html
```

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details on:

- Code of Conduct
- Development process
- Coding standards
- Pull request process

## Security

### Reporting Security Issues

Please report security vulnerabilities to security@catnet.io. Do not create public issues for security problems.

### Security Features

- mTLS for all inter-service communication
- AES-256-GCM encryption at rest
- Certificate and SSH key-based authentication
- Multi-factor authentication (TOTP)
- Comprehensive audit logging
- Role-based access control

For details, see [Security Architecture](docs/SECURITY_ARCHITECTURE.md).

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

- **Documentation**: [https://docs.catnet.io](https://docs.catnet.io)
- **Issues**: [GitHub Issues](https://github.com/catherinevee/catnet/issues)
- **Discussions**: [GitHub Discussions](https://github.com/catherinevee/catnet/discussions)
- **Security**: security@catnet.io
- **Commercial Support**: support@catnet.io

## Acknowledgments

- Built with [FastAPI](https://fastapi.tiangolo.com/)
- Network automation powered by [Netmiko](https://github.com/ktbyers/netmiko) and [NAPALM](https://napalm.readthedocs.io/)
- Security provided by [HashiCorp Vault](https://www.vaultproject.io/)

## Citation

If you use CatNet in your research or project, please cite:

```bibtex
@software{catnet2024,
  title = {CatNet: Security-First Network Configuration Management},
  author = {CatNet Team},
  year = {2024},
  url = {https://github.com/catherinevee/catnet}
}
```
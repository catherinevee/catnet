# CatNet

[![CI/CD Pipeline](https://github.com/catherinevee/catnet/workflows/CI/CD%20Pipeline/badge.svg)](https://github.com/catherinevee/catnet/actions/workflows/ci.yml)
[![Tests](https://img.shields.io/badge/tests-24%20passed-success)](https://github.com/catherinevee/catnet/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
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
# Initialize database
python -m src.main init-db

# Validate configuration
python -m src.main validate-config

# Start services (development mode)
python -m src.main run-server
```

### 2. Authentication

```bash
# Default admin credentials (change immediately)
# Username: admin
# Password: admin123

# API Authentication endpoint
curl -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123"}'
```

### 3. Test Device Connection

```bash
# Test connection to a network device
python -m src.main test-connection \
  --host 192.168.1.1 \
  --vendor cisco_ios
```

### 4. Deploy Configuration

```bash
# Use the API to create a deployment
curl -X POST http://localhost:8000/api/v1/deployments \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"config": "...", "devices": ["device-id"], "strategy": "canary"}'
```

## Usage

### Available CLI Commands

```bash
# System Management
python -m src.main init-db            # Initialize database
python -m src.main validate-config    # Validate configuration
python -m src.main test-connection    # Test device connection
python -m src.main generate-keys      # Generate RSA keypair
python -m src.main test              # Run test suite
python -m src.main run-server        # Start API server

# Server Startup
python -m src.main run-server        # Starts FastAPI on port 8000
```

### API Endpoints

Once the server is running, access the API documentation at:
- Interactive docs: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`

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
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Run tests
pytest tests/

# Format code
black src/ tests/

# Run linters
flake8 src/ tests/
bandit -r src/
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
pytest tests/

# Run with coverage
pytest tests/ --cov=src --cov-report=html --cov-report=term

# Run specific test file
pytest tests/test_security.py -v

# Run tests with verbose output
pytest tests/ -v
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

- **Issues**: [GitHub Issues](https://github.com/catherinevee/catnet/issues)
- **Source Code**: [GitHub Repository](https://github.com/catherinevee/catnet)
- **CI/CD Status**: [GitHub Actions](https://github.com/catherinevee/catnet/actions)

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
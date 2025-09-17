# CatNet - Secure Network Configuration Deployment System

[![CI/CD Pipeline](https://github.com/catherinevee/catnet/workflows/.github/workflows/ci.yml/badge.svg)](https://github.com/catherinevee/catnet/actions/workflows/ci.yml)

A zero-trust, GitOps-enabled network configuration deployment system for Cisco and Juniper devices with enterprise-grade security.

## Features

- **Multi-Vendor Support**: Cisco (IOS, IOS-XE, NX-OS) and Juniper (Junos)
- **GitOps Integration**: Automated deployments from Git repositories
- **Zero-Trust Security**: mTLS, MFA, certificate-based authentication
- **Audit Logging**: Immutable audit trail for compliance
- **Deployment Strategies**: Canary, rolling, blue-green deployments
- **Automatic Rollback**: Configuration rollback on failure
- **Session Recording**: Full device session recording
- **HashiCorp Vault Integration**: Secure credential management
- **Configuration Validation**: Multi-layer validation before deployment
- **Real-time Monitoring**: Prometheus and Grafana integration

## Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   Git Repos     │────▶│  GitOps Service │────▶│   Deployment    │
└─────────────────┘     └─────────────────┘     │     Service     │
                                                 └─────────────────┘
                                                          │
┌─────────────────┐     ┌─────────────────┐             ▼
│     Users       │────▶│  Auth Service   │     ┌─────────────────┐
└─────────────────┘     └─────────────────┘     │  Device Service │
                                                 └─────────────────┘
                                                          │
┌─────────────────┐                                      ▼
│  HashiCorp      │◀────────────────────────────┌─────────────────┐
│     Vault       │                              │ Network Devices │
└─────────────────┘                              └─────────────────┘
```

## Quick Start

### Prerequisites

- Python 3.11+
- Docker and Docker Compose
- PostgreSQL 14+
- Redis 7+
- HashiCorp Vault (optional)

### Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/catnet.git
cd catnet
```

2. Copy environment configuration:
```bash
cp .env.example .env
# Edit .env with your configuration
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Initialize database:
```bash
python -m src.main init
```

5. Start services with Docker:
```bash
docker-compose up -d
```

Or start services locally:
```bash
python -m src.main start --service all
```

## Configuration

### Environment Variables

Key environment variables (see `.env.example` for full list):

- `DATABASE_URL`: PostgreSQL connection string
- `VAULT_URL`: HashiCorp Vault URL
- `JWT_SECRET_KEY`: Secret key for JWT tokens
- `ENABLE_MFA`: Enable multi-factor authentication

### Device Configuration

Devices are configured in the database with the following properties:
- Hostname and IP address
- Vendor (Cisco/Juniper)
- Credentials stored in Vault
- Certificate thumbprint for mTLS

## Usage

### CLI Commands

```bash
# Initialize database
python -m src.main init

# Start all services
python -m src.main start --service all

# Test device connection
python -m src.main test-connection --host 192.168.1.1 --vendor cisco_ios

# Validate configuration
python -m src.main validate-config

# Run tests
python -m src.main test --coverage

# Generate RSA keypair
python -m src.main generate-keys
```

### API Endpoints

#### Authentication Service (Port 8081)
- `POST /auth/login` - User login
- `POST /auth/mfa/verify` - Verify MFA token
- `POST /auth/refresh` - Refresh access token
- `DELETE /auth/logout` - Logout

#### GitOps Service (Port 8082)
- `POST /git/connect` - Connect repository
- `POST /git/webhook` - Process webhook
- `GET /git/configs` - Get configurations
- `POST /git/sync` - Sync repository

#### Deployment Service (Port 8083)
- `POST /deploy/create` - Create deployment
- `GET /deploy/{id}/status` - Get deployment status
- `POST /deploy/{id}/approve` - Approve deployment
- `POST /deploy/{id}/rollback` - Rollback deployment

#### Device Service (Port 8084)
- `GET /devices` - List devices
- `POST /devices/connect` - Connect to device
- `POST /devices/{id}/backup` - Backup configuration
- `POST /devices/{id}/execute` - Execute command

## Security

### Security Features

1. **mTLS**: Mutual TLS for all inter-service communication
2. **Encryption**: AES-256-GCM for configs at rest
3. **Digital Signatures**: All configs are signed
4. **MFA**: Multi-factor authentication for users
5. **Audit Logging**: Immutable audit trail
6. **Secret Management**: HashiCorp Vault integration
7. **Session Recording**: All device sessions recorded
8. **RBAC**: Role-based access control

### Security Best Practices

- Never store credentials in code or config files
- Always verify webhook signatures
- Backup before deployment
- Use certificate-based device authentication
- Enable MFA for all users
- Regularly rotate secrets
- Monitor audit logs

## Deployment Strategies

### Canary Deployment
Gradually roll out changes:
```python
stages = [
    {'percentage': 5, 'wait_minutes': 5},
    {'percentage': 25, 'wait_minutes': 10},
    {'percentage': 50, 'wait_minutes': 15},
    {'percentage': 100, 'wait_minutes': 0}
]
```

### Rolling Deployment
Deploy to devices one by one with health checks.

### Blue-Green Deployment
Switch between two identical production environments.

## Monitoring

### Prometheus Metrics
- Deployment duration and success rate
- Authentication failures
- Device connection status
- API response times

### Grafana Dashboards
Access Grafana at `http://localhost:3000` (default password: `catnet_grafana_password_change_in_production`)

## Development

### Running Tests
```bash
# Run all tests
pytest tests/

# Run with coverage
pytest tests/ --cov=src --cov-report=html

# Run specific test file
pytest tests/test_security.py
```

### Code Quality
```bash
# Format code
black src/

# Type checking
mypy src/ --strict

# Security linting
bandit -r src/

# General linting
flake8 src/
```

## Troubleshooting

### Common Issues

1. **Database Connection Failed**
   - Check PostgreSQL is running
   - Verify DATABASE_URL in .env

2. **Vault Authentication Failed**
   - Ensure Vault is unsealed
   - Check VAULT_TOKEN is valid

3. **Device Connection Timeout**
   - Verify network connectivity
   - Check firewall rules
   - Ensure correct credentials in Vault

## License

MIT License - See LICENSE file for details

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

## Support

For issues and questions, please create an issue on GitHub.

## Roadmap

- [ ] Kubernetes operator
- [ ] Terraform provider
- [ ] Additional vendor support (Arista, Fortinet)
- [ ] Web UI dashboard
- [ ] AI-powered configuration validation
- [ ] Compliance reporting (PCI-DSS, SOC2)
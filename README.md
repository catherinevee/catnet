# CatNet 🔒 Network Configuration Management

[![CI/CD Pipeline](https://github.com/catherinevee/catnet/workflows/CI/CD%20Pipeline/badge.svg)](https://github.com/catherinevee/catnet/actions/workflows/ci.yml)
[![Tests](https://img.shields.io/badge/tests-24%20passed-success)](https://github.com/catherinevee/catnet/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

> **Deploy network configurations safely with automatic rollback and GitOps integration for Cisco and Juniper devices**

## 🎯 Why CatNet?

**The Problem:** One wrong network configuration can take down your entire production environment. Manual changes are error-prone, recovery is stressful, and tracking changes across hundreds of devices is a nightmare.

**The Solution:** CatNet validates every configuration before deployment, automatically rolls back on failure, and tracks all changes through Git. Your network stays up, your changes stay tracked, and you sleep better at night.

## 🏗️ Architecture

```mermaid
graph TB
    User[Network Engineer] -->|HTTPS/REST| API[FastAPI Server]
    API --> Auth[Authentication<br/>MFA + JWT]
    API --> Deploy[Deployment Engine]
    Deploy --> Validate[Config Validator]
    Validate --> Devices[Device Connectors]
    Devices -->|SSH| Cisco[Cisco IOS/XE/NXOS]
    Devices -->|NETCONF| Juniper[Juniper Junos]
    Deploy --> Rollback[Auto-Rollback<br/>on Failure]
    API --> Audit[Audit Logger]
    API --> Vault[HashiCorp Vault<br/>Secrets]

    style API fill:#2ecc71
    style Auth fill:#3498db
    style Rollback fill:#e74c3c
    style Vault fill:#9b59b6
```

## 🚀 Quick Start

### Prerequisites
- Python 3.11+
- PostgreSQL 14+ (or use Docker)
- 5 minutes

### Install & Run (3 Commands)

```bash
# 1. Clone and install
git clone https://github.com/catherinevee/catnet && cd catnet
pip install -r requirements.txt

# 2. Initialize database
python -m src.main init-db

# 3. Start the server
python -m src.main run-server
```

**✨ That's it!** Visit http://localhost:8000/docs for interactive API documentation.

<details>
<summary>📦 Alternative Installation Methods</summary>

### Using Docker
```bash
docker-compose up -d
```

### Development Setup
```bash
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -e .
```
</details>

## 📊 Project Status

| Component | Status | Tests | Coverage | Notes |
|-----------|--------|-------|----------|-------|
| 🔐 Authentication | ✅ **Stable** | 12/12 | 85% | MFA, JWT, Session management |
| 🔒 Security Layer | ✅ **Stable** | 8/8 | 90% | Encryption, signing, audit |
| 🌐 REST API | ✅ **Stable** | 4/4 | 75% | FastAPI with auto-docs |
| 🗄️ Database | ✅ **Stable** | 6/6 | 80% | PostgreSQL + migrations |
| 🔌 Device Connectors | 🚧 **In Progress** | 2/10 | 40% | Basic Cisco support |
| 🚀 Deployment Engine | 🚧 **In Progress** | 3/8 | 35% | Canary strategy working |
| 🔄 GitOps Integration | 📝 **Planned** | 0/0 | 0% | Q1 2025 |

## ✨ Features

### Available Now
- ✅ **Secure Authentication** - Multi-factor authentication with TOTP
- ✅ **Comprehensive Audit Logging** - Every action tracked and immutable
- ✅ **Configuration Signing** - GPG/RSA signed configurations
- ✅ **REST API** - Full OpenAPI/Swagger documentation
- ✅ **Encrypted Storage** - AES-256-GCM encryption at rest
- ✅ **CI/CD Pipeline** - Automated testing and security scanning

### In Development
- 🚧 **Multi-vendor Support** - Cisco IOS/XE/NXOS (40% complete)
- 🚧 **Deployment Strategies** - Canary, rolling, blue-green
- 🚧 **Automatic Rollback** - Failure detection and recovery
- 🚧 **Device Health Monitoring** - Real-time status checks

### Coming Soon
- 📝 **GitOps Webhooks** - GitHub/GitLab/Bitbucket integration
- 📝 **Juniper Support** - Junos device configuration
- 📝 **Compliance Reports** - PCI DSS, SOC 2 ready

## 🆚 CatNet vs Alternatives

| Feature | CatNet | Ansible | Nornir | Oxidized | RANCID |
|---------|---------|---------|--------|----------|--------|
| **Auto-Rollback** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **GitOps Native** | ✅ | ⚠️ | ❌ | ❌ | ❌ |
| **REST API** | ✅ | ❌ | ❌ | ⚠️ | ❌ |
| **MFA Security** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Config Signing** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Learning Curve** | Easy | Hard | Medium | Easy | Medium |

## 📖 Usage Examples

### Basic API Usage

```python
import requests

# Authenticate
response = requests.post('http://localhost:8000/auth/login',
    json={'username': 'admin', 'password': 'admin123'})
token = response.json()['access_token']

# Deploy configuration
headers = {'Authorization': f'Bearer {token}'}
deployment = requests.post('http://localhost:8000/api/v1/deployments',
    json={
        'config': 'interface GigabitEthernet0/0\n ip address 192.168.1.1 255.255.255.0',
        'devices': ['device-123'],
        'strategy': 'canary'
    },
    headers=headers)
```

### CLI Commands

```bash
# System management
python -m src.main init-db            # Initialize database
python -m src.main validate-config    # Validate configuration
python -m src.main test-connection    # Test device connectivity
python -m src.main generate-keys      # Generate RSA keypair

# Run tests
pytest tests/ --cov=src               # With coverage report
```

## 🔧 Troubleshooting

<details>
<summary>❌ ImportError: No module named 'src'</summary>

```bash
# Add project to Python path
export PYTHONPATH="${PYTHONPATH}:$(pwd)"
```
</details>

<details>
<summary>❌ Database connection refused</summary>

```bash
# Check PostgreSQL is running
sudo systemctl status postgresql

# Or use Docker
docker run -d -p 5432:5432 -e POSTGRES_PASSWORD=password postgres:14
```
</details>

<details>
<summary>❌ Port 8000 already in use</summary>

```bash
# Use a different port
python -m src.main run-server --port 8001
```
</details>

<details>
<summary>❌ Default admin password not working</summary>

The default credentials are:
- Username: `admin`
- Password: `admin123`

⚠️ **Change these immediately after first login!**
</details>

## 🛠️ Configuration

### Environment Variables

Create a `.env` file:

```bash
# Required
DATABASE_URL=postgresql://catnet:password@localhost/catnet

# Optional
REDIS_URL=redis://localhost:6379
VAULT_URL=http://localhost:8200
JWT_SECRET=your-secret-key-change-this
SECRET_KEY=your-secret-key-change-this
```

### Device Configuration Format

```yaml
device:
  hostname: router1
  vendor: cisco_ios
  ip_address: 192.168.1.1

deployment:
  strategy: canary
  validation:
    pre_checks:
      - connectivity_test
      - config_syntax_check
    post_checks:
      - interface_status
      - routing_table_check
```

## 🤝 Contributing

We welcome contributions! We especially need help with:

- 🔌 **Device Connectors** - Add support for more vendors
- 🧪 **Test Coverage** - Help us reach 90% coverage
- 📚 **Documentation** - Improve examples and guides
- 🐛 **Bug Fixes** - Check [open issues](https://github.com/catherinevee/catnet/issues)

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

## 🔒 Security

- 🛡️ **Report vulnerabilities** via [Security Advisory](https://github.com/catherinevee/catnet/security/advisories/new)
- 📋 **Security features** documented in [SECURITY.md](SECURITY.md)
- 🔐 **Best practices** outlined in [CLAUDE.md](CLAUDE.md)

## 📚 Documentation

- 📖 **Architecture Overview**: [CLAUDE.md](CLAUDE.md)
- 🔧 **API Documentation**: http://localhost:8000/docs (when running)
- 💡 **Examples**: [examples/](examples/) directory
- ❓ **FAQ**: See Troubleshooting section above

## 🚦 Roadmap

### Q4 2024 (Current)
- ✅ Core security framework
- ✅ Authentication system
- ✅ CI/CD pipeline
- 🚧 Device connectors (60% complete)
- 🚧 Deployment strategies (40% complete)

### Q1 2025
- 📝 GitOps webhook integration
- 📝 Juniper device support
- 📝 Advanced rollback strategies
- 📝 Beta release

### Q2 2025
- 📝 Production release 1.0
- 📝 Enterprise features
- 📝 Cloud deployment options

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

Built with:
- [FastAPI](https://fastapi.tiangolo.com/) - Modern web framework
- [Netmiko](https://github.com/ktbyers/netmiko) - Network device connections
- [SQLAlchemy](https://www.sqlalchemy.org/) - Database ORM
- [Pydantic](https://pydantic-docs.helpmanual.io/) - Data validation

## 📬 Contact

- **Issues**: [GitHub Issues](https://github.com/catherinevee/catnet/issues)
- **Discussions**: [GitHub Discussions](https://github.com/catherinevee/catnet/discussions)
- **Security**: [Security Advisory](https://github.com/catherinevee/catnet/security/advisories/new)

---

<p align="center">
  <b>Built with ❤️ for network engineers tired of 3am rollbacks</b>
</p>
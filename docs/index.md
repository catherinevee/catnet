# CatNet Documentation

Welcome to the CatNet documentation - your comprehensive guide to the security-first, GitOps-enabled network configuration deployment system.

## Quick Links

- [Getting Started](getting-started.md)
- [Installation Guide](installation.md)
- [API Reference](API_DOCUMENTATION.md)
- [CLI Reference](cli-reference.md)
- [Security Architecture](SECURITY_ARCHITECTURE.md)

## What is CatNet?

CatNet is an enterprise-grade network automation platform that provides:

- **Multi-vendor Support**: Cisco (IOS, IOS-XE, NX-OS) and Juniper (Junos)
- **GitOps Integration**: Configuration as Code with Git workflows
- **Security-First Design**: mTLS, encryption at rest, comprehensive audit logging
- **Advanced Deployment**: Rolling, canary, and blue-green strategies
- **Automatic Rollback**: Intelligent failure detection and recovery
- **Complete Observability**: Metrics, logging, and tracing

## Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                     GitOps Repository                    │
└────────────────────────┬────────────────────────────────┘
                         │ Webhook
                         ▼
┌─────────────────────────────────────────────────────────┐
│                    CatNet Core Services                  │
├──────────────┬──────────────┬──────────────┬───────────┤
│   Auth API   │  GitOps API  │ Deployment   │  Device   │
│   Port 8081  │  Port 8082   │ API (8083)   │ API (8084)│
└──────────────┴──────────────┴──────────────┴───────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│                   Security Layer                         │
├──────────────┬──────────────┬───────────────────────────┤
│ HashiCorp    │  PostgreSQL  │  Redis Cache  │           │
│   Vault      │   Database   │               │           │
└──────────────┴──────────────┴───────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│                  Network Devices                         │
├──────────────┬──────────────┬───────────────────────────┤
│  Cisco IOS   │   Juniper    │   Cisco NX-OS │           │
└──────────────┴──────────────┴───────────────────────────┘
```

## Key Features

### Security
- Certificate-based authentication
- SSH key authentication support
- Multi-factor authentication (TOTP)
- Encrypted configuration storage
- Comprehensive audit logging
- Role-based access control

### Automation
- GitOps workflow integration
- Automated deployment pipelines
- Configuration validation
- Health monitoring
- Automatic rollback on failure

### Scalability
- Microservices architecture
- Horizontal scaling support
- Async processing
- Connection pooling
- Caching layer

## Getting Started

### Prerequisites
- Python 3.11+
- PostgreSQL 14+
- Redis 7+
- HashiCorp Vault

### Quick Start

```bash
# Clone the repository
git clone https://github.com/catnet/catnet.git
cd catnet

# Install dependencies
make install

# Run database migrations
make migrate

# Start services
make run

# Access the API
curl http://localhost:8000/health
```

## Documentation Structure

- **[Getting Started](getting-started.md)**: Quick introduction and first steps
- **[Installation](installation.md)**: Detailed installation instructions
- **[Configuration](configuration.md)**: System configuration guide
- **[API Documentation](API_DOCUMENTATION.md)**: Complete API reference
- **[CLI Reference](cli-reference.md)**: Command-line interface guide
- **[Security](SECURITY_ARCHITECTURE.md)**: Security architecture and best practices
- **[Runbooks](RUNBOOKS.md)**: Operational procedures
- **[Compliance](COMPLIANCE.md)**: Regulatory compliance documentation
- **[Troubleshooting](troubleshooting.md)**: Common issues and solutions
- **[Contributing](../CONTRIBUTING.md)**: Contribution guidelines

## Support

- **Issues**: [GitHub Issues](https://github.com/catnet/catnet/issues)
- **Security**: security@catnet.io
- **Documentation**: docs@catnet.io

## License

CatNet is released under the MIT License. See [LICENSE](../LICENSE) for details.
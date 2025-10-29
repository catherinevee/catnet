CatNet Documentation
====================

Welcome to CatNet's documentation. CatNet is an enterprise-grade network configuration management platform with GitOps integration.

.. toctree::
   :maxdepth: 2
   :caption: Contents:

   getting_started
   architecture
   API_GUIDE
   OPERATIONAL_RUNBOOK
   TROUBLESHOOTING
   PERFORMANCE_GUIDE
   CODE_QUALITY_STANDARDS
   api/index

Quick Links
-----------

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

Features
--------

* **GitOps Integration**: Configuration as code with Git-based workflows
* **Multi-Vendor Support**: Cisco IOS/IOS-XE/NX-OS, Juniper Junos
* **Deployment Strategies**: Rolling, canary, and blue-green deployments
* **Security First**: HashiCorp Vault integration, mTLS, encryption at rest
* **Approval Workflows**: Multi-stage approvals with audit logging
* **Observability**: Prometheus metrics, Grafana dashboards, distributed tracing

Architecture
------------

CatNet uses a microservices architecture with the following components:

* **API Gateway**: Central entry point with authentication and rate limiting
* **Auth Service**: OAuth2, SAML, MFA with LDAP/AD integration
* **GitOps Service**: Webhook processing and configuration parsing
* **Deployment Service**: Deployment execution with multiple strategies
* **Device Service**: Device connection management and configuration
* **Monitoring Service**: Metrics collection and health monitoring

Getting Started
---------------

Installation
~~~~~~~~~~~~

.. code-block:: bash

   # Clone repository
   git clone https://github.com/your-org/catnet.git
   cd catnet

   # Install dependencies
   pip install -r requirements.txt

   # Set up environment
   cp .env.example .env
   # Edit .env with your configuration

   # Run database migrations
   alembic upgrade head

   # Start services
   docker-compose up -d

Quick Start
~~~~~~~~~~~

.. code-block:: python

   from catnet import CatNetClient

   # Initialize client
   client = CatNetClient(
       url="https://catnet.example.com",
       token="your-api-token"
   )

   # Create deployment
   deployment = client.deployments.create(
       name="ACL Update",
       strategy="canary",
       configs=[
           {
               "device_id": "device-123",
               "type": "acl",
               "content": "access-list 100 permit tcp any any eq 443"
           }
       ]
   )

   # Approve deployment
   client.deployments.approve(deployment.id)

   # Monitor progress
   status = client.deployments.get_status(deployment.id)
   print(f"Status: {status.state}")

API Reference
-------------

.. toctree::
   :maxdepth: 2
   :caption: API Reference

   api/core
   api/auth
   api/gitops
   api/deployment
   api/device
   api/monitoring

Core Modules
~~~~~~~~~~~~

.. autosummary::
   :toctree: api/generated
   :recursive:

   src.core.config
   src.core.deployment
   src.core.validators
   src.core.rollback

Authentication
~~~~~~~~~~~~~~

.. autosummary::
   :toctree: api/generated
   :recursive:

   src.auth.authentication
   src.auth.oauth
   src.auth.permissions

GitOps
~~~~~~

.. autosummary::
   :toctree: api/generated
   :recursive:

   src.gitops.workflow
   src.gitops.scanner
   src.gitops.parser

Deployment
~~~~~~~~~~

.. autosummary::
   :toctree: api/generated
   :recursive:

   src.services.deployment.strategies
   src.services.deployment.approval
   src.services.deployment.rollback
   src.services.deployment.monitoring

Device Management
~~~~~~~~~~~~~~~~~

.. autosummary::
   :toctree: api/generated
   :recursive:

   src.devices.device_connector
   src.devices.device_manager
   src.devices.vendors.cisco
   src.devices.vendors.juniper

Monitoring
~~~~~~~~~~

.. autosummary::
   :toctree: api/generated
   :recursive:

   src.monitoring.collector
   src.monitoring.dashboard
   src.monitoring.alerts
   src.monitoring.prometheus

Security
~~~~~~~~

.. autosummary::
   :toctree: api/generated
   :recursive:

   src.security.vault_client
   src.security.encryption
   src.security.audit
   src.security.secrets_scanner

Contributing
------------

See `CONTRIBUTING.md` for development guidelines.

License
-------

This project is licensed under the MIT License - see the `LICENSE` file for details.

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

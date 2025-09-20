#!/usr/bin/env python3
"""
Create test data for CatNet testing phases
"""
from sqlalchemy import select
from src.security.auth import AuthManager
from src.db.models import (
    User,
    Device,
    GitRepository,
    ConfigTemplate,
    DeviceVendor,
    DeploymentState,
)
from src.db.database import init_database
import asyncio
import sys
import os
import uuid
from datetime import datetime, timedelta
import random
import json

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


async def create_test_users(session):
    """Create test users for different roles"""
    auth_manager = AuthManager(secret_key="test-secret")

    test_users = [
        {
            "username": "admin_test",
            "email": "admin@test.catnet.local",
            "password": "Admin123!",
            "roles": ["admin"],
            "is_superuser": True,
        },
        {
            "username": "network_engineer",
            "email": "network@test.catnet.local",
            "password": "Network123!",
            "roles": ["operator", "network_engineer"],
            "is_superuser": False,
        },
        {
            "username": "security_analyst",
            "email": "security@test.catnet.local",
            "password": "Security123!",
            "roles": ["viewer", "security"],
            "is_superuser": False,
        },
        {
            "username": "devops_engineer",
            "email": "devops@test.catnet.local",
            "password": "DevOps123!",
            "roles": ["operator", "devops"],
            "is_superuser": False,
        },
        {
            "username": "manager_user",
            "email": "manager@test.catnet.local",
            "password": "Manager123!",
            "roles": ["approver", "viewer"],
            "is_superuser": False,
        },
    ]

    created_users = []
    for user_data in test_users:
        # Check if user already exists
        result = await session.execute(
            select(User).where(User.username == user_data["username"])
        )
        existing_user = result.scalar_one_or_none()

        if not existing_user:
            user = User(
                username=user_data["username"],
                email=user_data["email"],
                password_hash=auth_manager.get_password_hash(user_data["password"]),
                roles=user_data["roles"],
                is_superuser=user_data["is_superuser"],
                is_active=True,
            )
            session.add(user)
            created_users.append(user_data["username"])

    await session.commit()
    print(f"✓ Created {len(created_users)} test users")
    return created_users


async def create_test_devices(session):
    """Create test network devices"""
    test_devices = [
        # Cisco devices
        {
            "hostname": "cisco-router-01",
            "ip_address": "192.168.1.1",
            "vendor": DeviceVendor.CISCO_IOS,
            "model": "ISR4451-X",
            "serial_number": "FTX1234567A",
            "location": "US-East-DC1",
            "is_active": True,
            "port": 22,
        },
        {
            "hostname": "cisco-switch-01",
            "ip_address": "192.168.1.2",
            "vendor": DeviceVendor.CISCO_IOS_XE,
            "model": "Catalyst 9300",
            "serial_number": "FCW2234567B",
            "location": "US-East-DC1",
            "is_active": True,
            "port": 22,
        },
        {
            "hostname": "cisco-nexus-01",
            "ip_address": "192.168.1.3",
            "vendor": DeviceVendor.CISCO_NX_OS,
            "model": "Nexus 9000",
            "serial_number": "SAL1234567C",
            "location": "US-East-DC1",
            "is_active": True,
            "port": 22,
        },
        # Juniper devices
        {
            "hostname": "juniper-mx-01",
            "ip_address": "192.168.2.1",
            "vendor": DeviceVendor.JUNIPER_JUNOS,
            "model": "MX240",
            "serial_number": "JN1234567D",
            "location": "US-West-DC2",
            "is_active": True,
            "port": 22,
        },
        {
            "hostname": "juniper-srx-01",
            "ip_address": "192.168.2.2",
            "vendor": DeviceVendor.JUNIPER_JUNOS,
            "model": "SRX340",
            "serial_number": "JN2234567E",
            "location": "US-West-DC2",
            "is_active": True,
            "port": 22,
        },
        # Inactive device for testing
        {
            "hostname": "cisco-router-offline",
            "ip_address": "192.168.99.99",
            "vendor": DeviceVendor.CISCO_IOS,
            "model": "ISR4331",
            "serial_number": "FTX9999999Z",
            "location": "Storage",
            "is_active": False,
            "port": 22,
        },
    ]

    created_devices = []
    for device_data in test_devices:
        # Check if device already exists
        result = await session.execute(
            select(Device).where(Device.hostname == device_data["hostname"])
        )
        existing_device = result.scalar_one_or_none()

        if not existing_device:
            device = Device(**device_data)
            session.add(device)
            created_devices.append(device_data["hostname"])

    await session.commit()
    print(f"✓ Created {len(created_devices)} test devices")
    return created_devices


async def create_test_repositories(session):
    """Create test Git repositories"""
    test_repos = [
        {
            "url": "https://github.com/test-org/network-configs.git",
            "branch": "main",
            "config_path": "configs/",
            "auto_deploy": False,
            "gpg_verification": True,
        },
        {
            "url": "https://github.com/test-org/firewall-rules.git",
            "branch": "production",
            "config_path": "rules/",
            "auto_deploy": False,
            "gpg_verification": True,
        },
        {
            "url": "https://gitlab.com/test-org/switch-configs.git",
            "branch": "develop",
            "config_path": "switches/",
            "auto_deploy": True,
            "gpg_verification": False,
        },
    ]

    created_repos = []
    for repo_data in test_repos:
        # Check if repository already exists
        result = await session.execute(
            select(GitRepository).where(GitRepository.url == repo_data["url"])
        )
        existing_repo = result.scalar_one_or_none()

        if not existing_repo:
            repo = GitRepository(**repo_data)
            session.add(repo)
            created_repos.append(repo_data["url"])

    await session.commit()
    print(f"✓ Created {len(created_repos)} test repositories")
    return created_repos


async def create_test_templates(session):
    """Create test configuration templates"""
    test_templates = [
        {
            "name": "cisco-interface-template",
            "vendor": DeviceVendor.CISCO_IOS,
            "template_content": """interface {{ interface_name }}
 description {{ description }}
 ip address {{ ip_address }} {{ subnet_mask }}
 no shutdown""",
            "variables": {
                "interface_name": "string",
                "description": "string",
                "ip_address": "ipv4",
                "subnet_mask": "ipv4",
            },
            "is_active": True,
        },
        {
            "name": "juniper-vlan-template",
            "vendor": DeviceVendor.JUNIPER_JUNOS,
            "template_content": """set vlans {{ vlan_name }} vlan-id {{ vlan_id }}
set vlans {{ vlan_name }} description "{{ description }}"
set interfaces {{ interface }} unit 0 family ethernet-switching vlan members {{ vlan_name }}""",
            "variables": {
                "vlan_name": "string",
                "vlan_id": "integer",
                "description": "string",
                "interface": "string",
            },
            "is_active": True,
        },
        {
            "name": "cisco-acl-template",
            "vendor": DeviceVendor.CISCO_IOS,
            "template_content": """ip access-list extended {{ acl_name }}
 permit {{ protocol }} {{ source_ip }} {{ source_wildcard }} {{ dest_ip }} {{ \
     dest_wildcard }}
 deny ip any any log""",
            "variables": {
                "acl_name": "string",
                "protocol": "string",
                "source_ip": "ipv4",
                "source_wildcard": "ipv4",
                "dest_ip": "ipv4",
                "dest_wildcard": "ipv4",
            },
            "is_active": True,
        },
    ]

    created_templates = []
    for template_data in test_templates:
        # Check if template already exists
        result = await session.execute(
            select(ConfigTemplate).where(ConfigTemplate.name == template_data["name"])
        )
        existing_template = result.scalar_one_or_none()

        if not existing_template:
            template = ConfigTemplate(**template_data)
            session.add(template)
            created_templates.append(template_data["name"])

    await session.commit()
    print(f"✓ Created {len(created_templates)} test templates")
    return created_templates


async def create_sample_configs():
    """Create sample configuration files for testing"""
    configs_dir = "test_configs"
    os.makedirs(configs_dir, exist_ok=True)

    # Cisco IOS sample config
    cisco_config = """!
version 15.7
service timestamps debug datetime msec
service timestamps log datetime msec
no service password-encryption
!
hostname cisco-router-01
!
boot-start-marker
boot-end-marker
!
enable secret 5 $1$mERr$hx5rVt7rKStzQYk84./Dk0
!
interface GigabitEthernet0/0
 description WAN Interface
 ip address 203.0.113.1 255.255.255.0
 duplex auto
 speed auto
!
interface GigabitEthernet0/1
 description LAN Interface
 ip address 192.168.1.1 255.255.255.0
 duplex auto
 speed auto
!
router ospf 1
 network 203.0.113.0 0.0.0.255 area 0
 network 192.168.1.0 0.0.0.255 area 0
!
ip forward-protocol nd
!
ip http server
ip http secure-server
!
access-list 100 permit tcp any any eq 22
access-list 100 permit tcp any any eq 443
access-list 100 deny ip any any log
!
line con 0
line aux 0
line vty 0 4
 transport input ssh
!
end
"""

    with open(os.path.join(configs_dir, "cisco-router-01.cfg"), "w") as f:
        f.write(cisco_config)

    # Juniper Junos sample config
    juniper_config = """## Last changed: 2024-01-15 10:00:00 UTC
version 20.4R3.8;
system {
    host-name juniper-mx-01;
    time-zone UTC;
    root-authentication {
        encrypted-password "$6$encrypted"; ## SECRET-DATA
    }
    services {
        ssh {
            protocol-version v2;
        }
        netconf {
            ssh;
        }
    }
}
interfaces {
    ge-0/0/0 {
        description "WAN Interface";
        unit 0 {
            family inet {
                address 203.0.113.2/24;
            }
        }
    }
    ge-0/0/1 {
        description "LAN Interface";
        unit 0 {
            family inet {
                address 192.168.2.1/24;
            }
        }
    }
}
protocols {
    ospf {
        area 0.0.0.0 {
            interface ge-0/0/0.0;
            interface ge-0/0/1.0;
        }
    }
}
security {
    policies {
        from-zone trust to-zone untrust {
            policy allow-web {
                match {
                    source-address any;
                    destination-address any;
                    application [ junos-http junos-https ];
                }
                then {
                    permit;
                }
            }
        }
    }
}
"""

    with open(os.path.join(configs_dir, "juniper-mx-01.cfg"), "w") as f:
        f.write(juniper_config)

    print(f"✓ Created sample configuration files in {configs_dir}/")
    return configs_dir


async def generate_test_metrics():
    """Generate test metrics for monitoring validation"""
    metrics = {
        "deployment_duration_seconds": {
            "help": "Time taken for deployment",
            "type": "histogram",
            "samples": [random.uniform(30, 300) for _ in range(100)],
        },
        "deployment_success_total": {
            "help": "Total successful deployments",
            "type": "counter",
            "value": random.randint(100, 1000),
        },
        "deployment_failure_total": {
            "help": "Total failed deployments",
            "type": "counter",
            "value": random.randint(5, 50),
        },
        "device_connections_active": {
            "help": "Currently active device connections",
            "type": "gauge",
            "value": random.randint(10, 50),
        },
        "auth_failures_total": {
            "help": "Total authentication failures",
            "type": "counter",
            "value": random.randint(10, 100),
        },
        "api_request_duration_seconds": {
            "help": "API request duration",
            "type": "histogram",
            "samples": [random.uniform(0.01, 0.5) for _ in range(1000)],
        },
    }

    with open("test_metrics.json", "w") as f:
        json.dump(metrics, f, indent=2)

    print(f"✓ Generated test metrics in test_metrics.json")
    return metrics


async def main():
    """Main function to create all test data"""
    print("🚀 Creating CatNet test data...")

    # Initialize database
    db_manager = init_database()

    # Create tables if needed
    await db_manager.create_all()

    async with db_manager.session_scope() as session:
        # Create test data
        users = await create_test_users(session)
        devices = await create_test_devices(session)
        repos = await create_test_repositories(session)
        templates = await create_test_templates(session)

    # Create sample files
    configs_dir = await create_sample_configs()
    metrics = await generate_test_metrics()

    # Summary
    print("\n" + "=" * 50)
    print("✅ Test data creation completed successfully!")
    print("=" * 50)
    print(f"Created {len(users)} users")
    print(f"Created {len(devices)} devices")
    print(f"Created {len(repos)} repositories")
    print(f"Created {len(templates)} templates")
    print(f"Sample configs in: {configs_dir}/")
    print(f"Test metrics in: test_metrics.json")
    print("\nTest Credentials:")
    print("  Admin: admin_test / Admin123!")
    print("  Network: network_engineer / Network123!")
    print("  Security: security_analyst / Security123!")
    print("  DevOps: devops_engineer / DevOps123!")
    print("  Manager: manager_user / Manager123!")

    # Close database connection
    await db_manager.close()


if __name__ == "__main__":
    asyncio.run(main())

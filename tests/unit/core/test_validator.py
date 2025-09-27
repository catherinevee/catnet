"""
Unit tests for configuration validator.
Tests the multi-layer validation system including schema, syntax, and security validation.
"""

import pytest
from unittest.mock import Mock, AsyncMock, patch
from typing import Dict, Any

from src.core.validator import (
    ConfigValidator,
    ValidationResult,
    ValidationError,
    SecurityViolation
)
from src.core.exceptions import ValidationException


class TestConfigValidator:
    """Test configuration validator functionality."""

    @pytest.fixture
    def validator(self):
        """Create config validator instance."""
        return ConfigValidator()

    @pytest.fixture
    def valid_cisco_config(self):
        """Valid Cisco configuration for testing."""
        return {
            "vendor": "cisco",
            "platform": "ios",
            "hostname": "switch01",
            "version": "1.0",
            "interfaces": {
                "GigabitEthernet0/1": {
                    "description": "Uplink to Core",
                    "no shutdown": True,
                    "switchport": {
                        "mode": "trunk",
                        "allowed_vlans": "1,10,20"
                    }
                }
            },
            "vlans": {
                "10": {"name": "USERS"},
                "20": {"name": "SERVERS"}
            }
        }

    @pytest.fixture
    def valid_juniper_config(self):
        """Valid Juniper configuration for testing."""
        return {
            "vendor": "juniper",
            "platform": "junos",
            "hostname": "router01",
            "version": "1.0",
            "interfaces": {
                "ge-0/0/1": {
                    "description": "Uplink interface",
                    "unit": {
                        "0": {
                            "family": "inet",
                            "address": "192.168.1.1/24"
                        }
                    }
                }
            },
            "routing-options": {
                "static": {
                    "route": {
                        "0.0.0.0/0": {
                            "next-hop": "192.168.1.254"
                        }
                    }
                }
            }
        }

    @pytest.fixture
    def invalid_config(self):
        """Invalid configuration for testing."""
        return {
            "vendor": "unknown",
            "platform": "invalid",
            "hostname": "",
            "interfaces": {
                "invalid-interface": {
                    "description": "test"
                }
            }
        }

    @pytest.fixture
    def security_violation_config(self):
        """Configuration with security violations."""
        return {
            "vendor": "cisco",
            "platform": "ios",
            "hostname": "switch01",
            "version": "1.0",
            "users": {
                "admin": {
                    "password": "admin123",  # Weak password
                    "privilege": 15
                }
            },
            "snmp-server": {
                "community": "public read-only"  # Default community
            },
            "logging": {
                "host": "192.168.1.100"  # Unencrypted logging
            }
        }

    @pytest.mark.asyncio
    async def test_validate_valid_cisco_config(self, validator, valid_cisco_config):
        """Test validation of valid Cisco configuration."""
        result = await validator.validate_configuration(valid_cisco_config)

        assert result.is_valid
        assert len(result.errors) == 0
        assert result.vendor == "cisco"
        assert result.platform == "ios"

    @pytest.mark.asyncio
    async def test_validate_valid_juniper_config(self, validator, valid_juniper_config):
        """Test validation of valid Juniper configuration."""
        result = await validator.validate_configuration(valid_juniper_config)

        assert result.is_valid
        assert len(result.errors) == 0
        assert result.vendor == "juniper"
        assert result.platform == "junos"

    @pytest.mark.asyncio
    async def test_validate_invalid_config(self, validator, invalid_config):
        """Test validation of invalid configuration."""
        result = await validator.validate_configuration(invalid_config)

        assert not result.is_valid
        assert len(result.errors) > 0
        assert any("vendor" in error.lower() for error in result.errors)

    @pytest.mark.asyncio
    async def test_validate_missing_required_fields(self, validator):
        """Test validation with missing required fields."""
        config = {"vendor": "cisco"}  # Missing required fields

        result = await validator.validate_configuration(config)

        assert not result.is_valid
        assert any("hostname" in error.lower() for error in result.errors)
        assert any("platform" in error.lower() for error in result.errors)

    @pytest.mark.asyncio
    async def test_validate_schema_validation(self, validator):
        """Test schema validation layer."""
        config = {
            "vendor": "cisco",
            "platform": "ios",
            "hostname": "test",
            "version": "invalid_version_format",  # Should be semantic version
            "interfaces": "invalid_interfaces"  # Should be dict
        }

        result = await validator.validate_configuration(config)

        assert not result.is_valid
        assert len(result.errors) > 0

    @pytest.mark.asyncio
    async def test_validate_cisco_syntax(self, validator):
        """Test Cisco-specific syntax validation."""
        config = {
            "vendor": "cisco",
            "platform": "ios",
            "hostname": "switch01",
            "version": "1.0",
            "interfaces": {
                "Invalid-Interface-Name": {  # Invalid interface name
                    "description": "test"
                }
            }
        }

        result = await validator.validate_configuration(config)

        assert not result.is_valid
        assert any("interface" in error.lower() for error in result.errors)

    @pytest.mark.asyncio
    async def test_validate_juniper_syntax(self, validator):
        """Test Juniper-specific syntax validation."""
        config = {
            "vendor": "juniper",
            "platform": "junos",
            "hostname": "router01",
            "version": "1.0",
            "interfaces": {
                "invalid-interface": {  # Invalid Juniper interface format
                    "unit": {
                        "0": {
                            "family": "inet"
                        }
                    }
                }
            }
        }

        result = await validator.validate_configuration(config)

        assert not result.is_valid
        assert any("interface" in error.lower() for error in result.errors)

    @pytest.mark.asyncio
    async def test_security_compliance_check(self, validator, security_violation_config):
        """Test security compliance validation."""
        result = await validator.validate_configuration(security_violation_config)

        # Should have warnings for security violations
        assert len(result.warnings) > 0
        assert any("password" in warning.lower() for warning in result.warnings)
        assert any("community" in warning.lower() for warning in result.warnings)

    @pytest.mark.asyncio
    async def test_business_rules_validation(self, validator):
        """Test business rules validation."""
        config = {
            "vendor": "cisco",
            "platform": "ios",
            "hostname": "switch01",
            "version": "1.0",
            "vlans": {
                "1": {"name": "MANAGEMENT"},  # VLAN 1 should not be used
                "4095": {"name": "INVALID"}   # VLAN 4095 is reserved
            }
        }

        result = await validator.validate_configuration(config)

        # Should have warnings for business rule violations
        assert len(result.warnings) > 0 or len(result.errors) > 0

    @pytest.mark.asyncio
    async def test_conflict_detection(self, validator):
        """Test configuration conflict detection."""
        config = {
            "vendor": "cisco",
            "platform": "ios",
            "hostname": "switch01",
            "version": "1.0",
            "interfaces": {
                "GigabitEthernet0/1": {
                    "switchport": {
                        "mode": "access",
                        "access_vlan": 10
                    },
                    "no switchport": True  # Conflict: can't be both switchport and routed
                }
            }
        }

        result = await validator.validate_configuration(config)

        # Should detect conflict
        assert len(result.warnings) > 0 or len(result.errors) > 0

    @pytest.mark.asyncio
    async def test_validate_configuration_with_exception(self, validator):
        """Test handling of validation exceptions."""
        with patch.object(validator, '_validate_schema', side_effect=Exception("Test error")):
            result = await validator.validate_configuration({"vendor": "cisco"})

            assert not result.is_valid
            assert any("validation failed" in error.lower() for error in result.errors)

    @pytest.mark.asyncio
    async def test_validate_large_configuration(self, validator):
        """Test validation of large configuration."""
        # Generate large config with many interfaces
        config = {
            "vendor": "cisco",
            "platform": "ios",
            "hostname": "switch01",
            "version": "1.0",
            "interfaces": {}
        }

        # Add 100 interfaces
        for i in range(100):
            config["interfaces"][f"GigabitEthernet0/{i}"] = {
                "description": f"Interface {i}",
                "no shutdown": True
            }

        result = await validator.validate_configuration(config)

        assert result.is_valid

    @pytest.mark.asyncio
    async def test_validate_nested_configuration(self, validator):
        """Test validation of deeply nested configuration."""
        config = {
            "vendor": "cisco",
            "platform": "ios",
            "hostname": "switch01",
            "version": "1.0",
            "policy-map": {
                "VOICE": {
                    "class": {
                        "VOICE_CLASS": {
                            "priority": {
                                "level": 1,
                                "bandwidth": {
                                    "percent": 30
                                }
                            }
                        }
                    }
                }
            }
        }

        result = await validator.validate_configuration(config)

        assert result.is_valid

    def test_validation_result_properties(self):
        """Test ValidationResult properties and methods."""
        result = ValidationResult()

        # Test initial state
        assert result.is_valid
        assert len(result.errors) == 0
        assert len(result.warnings) == 0

        # Test adding errors
        result.add_error("Test error")
        assert not result.is_valid
        assert len(result.errors) == 1

        # Test adding warnings
        result.add_warning("Test warning")
        assert len(result.warnings) == 1

        # Test summary
        summary = result.get_summary()
        assert "Test error" in summary
        assert "Test warning" in summary

    @pytest.mark.asyncio
    async def test_validate_with_custom_rules(self, validator):
        """Test validation with custom business rules."""
        # Mock custom rule that forbids certain hostnames
        def custom_hostname_rule(config):
            if config.get("hostname") in ["forbidden", "invalid"]:
                return ["Hostname is not allowed"]
            return []

        validator._custom_rules = [custom_hostname_rule]

        config = {
            "vendor": "cisco",
            "platform": "ios",
            "hostname": "forbidden",
            "version": "1.0"
        }

        result = await validator.validate_configuration(config)

        assert not result.is_valid
        assert any("hostname" in error.lower() for error in result.errors)

    @pytest.mark.asyncio
    async def test_validate_concurrent_requests(self, validator, valid_cisco_config):
        """Test validator handles concurrent requests correctly."""
        import asyncio

        # Run multiple validations concurrently
        tasks = []
        for _ in range(10):
            task = validator.validate_configuration(valid_cisco_config.copy())
            tasks.append(task)

        results = await asyncio.gather(*tasks)

        # All should succeed
        for result in results:
            assert result.is_valid

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_security_scan_secrets(self, validator):
        """Test security scanning detects secrets in configuration."""
        config = {
            "vendor": "cisco",
            "platform": "ios",
            "hostname": "switch01",
            "version": "1.0",
            "users": {
                "admin": {
                    "secret": "ThisIsASecretPassword123!",
                    "privilege": 15
                }
            },
            "crypto": {
                "key": "rsa_private_key_here_abcdef123456"
            }
        }

        result = await validator.validate_configuration(config)

        # Should detect potential secrets
        assert len(result.warnings) > 0
        assert any("secret" in warning.lower() or "password" in warning.lower()
                  for warning in result.warnings)

    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_validator_performance(self, validator, valid_cisco_config):
        """Test validator performance with timing."""
        import time

        start_time = time.time()

        # Run validation 100 times
        for _ in range(100):
            await validator.validate_configuration(valid_cisco_config)

        end_time = time.time()
        duration = end_time - start_time

        # Should complete 100 validations in reasonable time (< 5 seconds)
        assert duration < 5.0

    @pytest.mark.asyncio
    async def test_validate_empty_configuration(self, validator):
        """Test validation of empty configuration."""
        result = await validator.validate_configuration({})

        assert not result.is_valid
        assert len(result.errors) > 0

    @pytest.mark.asyncio
    async def test_validate_none_configuration(self, validator):
        """Test validation of None configuration."""
        result = await validator.validate_configuration(None)

        assert not result.is_valid
        assert len(result.errors) > 0
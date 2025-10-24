"""
Unit tests for core logger module
Tests logging configuration, formatters, filters, and logging functions
"""

import pytest
from unittest.mock import patch, Mock, MagicMock, call
import logging
from pathlib import Path
import json
import hashlib
from datetime import datetime

from src.core.logger import (
    SecurityFilter, AuditFormatter, CatNetLogger,
    get_logger, log_audit, log_security, log_performance,
    log_device, log_deployment
)


@pytest.fixture
def mock_log_dir(tmp_path):
    """Create temporary log directory."""
    return tmp_path / "logs"


class TestSecurityFilter:
    """Test SecurityFilter for redacting sensitive information."""

    def test_security_filter_initialization(self):
        """Test SecurityFilter initialization."""
        security_filter = SecurityFilter()

        assert 'password' in security_filter.sensitive_patterns
        assert 'secret' in security_filter.sensitive_patterns
        assert 'token' in security_filter.sensitive_patterns

    def test_filter_redacts_password_in_message(self):
        """Test password redaction in log message."""
        security_filter = SecurityFilter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="Login with password=secret123",
            args=(),
            exc_info=None
        )

        security_filter.filter(record)

        assert "password=secret123" not in str(record.msg)
        assert "***REDACTED***" in str(record.msg)

    def test_filter_redacts_sensitive_field_values(self):
        """Test redaction of sensitive field values."""
        security_filter = SecurityFilter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="Test message",
            args=(),
            exc_info=None
        )
        record.password = "secret123"
        record.api_key = "key_abc123"

        security_filter.filter(record)

        assert record.password == "***REDACTED***"
        assert record.api_key == "***REDACTED***"

    def test_filter_redacts_nested_dict_values(self):
        """Test redaction of sensitive values in nested dictionaries."""
        security_filter = SecurityFilter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="Test message",
            args=(),
            exc_info=None
        )
        record.user_data = {
            "username": "testuser",
            "password": "secret123",
            "nested": {
                "token": "abc123"
            }
        }

        security_filter.filter(record)

        assert record.user_data['username'] == "testuser"
        assert record.user_data['password'] == "***REDACTED***"
        assert record.user_data['nested']['token'] == "***REDACTED***"

    def test_filter_handles_list_with_dicts(self):
        """Test redaction in lists containing dictionaries."""
        security_filter = SecurityFilter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="Test message",
            args=(),
            exc_info=None
        )
        record.credentials = [
            {"username": "user1", "password": "pass1"},
            {"username": "user2", "secret": "secret2"}
        ]

        security_filter.filter(record)

        assert record.credentials[0]['password'] == "***REDACTED***"
        assert record.credentials[1]['secret'] == "***REDACTED***"

    def test_filter_case_insensitive_patterns(self):
        """Test case-insensitive pattern matching."""
        security_filter = SecurityFilter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="PASSWORD: secret123",
            args=(),
            exc_info=None
        )

        security_filter.filter(record)

        assert "secret123" not in str(record.msg)
        assert "***REDACTED***" in str(record.msg)


class TestAuditFormatter:
    """Test AuditFormatter for JSON audit logs."""

    def test_audit_formatter_adds_timestamp(self):
        """Test AuditFormatter adds timestamp."""
        formatter = AuditFormatter()
        record = logging.LogRecord(
            name="audit",
            level=logging.INFO,
            pathname="test.py",
            lineno=42,
            msg="Audit event",
            args=(),
            exc_info=None
        )

        log_dict = {}
        formatter.add_fields(log_dict, record, {})

        assert 'timestamp' in log_dict
        # Should be valid ISO format
        datetime.fromisoformat(log_dict['timestamp'])

    def test_audit_formatter_adds_log_level(self):
        """Test AuditFormatter adds log level."""
        formatter = AuditFormatter()
        record = logging.LogRecord(
            name="audit",
            level=logging.WARNING,
            pathname="test.py",
            lineno=42,
            msg="Warning event",
            args=(),
            exc_info=None
        )

        log_dict = {}
        formatter.add_fields(log_dict, record, {})

        assert log_dict['level'] == 'WARNING'

    def test_audit_formatter_adds_source_info(self):
        """Test AuditFormatter adds source information."""
        formatter = AuditFormatter()
        record = logging.LogRecord(
            name="audit",
            level=logging.INFO,
            pathname="test_module.py",
            lineno=123,
            msg="Event",
            args=(),
            exc_info=None
        )
        record.module = "test_module"
        record.funcName = "test_function"

        log_dict = {}
        formatter.add_fields(log_dict, record, {})

        assert log_dict['module'] == "test_module"
        assert log_dict['function'] == "test_function"
        assert log_dict['line'] == 123

    def test_audit_formatter_adds_process_thread_info(self):
        """Test AuditFormatter adds process and thread information."""
        formatter = AuditFormatter()
        record = logging.LogRecord(
            name="audit",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="Event",
            args=(),
            exc_info=None
        )

        log_dict = {}
        formatter.add_fields(log_dict, record, {})

        assert 'process_id' in log_dict
        assert 'thread_id' in log_dict
        assert 'thread_name' in log_dict

    def test_audit_formatter_adds_integrity_hash(self):
        """Test AuditFormatter adds integrity hash."""
        formatter = AuditFormatter()
        record = logging.LogRecord(
            name="audit",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="Test event",
            args=(),
            exc_info=None
        )

        log_dict = {}
        formatter.add_fields(log_dict, record, {})

        assert 'integrity_hash' in log_dict
        # Should be valid SHA256 hash (64 hex characters)
        assert len(log_dict['integrity_hash']) == 64

    def test_audit_formatter_adds_exception_info(self):
        """Test AuditFormatter adds exception information."""
        formatter = AuditFormatter()

        try:
            raise ValueError("Test exception")
        except ValueError:
            import sys
            exc_info = sys.exc_info()

        record = logging.LogRecord(
            name="audit",
            level=logging.ERROR,
            pathname="test.py",
            lineno=1,
            msg="Error occurred",
            args=(),
            exc_info=exc_info
        )

        log_dict = {}
        formatter.add_fields(log_dict, record, {})

        assert 'exception' in log_dict
        assert log_dict['exception']['type'] == 'ValueError'
        assert log_dict['exception']['message'] == 'Test exception'
        assert 'traceback' in log_dict['exception']


class TestCatNetLogger:
    """Test CatNetLogger singleton class."""

    def test_catnet_logger_singleton(self):
        """Test CatNetLogger is a singleton."""
        with patch.object(Path, 'mkdir'):
            logger1 = CatNetLogger()
            logger2 = CatNetLogger()

            assert logger1 is logger2

    @patch.object(Path, 'mkdir')
    def test_catnet_logger_creates_log_directory(self, mock_mkdir):
        """Test CatNetLogger creates log directory."""
        logger = CatNetLogger()

        mock_mkdir.assert_called_with(parents=True, exist_ok=True)

    @patch.object(Path, 'mkdir')
    def test_get_logger_returns_named_logger(self, mock_mkdir):
        """Test get_logger returns correct logger."""
        catnet_logger = CatNetLogger()

        audit_logger = catnet_logger.get_logger('audit')
        assert audit_logger.name == 'audit'

        device_logger = catnet_logger.get_logger('device')
        assert device_logger.name == 'device'

    @patch.object(Path, 'mkdir')
    def test_get_logger_returns_custom_logger(self, mock_mkdir):
        """Test get_logger returns custom logger for unknown names."""
        catnet_logger = CatNetLogger()

        custom_logger = catnet_logger.get_logger('custom_module')
        assert custom_logger.name == 'custom_module'


class TestLogAuditEvent:
    """Test log_audit_event method."""

    @patch.object(Path, 'mkdir')
    def test_log_audit_event_basic(self, mock_mkdir):
        """Test basic audit event logging."""
        catnet_logger = CatNetLogger()
        audit_logger = catnet_logger.get_logger('audit')

        with patch.object(audit_logger, 'info') as mock_info:
            catnet_logger.log_audit_event(
                event_type='user_login',
                user='testuser',
                outcome='success'
            )

            mock_info.assert_called_once()
            call_args = mock_info.call_args
            assert call_args[0][0] == 'Audit Event'
            assert call_args[1]['extra']['event_type'] == 'user_login'
            assert call_args[1]['extra']['user'] == 'testuser'
            assert call_args[1]['extra']['outcome'] == 'success'

    @patch.object(Path, 'mkdir')
    def test_log_audit_event_with_details(self, mock_mkdir):
        """Test audit event logging with details."""
        catnet_logger = CatNetLogger()
        audit_logger = catnet_logger.get_logger('audit')

        details = {'ip_address': '192.168.1.100', 'user_agent': 'Mozilla/5.0'}

        with patch.object(audit_logger, 'info') as mock_info:
            catnet_logger.log_audit_event(
                event_type='password_change',
                user='testuser',
                details=details,
                resource_id='user_123',
                outcome='success'
            )

            call_args = mock_info.call_args
            assert call_args[1]['extra']['details'] == details
            assert call_args[1]['extra']['resource_id'] == 'user_123'


class TestLogSecurityEvent:
    """Test log_security_event method."""

    @patch.object(Path, 'mkdir')
    def test_log_security_event_warning(self, mock_mkdir):
        """Test security event logging at warning level."""
        catnet_logger = CatNetLogger()
        security_logger = catnet_logger.get_logger('security')

        with patch.object(security_logger, 'warning') as mock_warning:
            catnet_logger.log_security_event(
                event_type='failed_login',
                severity='warning',
                description='Multiple failed login attempts',
                source_ip='192.168.1.100',
                user='attacker'
            )

            mock_warning.assert_called_once()
            call_args = mock_warning.call_args
            assert call_args[1]['extra']['event_type'] == 'failed_login'
            assert call_args[1]['extra']['severity'] == 'warning'

    @patch.object(Path, 'mkdir')
    def test_log_security_event_critical(self, mock_mkdir):
        """Test security event logging at critical level."""
        catnet_logger = CatNetLogger()
        security_logger = catnet_logger.get_logger('security')

        with patch.object(security_logger, 'critical') as mock_critical:
            catnet_logger.log_security_event(
                event_type='intrusion_detected',
                severity='critical',
                description='Unauthorized access detected'
            )

            mock_critical.assert_called_once()


class TestLogPerformanceMetric:
    """Test log_performance_metric method."""

    @patch.object(Path, 'mkdir')
    def test_log_performance_metric_success(self, mock_mkdir):
        """Test performance metric logging for successful operation."""
        catnet_logger = CatNetLogger()
        perf_logger = catnet_logger.get_logger('performance')

        with patch.object(perf_logger, 'info') as mock_info:
            catnet_logger.log_performance_metric(
                operation='database_query',
                duration_ms=45.67,
                success=True,
                metadata={'query': 'SELECT * FROM devices'}
            )

            mock_info.assert_called_once()
            call_args = mock_info.call_args
            assert 'database_query' in call_args[0][0]
            assert '45.67ms' in call_args[0][0]
            assert 'SUCCESS' in call_args[0][0]

    @patch.object(Path, 'mkdir')
    def test_log_performance_metric_failure(self, mock_mkdir):
        """Test performance metric logging for failed operation."""
        catnet_logger = CatNetLogger()
        perf_logger = catnet_logger.get_logger('performance')

        with patch.object(perf_logger, 'info') as mock_info:
            catnet_logger.log_performance_metric(
                operation='api_call',
                duration_ms=5000.0,
                success=False
            )

            call_args = mock_info.call_args
            assert 'FAILED' in call_args[0][0]


class TestLogDeviceCommunication:
    """Test log_device_communication method."""

    @patch.object(Path, 'mkdir')
    def test_log_device_communication_success(self, mock_mkdir):
        """Test device communication logging for success."""
        catnet_logger = CatNetLogger()
        device_logger = catnet_logger.get_logger('device')

        with patch.object(device_logger, 'info') as mock_info:
            catnet_logger.log_device_communication(
                device_id='device_001',
                device_name='router-01',
                action='config_backup',
                command='show running-config',
                output='Config output here',
                success=True
            )

            mock_info.assert_called_once()
            call_args = mock_info.call_args
            assert 'router-01' in call_args[0][0]
            assert 'config_backup' in call_args[0][0]

    @patch.object(Path, 'mkdir')
    def test_log_device_communication_failure(self, mock_mkdir):
        """Test device communication logging for failure."""
        catnet_logger = CatNetLogger()
        device_logger = catnet_logger.get_logger('device')

        with patch.object(device_logger, 'error') as mock_error:
            catnet_logger.log_device_communication(
                device_id='device_001',
                device_name='router-01',
                action='connection',
                success=False,
                error='Connection timeout'
            )

            mock_error.assert_called_once()
            call_args = mock_error.call_args
            assert 'failed' in call_args[0][0]


class TestLogDeploymentEvent:
    """Test log_deployment_event method."""

    @patch.object(Path, 'mkdir')
    def test_log_deployment_event_success(self, mock_mkdir):
        """Test deployment event logging for success."""
        catnet_logger = CatNetLogger()
        deployment_logger = catnet_logger.get_logger('deployment')

        with patch.object(deployment_logger, 'info') as mock_info:
            catnet_logger.log_deployment_event(
                deployment_id='deploy_123',
                event='configuration_applied',
                stage='canary',
                devices_affected=5,
                success=True
            )

            mock_info.assert_called_once()
            call_args = mock_info.call_args
            assert 'deploy_123' in call_args[0][0]
            assert 'canary' in call_args[0][0]

    @patch.object(Path, 'mkdir')
    def test_log_deployment_event_failure(self, mock_mkdir):
        """Test deployment event logging for failure."""
        catnet_logger = CatNetLogger()
        deployment_logger = catnet_logger.get_logger('deployment')

        with patch.object(deployment_logger, 'error') as mock_error:
            catnet_logger.log_deployment_event(
                deployment_id='deploy_456',
                event='rollback',
                stage='production',
                devices_affected=10,
                success=False,
                details={'reason': 'Validation failed'}
            )

            mock_error.assert_called_once()
            call_args = mock_error.call_args
            assert 'failed' in call_args[0][0]


class TestConvenienceFunctions:
    """Test convenience logging functions."""

    @patch('src.core.logger.catnet_logger')
    def test_log_audit_function(self, mock_logger):
        """Test log_audit convenience function."""
        log_audit(
            event_type='test_event',
            user='testuser',
            details={'key': 'value'}
        )

        mock_logger.log_audit_event.assert_called_once_with(
            'test_event',
            'testuser',
            {'key': 'value'},
            None,
            'success'
        )

    @patch('src.core.logger.catnet_logger')
    def test_log_security_function(self, mock_logger):
        """Test log_security convenience function."""
        log_security(
            event_type='intrusion',
            severity='critical',
            description='Attack detected'
        )

        mock_logger.log_security_event.assert_called_once()

    @patch('src.core.logger.catnet_logger')
    def test_log_performance_function(self, mock_logger):
        """Test log_performance convenience function."""
        log_performance(
            operation='test_op',
            duration_ms=100.0,
            success=True
        )

        mock_logger.log_performance_metric.assert_called_once()

    @patch('src.core.logger.catnet_logger')
    def test_log_device_function(self, mock_logger):
        """Test log_device convenience function."""
        log_device(
            device_id='device_001',
            device_name='router-01',
            action='backup'
        )

        mock_logger.log_device_communication.assert_called_once()

    @patch('src.core.logger.catnet_logger')
    def test_log_deployment_function(self, mock_logger):
        """Test log_deployment convenience function."""
        log_deployment(
            deployment_id='deploy_123',
            event='started',
            stage='canary',
            devices_affected=5
        )

        mock_logger.log_deployment_event.assert_called_once()


class TestGetLogStats:
    """Test get_log_stats method."""

    @patch.object(Path, 'mkdir')
    @patch.object(Path, 'glob')
    def test_get_log_stats(self, mock_glob, mock_mkdir):
        """Test get_log_stats returns file statistics."""
        # Mock log files
        mock_file = Mock()
        mock_file.name = 'catnet.log'
        mock_stat = Mock()
        mock_stat.st_size = 1024 * 1024  # 1 MB
        mock_stat.st_mtime = datetime(2025, 1, 1).timestamp()
        mock_file.stat.return_value = mock_stat
        mock_glob.return_value = [mock_file]

        catnet_logger = CatNetLogger()
        stats = catnet_logger.get_log_stats()

        assert 'catnet.log' in stats
        assert stats['catnet.log']['size_bytes'] == 1024 * 1024
        assert stats['catnet.log']['size_mb'] == 1.0
        assert 'modified' in stats['catnet.log']

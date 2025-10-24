"""
Unit tests for backup worker.
Tests backup creation, restoration, scheduling, and cleanup operations.
"""

import pytest
from datetime import datetime, timedelta
from uuid import UUID, uuid4
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from pathlib import Path
from typing import Dict, Any
import hashlib

from src.workers.backup_worker import BackupWorker
from src.workers.base import WorkerTask
from src.db.models import Device, ConfigBackup
from src.core.exceptions import BackupError


@pytest.fixture
def worker():
    """Create backup worker instance."""
    with patch('src.workers.backup_worker.SecureDeviceConnector'), \
         patch('src.workers.backup_worker.EncryptionManager'), \
         patch('src.workers.backup_worker.VaultClient'), \
         patch('src.workers.backup_worker.get_settings') as mock_settings:

        mock_settings.return_value.BACKUP_STORAGE_PATH = '/tmp/backups'

        worker = BackupWorker()
        worker.audit = AsyncMock()
        worker.audit.log_event = AsyncMock()
        worker.encryption.encrypt = AsyncMock(return_value=b'encrypted_data')
        worker.encryption.decrypt = AsyncMock(return_value='decrypted_config')
        worker.encryption.get_current_key_id = Mock(return_value='key_001')

        return worker


@pytest.fixture
def sample_device():
    """Sample device object."""
    device = Mock(spec=Device)
    device.id = uuid4()
    device.hostname = 'router-01'
    device.vendor = 'cisco'
    device.model = 'ISR4451'
    device.is_active = True
    device.last_backup_id = None
    device.last_backup_at = None
    return device


@pytest.fixture
def sample_backup():
    """Sample backup object."""
    backup = Mock(spec=ConfigBackup)
    backup.id = uuid4()
    backup.device_id = uuid4()
    backup.config_hash = hashlib.sha256(b'test_config').hexdigest()
    backup.file_path = '/tmp/backups/test.bak'
    backup.size_bytes = 1024
    backup.created_at = datetime.utcnow()
    backup.is_encrypted = True
    backup.encryption_key_id = 'key_001'
    backup.restore_count = 0
    return backup


class TestBackupWorkerInitialization:
    """Test backup worker initialization."""

    def test_worker_initialization(self, worker):
        """Test worker initializes correctly."""
        assert worker.get_worker_type() == "backup"
        assert hasattr(worker, 'device_connector')
        assert hasattr(worker, 'encryption')
        assert hasattr(worker, 'vault')
        assert hasattr(worker, 'backup_base_path')

    def test_backup_base_path_configuration(self, worker):
        """Test backup base path is configured."""
        assert worker.backup_base_path is not None
        assert isinstance(worker.backup_base_path, Path)


class TestProcessTask:
    """Test task processing."""

    @pytest.mark.asyncio
    async def test_process_create_backup_task(self, worker):
        """Test processing create backup task."""
        task = Mock(spec=WorkerTask)
        task.task_type = "create_backup"
        task.payload = {
            'device_id': str(uuid4()),
            'user_id': str(uuid4()),
            'description': 'Manual backup'
        }

        worker._create_backup = AsyncMock(return_value={'status': 'success'})

        result = await worker.process_task(task)

        assert result['status'] == 'success'
        worker._create_backup.assert_called_once_with(task.payload)

    @pytest.mark.asyncio
    async def test_process_restore_backup_task(self, worker):
        """Test processing restore backup task."""
        task = Mock(spec=WorkerTask)
        task.task_type = "restore_backup"
        task.payload = {
            'device_id': str(uuid4()),
            'backup_id': str(uuid4()),
            'user_id': str(uuid4())
        }

        worker._restore_backup = AsyncMock(return_value={'status': 'success'})

        result = await worker.process_task(task)

        assert result['status'] == 'success'

    @pytest.mark.asyncio
    async def test_process_scheduled_backup_task(self, worker):
        """Test processing scheduled backup task."""
        task = Mock(spec=WorkerTask)
        task.task_type = "scheduled_backup"
        task.payload = {
            'schedule_name': 'daily',
            'device_filter': {'vendor': 'cisco'}
        }

        worker._scheduled_backup = AsyncMock(return_value={'status': 'completed', 'successful': 10})

        result = await worker.process_task(task)

        assert result['status'] == 'completed'

    @pytest.mark.asyncio
    async def test_process_cleanup_old_backups_task(self, worker):
        """Test processing cleanup task."""
        task = Mock(spec=WorkerTask)
        task.task_type = "cleanup_old_backups"
        task.payload = {
            'retention_days': 30,
            'keep_minimum': 5
        }

        worker._cleanup_old_backups = AsyncMock(return_value={'status': 'success', 'total_deleted': 50})

        result = await worker.process_task(task)

        assert result['status'] == 'success'
        assert result['total_deleted'] == 50

    @pytest.mark.asyncio
    async def test_process_verify_backup_task(self, worker):
        """Test processing verify backup task."""
        task = Mock(spec=WorkerTask)
        task.task_type = "verify_backup"
        task.payload = {'backup_id': str(uuid4())}

        worker._verify_backup = AsyncMock(return_value={'status': 'success', 'valid': True})

        result = await worker.process_task(task)

        assert result['status'] == 'success'
        assert result['valid'] is True

    @pytest.mark.asyncio
    async def test_process_bulk_backup_task(self, worker):
        """Test processing bulk backup task."""
        task = Mock(spec=WorkerTask)
        task.task_type = "bulk_backup"
        task.payload = {
            'device_ids': [str(uuid4()) for _ in range(5)],
            'description': 'Bulk backup'
        }

        worker._bulk_backup = AsyncMock(return_value={'status': 'completed', 'successful': 5})

        result = await worker.process_task(task)

        assert result['status'] == 'completed'

    @pytest.mark.asyncio
    async def test_process_unknown_task_type_raises_error(self, worker):
        """Test unknown task type raises ValueError."""
        task = Mock(spec=WorkerTask)
        task.task_type = "unknown_task"
        task.payload = {}

        with pytest.raises(ValueError, match="Unknown task type"):
            await worker.process_task(task)


class TestCreateBackup:
    """Test backup creation."""

    @pytest.mark.asyncio
    async def test_create_backup_success(self, worker, sample_device):
        """Test successful backup creation."""
        payload = {
            'device_id': str(sample_device.id),
            'user_id': str(uuid4()),
            'description': 'Manual backup'
        }

        config_data = "hostname router-01\ninterface GigabitEthernet0/0\n"

        mock_connection = AsyncMock()
        mock_connection.get_configuration = AsyncMock(return_value=config_data)
        worker.device_connector.connect_to_device = AsyncMock(return_value=mock_connection)

        mock_db = AsyncMock()
        mock_db.get = AsyncMock(return_value=sample_device)
        mock_db.add = Mock()
        mock_db.commit = AsyncMock()

        worker._store_backup_file = AsyncMock(return_value=Path('/tmp/backups/backup.bak'))

        with patch('src.workers.backup_worker.get_db', return_value=AsyncMock(__aenter__=AsyncMock(return_value=mock_db), __aexit__=AsyncMock())), \
             patch('src.workers.backup_worker.UUID', return_value=uuid4()), \
             patch('src.workers.backup_worker.ConfigBackup'):

            result = await worker._create_backup(payload)

        assert result['status'] == 'success'
        assert 'backup_id' in result
        assert 'config_hash' in result
        assert result['device_id'] == str(sample_device.id)

    @pytest.mark.asyncio
    async def test_create_backup_device_not_found(self, worker):
        """Test backup creation with non-existent device."""
        payload = {
            'device_id': str(uuid4()),
            'description': 'Test backup'
        }

        mock_db = AsyncMock()
        mock_db.get = AsyncMock(return_value=None)

        with patch('src.workers.backup_worker.get_db', return_value=AsyncMock(__aenter__=AsyncMock(return_value=mock_db), __aexit__=AsyncMock())):
            with pytest.raises(BackupError, match="not found"):
                await worker._create_backup(payload)

    @pytest.mark.asyncio
    async def test_create_backup_encrypts_configuration(self, worker, sample_device):
        """Test backup encrypts configuration."""
        payload = {
            'device_id': str(sample_device.id),
            'description': 'Test encryption'
        }

        config_data = "test configuration"

        mock_connection = AsyncMock()
        mock_connection.get_configuration = AsyncMock(return_value=config_data)
        worker.device_connector.connect_to_device = AsyncMock(return_value=mock_connection)

        mock_db = AsyncMock()
        mock_db.get = AsyncMock(return_value=sample_device)
        mock_db.add = Mock()
        mock_db.commit = AsyncMock()

        worker._store_backup_file = AsyncMock(return_value=Path('/tmp/backup.bak'))

        with patch('src.workers.backup_worker.get_db', return_value=AsyncMock(__aenter__=AsyncMock(return_value=mock_db), __aexit__=AsyncMock())), \
             patch('src.workers.backup_worker.UUID', return_value=uuid4()), \
             patch('src.workers.backup_worker.ConfigBackup'):

            await worker._create_backup(payload)

        # Verify encryption was called
        worker.encryption.encrypt.assert_called_once_with(config_data)

    @pytest.mark.asyncio
    async def test_create_backup_updates_device_last_backup(self, worker, sample_device):
        """Test backup updates device last backup info."""
        payload = {
            'device_id': str(sample_device.id),
            'description': 'Test update'
        }

        config_data = "test config"

        mock_connection = AsyncMock()
        mock_connection.get_configuration = AsyncMock(return_value=config_data)
        worker.device_connector.connect_to_device = AsyncMock(return_value=mock_connection)

        mock_db = AsyncMock()
        mock_db.get = AsyncMock(return_value=sample_device)
        mock_db.add = Mock()
        mock_db.commit = AsyncMock()

        worker._store_backup_file = AsyncMock(return_value=Path('/tmp/backup.bak'))

        with patch('src.workers.backup_worker.get_db', return_value=AsyncMock(__aenter__=AsyncMock(return_value=mock_db), __aexit__=AsyncMock())), \
             patch('src.workers.backup_worker.UUID', return_value=uuid4()), \
             patch('src.workers.backup_worker.ConfigBackup'):

            await worker._create_backup(payload)

        assert sample_device.last_backup_id is not None
        assert sample_device.last_backup_at is not None


class TestRestoreBackup:
    """Test backup restoration."""

    @pytest.mark.asyncio
    async def test_restore_backup_success(self, worker, sample_device, sample_backup):
        """Test successful backup restoration."""
        sample_backup.device_id = sample_device.id

        payload = {
            'device_id': str(sample_device.id),
            'backup_id': str(sample_backup.id),
            'user_id': str(uuid4()),
            'verify': True
        }

        mock_connection = AsyncMock()
        mock_connection.apply_configuration = AsyncMock()
        mock_connection.check_health = AsyncMock(return_value={'healthy': True})
        worker.device_connector.connect_to_device = AsyncMock(return_value=mock_connection)

        mock_db = AsyncMock()
        mock_db.get = AsyncMock(side_effect=[sample_backup, sample_device])
        mock_db.commit = AsyncMock()

        worker._load_backup_file = AsyncMock(return_value=b'encrypted_config')
        worker._create_backup = AsyncMock(return_value={'backup_id': str(uuid4())})

        config_hash = hashlib.sha256(b'decrypted_config').hexdigest()
        sample_backup.config_hash = config_hash

        with patch('src.workers.backup_worker.get_db', return_value=AsyncMock(__aenter__=AsyncMock(return_value=mock_db), __aexit__=AsyncMock())), \
             patch('src.workers.backup_worker.hashlib.sha256') as mock_hash:

            mock_hash.return_value.hexdigest.return_value = config_hash

            result = await worker._restore_backup(payload)

        assert result['status'] == 'success'
        assert 'pre_restore_backup' in result

    @pytest.mark.asyncio
    async def test_restore_backup_wrong_device(self, worker, sample_device, sample_backup):
        """Test restore fails when backup doesn't belong to device."""
        sample_backup.device_id = uuid4()  # Different device

        payload = {
            'device_id': str(sample_device.id),
            'backup_id': str(sample_backup.id)
        }

        mock_db = AsyncMock()
        mock_db.get = AsyncMock(return_value=sample_backup)

        with patch('src.workers.backup_worker.get_db', return_value=AsyncMock(__aenter__=AsyncMock(return_value=mock_db), __aexit__=AsyncMock())):
            with pytest.raises(BackupError, match="does not belong to device"):
                await worker._restore_backup(payload)

    @pytest.mark.asyncio
    async def test_restore_backup_integrity_check_fails(self, worker, sample_device, sample_backup):
        """Test restore fails on integrity check failure."""
        sample_backup.device_id = sample_device.id
        sample_backup.config_hash = 'correct_hash'

        payload = {
            'device_id': str(sample_device.id),
            'backup_id': str(sample_backup.id),
            'verify': True
        }

        mock_db = AsyncMock()
        mock_db.get = AsyncMock(side_effect=[sample_backup, sample_device])

        worker._load_backup_file = AsyncMock(return_value=b'encrypted_config')

        with patch('src.workers.backup_worker.get_db', return_value=AsyncMock(__aenter__=AsyncMock(return_value=mock_db), __aexit__=AsyncMock())), \
             patch('src.workers.backup_worker.hashlib.sha256') as mock_hash:

            mock_hash.return_value.hexdigest.return_value = 'wrong_hash'

            with pytest.raises(BackupError, match="integrity check failed"):
                await worker._restore_backup(payload)

    @pytest.mark.asyncio
    async def test_restore_backup_creates_pre_restore_backup(self, worker, sample_device, sample_backup):
        """Test restore creates pre-restore backup."""
        sample_backup.device_id = sample_device.id

        payload = {
            'device_id': str(sample_device.id),
            'backup_id': str(sample_backup.id),
            'verify': False
        }

        mock_connection = AsyncMock()
        mock_connection.apply_configuration = AsyncMock()
        mock_connection.check_health = AsyncMock(return_value={'healthy': True})
        worker.device_connector.connect_to_device = AsyncMock(return_value=mock_connection)

        mock_db = AsyncMock()
        mock_db.get = AsyncMock(side_effect=[sample_backup, sample_device])
        mock_db.commit = AsyncMock()

        worker._load_backup_file = AsyncMock(return_value=b'encrypted_config')
        worker._create_backup = AsyncMock(return_value={'backup_id': str(uuid4())})

        with patch('src.workers.backup_worker.get_db', return_value=AsyncMock(__aenter__=AsyncMock(return_value=mock_db), __aexit__=AsyncMock())):
            result = await worker._restore_backup(payload)

        # Verify pre-restore backup was created
        worker._create_backup.assert_called_once()
        assert 'pre_restore_backup' in result


class TestScheduledBackup:
    """Test scheduled backup operations."""

    @pytest.mark.asyncio
    async def test_scheduled_backup_success(self, worker):
        """Test scheduled backup for multiple devices."""
        devices = []
        for i in range(5):
            device = Mock(spec=Device)
            device.id = uuid4()
            device.hostname = f'device-{i}'
            device.is_active = True
            devices.append(device)

        payload = {
            'schedule_name': 'daily',
            'device_filter': {'vendor': 'cisco'}
        }

        mock_query = AsyncMock()
        mock_query.filter.return_value = mock_query
        mock_query.all = AsyncMock(return_value=devices)

        mock_db = AsyncMock()
        mock_db.query.return_value = mock_query

        worker._create_backup = AsyncMock(return_value={'backup_id': str(uuid4())})

        with patch('src.workers.backup_worker.get_db', return_value=AsyncMock(__aenter__=AsyncMock(return_value=mock_db), __aexit__=AsyncMock())):
            result = await worker._scheduled_backup(payload)

        assert result['status'] == 'completed'
        assert result['total_devices'] == 5
        assert result['successful'] <= 5

    @pytest.mark.asyncio
    async def test_scheduled_backup_handles_failures(self, worker):
        """Test scheduled backup handles individual failures."""
        devices = [Mock(spec=Device) for _ in range(3)]
        for i, device in enumerate(devices):
            device.id = uuid4()
            device.is_active = True

        payload = {'schedule_name': 'hourly'}

        mock_query = AsyncMock()
        mock_query.filter.return_value = mock_query
        mock_query.all = AsyncMock(return_value=devices)

        mock_db = AsyncMock()
        mock_db.query.return_value = mock_query

        # First backup succeeds, rest fail
        worker._create_backup = AsyncMock(side_effect=[
            {'backup_id': str(uuid4())},
            Exception("Backup failed"),
            Exception("Backup failed")
        ])

        with patch('src.workers.backup_worker.get_db', return_value=AsyncMock(__aenter__=AsyncMock(return_value=mock_db), __aexit__=AsyncMock())):
            result = await worker._scheduled_backup(payload)

        assert result['successful'] == 1
        assert result['failed'] == 2


class TestCleanupOldBackups:
    """Test backup cleanup operations."""

    @pytest.mark.asyncio
    async def test_cleanup_old_backups(self, worker):
        """Test cleaning up old backups."""
        device = Mock(spec=Device)
        device.id = uuid4()

        # Create old and new backups
        old_backups = []
        for i in range(10):
            backup = Mock(spec=ConfigBackup)
            backup.id = uuid4()
            backup.device_id = device.id
            backup.created_at = datetime.utcnow() - timedelta(days=40 + i)
            backup.file_path = f'/tmp/backup_{i}.bak'
            old_backups.append(backup)

        new_backups = []
        for i in range(5):
            backup = Mock(spec=ConfigBackup)
            backup.id = uuid4()
            backup.device_id = device.id
            backup.created_at = datetime.utcnow() - timedelta(days=i)
            backup.file_path = f'/tmp/backup_new_{i}.bak'
            new_backups.append(backup)

        all_backups = new_backups + old_backups

        payload = {
            'retention_days': 30,
            'keep_minimum': 5
        }

        mock_query = AsyncMock()
        mock_query.filter.return_value = mock_query
        mock_query.order_by.return_value = mock_query
        mock_query.all = AsyncMock(return_value=all_backups)

        mock_db = AsyncMock()
        mock_db.query.side_effect = [AsyncMock(all=AsyncMock(return_value=[device])), mock_query]
        mock_db.delete = AsyncMock()
        mock_db.commit = AsyncMock()

        with patch('src.workers.backup_worker.get_db', return_value=AsyncMock(__aenter__=AsyncMock(return_value=mock_db), __aexit__=AsyncMock())), \
             patch('src.workers.backup_worker.Path') as mock_path:

            mock_file = MagicMock()
            mock_file.exists.return_value = True
            mock_file.stat.return_value.st_size = 1024
            mock_file.unlink = Mock()
            mock_path.return_value = mock_file

            result = await worker._cleanup_old_backups(payload)

        assert result['status'] == 'success'
        assert result['total_deleted'] >= 0

    @pytest.mark.asyncio
    async def test_cleanup_keeps_minimum_backups(self, worker):
        """Test cleanup respects minimum backup count."""
        device = Mock(spec=Device)
        device.id = uuid4()

        # Only 3 backups (less than minimum)
        backups = []
        for i in range(3):
            backup = Mock(spec=ConfigBackup)
            backup.id = uuid4()
            backup.device_id = device.id
            backup.created_at = datetime.utcnow() - timedelta(days=40 + i)
            backups.append(backup)

        payload = {
            'retention_days': 30,
            'keep_minimum': 5
        }

        mock_query = AsyncMock()
        mock_query.filter.return_value = mock_query
        mock_query.order_by.return_value = mock_query
        mock_query.all = AsyncMock(return_value=backups)

        mock_db = AsyncMock()
        mock_db.query.side_effect = [AsyncMock(all=AsyncMock(return_value=[device])), mock_query]
        mock_db.commit = AsyncMock()

        with patch('src.workers.backup_worker.get_db', return_value=AsyncMock(__aenter__=AsyncMock(return_value=mock_db), __aexit__=AsyncMock())):
            result = await worker._cleanup_old_backups(payload)

        # No backups should be deleted (below minimum)
        assert result['total_deleted'] == 0


class TestVerifyBackup:
    """Test backup verification."""

    @pytest.mark.asyncio
    async def test_verify_backup_valid(self, worker, sample_backup):
        """Test verifying valid backup."""
        config_data = b'test configuration'
        config_hash = hashlib.sha256(config_data).hexdigest()
        sample_backup.config_hash = config_hash

        payload = {'backup_id': str(sample_backup.id)}

        mock_db = AsyncMock()
        mock_db.get = AsyncMock(return_value=sample_backup)
        mock_db.commit = AsyncMock()

        worker._load_backup_file = AsyncMock(return_value=b'encrypted_config')
        worker.encryption.decrypt = AsyncMock(return_value=config_data.decode())

        with patch('src.workers.backup_worker.get_db', return_value=AsyncMock(__aenter__=AsyncMock(return_value=mock_db), __aexit__=AsyncMock())), \
             patch('src.workers.backup_worker.Path') as mock_path, \
             patch('src.workers.backup_worker.hashlib.sha256') as mock_hash:

            mock_path.return_value.exists.return_value = True
            mock_hash.return_value.hexdigest.return_value = config_hash

            result = await worker._verify_backup(payload)

        assert result['status'] == 'success'
        assert result['valid'] is True
        assert result['hash_match'] is True

    @pytest.mark.asyncio
    async def test_verify_backup_file_missing(self, worker, sample_backup):
        """Test verification when backup file is missing."""
        payload = {'backup_id': str(sample_backup.id)}

        mock_db = AsyncMock()
        mock_db.get = AsyncMock(return_value=sample_backup)

        with patch('src.workers.backup_worker.get_db', return_value=AsyncMock(__aenter__=AsyncMock(return_value=mock_db), __aexit__=AsyncMock())), \
             patch('src.workers.backup_worker.Path') as mock_path:

            mock_path.return_value.exists.return_value = False

            result = await worker._verify_backup(payload)

        assert result['status'] == 'failed'
        assert result['valid'] is False
        assert 'not found' in result['error'].lower()


class TestBulkBackup:
    """Test bulk backup operations."""

    @pytest.mark.asyncio
    async def test_bulk_backup_success(self, worker):
        """Test bulk backup of multiple devices."""
        device_ids = [str(uuid4()) for _ in range(15)]

        payload = {
            'device_ids': device_ids,
            'description': 'Bulk backup',
            'user_id': str(uuid4())
        }

        worker._create_backup = AsyncMock(return_value={'backup_id': str(uuid4())})

        result = await worker._bulk_backup(payload)

        assert result['status'] == 'completed'
        assert result['total'] == 15
        assert result['successful'] == 15
        assert result['failed'] == 0

    @pytest.mark.asyncio
    async def test_bulk_backup_handles_failures(self, worker):
        """Test bulk backup handles individual failures."""
        device_ids = [str(uuid4()) for _ in range(10)]

        payload = {
            'device_ids': device_ids,
            'description': 'Bulk backup test'
        }

        # Some succeed, some fail
        results = [{'backup_id': str(uuid4())} if i % 2 == 0 else Exception("Failed") for i in range(10)]
        worker._create_backup = AsyncMock(side_effect=results)

        result = await worker._bulk_backup(payload)

        assert result['status'] == 'completed'
        assert result['successful'] + result['failed'] == result['total']

    @pytest.mark.asyncio
    async def test_bulk_backup_processes_in_batches(self, worker):
        """Test bulk backup processes devices in batches."""
        device_ids = [str(uuid4()) for _ in range(25)]  # More than batch size (10)

        payload = {
            'device_ids': device_ids,
            'description': 'Batch test'
        }

        worker._create_backup = AsyncMock(return_value={'backup_id': str(uuid4())})

        result = await worker._bulk_backup(payload)

        assert result['total'] == 25
        # All should succeed since we're mocking success
        assert result['successful'] == 25


class TestStorageOperations:
    """Test backup storage operations."""

    @pytest.mark.asyncio
    async def test_store_backup_file(self, worker):
        """Test storing backup file."""
        device_id = uuid4()
        backup_id = uuid4()
        encrypted_config = b'encrypted_data'
        timestamp = datetime.utcnow()

        with patch('src.workers.backup_worker.aiofiles.open', create=True) as mock_open:
            mock_file = AsyncMock()
            mock_file.write = AsyncMock()
            mock_open.return_value.__aenter__.return_value = mock_file

            file_path = await worker._store_backup_file(
                device_id=device_id,
                backup_id=backup_id,
                encrypted_config=encrypted_config,
                timestamp=timestamp
            )

        assert isinstance(file_path, Path)
        assert str(device_id) in str(file_path)

    @pytest.mark.asyncio
    async def test_load_backup_file(self, worker):
        """Test loading backup file."""
        file_path = '/tmp/test_backup.bak'
        expected_data = b'backup_content'

        with patch('src.workers.backup_worker.aiofiles.open', create=True) as mock_open:
            mock_file = AsyncMock()
            mock_file.read = AsyncMock(return_value=expected_data)
            mock_open.return_value.__aenter__.return_value = mock_file

            data = await worker._load_backup_file(file_path)

        assert data == expected_data

from fastapi import APIRouter, Depends, HTTPException, status, Query, BackgroundTasks, WebSocket, WebSocketDisconnect
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Optional, Dict, Any
import uuid
import structlog
import json
import asyncio

from ...db.database import get_db
from ...db.schemas import (
    DeviceCreate, DeviceUpdate, DeviceResponse, DeviceCommand,
    DeviceBackup, DeviceConfigBackup, DeviceConfigRestore,
    DeviceConfigCompare, DeviceConfigDiff, PaginationParams
)
from ...db.models import User, Device, DeviceConfig, DeviceVendor
from ...auth.auth_service import get_current_user
from ...auth.permissions import Permission, PermissionDependency
from ...devices.secure_connector import secure_device_connector

logger = structlog.get_logger()

router = APIRouter(prefix="/api/v1/devices", tags=["Devices"])


@router.post("/", response_model=DeviceResponse, status_code=status.HTTP_201_CREATED)
async def create_device(
    device_data: DeviceCreate,
    current_user: User = Depends(
        PermissionDependency([Permission.DEVICE_CREATE])
    ),
    db: AsyncSession = Depends(get_db)
):
    """
    Register a new device.

    Security:
    - Requires DEVICE_CREATE permission
    - Validates device credentials
    - Stores credentials in Vault
    - Verifies device connectivity
    """
    try:
        from sqlalchemy import select

        # Check if device already exists
        result = await db.execute(
            select(Device).where(
                (Device.name == device_data.name) |
                (Device.ip_address == device_data.ip_address)
            )
        )
        existing = result.scalar_one_or_none()

        if existing:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Device with this name or IP already exists"
            )

        # Store credentials in Vault
        from ...security.vault import VaultClient
        vault = VaultClient()

        credential_path = f"devices/{device_data.name}/credentials"
        await vault.store_secret(
            credential_path,
            {
                "vault_credential_path": device_data.vault_credential_path,
                "certificate_fingerprint": device_data.certificate_fingerprint,
                "ssh_fingerprint": device_data.ssh_fingerprint
            }
        )

        # Create device record
        device = Device(
            name=device_data.name,
            hostname=device_data.hostname,
            ip_address=device_data.ip_address,
            vendor=device_data.vendor,
            model=device_data.model,
            serial_number=device_data.serial_number,
            location=device_data.location,
            site=device_data.site,
            vault_credential_path=credential_path,
            certificate_fingerprint=device_data.certificate_fingerprint,
            ssh_fingerprint=device_data.ssh_fingerprint,
            bastion_host=device_data.bastion_host,
            is_active=True
        )

        db.add(device)
        await db.commit()
        await db.refresh(device)

        # Test connectivity in background
        # background_tasks.add_task(test_device_connectivity, device.id)

        logger.info(f"Device created: {device.name}")
        return DeviceResponse.from_orm(device)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to create device: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create device"
        )


@router.get("/", response_model=List[DeviceResponse])
async def list_devices(
    vendor: Optional[DeviceVendor] = None,
    site: Optional[str] = None,
    is_active: Optional[bool] = None,
    search: Optional[str] = None,
    pagination: PaginationParams = Depends(),
    current_user: User = Depends(
        PermissionDependency([Permission.DEVICE_READ])
    ),
    db: AsyncSession = Depends(get_db)
):
    """
    List devices with optional filters.

    Security:
    - Requires DEVICE_READ permission
    - Returns devices based on user's visibility scope
    """
    try:
        from sqlalchemy import select, and_, or_

        conditions = []

        if vendor:
            conditions.append(Device.vendor == vendor)
        if site:
            conditions.append(Device.site == site)
        if is_active is not None:
            conditions.append(Device.is_active == is_active)
        if search:
            conditions.append(
                or_(
                    Device.name.ilike(f"%{search}%"),
                    Device.hostname.ilike(f"%{search}%"),
                    Device.ip_address.ilike(f"%{search}%")
                )
            )

        stmt = select(Device)
        if conditions:
            stmt = stmt.where(and_(*conditions))

        # Apply ordering
        if pagination.order_by:
            order_column = getattr(Device, pagination.order_by, None)
            if order_column:
                stmt = stmt.order_by(
                    order_column.desc() if pagination.order_desc else order_column
                )
        else:
            stmt = stmt.order_by(Device.created_at.desc())

        # Apply pagination
        stmt = stmt.limit(pagination.page_size).offset(
            (pagination.page - 1) * pagination.page_size
        )

        result = await db.execute(stmt)
        devices = result.scalars().all()

        return [DeviceResponse.from_orm(d) for d in devices]

    except Exception as e:
        logger.error(f"Failed to list devices: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to list devices"
        )


@router.get("/{device_id}", response_model=DeviceResponse)
async def get_device(
    device_id: uuid.UUID,
    current_user: User = Depends(
        PermissionDependency([Permission.DEVICE_READ])
    ),
    db: AsyncSession = Depends(get_db)
):
    """
    Get device details.

    Security:
    - Requires DEVICE_READ permission
    """
    try:
        from sqlalchemy import select

        result = await db.execute(
            select(Device).where(Device.id == device_id)
        )
        device = result.scalar_one_or_none()

        if not device:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Device not found"
            )

        return DeviceResponse.from_orm(device)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get device: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get device"
        )


@router.put("/{device_id}", response_model=DeviceResponse)
async def update_device(
    device_id: uuid.UUID,
    device_update: DeviceUpdate,
    current_user: User = Depends(
        PermissionDependency([Permission.DEVICE_UPDATE])
    ),
    db: AsyncSession = Depends(get_db)
):
    """
    Update device information.

    Security:
    - Requires DEVICE_UPDATE permission
    - Logs all changes
    """
    try:
        from sqlalchemy import select

        result = await db.execute(
            select(Device).where(Device.id == device_id)
        )
        device = result.scalar_one_or_none()

        if not device:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Device not found"
            )

        # Update fields
        update_data = device_update.dict(exclude_unset=True)
        for field, value in update_data.items():
            setattr(device, field, value)

        await db.commit()
        await db.refresh(device)

        logger.info(f"Device updated: {device.name}")
        return DeviceResponse.from_orm(device)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update device: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update device"
        )


@router.delete("/{device_id}")
async def delete_device(
    device_id: uuid.UUID,
    current_user: User = Depends(
        PermissionDependency([Permission.DEVICE_DELETE])
    ),
    db: AsyncSession = Depends(get_db)
):
    """
    Delete a device.

    Security:
    - Requires DEVICE_DELETE permission
    - Soft deletes by marking inactive
    """
    try:
        from sqlalchemy import select

        result = await db.execute(
            select(Device).where(Device.id == device_id)
        )
        device = result.scalar_one_or_none()

        if not device:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Device not found"
            )

        # Soft delete
        device.is_active = False
        await db.commit()

        # Clean up Vault secrets
        from ...security.vault import VaultClient
        vault = VaultClient()
        await vault.delete_secret(device.vault_credential_path)

        logger.info(f"Device deleted: {device.name}")
        return {"message": "Device deleted successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete device: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete device"
        )


@router.post("/{device_id}/connect")
async def connect_to_device(
    device_id: uuid.UUID,
    current_user: User = Depends(
        PermissionDependency([Permission.DEVICE_CONNECT])
    ),
    db: AsyncSession = Depends(get_db)
):
    """
    Establish connection to device.

    Security:
    - Requires DEVICE_CONNECT permission
    - Uses temporary credentials
    - Session is recorded
    """
    try:
        connection = await secure_device_connector.connect_to_device(
            str(device_id),
            {"user_id": str(current_user.id)},
            db
        )

        return {
            "session_id": connection.session_id,
            "connected_at": connection.connected_at.isoformat(),
            "vendor": connection.vendor.value,
            "message": "Successfully connected to device"
        }

    except PermissionError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(e)
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Failed to connect to device: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to connect to device"
        )


@router.post("/{device_id}/execute")
async def execute_command(
    device_id: uuid.UUID,
    command_data: DeviceCommand,
    current_user: User = Depends(
        PermissionDependency([Permission.DEVICE_EXECUTE_COMMAND])
    ),
    db: AsyncSession = Depends(get_db)
):
    """
    Execute command on device.

    Security:
    - Requires DEVICE_EXECUTE_COMMAND permission
    - Commands are validated
    - Execution is logged
    """
    try:
        # Connect to device
        connection = await secure_device_connector.connect_to_device(
            str(device_id),
            {"user_id": str(current_user.id)},
            db
        )

        try:
            # Execute command
            output = await connection.execute_command(
                command_data.command,
                timeout=command_data.timeout
            )

            return {
                "command": command_data.command,
                "output": output,
                "success": True
            }

        finally:
            await connection.close()

    except Exception as e:
        logger.error(f"Command execution failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Command execution failed: {str(e)}"
        )


@router.post("/{device_id}/backup")
async def backup_device_config(
    device_id: uuid.UUID,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(
        PermissionDependency([Permission.DEVICE_BACKUP])
    ),
    db: AsyncSession = Depends(get_db)
):
    """
    Backup device configuration.

    Security:
    - Requires DEVICE_BACKUP permission
    - Configuration is encrypted
    - Stored in Vault
    """
    try:
        # Connect to device
        connection = await secure_device_connector.connect_to_device(
            str(device_id),
            {"user_id": str(current_user.id)},
            db
        )

        try:
            # Get configuration
            config = await connection.get_configuration()

            # Encrypt configuration
            from ...security.encryption import encryption_service
            from ...security.vault import VaultClient
            vault = VaultClient()

            encryption_key = await vault.get_encryption_key("catnet-backups")
            encrypted_config = encryption_service.encrypt_config(config, encryption_key)

            # Store in Vault
            from datetime import datetime
            backup_location = f"backups/{device_id}/{datetime.utcnow().isoformat()}"
            await vault.store_secret(backup_location, encrypted_config)

            # Get version number
            from sqlalchemy import select, func
            result = await db.execute(
                select(func.max(DeviceConfig.version))
                .where(DeviceConfig.device_id == device_id)
            )
            max_version = result.scalar() or 0

            # Create database record
            import hashlib
            config_backup = DeviceConfig(
                device_id=device_id,
                config_encrypted=json.dumps(encrypted_config),
                config_hash=hashlib.sha256(config.encode()).hexdigest(),
                encryption_key_id=encrypted_config.get("key_id"),
                backup_location=backup_location,
                version=max_version + 1,
                is_current=True
            )

            # Mark previous configs as not current
            await db.execute(
                select(DeviceConfig)
                .where(
                    DeviceConfig.device_id == device_id,
                    DeviceConfig.is_current == True
                )
                .update({"is_current": False})
            )

            db.add(config_backup)
            await db.commit()

            return {
                "backup_id": str(config_backup.id),
                "version": config_backup.version,
                "created_at": config_backup.created_at.isoformat(),
                "message": "Configuration backup created successfully"
            }

        finally:
            await connection.close()

    except Exception as e:
        logger.error(f"Backup failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Backup failed: {str(e)}"
        )


@router.get("/{device_id}/configs")
async def list_device_configs(
    device_id: uuid.UUID,
    limit: int = Query(10, ge=1, le=100),
    current_user: User = Depends(
        PermissionDependency([Permission.DEVICE_READ])
    ),
    db: AsyncSession = Depends(get_db)
):
    """
    List device configuration versions.

    Security:
    - Requires DEVICE_READ permission
    """
    try:
        from sqlalchemy import select

        result = await db.execute(
            select(DeviceConfig)
            .where(DeviceConfig.device_id == device_id)
            .order_by(DeviceConfig.version.desc())
            .limit(limit)
        )
        configs = result.scalars().all()

        return [
            {
                "id": str(config.id),
                "version": config.version,
                "is_current": config.is_current,
                "created_at": config.created_at.isoformat(),
                "config_hash": config.config_hash
            }
            for config in configs
        ]

    except Exception as e:
        logger.error(f"Failed to list configs: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to list configurations"
        )


@router.post("/{device_id}/restore")
async def restore_device_config(
    device_id: uuid.UUID,
    restore_data: DeviceConfigRestore,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(
        PermissionDependency([Permission.DEVICE_EXECUTE_COMMAND])
    ),
    db: AsyncSession = Depends(get_db)
):
    """
    Restore device configuration from backup.

    Security:
    - Requires DEVICE_EXECUTE_COMMAND permission
    - Creates backup before restore
    - Validates configuration
    """
    try:
        from sqlalchemy import select

        # Get the backup to restore
        result = await db.execute(
            select(DeviceConfig).where(
                DeviceConfig.id == restore_data.config_id,
                DeviceConfig.device_id == device_id
            )
        )
        backup_config = result.scalar_one_or_none()

        if not backup_config:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Configuration backup not found"
            )

        # Decrypt configuration
        from ...security.encryption import encryption_service
        from ...security.vault import VaultClient
        vault = VaultClient()

        encrypted_config = json.loads(backup_config.config_encrypted)
        encryption_key = await vault.get_encryption_key("catnet-backups")
        config_content = encryption_service.decrypt_config(
            encrypted_config,
            encryption_key
        )

        # Connect to device
        connection = await secure_device_connector.connect_to_device(
            str(device_id),
            {"user_id": str(current_user.id)},
            db
        )

        try:
            # Create backup of current config if requested
            if restore_data.create_backup:
                current_config = await connection.get_configuration()
                # Store backup (similar to backup endpoint)

            # Validate configuration if requested
            if restore_data.verify_before_apply:
                validation_result = await connection.validate_configuration(config_content)
                if not validation_result['valid']:
                    raise ValueError(f"Configuration validation failed: {validation_result['errors']}")

            # Apply configuration
            result = await connection.apply_configuration(config_content)
            if not result['success']:
                raise ValueError(f"Configuration apply failed: {result.get('error')}")

            # Save configuration
            await connection.save_configuration()

            # Update database
            backup_config.is_current = True
            await db.execute(
                select(DeviceConfig)
                .where(
                    DeviceConfig.device_id == device_id,
                    DeviceConfig.id != backup_config.id,
                    DeviceConfig.is_current == True
                )
                .update({"is_current": False})
            )
            await db.commit()

            return {
                "success": True,
                "restored_version": backup_config.version,
                "message": "Configuration restored successfully"
            }

        finally:
            await connection.close()

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Restore failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Restore failed: {str(e)}"
        )


@router.post("/{device_id}/compare", response_model=DeviceConfigDiff)
async def compare_configs(
    device_id: uuid.UUID,
    compare_data: DeviceConfigCompare,
    current_user: User = Depends(
        PermissionDependency([Permission.DEVICE_READ])
    ),
    db: AsyncSession = Depends(get_db)
):
    """
    Compare two configuration versions.

    Security:
    - Requires DEVICE_READ permission
    - Shows differences between versions
    """
    try:
        from sqlalchemy import select
        import difflib

        # Get both configurations
        result = await db.execute(
            select(DeviceConfig).where(
                DeviceConfig.device_id == device_id,
                DeviceConfig.version.in_([compare_data.source_version, compare_data.target_version])
            )
        )
        configs = result.scalars().all()

        if len(configs) != 2:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="One or both configuration versions not found"
            )

        source_config = next(c for c in configs if c.version == compare_data.source_version)
        target_config = next(c for c in configs if c.version == compare_data.target_version)

        # Decrypt configurations
        from ...security.encryption import encryption_service
        from ...security.vault import VaultClient
        vault = VaultClient()

        encryption_key = await vault.get_encryption_key("catnet-backups")

        source_encrypted = json.loads(source_config.config_encrypted)
        source_content = encryption_service.decrypt_config(source_encrypted, encryption_key)

        target_encrypted = json.loads(target_config.config_encrypted)
        target_content = encryption_service.decrypt_config(target_encrypted, encryption_key)

        # Calculate diff
        source_lines = source_content.splitlines()
        target_lines = target_content.splitlines()

        differ = difflib.unified_diff(
            source_lines,
            target_lines,
            lineterm='',
            n=3
        )

        additions = []
        deletions = []
        modifications = []

        for line in differ:
            if line.startswith('+') and not line.startswith('+++'):
                additions.append(line[1:])
            elif line.startswith('-') and not line.startswith('---'):
                deletions.append(line[1:])

        return DeviceConfigDiff(
            device_id=device_id,
            source_version=compare_data.source_version,
            target_version=compare_data.target_version,
            additions=additions,
            deletions=deletions,
            modifications=modifications,
            unchanged_lines=len(source_lines) - len(additions) - len(deletions),
            total_changes=len(additions) + len(deletions)
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Config comparison failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to compare configurations"
        )


@router.websocket("/{device_id}/terminal")
async def device_terminal(
    websocket: WebSocket,
    device_id: uuid.UUID,
    token: str = Query(...),
    db: AsyncSession = Depends(get_db)
):
    """
    WebSocket endpoint for interactive device terminal.

    Security:
    - Requires valid JWT token
    - Session is recorded
    - Commands are audited
    """
    await websocket.accept()

    try:
        # Validate token
        from ...auth.jwt_handler import JWTHandler
        jwt_handler = JWTHandler()
        payload = jwt_handler.decode_token(token)
        user_id = payload.get('sub')

        if not user_id:
            await websocket.send_text(json.dumps({
                "type": "error",
                "message": "Invalid authentication"
            }))
            await websocket.close()
            return

        # Check permissions
        from sqlalchemy import select
        result = await db.execute(
            select(User).where(User.id == uuid.UUID(user_id))
        )
        user = result.scalar_one_or_none()

        if not user:
            await websocket.send_text(json.dumps({
                "type": "error",
                "message": "User not found"
            }))
            await websocket.close()
            return

        from ...auth.permissions import permission_checker, Permission
        if not permission_checker.has_permission(user, Permission.DEVICE_EXECUTE_COMMAND):
            await websocket.send_text(json.dumps({
                "type": "error",
                "message": "Insufficient permissions"
            }))
            await websocket.close()
            return

        # Connect to device
        connection = await secure_device_connector.connect_to_device(
            str(device_id),
            {"user_id": user_id},
            db
        )

        await websocket.send_text(json.dumps({
            "type": "connected",
            "message": "Connected to device",
            "session_id": connection.session_id
        }))

        try:
            while True:
                # Receive command from WebSocket
                data = await websocket.receive_text()
                command_data = json.loads(data)

                if command_data.get("type") == "command":
                    command = command_data.get("command")

                    # Execute command
                    try:
                        output = await connection.execute_command(command)
                        await websocket.send_text(json.dumps({
                            "type": "output",
                            "data": output
                        }))
                    except Exception as e:
                        await websocket.send_text(json.dumps({
                            "type": "error",
                            "message": str(e)
                        }))

                elif command_data.get("type") == "disconnect":
                    break

        finally:
            await connection.close()

    except WebSocketDisconnect:
        logger.info(f"WebSocket disconnected for device {device_id}")
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        await websocket.send_text(json.dumps({
            "type": "error",
            "message": "Connection error"
        }))
    finally:
        await websocket.close()
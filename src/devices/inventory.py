from typing import Dict, List, Optional, Any
import asyncio
import uuid
import structlog
from datetime import datetime, timedelta
from dataclasses import dataclass, field

from ..db.models import Device, DeviceVendor, Site
from ..db.database import get_db_session
from ..security.audit import AuditLogger
from ..core.exceptions import ValidationError, DatabaseError

logger = structlog.get_logger()

@dataclass
class DeviceInventoryFilter:
    vendor: Optional[DeviceVendor] = None
    device_type: Optional[str] = None
    site: Optional[str] = None
    status: Optional[str] = None
    ip_range: Optional[str] = None
    hostname_pattern: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    last_backup_before: Optional[datetime] = None
    created_after: Optional[datetime] = None

@dataclass
class InventoryStats:
    total_devices: int = 0
    by_vendor: Dict[str, int] = field(default_factory=dict)
    by_type: Dict[str, int] = field(default_factory=dict)
    by_status: Dict[str, int] = field(default_factory=dict)
    by_site: Dict[str, int] = field(default_factory=dict)
    needs_backup: int = 0
    stale_devices: int = 0
    active_connections: int = 0

class DeviceInventoryManager:
    def __init__(self):
        self.audit = AuditLogger()
        self.backup_warning_days = 7
        self.stale_device_days = 30

    async def get_device_inventory(
        self,
        user_context: Dict[str, Any],
        filters: Optional[DeviceInventoryFilter] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None
    ) -> Dict[str, Any]:
        """Get device inventory with filtering and pagination"""
        try:
            async with get_db_session() as session:
                query = session.query(Device)

                # Apply filters
                if filters:
                    if filters.vendor:
                        query = query.filter(Device.vendor == filters.vendor)

                    if filters.device_type:
                        query = query.filter(Device.device_type == filters.device_type)

                    if filters.site:
                        query = query.filter(Device.site == filters.site)

                    if filters.status:
                        query = query.filter(Device.status == filters.status)

                    if filters.hostname_pattern:
                        query = query.filter(
                            Device.hostname.ilike(f"%{filters.hostname_pattern}%")
                        )

                    if filters.ip_range:
                        # Basic IP range filtering (could be enhanced with proper CIDR)
                        ip_base = filters.ip_range.split('/')[0].rsplit('.', 1)[0]
                        query = query.filter(Device.ip_address.like(f"{ip_base}.%"))

                    if filters.last_backup_before:
                        query = query.filter(
                            Device.last_backup < filters.last_backup_before
                        )

                    if filters.created_after:
                        query = query.filter(Device.created_at > filters.created_after)

                    if filters.tags:
                        for tag in filters.tags:
                            query = query.filter(Device.tags.contains([tag]))

                # Get total count before pagination
                total_count = await query.count()

                # Apply pagination
                if offset:
                    query = query.offset(offset)
                if limit:
                    query = query.limit(limit)

                # Order by hostname
                query = query.order_by(Device.hostname)

                devices = await query.all()

                device_list = []
                for device in devices:
                    device_info = {
                        'id': str(device.id),
                        'hostname': device.hostname,
                        'ip_address': device.ip_address,
                        'vendor': device.vendor.value,
                        'device_type': device.device_type,
                        'model': device.model,
                        'os_version': device.os_version,
                        'site': device.site,
                        'status': device.status,
                        'tags': device.tags or [],
                        'last_backup': device.last_backup.isoformat() if device.last_backup else None,
                        'created_at': device.created_at.isoformat(),
                        'updated_at': device.updated_at.isoformat(),
                        'backup_status': self._get_backup_status(device.last_backup),
                        'connection_info': {
                            'ssh_port': device.ssh_port,
                            'jump_host': device.jump_host,
                            'management_ip': device.management_ip
                        }
                    }
                    device_list.append(device_info)

                result = {
                    'devices': device_list,
                    'total_count': total_count,
                    'returned_count': len(device_list),
                    'filters_applied': filters.__dict__ if filters else None
                }

                await self.audit.log_inventory_access(
                    user_id=user_context['user_id'],
                    device_count=len(device_list),
                    filters=filters.__dict__ if filters else None
                )

                return result

        except Exception as e:
            logger.error(f"Failed to get device inventory: {e}")
            raise DatabaseError(f"Inventory query failed: {str(e)}")

    async def get_inventory_statistics(
        self,
        user_context: Dict[str, Any]
    ) -> InventoryStats:
        """Get comprehensive inventory statistics"""
        try:
            async with get_db_session() as session:
                stats = InventoryStats()

                # Total devices
                total_query = await session.execute("SELECT COUNT(*) FROM devices")
                stats.total_devices = total_query.scalar()

                # By vendor
                vendor_query = await session.execute(
                    "SELECT vendor, COUNT(*) FROM devices GROUP BY vendor"
                )
                for row in vendor_query:
                    stats.by_vendor[row[0]] = row[1]

                # By device type
                type_query = await session.execute(
                    "SELECT device_type, COUNT(*) FROM devices GROUP BY device_type"
                )
                for row in type_query:
                    stats.by_type[row[0]] = row[1]

                # By status
                status_query = await session.execute(
                    "SELECT status, COUNT(*) FROM devices GROUP BY status"
                )
                for row in status_query:
                    stats.by_status[row[0]] = row[1]

                # By site
                site_query = await session.execute(
                    "SELECT site, COUNT(*) FROM devices GROUP BY site"
                )
                for row in site_query:
                    stats.by_site[row[0]] = row[1]

                # Devices needing backup
                backup_threshold = datetime.utcnow() - timedelta(days=self.backup_warning_days)
                backup_query = await session.execute(
                    "SELECT COUNT(*) FROM devices WHERE last_backup < %s OR last_backup IS NULL",
                    (backup_threshold,)
                )
                stats.needs_backup = backup_query.scalar()

                # Stale devices (not updated recently)
                stale_threshold = datetime.utcnow() - timedelta(days=self.stale_device_days)
                stale_query = await session.execute(
                    "SELECT COUNT(*) FROM devices WHERE updated_at < %s",
                    (stale_threshold,)
                )
                stats.stale_devices = stale_query.scalar()

                # Active connections
                active_conn_query = await session.execute(
                    "SELECT COUNT(*) FROM device_connections WHERE status = 'active'"
                )
                stats.active_connections = active_conn_query.scalar()

                await self.audit.log_inventory_stats_access(
                    user_id=user_context['user_id'],
                    stats=stats.__dict__
                )

                return stats

        except Exception as e:
            logger.error(f"Failed to get inventory statistics: {e}")
            raise DatabaseError(f"Statistics query failed: {str(e)}")

    async def register_device(
        self,
        device_data: Dict[str, Any],
        user_context: Dict[str, Any]
    ) -> str:
        """Register a new device in the inventory"""
        try:
            # Validate required fields
            required_fields = ['hostname', 'ip_address', 'vendor', 'device_type']
            for field in required_fields:
                if not device_data.get(field):
                    raise ValidationError(f"Missing required field: {field}")

            # Validate vendor
            try:
                vendor = DeviceVendor(device_data['vendor'])
            except ValueError:
                raise ValidationError(f"Invalid vendor: {device_data['vendor']}")

            # Check for duplicate IP or hostname
            async with get_db_session() as session:
                existing_ip = await session.execute(
                    "SELECT id FROM devices WHERE ip_address = %s",
                    (device_data['ip_address'],)
                )
                if existing_ip.scalar():
                    raise ValidationError(f"Device with IP {device_data['ip_address']} already exists")

                existing_hostname = await session.execute(
                    "SELECT id FROM devices WHERE hostname = %s",
                    (device_data['hostname'],)
                )
                if existing_hostname.scalar():
                    raise ValidationError(f"Device with hostname {device_data['hostname']} already exists")

                device_id = uuid.uuid4()
                device = Device(
                    id=device_id,
                    hostname=device_data['hostname'],
                    ip_address=device_data['ip_address'],
                    vendor=vendor,
                    device_type=device_data['device_type'],
                    model=device_data.get('model'),
                    os_version=device_data.get('os_version'),
                    site=device_data.get('site', 'default'),
                    status=device_data.get('status', 'active'),
                    ssh_port=device_data.get('ssh_port', 22),
                    jump_host=device_data.get('jump_host'),
                    management_ip=device_data.get('management_ip'),
                    tags=device_data.get('tags', []),
                    device_metadata=device_data.get('metadata', {}),
                    created_by=uuid.UUID(user_context['user_id'])
                )

                session.add(device)
                await session.commit()

                await self.audit.log_device_registration(
                    user_id=user_context['user_id'],
                    device_id=str(device_id),
                    hostname=device_data['hostname'],
                    ip_address=device_data['ip_address']
                )

                logger.info(f"Device registered: {device_data['hostname']} ({device_data['ip_address']})")
                return str(device_id)

        except Exception as e:
            logger.error(f"Device registration failed: {e}")
            raise DatabaseError(f"Failed to register device: {str(e)}")

    async def update_device(
        self,
        device_id: str,
        updates: Dict[str, Any],
        user_context: Dict[str, Any]
    ) -> bool:
        """Update device information"""
        try:
            async with get_db_session() as session:
                device = await session.get(Device, device_id)
                if not device:
                    raise ValidationError(f"Device {device_id} not found")

                # Track changes for audit
                changes = {}

                # Update allowed fields
                updateable_fields = [
                    'hostname', 'ip_address', 'model', 'os_version',
                    'site', 'status', 'ssh_port', 'jump_host',
                    'management_ip', 'tags', 'device_metadata'
                ]

                for field in updateable_fields:
                    if field in updates:
                        old_value = getattr(device, field)
                        new_value = updates[field]
                        if old_value != new_value:
                            setattr(device, field, new_value)
                            changes[field] = {'old': old_value, 'new': new_value}

                # Handle vendor update separately due to enum
                if 'vendor' in updates:
                    try:
                        new_vendor = DeviceVendor(updates['vendor'])
                        if device.vendor != new_vendor:
                            changes['vendor'] = {
                                'old': device.vendor.value,
                                'new': new_vendor.value
                            }
                            device.vendor = new_vendor
                    except ValueError:
                        raise ValidationError(f"Invalid vendor: {updates['vendor']}")

                if changes:
                    device.updated_at = datetime.utcnow()
                    await session.commit()

                    await self.audit.log_device_update(
                        user_id=user_context['user_id'],
                        device_id=device_id,
                        changes=changes
                    )

                    logger.info(f"Device {device_id} updated with {len(changes)} changes")
                    return True
                else:
                    logger.info(f"No changes applied to device {device_id}")
                    return False

        except Exception as e:
            logger.error(f"Device update failed: {e}")
            raise DatabaseError(f"Failed to update device: {str(e)}")

    async def remove_device(
        self,
        device_id: str,
        user_context: Dict[str, Any],
        force: bool = False
    ) -> bool:
        """Remove device from inventory"""
        try:
            async with get_db_session() as session:
                device = await session.get(Device, device_id)
                if not device:
                    raise ValidationError(f"Device {device_id} not found")

                # Check for active connections
                active_connections = await session.execute(
                    "SELECT COUNT(*) FROM device_connections WHERE device_id = %s AND status = 'active'",
                    (device_id,)
                )
                if active_connections.scalar() > 0 and not force:
                    raise ValidationError(
                        f"Device {device_id} has active connections. Use force=True to remove anyway."
                    )

                # Check for recent deployments
                recent_deployments = await session.execute(
                    "SELECT COUNT(*) FROM deployments d "
                    "JOIN deployment_devices dd ON d.id = dd.deployment_id "
                    "WHERE dd.device_id = %s AND d.created_at > %s",
                    (device_id, datetime.utcnow() - timedelta(days=1))
                )
                if recent_deployments.scalar() > 0 and not force:
                    raise ValidationError(
                        f"Device {device_id} has recent deployments. Use force=True to remove anyway."
                    )

                # Mark device as deleted instead of actual deletion for audit trail
                device.status = 'deleted'
                device.updated_at = datetime.utcnow()
                await session.commit()

                await self.audit.log_device_removal(
                    user_id=user_context['user_id'],
                    device_id=device_id,
                    hostname=device.hostname,
                    force=force
                )

                logger.info(f"Device {device_id} removed from inventory")
                return True

        except Exception as e:
            logger.error(f"Device removal failed: {e}")
            raise DatabaseError(f"Failed to remove device: {str(e)}")

    async def discover_devices(
        self,
        ip_range: str,
        user_context: Dict[str, Any],
        discovery_method: str = "ping_sweep"
    ) -> Dict[str, Any]:
        """Discover devices on the network"""
        try:
            discovery_result = {
                'ip_range': ip_range,
                'method': discovery_method,
                'discovered_devices': [],
                'total_checked': 0,
                'responsive_devices': 0,
                'start_time': datetime.utcnow().isoformat(),
                'end_time': None
            }

            if discovery_method == "ping_sweep":
                discovered = await self._ping_sweep_discovery(ip_range)
                discovery_result.update(discovered)

            discovery_result['end_time'] = datetime.utcnow().isoformat()

            await self.audit.log_device_discovery(
                user_id=user_context['user_id'],
                ip_range=ip_range,
                method=discovery_method,
                devices_found=len(discovery_result['discovered_devices'])
            )

            return discovery_result

        except Exception as e:
            logger.error(f"Device discovery failed: {e}")
            raise ValidationError(f"Discovery failed: {str(e)}")

    async def _ping_sweep_discovery(self, ip_range: str) -> Dict[str, Any]:
        """Perform ping sweep discovery"""
        import ipaddress
        import asyncio
        import subprocess

        result = {
            'discovered_devices': [],
            'total_checked': 0,
            'responsive_devices': 0
        }

        try:
            network = ipaddress.ip_network(ip_range, strict=False)

            async def ping_host(ip_str: str) -> Optional[str]:
                try:
                    # Use ping command (cross-platform)
                    process = await asyncio.create_subprocess_exec(
                        'ping', '-c', '1', '-W', '2', ip_str,
                        stdout=asyncio.subprocess.DEVNULL,
                        stderr=asyncio.subprocess.DEVNULL
                    )
                    await process.wait()

                    if process.returncode == 0:
                        return ip_str
                    return None
                except Exception:
                    return None

            # Limit concurrent pings to avoid overwhelming the network
            semaphore = asyncio.Semaphore(50)

            async def ping_with_semaphore(ip_str: str) -> Optional[str]:
                async with semaphore:
                    return await ping_host(ip_str)

            # Create tasks for all IPs in range
            tasks = []
            for ip in network.hosts():
                tasks.append(ping_with_semaphore(str(ip)))
                result['total_checked'] += 1

            # Execute pings
            ping_results = await asyncio.gather(*tasks, return_exceptions=True)

            # Process results
            for ip_result in ping_results:
                if isinstance(ip_result, str):  # Successful ping
                    result['responsive_devices'] += 1

                    # Try to get more information about the device
                    device_info = {
                        'ip_address': ip_result,
                        'responsive': True,
                        'discovery_time': datetime.utcnow().isoformat()
                    }

                    # Try to determine device type through banner grabbing
                    try:
                        banner_info = await self._get_device_banner(ip_result)
                        device_info.update(banner_info)
                    except Exception as e:
                        logger.debug(f"Banner detection failed for {ip_result}: {e}")

                    result['discovered_devices'].append(device_info)

            return result

        except Exception as e:
            logger.error(f"Ping sweep failed: {e}")
            raise ValidationError(f"Ping sweep failed: {str(e)}")

    async def _get_device_banner(self, ip_address: str) -> Dict[str, Any]:
        """Try to get device information through banner grabbing"""
        banner_info = {}

        try:
            # Try SSH banner
            import socket

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)

            try:
                sock.connect((ip_address, 22))
                banner = sock.recv(1024).decode('utf-8', errors='ignore')

                # Parse SSH banner for device information
                if 'Cisco' in banner:
                    banner_info['probable_vendor'] = 'cisco'
                elif 'Juniper' in banner:
                    banner_info['probable_vendor'] = 'juniper'
                elif 'OpenSSH' in banner:
                    banner_info['probable_vendor'] = 'linux'

                banner_info['ssh_banner'] = banner.strip()

            except Exception:
                pass
            finally:
                sock.close()

        except Exception as e:
            logger.debug(f"Banner grabbing failed for {ip_address}: {e}")

        return banner_info

    def _get_backup_status(self, last_backup: Optional[datetime]) -> str:
        """Determine backup status based on last backup time"""
        if not last_backup:
            return 'never'

        days_since_backup = (datetime.utcnow() - last_backup).days

        if days_since_backup == 0:
            return 'current'
        elif days_since_backup <= 1:
            return 'recent'
        elif days_since_backup <= self.backup_warning_days:
            return 'warning'
        else:
            return 'stale'

    async def bulk_update_devices(
        self,
        device_updates: List[Dict[str, Any]],
        user_context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Perform bulk updates on multiple devices"""
        try:
            update_results = {
                'total_updates': len(device_updates),
                'successful_updates': 0,
                'failed_updates': 0,
                'errors': []
            }

            for update_data in device_updates:
                try:
                    device_id = update_data.get('device_id')
                    updates = update_data.get('updates', {})

                    if not device_id:
                        update_results['errors'].append("Missing device_id in update data")
                        update_results['failed_updates'] += 1
                        continue

                    success = await self.update_device(device_id, updates, user_context)
                    if success:
                        update_results['successful_updates'] += 1
                    else:
                        update_results['failed_updates'] += 1

                except Exception as e:
                    update_results['errors'].append(f"Update failed for device {device_id}: {str(e)}")
                    update_results['failed_updates'] += 1

            await self.audit.log_bulk_device_update(
                user_id=user_context['user_id'],
                total_updates=update_results['total_updates'],
                successful_updates=update_results['successful_updates'],
                failed_updates=update_results['failed_updates']
            )

            return update_results

        except Exception as e:
            logger.error(f"Bulk device update failed: {e}")
            raise DatabaseError(f"Bulk update failed: {str(e)}")
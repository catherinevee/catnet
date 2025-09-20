"""
Simple In-Memory Device Store
Phase 2 Implementation - Keeping it simple to avoid over-engineering
"""

from typing import Dict, List, Optional
from datetime import datetime
import uuid
from dataclasses import dataclass, field, asdict


@dataclass
class DeviceInfo: """Simple device information model"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    hostname: str = ""
    ip_address: str = ""
    vendor: str = "cisco_ios"  # cisco_ios, cisco_xe, cisco_nxos, juniper_junos
    username: str = "admin"
    ssh_port: int = 22
    added_at: datetime = field(default_factory=datetime.utcnow)
    last_seen: Optional[datetime] = None
    is_active: bool = True
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Convert to dictionary for API responses"""
        data = asdict(self)
        # Convert datetime objects to ISO format
        if self.added_at:
            data['added_at'] = self.added_at.isoformat()
        if self.last_seen:
            data['last_seen'] = self.last_seen.isoformat()
        return data


class DeviceStore: """
    Simple in-memory device store
    No complex database required initially
    """

    def __init__(self):
        """TODO: Add docstring"""
        self._devices: Dict[str, DeviceInfo] = {}
        self._hostname_index: Dict[str, str] = {}  # hostname -> id mapping

    def add_device(
    self,
     device: DeviceInfo) -> DeviceInfo: """Add a device to the store"""
        # Check for duplicate hostname
        if device.hostname in self._hostname_index:
            existing_id = self._hostname_index[device.hostname]
            if existing_id != device.id:
                raise ValueError(f"Device with hostname {device.hostname}"
    already exists")

        self._devices[device.id] = device
        self._hostname_index[device.hostname] = device.id
        return device

    def get_device(self, device_id: str) -> Optional[DeviceInfo]:
        """Get device by ID"""
        return self._devices.get(device_id)

    def get_device_by_hostname(self, hostname: str) -> Optional[DeviceInfo]:"""Get device by hostname"""
        device_id = self._hostname_index.get(hostname)
        if device_id:
            return self._devices.get(device_id)
        return None

    def list_devices(self, active_only: bool = False) -> List[DeviceInfo]:"""List all devices"""
        devices = list(self._devices.values())
        if active_only:
            devices = [d for d in devices if d.is_active]
        return devices

        def update_device(
        self,
        device_id: str,
        updates: dict
    ) -> Optional[DeviceInfo]:"""Update device information"""
        device = self._devices.get(device_id)
        if not device:
            return None

        # Update hostname index if hostname is changing
        if 'hostname' in updates and updates['hostname'] != device.hostname:
            # Remove old hostname mapping
            del self._hostname_index[device.hostname]
            # Add new hostname mapping
            self._hostname_index[updates['hostname']] = device_id

        # Apply updates
        for key, value in updates.items():
            if hasattr(device, key):
                setattr(device, key, value)

        return device

    def delete_device(self, device_id: str) -> bool:"""Delete a device"""
        device = self._devices.get(device_id)
        if not device:
            return False

        # Remove from hostname index
        if device.hostname in self._hostname_index:
            del self._hostname_index[device.hostname]

        # Remove from devices
        del self._devices[device_id]
        return True

    def mark_device_seen(self, device_id: str) -> Optional[DeviceInfo]:"""Update last seen timestamp"""
        device = self._devices.get(device_id)
        if device:
            device.last_seen = datetime.utcnow()
        return device

    def get_devices_by_vendor(self, vendor: str) -> List[DeviceInfo]:"""Get all devices of a specific vendor"""
        return [d for d in self._devices.values() if d.vendor == vendor]

    def get_devices_by_tag(self, tag: str) -> List[DeviceInfo]:"""Get all devices with a specific tag"""
        return [d for d in self._devices.values() if tag in d.tags]

    def count_devices(self) -> int:"""Get total device count"""
        return len(self._devices)

    def clear_all(self):"""Clear all devices (useful for testing)"""
        self._devices.clear()
        self._hostname_index.clear()

    def add_sample_devices(self):"""Add sample devices for testing"""
        sample_devices = [
            DeviceInfo(
                hostname="router1.lab.local",
                ip_address="192.168.1.1",
                vendor="cisco_ios",
                username="admin",
                tags=["core", "production"]
            ),
            DeviceInfo(
                hostname="switch1.lab.local",
                ip_address="192.168.1.10",
                vendor="cisco_ios",
                username="admin",
                tags=["access", "production"]
            ),
            DeviceInfo(
                hostname="firewall1.lab.local",
                ip_address="192.168.1.254",
                vendor="juniper_junos",
                username="root",
                tags=["security", "edge"]
            )
        ]

        for device in sample_devices:
            self.add_device(device)

        return sample_devices


# Global instance for simplicity
device_store = DeviceStore()

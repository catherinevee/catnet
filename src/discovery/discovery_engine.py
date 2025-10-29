"""
Network Discovery Engine
Automated network discovery using CDP, LLDP, and SNMP
"""
import asyncio
import re
from typing import List, Dict, Set, Optional, Tuple
from datetime import datetime
import structlog

from src.db.models.discovery import (
    DeviceInventory,
    NetworkTopology,
    DiscoveryJob,
    DeviceChange,
    DiscoveryMethod,
    DiscoveryStatus
)

logger = structlog.get_logger()


class NetworkDiscoveryEngine:
    """
    Automated network discovery engine

    Features:
    - CDP (Cisco Discovery Protocol) neighbor discovery
    - LLDP (Link Layer Discovery Protocol) neighbor discovery
    - SNMP-based discovery
    - Recursive neighbor traversal
    - Topology mapping
    - Change detection
    """

    def __init__(self):
        self.max_concurrent_discoveries = 10
        self.discovery_timeout = 30  # seconds

    async def discover_network(
        self,
        job: DiscoveryJob
    ) -> NetworkTopology:
        """
        Discover network topology starting from seed devices

        Process:
        1. Connect to seed devices
        2. Get neighbor information (CDP/LLDP)
        3. Recursively discover neighbors up to max_depth
        4. Build topology map
        5. Store discovered devices in inventory
        6. Detect changes from previous discovery

        Args:
            job: DiscoveryJob with parameters

        Returns:
            NetworkTopology with discovered devices and connections
        """
        logger.info(
            "Starting network discovery",
            job_id=job.id,
            seed_devices=len(job.seed_devices),
            methods=job.methods,
            max_depth=job.discovery_depth
        )

        job.status = DiscoveryStatus.RUNNING
        job.started_at = datetime.utcnow()

        discovered = set()  # IPs already discovered
        to_discover = set(job.seed_devices)  # IPs to discover
        topology = {"nodes": [], "edges": []}

        try:
            for depth in range(job.discovery_depth):
                if not to_discover:
                    logger.info(f"No more devices to discover at depth {depth}")
                    break

                logger.info(
                    f"Discovery depth {depth + 1}/{job.discovery_depth}",
                    devices_to_discover=len(to_discover),
                    devices_discovered=len(discovered)
                )

                current_batch = list(to_discover)
                to_discover.clear()

                # Discover devices in parallel with concurrency limit
                semaphore = asyncio.Semaphore(job.parallel_workers)

                async def discover_with_limit(device_ip):
                    async with semaphore:
                        return await self._discover_device(device_ip, job.methods, job.timeout_seconds)

                # Run discoveries in parallel
                results = await asyncio.gather(
                    *[discover_with_limit(ip) for ip in current_batch],
                    return_exceptions=True
                )

                # Process results
                for device_ip, result in zip(current_batch, results):
                    if device_ip in discovered:
                        continue

                    if isinstance(result, Exception):
                        logger.error(f"Failed to discover {device_ip}", error=str(result))
                        job.failed_device_ips.append(device_ip)
                        job.devices_failed += 1
                        continue

                    if result:
                        discovered.add(device_ip)
                        job.devices_discovered += 1

                        # Add device to topology
                        topology["nodes"].append({
                            "id": device_ip,
                            "label": result.get("hostname", device_ip),
                            "type": self._determine_device_type(result),
                            "vendor": result.get("vendor"),
                            "model": result.get("model"),
                            "data": result
                        })

                        # Store in inventory
                        inventory_device = await self._store_in_inventory(result, job.id)
                        job.discovered_device_ids.append(inventory_device.id)

                        # Add neighbors to discovery queue
                        for neighbor in result.get("neighbors", []):
                            neighbor_ip = neighbor.get("ip_address")

                            if neighbor_ip and neighbor_ip not in discovered:
                                # Apply vendor filter if specified
                                if not job.vendor_filter or neighbor.get("vendor") in job.vendor_filter:
                                    to_discover.add(neighbor_ip)

                                    # Add edge to topology
                                    topology["edges"].append({
                                        "source": device_ip,
                                        "target": neighbor_ip,
                                        "local_interface": neighbor.get("local_interface"),
                                        "remote_interface": neighbor.get("remote_interface"),
                                        "protocol": neighbor.get("protocol", "cdp")
                                    })
                                    job.connections_found += 1

            # Create topology record
            network_topology = NetworkTopology(
                name=job.name,
                topology_type="physical",
                nodes=topology["nodes"],
                edges=topology["edges"],
                device_count=len(topology["nodes"]),
                connection_count=len(topology["edges"]),
                generated_by=job.created_by,
                discovery_job_id=job.id
            )

            job.status = DiscoveryStatus.COMPLETED
            job.completed_at = datetime.utcnow()
            job.calculate_duration()

            logger.info(
                "Discovery completed",
                job_id=job.id,
                devices_discovered=job.devices_discovered,
                devices_failed=job.devices_failed,
                connections=job.connections_found,
                duration_seconds=job.duration_seconds
            )

            return network_topology

        except Exception as e:
            job.status = DiscoveryStatus.FAILED
            job.completed_at = datetime.utcnow()
            job.error_messages.append(str(e))
            logger.error("Discovery failed", job_id=job.id, error=str(e))
            raise

    async def _discover_device(
        self,
        device_ip: str,
        methods: List[str],
        timeout: int
    ) -> Optional[Dict]:
        """
        Discover single device using specified methods

        Args:
            device_ip: IP address to discover
            methods: List of discovery methods (cdp, lldp, snmp)
            timeout: Discovery timeout in seconds

        Returns:
            Dictionary with device information or None if failed
        """
        device_info = {
            "ip_address": device_ip,
            "neighbors": [],
            "discovery_method": None,
            "discovered_at": datetime.utcnow()
        }

        try:
            from src.devices.secure_connector import secure_device_connector

            # Try to connect with timeout
            async with asyncio.timeout(timeout):
                async with secure_device_connector.connect(device_ip) as conn:
                    # Get basic device information
                    device_info["hostname"] = await self._get_hostname(conn)
                    device_info["vendor"] = await self._get_vendor(conn)
                    device_info["model"] = await self._get_model(conn)
                    device_info["os_version"] = await self._get_os_version(conn)
                    device_info["serial_number"] = await self._get_serial_number(conn)
                    device_info["uptime"] = await self._get_uptime(conn)

                    # Get interface information
                    device_info["interfaces"] = await self._get_interfaces(conn)

                    # CDP discovery
                    if "cdp" in methods:
                        cdp_neighbors = await self._get_cdp_neighbors(conn)
                        if cdp_neighbors:
                            device_info["neighbors"].extend(cdp_neighbors)
                            device_info["discovery_method"] = DiscoveryMethod.CDP

                    # LLDP discovery
                    if "lldp" in methods:
                        lldp_neighbors = await self._get_lldp_neighbors(conn)
                        if lldp_neighbors:
                            device_info["neighbors"].extend(lldp_neighbors)
                            if not device_info["discovery_method"]:
                                device_info["discovery_method"] = DiscoveryMethod.LLDP

                    # SNMP discovery (if configured)
                    if "snmp" in methods:
                        snmp_info = await self._get_snmp_info(device_ip)
                        if snmp_info:
                            device_info.update(snmp_info)
                            if not device_info["discovery_method"]:
                                device_info["discovery_method"] = DiscoveryMethod.SNMP

                    logger.debug(
                        "Device discovered",
                        ip=device_ip,
                        hostname=device_info.get("hostname"),
                        neighbors=len(device_info["neighbors"])
                    )

                    return device_info

        except asyncio.TimeoutError:
            logger.warning(f"Discovery timeout for {device_ip}")
            return None
        except Exception as e:
            logger.error(f"Failed to discover {device_ip}", error=str(e))
            return None

    async def _get_hostname(self, conn) -> str:
        """Get device hostname"""
        try:
            output = await conn.send_command("show running-config | include hostname")
            match = re.search(r"hostname\s+(\S+)", output)
            return match.group(1) if match else conn.host
        except:
            return conn.host

    async def _get_vendor(self, conn) -> str:
        """Determine device vendor from device type"""
        device_type = getattr(conn, "device_type", "unknown")

        if "cisco" in device_type:
            return "cisco"
        elif "juniper" in device_type:
            return "juniper"
        elif "arista" in device_type:
            return "arista"
        elif "hp" in device_type or "procurve" in device_type:
            return "hp"
        else:
            return "unknown"

    async def _get_model(self, conn) -> Optional[str]:
        """Get device model"""
        try:
            output = await conn.send_command("show version")

            # Cisco
            match = re.search(r"cisco\s+(\S+)", output, re.IGNORECASE)
            if match:
                return match.group(1)

            # Juniper
            match = re.search(r"Model:\s+(\S+)", output)
            if match:
                return match.group(1)

            return None
        except:
            return None

    async def _get_os_version(self, conn) -> Optional[str]:
        """Get OS version"""
        try:
            output = await conn.send_command("show version")

            # Cisco IOS
            match = re.search(r"Version\s+([0-9.()A-Za-z]+)", output)
            if match:
                return match.group(1)

            # Juniper Junos
            match = re.search(r"JUNOS\s+([0-9.A-Za-z-]+)", output)
            if match:
                return match.group(1)

            return None
        except:
            return None

    async def _get_serial_number(self, conn) -> Optional[str]:
        """Get device serial number"""
        try:
            output = await conn.send_command("show version")

            # Cisco
            match = re.search(r"System serial number\s*:\s*(\S+)", output)
            if match:
                return match.group(1)

            match = re.search(r"Processor board ID\s+(\S+)", output)
            if match:
                return match.group(1)

            return None
        except:
            return None

    async def _get_uptime(self, conn) -> Optional[int]:
        """Get device uptime in seconds"""
        try:
            output = await conn.send_command("show version")

            # Parse uptime (simplified)
            match = re.search(r"uptime is.*?(\d+)\s+days?", output)
            if match:
                days = int(match.group(1))
                return days * 86400  # Convert to seconds

            return None
        except:
            return None

    async def _get_interfaces(self, conn) -> List[Dict]:
        """Get interface information"""
        try:
            output = await conn.send_command("show ip interface brief")
            interfaces = []

            # Parse interface output (simplified)
            for line in output.split("\n"):
                match = re.search(r"(\S+)\s+(\d+\.\d+\.\d+\.\d+)\s+\w+\s+\w+\s+(\w+)", line)
                if match:
                    interfaces.append({
                        "name": match.group(1),
                        "ip_address": match.group(2),
                        "status": match.group(3)
                    })

            return interfaces
        except:
            return []

    async def _get_cdp_neighbors(self, conn) -> List[Dict]:
        """Get CDP neighbors"""
        try:
            output = await conn.send_command("show cdp neighbors detail")
            neighbors = []

            # Parse CDP output (simplified - real implementation needs robust parsing)
            current_neighbor = {}

            for line in output.split("\n"):
                # Device ID
                if "Device ID:" in line:
                    if current_neighbor:
                        neighbors.append(current_neighbor)
                    current_neighbor = {"protocol": "cdp"}
                    current_neighbor["remote_hostname"] = line.split(":")[-1].strip()

                # IP Address
                elif "IP address:" in line:
                    match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
                    if match:
                        current_neighbor["ip_address"] = match.group(1)

                # Platform
                elif "Platform:" in line:
                    parts = line.split(",")
                    if parts:
                        current_neighbor["platform"] = parts[0].split(":")[-1].strip()

                # Interface
                elif "Interface:" in line:
                    match = re.search(r"Interface:\s+(\S+),\s+Port ID.*?:\s+(\S+)", line)
                    if match:
                        current_neighbor["local_interface"] = match.group(1)
                        current_neighbor["remote_interface"] = match.group(2)

            if current_neighbor:
                neighbors.append(current_neighbor)

            logger.debug(f"Found {len(neighbors)} CDP neighbors")
            return neighbors

        except Exception as e:
            logger.error("Failed to get CDP neighbors", error=str(e))
            return []

    async def _get_lldp_neighbors(self, conn) -> List[Dict]:
        """Get LLDP neighbors"""
        try:
            output = await conn.send_command("show lldp neighbors detail")
            neighbors = []

            # Parse LLDP output (simplified)
            # Real implementation would need proper LLDP parsing

            logger.debug(f"Found {len(neighbors)} LLDP neighbors")
            return neighbors

        except Exception as e:
            logger.debug("LLDP not available or failed", error=str(e))
            return []

    async def _get_snmp_info(self, device_ip: str) -> Optional[Dict]:
        """Get device info via SNMP"""
        # SNMP discovery implementation would go here
        # Requires SNMP library (pysnmp or easysnmp)
        return None

    def _determine_device_type(self, device_info: Dict) -> str:
        """Determine device type from capabilities"""
        capabilities = device_info.get("capabilities", {})

        if capabilities.get("router"):
            return "router"
        elif capabilities.get("switch"):
            return "switch"
        elif capabilities.get("wireless"):
            return "wireless"
        else:
            return "unknown"

    async def _store_in_inventory(
        self,
        device_info: Dict,
        discovery_job_id: str
    ) -> DeviceInventory:
        """
        Store or update device in inventory

        Args:
            device_info: Discovered device information
            discovery_job_id: Discovery job that found this device

        Returns:
            DeviceInventory record
        """
        from src.db.session import get_db

        async with get_db() as db:
            # Check if device already exists (by IP or serial number)
            existing = None

            if device_info.get("serial_number"):
                existing = await db.query(DeviceInventory).filter(
                    DeviceInventory.serial_number == device_info["serial_number"]
                ).first()

            if not existing:
                existing = await db.query(DeviceInventory).filter(
                    DeviceInventory.ip_address == device_info["ip_address"]
                ).first()

            if existing:
                # Update existing device
                old_version = existing.os_version

                existing.hostname = device_info.get("hostname", existing.hostname)
                existing.vendor = device_info.get("vendor", existing.vendor)
                existing.model = device_info.get("model", existing.model)
                existing.os_version = device_info.get("os_version", existing.os_version)
                existing.last_seen_at = datetime.utcnow()
                existing.is_reachable = True
                existing.interfaces = device_info.get("interfaces", [])
                existing.neighbors = device_info.get("neighbors", [])

                # Detect OS version change
                if old_version and old_version != existing.os_version:
                    await self._record_change(
                        existing.id,
                        "modified",
                        "os_version",
                        old_version,
                        existing.os_version,
                        discovery_job_id
                    )

                device = existing
                logger.debug(f"Updated existing device in inventory: {device.hostname}")

            else:
                # Create new device
                device = DeviceInventory(
                    hostname=device_info.get("hostname", "unknown"),
                    ip_address=device_info["ip_address"],
                    vendor=device_info.get("vendor"),
                    model=device_info.get("model"),
                    serial_number=device_info.get("serial_number"),
                    os_version=device_info.get("os_version"),
                    discovery_method=device_info.get("discovery_method", DiscoveryMethod.CDP),
                    discovered_by=discovery_job_id,
                    interfaces=device_info.get("interfaces", []),
                    neighbors=device_info.get("neighbors", [])
                )

                db.add(device)

                # Record as new device
                await self._record_change(
                    device.id,
                    "added",
                    None,
                    None,
                    None,
                    discovery_job_id
                )

                logger.info(f"Added new device to inventory: {device.hostname}")

            await db.commit()
            await db.refresh(device)

            return device

    async def _record_change(
        self,
        device_id: str,
        change_type: str,
        field: Optional[str],
        old_value: Optional[str],
        new_value: Optional[str],
        detected_by: str
    ):
        """Record device change for alerting"""
        from src.db.session import get_db

        async with get_db() as db:
            change = DeviceChange(
                device_id=device_id,
                change_type=change_type,
                field_changed=field,
                old_value=str(old_value) if old_value else None,
                new_value=str(new_value) if new_value else None,
                detected_by=detected_by,
                severity="info" if change_type == "modified" else "warning"
            )

            db.add(change)
            await db.commit()


# Global instance
discovery_engine = NetworkDiscoveryEngine()

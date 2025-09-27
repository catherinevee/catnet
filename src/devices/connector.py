"""
Secure Device Connector
Implements secure connection management for network devices
"""

from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta
from uuid import UUID, uuid4
import asyncio
import hashlib
import json
import ipaddress
from dataclasses import dataclass

from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException
from napalm import get_network_driver
from nornir import InitNornir
from nornir.core.task import Task, Result
import asyncssh
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.config import settings
from src.db.models import Device, DeviceCredential, DeviceConnection, DeviceAudit
from src.security.vault import VaultClient
from src.security.audit import AuditLogger
from src.core.exceptions import (
    DeviceConnectionError,
    DeviceAuthenticationError,
    DeviceTimeoutError
)


@dataclass
class BastionHost:
    """Represents a bastion/jump host for device connections"""
    id: str
    hostname: str
    ip_address: str
    zone: str
    environment: str
    health_score: float
    load_score: float
    max_connections: int
    current_connections: int
    last_health_check: datetime
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


class DeviceConnection:
    """
    Represents an active device connection
    """

    def __init__(
        self,
        session_id: str,
        device_id: str,
        connection_handler: Any,
        protocol: str,
        source_ip: str,
        user_id: str
    ):
        self.session_id = session_id
        self.device_id = device_id
        self.connection_handler = connection_handler
        self.protocol = protocol
        self.source_ip = source_ip
        self.user_id = user_id
        self.established_at = datetime.utcnow()
        self.last_activity = datetime.utcnow()
        self.command_count = 0

    def is_active(self) -> bool:
        """Check if connection is still active"""
        timeout = timedelta(minutes=settings.DEVICE_CONNECTION_TIMEOUT_MINUTES)
        return (datetime.utcnow() - self.last_activity) < timeout

    def update_activity(self):
        """Update last activity timestamp"""
        self.last_activity = datetime.utcnow()
        self.command_count += 1


class SecureDeviceConnector:
    """
    Secure device connection manager with Vault integration
    """

    def __init__(
        self,
        db: AsyncSession,
        redis,
        vault: VaultClient,
        audit: AuditLogger
    ):
        self.db = db
        self.redis = redis
        self.vault = vault
        self.audit = audit
        self.active_connections: Dict[str, DeviceConnection] = {}
        self.connection_pool_size = settings.DEVICE_CONNECTION_POOL_SIZE
        self.max_retries = 3
        self.retry_delay = 5

    async def connect_to_device(
        self,
        device_id: str,
        user_context: Dict[str, Any],
        protocol: str = "ssh",
        port: Optional[int] = None,
        use_jumphost: bool = False,
        jumphost_id: Optional[str] = None,
        connection_timeout: int = 30
    ) -> DeviceConnection:
        """
        Establish secure connection to device
        """

        # Step 1: Verify user authorization
        if not await self.check_authorization(user_context, device_id):
            await self.audit.log_unauthorized_attempt(user_context, device_id)
            raise DeviceAuthenticationError("User not authorized for this device")

        # Step 2: Get device information
        device = await self.db.get(Device, UUID(device_id))
        if not device:
            raise DeviceConnectionError(f"Device {device_id} not found")

        # Step 3: Get temporary credentials from Vault
        creds = await self.get_device_credentials(device_id, user_context["user_id"])

        # Step 4: Select connection method
        if use_jumphost:
            # Auto-select bastion if not specified
            if not jumphost_id:
                jumphost_id = await self.select_bastion(device_id)
                if not jumphost_id:
                    raise DeviceConnectionError("No suitable bastion host available")

            connection = await self.connect_via_jumphost(
                device, creds, jumphost_id, protocol, port, connection_timeout
            )
        else:
            connection = await self.direct_connect(
                device, creds, protocol, port, connection_timeout
            )

        # Step 5: Create connection record
        session_id = str(uuid4())
        device_conn = DeviceConnection(
            session_id=session_id,
            device_id=device_id,
            connection_handler=connection,
            protocol=protocol,
            source_ip=user_context.get("ip_address", "unknown"),
            user_id=user_context["user_id"]
        )

        # Step 6: Enable session recording
        await self.start_session_recording(session_id, device_id, user_context)

        # Step 7: Store connection
        self.active_connections[session_id] = device_conn

        # Step 8: Log successful connection
        await self.audit.log_event(
            user_id=user_context["user_id"],
            action="device_connection_established",
            resource_type="device",
            resource_id=device_id,
            details={
                "session_id": session_id,
                "protocol": protocol,
                "jumphost_used": use_jumphost
            }
        )

        return device_conn

    async def check_authorization(
        self,
        user_context: Dict[str, Any],
        device_id: str
    ) -> bool:
        """
        Check if user is authorized to access device
        """

        # Check user roles and permissions
        user_roles = user_context.get("roles", [])

        # Admin role has full access
        if "admin" in user_roles:
            return True

        # Check specific device permissions
        if self.redis:
            permission_key = f"device_access:{user_context['user_id']}:{device_id}"
            has_permission = await self.redis.get(permission_key)
            if has_permission:
                return True

        # Check device group permissions
        device = await self.db.get(Device, UUID(device_id))
        if device:
            # Check environment-based access
            if device.environment == "development" and "developer" in user_roles:
                return True
            if device.environment == "staging" and "operator" in user_roles:
                return True
            if device.environment == "production" and "senior_operator" in user_roles:
                return True

        return False

    async def get_device_credentials(
        self,
        device_id: str,
        user_id: str
    ) -> Dict[str, str]:
        """
        Get temporary device credentials from Vault
        """

        # Generate temporary credentials with TTL
        vault_path = f"devices/{device_id}/credentials"

        try:
            # Request temporary credentials
            creds = await self.vault.get_dynamic_credentials(
                path=vault_path,
                requestor=user_id,
                ttl=1800  # 30 minutes
            )

            if not creds:
                # Fallback to static credentials (encrypted)
                static_creds = await self.vault.get_secret(f"devices/{device_id}/static")
                if static_creds:
                    return {
                        "username": static_creds.get("username"),
                        "password": static_creds.get("password"),
                        "enable_password": static_creds.get("enable_password")
                    }

                raise DeviceAuthenticationError("No credentials available")

            return creds

        except Exception as e:
            await self.audit.log_error(
                error_type="credential_retrieval_error",
                error_message=str(e),
                context={
                    "device_id": device_id,
                    "user_id": user_id
                }
            )
            raise DeviceAuthenticationError(f"Failed to retrieve credentials: {str(e)}")

    async def direct_connect(
        self,
        device: Device,
        credentials: Dict[str, str],
        protocol: str,
        port: Optional[int],
        timeout: int
    ) -> Any:
        """
        Establish direct connection to device
        """

        device_params = {
            "device_type": self.get_device_type(device.vendor, device.os_version),
            "host": device.ip_address,
            "username": credentials["username"],
            "password": credentials["password"],
            "port": port or (22 if protocol == "ssh" else 23),
            "timeout": timeout,
            "session_log": f"/tmp/catnet_session_{device.hostname}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.log"
        }

        # Add vendor-specific parameters
        if device.vendor == "cisco":
            device_params["secret"] = credentials.get("enable_password", credentials["password"])
            device_params["global_delay_factor"] = 2
        elif device.vendor == "juniper":
            device_params["global_delay_factor"] = 4

        # Attempt connection with retries
        for attempt in range(self.max_retries):
            try:
                if protocol == "ssh":
                    connection = ConnectHandler(**device_params)
                    # Enter enable mode for Cisco devices
                    if device.vendor == "cisco" and credentials.get("enable_password"):
                        connection.enable()
                    return connection

                elif protocol == "netconf":
                    # Use NAPALM for NETCONF connections
                    driver = get_network_driver(device.vendor)
                    napalm_device = driver(
                        hostname=device.ip_address,
                        username=credentials["username"],
                        password=credentials["password"],
                        timeout=timeout
                    )
                    napalm_device.open()
                    return napalm_device

                else:
                    raise DeviceConnectionError(f"Unsupported protocol: {protocol}")

            except NetmikoAuthenticationException as e:
                raise DeviceAuthenticationError(f"Authentication failed: {str(e)}")

            except NetmikoTimeoutException as e:
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(self.retry_delay)
                    continue
                raise DeviceTimeoutError(f"Connection timeout: {str(e)}")

            except Exception as e:
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(self.retry_delay)
                    continue
                raise DeviceConnectionError(f"Connection failed: {str(e)}")

    async def connect_via_jumphost(
        self,
        device: Device,
        credentials: Dict[str, str],
        jumphost_id: str,
        protocol: str,
        port: Optional[int],
        timeout: int
    ) -> Any:
        """
        Connect to device through jumphost/bastion
        """

        # Get jumphost details
        jumphost = await self.db.get(Device, UUID(jumphost_id))
        if not jumphost:
            raise DeviceConnectionError(f"Jumphost {jumphost_id} not found")

        # Get jumphost credentials
        jump_creds = await self.get_device_credentials(jumphost_id, "system")

        # Establish SSH tunnel through jumphost
        async with asyncssh.connect(
            jumphost.ip_address,
            username=jump_creds["username"],
            password=jump_creds["password"],
            known_hosts=None
        ) as tunnel:

            # Connect to target device through tunnel
            device_params = {
                "device_type": self.get_device_type(device.vendor, device.os_version),
                "host": device.ip_address,
                "username": credentials["username"],
                "password": credentials["password"],
                "port": port or 22,
                "timeout": timeout,
                "ssh_config_file": False,
                "ssh_tunnel": tunnel
            }

            try:
                connection = ConnectHandler(**device_params)
                if device.vendor == "cisco" and credentials.get("enable_password"):
                    connection.enable()
                return connection

            except Exception as e:
                raise DeviceConnectionError(f"Failed to connect through jumphost: {str(e)}")

    def get_device_type(self, vendor: str, os_version: Optional[str]) -> str:
        """
        Map vendor and OS to Netmiko device type
        """

        device_type_map = {
            "cisco": {
                "ios": "cisco_ios",
                "ios-xe": "cisco_xe",
                "ios-xr": "cisco_xr",
                "nxos": "cisco_nxos",
                "asa": "cisco_asa"
            },
            "juniper": {
                "junos": "juniper_junos",
                "junos-evo": "juniper_junos"
            },
            "arista": {
                "eos": "arista_eos"
            },
            "huawei": {
                "vrp": "huawei"
            }
        }

        vendor_map = device_type_map.get(vendor.lower(), {})

        if os_version:
            for os_key, device_type in vendor_map.items():
                if os_key in os_version.lower():
                    return device_type

        # Default mappings
        default_map = {
            "cisco": "cisco_ios",
            "juniper": "juniper_junos",
            "arista": "arista_eos",
            "huawei": "huawei"
        }

        return default_map.get(vendor.lower(), "generic")

    async def start_session_recording(
        self,
        session_id: str,
        device_id: str,
        user_context: Dict[str, Any]
    ):
        """
        Start recording device session for audit
        """

        recording_data = {
            "session_id": session_id,
            "device_id": device_id,
            "user_id": user_context["user_id"],
            "started_at": datetime.utcnow().isoformat(),
            "commands": []
        }

        if self.redis:
            await self.redis.set(
                f"session_recording:{session_id}",
                json.dumps(recording_data),
                ex=7200  # Expire after 2 hours
            )

        # Create audit record
        device_audit = DeviceAudit(
            device_id=UUID(device_id),
            user_id=UUID(user_context["user_id"]),
            session_id=session_id,
            action="session_started",
            details={
                "ip_address": user_context.get("ip_address"),
                "user_agent": user_context.get("user_agent")
            }
        )
        self.db.add(device_audit)
        await self.db.commit()

    async def execute_command(
        self,
        session_id: str,
        command: str,
        timeout: int = 30
    ) -> str:
        """
        Execute command on device through existing connection
        """

        if session_id not in self.active_connections:
            raise DeviceConnectionError("Session not found or expired")

        connection = self.active_connections[session_id]

        if not connection.is_active():
            raise DeviceConnectionError("Connection timeout")

        try:
            # Execute command
            handler = connection.connection_handler

            if isinstance(handler, ConnectHandler):
                output = handler.send_command(command, expect_string=r"#|>", read_timeout=timeout)
            else:
                # NAPALM or other handler
                output = handler.cli([command])[command]

            # Update activity
            connection.update_activity()

            # Record command in session
            if self.redis:
                recording_key = f"session_recording:{session_id}"
                recording = await self.redis.get(recording_key)
                if recording:
                    data = json.loads(recording)
                    data["commands"].append({
                        "command": command,
                        "timestamp": datetime.utcnow().isoformat(),
                        "output_length": len(output)
                    })
                    await self.redis.set(recording_key, json.dumps(data), ex=7200)

            return output

        except Exception as e:
            await self.audit.log_error(
                error_type="command_execution_error",
                error_message=str(e),
                context={
                    "session_id": session_id,
                    "command": command
                }
            )
            raise DeviceConnectionError(f"Command execution failed: {str(e)}")

    async def disconnect(self, session_id: str):
        """
        Disconnect device session
        """

        if session_id not in self.active_connections:
            return

        connection = self.active_connections[session_id]

        try:
            handler = connection.connection_handler
            if isinstance(handler, ConnectHandler):
                handler.disconnect()
            elif hasattr(handler, "close"):
                handler.close()

        except Exception as e:
            # Log but don't raise
            await self.audit.log_error(
                error_type="disconnect_error",
                error_message=str(e),
                context={"session_id": session_id}
            )

        finally:
            # Remove from active connections
            del self.active_connections[session_id]

            # Update audit
            device_audit = DeviceAudit(
                device_id=UUID(connection.device_id),
                user_id=UUID(connection.user_id),
                session_id=session_id,
                action="session_ended",
                details={
                    "duration_seconds": (datetime.utcnow() - connection.established_at).total_seconds(),
                    "command_count": connection.command_count
                }
            )
            self.db.add(device_audit)
            await self.db.commit()

    async def cleanup_stale_connections(self):
        """
        Clean up stale connections (background task)
        """

        stale_sessions = []

        for session_id, connection in self.active_connections.items():
            if not connection.is_active():
                stale_sessions.append(session_id)

        for session_id in stale_sessions:
            await self.disconnect(session_id)

        if stale_sessions:
            await self.audit.log_event(
                action="stale_connections_cleaned",
                resource_type="device_connection",
                details={"count": len(stale_sessions), "sessions": stale_sessions}
            )

    async def select_bastion(self, device_id: str) -> Optional[str]:
        """
        Select appropriate bastion host for device based on:
        - Device location/zone
        - Load balancing
        - Bastion health status
        - Network topology
        """
        try:
            # Get device information
            device = await self.db.get(Device, UUID(device_id))
            if not device:
                return None

            # Get available bastion hosts
            available_bastions = await self._get_available_bastions()
            if not available_bastions:
                return None

            # Filter bastions by network reachability
            reachable_bastions = await self._filter_reachable_bastions(
                device, available_bastions
            )

            if not reachable_bastions:
                return None

            # Select best bastion based on multiple criteria
            selected_bastion = await self._select_optimal_bastion(
                device, reachable_bastions
            )

            if selected_bastion:
                # Update bastion usage statistics
                await self._update_bastion_stats(selected_bastion.id, device_id)

                await self.audit.log_event(
                    action="bastion_selected",
                    resource_type="device_connection",
                    resource_id=device_id,
                    details={
                        "bastion_id": selected_bastion.id,
                        "bastion_host": selected_bastion.ip_address,
                        "selection_criteria": {
                            "zone_match": selected_bastion.zone == device.zone,
                            "load_score": selected_bastion.load_score,
                            "health_score": selected_bastion.health_score
                        }
                    }
                )

                return selected_bastion.id

        except Exception as e:
            await self.audit.log_error(
                error_type="bastion_selection_error",
                error_message=str(e),
                context={"device_id": device_id}
            )

        return None

    async def _get_available_bastions(self) -> List['BastionHost']:
        """
        Get all available bastion hosts
        """
        from sqlalchemy import select

        # Query bastion hosts from devices table where is_bastion=True
        query = select(Device).where(
            Device.is_bastion == True,
            Device.is_active == True,
            Device.status == "connected"
        )

        result = await self.db.execute(query)
        bastion_devices = result.scalars().all()

        bastions = []
        for device in bastion_devices:
            # Get health and load metrics from Redis cache
            health_score = await self._get_bastion_health_score(device.id)
            load_score = await self._get_bastion_load_score(device.id)

            bastion = BastionHost(
                id=str(device.id),
                hostname=device.hostname,
                ip_address=device.ip_address,
                zone=device.zone or "default",
                environment=device.environment,
                health_score=health_score,
                load_score=load_score,
                max_connections=device.metadata.get("max_connections", 100),
                current_connections=await self._get_current_connections(device.id),
                last_health_check=device.last_seen or datetime.utcnow()
            )
            bastions.append(bastion)

        return bastions

    async def _filter_reachable_bastions(
        self,
        target_device: Device,
        bastions: List['BastionHost']
    ) -> List['BastionHost']:
        """
        Filter bastions that can reach the target device
        """
        reachable = []

        for bastion in bastions:
            # Check network reachability
            if await self._can_reach_device(bastion, target_device):
                reachable.append(bastion)

        return reachable

    async def _can_reach_device(
        self,
        bastion: 'BastionHost',
        target_device: Device
    ) -> bool:
        """
        Check if bastion can reach target device
        """
        try:
            # Same zone/environment priority
            if bastion.zone == target_device.zone:
                return True

            # Check if bastion has routing to target network
            target_network = self._get_device_network(target_device.ip_address)
            bastion_networks = await self._get_bastion_networks(bastion.id)

            # Check if target network is in bastion's routing table
            for network in bastion_networks:
                if target_network.subnet_of(network) or network.subnet_of(target_network):
                    return True

            # Check explicit routing rules from metadata
            routing_rules = bastion.metadata.get("routing_rules", [])
            for rule in routing_rules:
                if self._match_routing_rule(target_device, rule):
                    return True

            # Default: allow if no specific restrictions
            return True

        except Exception as e:
            # If we can't determine reachability, assume it's reachable
            return True

    def _get_device_network(self, ip_address: str) -> ipaddress.IPv4Network:
        """
        Get network for device IP (assuming /24 for simplicity)
        """
        try:
            ip = ipaddress.IPv4Address(ip_address)
            # Assume /24 network for most enterprise networks
            network = ipaddress.IPv4Network(f"{ip}/24", strict=False)
            return network
        except:
            # Fallback to /16 if parsing fails
            return ipaddress.IPv4Network(f"{ip_address}/16", strict=False)

    async def _get_bastion_networks(self, bastion_id: str) -> List[ipaddress.IPv4Network]:
        """
        Get networks accessible from bastion
        """
        if self.redis:
            cache_key = f"bastion_networks:{bastion_id}"
            cached_data = await self.redis.get(cache_key)

            if cached_data:
                networks_data = json.loads(cached_data)
                return [
                    ipaddress.IPv4Network(net) for net in networks_data
                ]

        # Default: assume bastion can reach common enterprise networks
        default_networks = [
            ipaddress.IPv4Network("10.0.0.0/8"),
            ipaddress.IPv4Network("172.16.0.0/12"),
            ipaddress.IPv4Network("192.168.0.0/16")
        ]
        return default_networks

    def _match_routing_rule(self, device: Device, rule: Dict[str, Any]) -> bool:
        """
        Check if device matches routing rule
        """
        # Rule format: {"type": "subnet", "value": "10.1.0.0/16"}
        # or {"type": "zone", "value": "dmz"}
        # or {"type": "vendor", "value": "cisco"}

        rule_type = rule.get("type")
        rule_value = rule.get("value")

        if rule_type == "subnet":
            try:
                rule_network = ipaddress.IPv4Network(rule_value)
                device_ip = ipaddress.IPv4Address(device.ip_address)
                return device_ip in rule_network
            except:
                return False

        elif rule_type == "zone":
            return device.zone == rule_value

        elif rule_type == "vendor":
            return device.vendor.lower() == rule_value.lower()

        elif rule_type == "environment":
            return device.environment == rule_value

        return False

    async def _select_optimal_bastion(
        self,
        target_device: Device,
        candidates: List['BastionHost']
    ) -> Optional['BastionHost']:
        """
        Select the best bastion based on multiple criteria
        """
        if not candidates:
            return None

        scored_bastions = []

        for bastion in candidates:
            score = await self._calculate_bastion_score(target_device, bastion)
            scored_bastions.append((score, bastion))

        # Sort by score (higher is better)
        scored_bastions.sort(key=lambda x: x[0], reverse=True)

        return scored_bastions[0][1]

    async def _calculate_bastion_score(
        self,
        target_device: Device,
        bastion: 'BastionHost'
    ) -> float:
        """
        Calculate selection score for bastion
        """
        score = 0.0

        # Zone affinity (highest priority)
        if bastion.zone == target_device.zone:
            score += 100.0
        elif bastion.zone == "shared" or target_device.zone == "shared":
            score += 50.0

        # Environment matching
        if bastion.environment == target_device.environment:
            score += 50.0

        # Health score (0-100)
        score += bastion.health_score * 0.5

        # Load balancing (favor less loaded bastions)
        load_ratio = bastion.current_connections / max(bastion.max_connections, 1)
        load_score = max(0, 100 - (load_ratio * 100))
        score += load_score * 0.3

        # Response time bonus (if available)
        response_time = await self._get_bastion_response_time(bastion.id)
        if response_time < 50:  # Less than 50ms
            score += 20.0
        elif response_time < 100:  # Less than 100ms
            score += 10.0

        # Geographic proximity (if coordinates available)
        proximity_bonus = await self._calculate_proximity_bonus(
            target_device, bastion
        )
        score += proximity_bonus

        return score

    async def _get_bastion_health_score(self, bastion_id: str) -> float:
        """
        Get bastion health score from monitoring
        """
        if self.redis:
            health_key = f"bastion_health:{bastion_id}"
            health_data = await self.redis.get(health_key)

            if health_data:
                try:
                    health_info = json.loads(health_data)
                    return float(health_info.get("score", 100.0))
                except:
                    pass

        return 100.0  # Default healthy score

    async def _get_bastion_load_score(self, bastion_id: str) -> float:
        """
        Get bastion load score
        """
        if self.redis:
            load_key = f"bastion_load:{bastion_id}"
            load_data = await self.redis.get(load_key)

            if load_data:
                try:
                    load_info = json.loads(load_data)
                    cpu_usage = float(load_info.get("cpu_percent", 0))
                    memory_usage = float(load_info.get("memory_percent", 0))
                    # Calculate load score (lower usage = higher score)
                    return max(0, 100 - max(cpu_usage, memory_usage))
                except:
                    pass

        return 90.0  # Default good load score

    async def _get_current_connections(self, bastion_id: str) -> int:
        """
        Get current connection count for bastion
        """
        if self.redis:
            conn_key = f"bastion_connections:{bastion_id}"
            count = await self.redis.get(conn_key)
            if count:
                try:
                    return int(count)
                except:
                    pass

        return 0

    async def _get_bastion_response_time(self, bastion_id: str) -> float:
        """
        Get average response time for bastion
        """
        if self.redis:
            rt_key = f"bastion_response_time:{bastion_id}"
            rt_data = await self.redis.get(rt_key)
            if rt_data:
                try:
                    return float(rt_data)
                except:
                    pass

        return 50.0  # Default 50ms

    async def _calculate_proximity_bonus(
        self,
        target_device: Device,
        bastion: 'BastionHost'
    ) -> float:
        """
        Calculate geographic proximity bonus
        """
        try:
            target_coords = target_device.metadata.get("coordinates")
            bastion_coords = bastion.metadata.get("coordinates")

            if target_coords and bastion_coords:
                # Simple distance calculation
                lat_diff = abs(target_coords["lat"] - bastion_coords["lat"])
                lon_diff = abs(target_coords["lon"] - bastion_coords["lon"])
                distance = (lat_diff ** 2 + lon_diff ** 2) ** 0.5

                # Closer = higher bonus (max 10 points)
                return max(0, 10 - distance)

        except:
            pass

        return 0.0

    async def _update_bastion_stats(
        self,
        bastion_id: str,
        device_id: str
    ):
        """
        Update bastion usage statistics
        """
        if self.redis:
            # Increment connection counter
            conn_key = f"bastion_connections:{bastion_id}"
            await self.redis.incr(conn_key)
            await self.redis.expire(conn_key, 3600)  # Expire in 1 hour

            # Track usage history
            usage_key = f"bastion_usage:{bastion_id}:{datetime.utcnow().strftime('%Y%m%d%H')}"
            await self.redis.incr(usage_key)
            await self.redis.expire(usage_key, 86400)  # Expire in 24 hours

            # Track device connections
            device_key = f"bastion_device_connections:{bastion_id}"
            await self.redis.sadd(device_key, device_id)
            await self.redis.expire(device_key, 3600)
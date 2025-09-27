"""
Metric collectors for monitoring service.
"""

import asyncio
import aiohttp
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
import json
import struct
import socket

from prometheus_client.parser import text_string_to_metric_families
from pysnmp.hlapi.asyncio import (
    getCmd, nextCmd, SnmpEngine, CommunityData, UdpTransportTarget,
    ContextData, ObjectType, ObjectIdentity
)
import syslog
import netflow

from .models import (
    Metric, MetricType, LogEntry, LogLevel,
    NetworkMetrics, DeviceMetrics, SystemMetrics
)

logger = logging.getLogger(__name__)


class MetricCollector:
    """Base metric collector."""

    def __init__(self):
        self.sources = []
        self.collection_interval = 30  # seconds
        self.timeout = 10
        self.metrics_buffer = []

    async def collect(self) -> List[Metric]:
        """Collect metrics from all sources."""
        metrics = []

        for source in self.sources:
            try:
                source_metrics = await self.collect_from_source(source)
                metrics.extend(source_metrics)
            except Exception as e:
                logger.error(f"Error collecting from {source}: {e}")

        return metrics

    async def collect_from_source(self, source: Dict[str, Any]) -> List[Metric]:
        """Collect metrics from a single source."""
        # This is an abstract method - implemented by subclasses
        return []

    def add_source(self, source: Dict[str, Any]):
        """Add collection source."""
        self.sources.append(source)

    def remove_source(self, source_id: str):
        """Remove collection source."""
        self.sources = [s for s in self.sources if s.get('id') != source_id]

    async def validate_source(self, source: Dict[str, Any]) -> bool:
        """Validate source connectivity."""
        try:
            metrics = await self.collect_from_source(source)
            return len(metrics) > 0
        except Exception:
            return False


class PrometheusCollector(MetricCollector):
    """Prometheus metrics collector."""

    async def collect_from_source(self, source: Dict[str, Any]) -> List[Metric]:
        """Collect metrics from Prometheus endpoint."""
        metrics = []
        url = source.get('url')
        labels = source.get('labels', {})

        async with aiohttp.ClientSession() as session:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=self.timeout)
            ) as response:
                if response.status == 200:
                    text = await response.text()

                    for family in text_string_to_metric_families(text):
                        for sample in family.samples:
                            metric = Metric(
                                name=sample.name,
                                type=self._map_metric_type(family.type),
                                value=sample.value,
                                labels={**labels, **sample.labels},
                                source=source.get('name', 'prometheus'),
                                timestamp=datetime.utcnow()
                            )
                            metrics.append(metric)

        return metrics

    def _map_metric_type(self, prom_type: str) -> MetricType:
        """Map Prometheus metric type to internal type."""
        mapping = {
            'counter': MetricType.COUNTER,
            'gauge': MetricType.GAUGE,
            'histogram': MetricType.HISTOGRAM,
            'summary': MetricType.SUMMARY
        }
        return mapping.get(prom_type, MetricType.GAUGE)


class DeviceMetricCollector(MetricCollector):
    """Device metrics collector."""

    async def collect_from_source(self, source: Dict[str, Any]) -> List[Metric]:
        """Collect metrics from network device."""
        device_id = source.get('device_id')
        device_type = source.get('type')

        metrics = []

        # Collect via API or CLI based on device type
        if device_type == 'cisco':
            metrics = await self._collect_cisco_metrics(source)
        elif device_type == 'juniper':
            metrics = await self._collect_juniper_metrics(source)
        elif device_type == 'arista':
            metrics = await self._collect_arista_metrics(source)
        else:
            logger.warning(f"Unknown device type: {device_type}")

        return metrics

    async def _collect_cisco_metrics(self, source: Dict[str, Any]) -> List[Metric]:
        """Collect Cisco device metrics."""
        metrics = []
        device_id = source.get('device_id')

        # CPU utilization
        cpu_cmd = "show processes cpu | include CPU"
        cpu_output = await self._execute_command(source, cpu_cmd)
        if cpu_output:
            cpu_value = self._parse_cisco_cpu(cpu_output)
            metrics.append(Metric(
                name="device_cpu_usage",
                type=MetricType.GAUGE,
                value=cpu_value,
                unit="percent",
                labels={"device_id": device_id, "vendor": "cisco"},
                source="device_collector"
            ))

        # Memory utilization
        mem_cmd = "show memory statistics"
        mem_output = await self._execute_command(source, mem_cmd)
        if mem_output:
            mem_value = self._parse_cisco_memory(mem_output)
            metrics.append(Metric(
                name="device_memory_usage",
                type=MetricType.GAUGE,
                value=mem_value,
                unit="percent",
                labels={"device_id": device_id, "vendor": "cisco"},
                source="device_collector"
            ))

        # Interface statistics
        int_cmd = "show interfaces | include line protocol|packets"
        int_output = await self._execute_command(source, int_cmd)
        if int_output:
            interface_metrics = self._parse_cisco_interfaces(int_output, device_id)
            metrics.extend(interface_metrics)

        return metrics

    async def _collect_juniper_metrics(self, source: Dict[str, Any]) -> List[Metric]:
        """Collect Juniper device metrics."""
        metrics = []
        device_id = source.get('device_id')

        # Use XML API for Juniper devices
        api_url = f"https://{source['host']}/rpc"

        async with aiohttp.ClientSession() as session:
            # CPU utilization
            cpu_rpc = "<get-system-information/>"
            cpu_data = await self._juniper_rpc(session, api_url, cpu_rpc, source)
            if cpu_data:
                cpu_value = self._parse_juniper_cpu(cpu_data)
                metrics.append(Metric(
                    name="device_cpu_usage",
                    type=MetricType.GAUGE,
                    value=cpu_value,
                    unit="percent",
                    labels={"device_id": device_id, "vendor": "juniper"},
                    source="device_collector"
                ))

            # Memory utilization
            mem_rpc = "<get-system-memory-information/>"
            mem_data = await self._juniper_rpc(session, api_url, mem_rpc, source)
            if mem_data:
                mem_value = self._parse_juniper_memory(mem_data)
                metrics.append(Metric(
                    name="device_memory_usage",
                    type=MetricType.GAUGE,
                    value=mem_value,
                    unit="percent",
                    labels={"device_id": device_id, "vendor": "juniper"},
                    source="device_collector"
                ))

        return metrics

    async def _collect_arista_metrics(self, source: Dict[str, Any]) -> List[Metric]:
        """Collect Arista device metrics via eAPI."""
        metrics = []
        device_id = source.get('device_id')

        api_url = f"https://{source['host']}/command-api"

        async with aiohttp.ClientSession() as session:
            # Get system resources
            commands = [
                "show version",
                "show processes top once",
                "show interfaces counters"
            ]

            payload = {
                "jsonrpc": "2.0",
                "method": "runCmds",
                "params": {
                    "version": 1,
                    "cmds": commands,
                    "format": "json"
                },
                "id": "1"
            }

            async with session.post(
                api_url,
                json=payload,
                auth=aiohttp.BasicAuth(source['username'], source['password']),
                ssl=False
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    results = data.get('result', [])

                    # Parse CPU from processes
                    if len(results) > 1:
                        cpu_value = self._parse_arista_cpu(results[1])
                        metrics.append(Metric(
                            name="device_cpu_usage",
                            type=MetricType.GAUGE,
                            value=cpu_value,
                            unit="percent",
                            labels={"device_id": device_id, "vendor": "arista"},
                            source="device_collector"
                        ))

                    # Parse interface counters
                    if len(results) > 2:
                        interface_metrics = self._parse_arista_interfaces(results[2], device_id)
                        metrics.extend(interface_metrics)

        return metrics

    async def _execute_command(self, source: Dict[str, Any], command: str) -> Optional[str]:
        """Execute command on device."""
        # This would use the actual device connection from device service
        from ...devices.connector import DeviceConnector

        try:
            connector = DeviceConnector()
            connection = await connector.connect(
                host=source['host'],
                username=source['username'],
                password=source['password'],
                device_type=source['type'],
                port=source.get('port', 22)
            )

            output = await connection.execute(command)
            await connection.disconnect()
            return output
        except Exception as e:
            logger.error(f"Failed to execute command on {source['host']}: {e}")
            return None

    async def _juniper_rpc(
        self,
        session: aiohttp.ClientSession,
        url: str,
        rpc: str,
        source: Dict[str, Any]
    ) -> Optional[Dict]:
        """Execute Juniper RPC."""
        try:
            headers = {'Content-Type': 'application/xml'}
            auth = aiohttp.BasicAuth(source['username'], source['password'])

            async with session.post(
                url,
                data=rpc,
                headers=headers,
                auth=auth,
                ssl=False,
                timeout=aiohttp.ClientTimeout(total=self.timeout)
            ) as response:
                if response.status == 200:
                    text = await response.text()
                    # Parse XML response
                    import xml.etree.ElementTree as ET
                    root = ET.fromstring(text)
                    return self._xml_to_dict(root)
        except Exception as e:
            logger.error(f"Juniper RPC error: {e}")
        return None

    def _xml_to_dict(self, element) -> Dict:
        """Convert XML element to dictionary."""
        result = {}
        for child in element:
            if len(child) == 0:
                result[child.tag] = child.text
            else:
                result[child.tag] = self._xml_to_dict(child)
        return result

    def _parse_cisco_cpu(self, output: str) -> float:
        """Parse Cisco CPU output."""
        # Parse "CPU utilization for five seconds: 15%/2%"
        import re
        match = re.search(r'five seconds:\s*(\d+)%', output)
        if match:
            return float(match.group(1))
        return 0.0

    def _parse_cisco_memory(self, output: str) -> float:
        """Parse Cisco memory output."""
        import re
        lines = output.split('\n')
        total_memory = 0
        used_memory = 0

        for line in lines:
            if 'Processor' in line:
                # Parse "Processor   12345678   87654321   24691357"
                match = re.search(r'Processor\s+(\d+)\s+(\d+)', line)
                if match:
                    total = int(match.group(1))
                    used = int(match.group(2))
                    total_memory += total
                    used_memory += used

        if total_memory > 0:
            return (used_memory / total_memory) * 100
        return 0.0

    def _parse_cisco_interfaces(self, output: str, device_id: str) -> List[Metric]:
        """Parse Cisco interface statistics."""
        import re
        metrics = []
        lines = output.split('\n')
        current_interface = None

        for line in lines:
            # Match interface line
            int_match = re.match(r'^(\S+) is (up|down)', line)
            if int_match:
                current_interface = int_match.group(1)
                status = 1 if int_match.group(2) == 'up' else 0
                metrics.append(Metric(
                    name="interface_status",
                    type=MetricType.GAUGE,
                    value=status,
                    labels={"device_id": device_id, "interface": current_interface},
                    source="device_collector"
                ))

            # Match packet statistics
            if current_interface:
                in_match = re.search(r'(\d+) packets input, (\d+) bytes', line)
                if in_match:
                    metrics.append(Metric(
                        name="interface_rx_packets",
                        type=MetricType.COUNTER,
                        value=int(in_match.group(1)),
                        labels={"device_id": device_id, "interface": current_interface},
                        source="device_collector"
                    ))
                    metrics.append(Metric(
                        name="interface_rx_bytes",
                        type=MetricType.COUNTER,
                        value=int(in_match.group(2)),
                        labels={"device_id": device_id, "interface": current_interface},
                        source="device_collector"
                    ))

                out_match = re.search(r'(\d+) packets output, (\d+) bytes', line)
                if out_match:
                    metrics.append(Metric(
                        name="interface_tx_packets",
                        type=MetricType.COUNTER,
                        value=int(out_match.group(1)),
                        labels={"device_id": device_id, "interface": current_interface},
                        source="device_collector"
                    ))
                    metrics.append(Metric(
                        name="interface_tx_bytes",
                        type=MetricType.COUNTER,
                        value=int(out_match.group(2)),
                        labels={"device_id": device_id, "interface": current_interface},
                        source="device_collector"
                    ))

        return metrics

    def _parse_juniper_cpu(self, data: Dict) -> float:
        """Parse Juniper CPU data."""
        try:
            # Navigate through nested dict structure
            system_info = data.get('system-information', {})
            cpu_info = system_info.get('cpu-information', {})
            cpu_usage = cpu_info.get('cpu-usage', '0')
            return float(cpu_usage.strip('%'))
        except (KeyError, ValueError, AttributeError):
            return 0.0

    def _parse_juniper_memory(self, data: Dict) -> float:
        """Parse Juniper memory data."""
        try:
            # Navigate through nested dict structure
            memory_info = data.get('system-memory-information', {})
            memory_summary = memory_info.get('system-memory-summary', {})
            used_percent = memory_summary.get('system-memory-used-percent', '0')
            return float(used_percent.strip('%'))
        except (KeyError, ValueError, AttributeError):
            return 0.0

    def _parse_arista_cpu(self, data: Dict) -> float:
        """Parse Arista CPU data."""
        try:
            # Parse from 'show processes top once' output
            if 'processes' in data:
                cpu_stats = data.get('cpuInfo', {})
                idle_percent = float(cpu_stats.get('%Idle', 100))
                return 100 - idle_percent
        except (KeyError, ValueError):
            pass
        return 0.0

    def _parse_arista_interfaces(self, data: Dict, device_id: str) -> List[Metric]:
        """Parse Arista interface data."""
        metrics = []

        try:
            interfaces = data.get('interfaces', {})
            for interface_name, counters in interfaces.items():
                # Interface status
                link_status = counters.get('linkStatus', 'down')
                metrics.append(Metric(
                    name="interface_status",
                    type=MetricType.GAUGE,
                    value=1 if link_status == 'up' else 0,
                    labels={"device_id": device_id, "interface": interface_name},
                    source="device_collector"
                ))

                # Traffic counters
                in_octets = counters.get('inOctets', 0)
                out_octets = counters.get('outOctets', 0)
                in_pkts = counters.get('inUcastPkts', 0) + counters.get('inMulticastPkts', 0)
                out_pkts = counters.get('outUcastPkts', 0) + counters.get('outMulticastPkts', 0)

                metrics.extend([
                    Metric(
                        name="interface_rx_bytes",
                        type=MetricType.COUNTER,
                        value=in_octets,
                        labels={"device_id": device_id, "interface": interface_name},
                        source="device_collector"
                    ),
                    Metric(
                        name="interface_tx_bytes",
                        type=MetricType.COUNTER,
                        value=out_octets,
                        labels={"device_id": device_id, "interface": interface_name},
                        source="device_collector"
                    ),
                    Metric(
                        name="interface_rx_packets",
                        type=MetricType.COUNTER,
                        value=in_pkts,
                        labels={"device_id": device_id, "interface": interface_name},
                        source="device_collector"
                    ),
                    Metric(
                        name="interface_tx_packets",
                        type=MetricType.COUNTER,
                        value=out_pkts,
                        labels={"device_id": device_id, "interface": interface_name},
                        source="device_collector"
                    )
                ])
        except Exception as e:
            logger.error(f"Error parsing Arista interfaces: {e}")

        return metrics


class ServiceMetricCollector(MetricCollector):
    """Service metrics collector."""

    async def collect_from_source(self, source: Dict[str, Any]) -> List[Metric]:
        """Collect metrics from microservice."""
        metrics = []
        service_name = source.get('service')
        endpoint = source.get('metrics_endpoint', '/metrics')

        url = f"https://{source['host']}:{source['port']}{endpoint}"

        async with aiohttp.ClientSession() as session:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=self.timeout)
            ) as response:
                if response.status == 200:
                    data = await response.json()

                    # Parse service-specific metrics
                    for metric_name, value in data.items():
                        metric = Metric(
                            name=f"service_{metric_name}",
                            type=MetricType.GAUGE,
                            value=value,
                            labels={"service": service_name},
                            source="service_collector"
                        )
                        metrics.append(metric)

        return metrics


class LogCollector(MetricCollector):
    """Log collector."""

    def __init__(self):
        super().__init__()
        self.log_sources = []
        self.log_patterns = []
        self.severity_mapping = {
            'DEBUG': LogLevel.DEBUG,
            'INFO': LogLevel.INFO,
            'WARNING': LogLevel.WARNING,
            'ERROR': LogLevel.ERROR,
            'CRITICAL': LogLevel.CRITICAL
        }

    async def collect(self) -> List[LogEntry]:
        """Collect logs from all sources."""
        logs = []

        for source in self.log_sources:
            try:
                source_logs = await self.collect_logs_from_source(source)
                logs.extend(source_logs)
            except Exception as e:
                logger.error(f"Error collecting logs from {source}: {e}")

        return logs

    async def collect_logs_from_source(self, source: Dict[str, Any]) -> List[LogEntry]:
        """Collect logs from a single source."""
        source_type = source.get('type')

        if source_type == 'file':
            return await self._collect_file_logs(source)
        elif source_type == 'syslog':
            return await self._collect_syslog(source)
        elif source_type == 'api':
            return await self._collect_api_logs(source)
        else:
            logger.warning(f"Unknown log source type: {source_type}")
            return []

    async def _collect_file_logs(self, source: Dict[str, Any]) -> List[LogEntry]:
        """Collect logs from file."""
        logs = []
        file_path = source.get('path')
        service = source.get('service', 'unknown')

        # Read and parse log file
        # Implementation would tail the file and parse new entries

        return logs

    async def _collect_syslog(self, source: Dict[str, Any]) -> List[LogEntry]:
        """Collect syslog messages."""
        logs = []
        # Implementation would receive syslog messages
        return logs

    async def _collect_api_logs(self, source: Dict[str, Any]) -> List[LogEntry]:
        """Collect logs via API."""
        logs = []
        url = source.get('url')

        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    for entry in data.get('logs', []):
                        log = LogEntry(
                            timestamp=datetime.fromisoformat(entry['timestamp']),
                            level=self.severity_mapping.get(entry['level'], LogLevel.INFO),
                            service=entry.get('service', 'unknown'),
                            message=entry['message'],
                            metadata=entry.get('metadata', {})
                        )
                        logs.append(log)

        return logs


class TraceCollector(MetricCollector):
    """Distributed tracing collector."""

    def __init__(self):
        super().__init__()
        self.trace_buffer = []
        self.span_buffer = []

    async def collect(self) -> List[Dict[str, Any]]:
        """Collect traces."""
        traces = []

        # Collect from OpenTelemetry or Jaeger
        for source in self.sources:
            source_traces = await self.collect_traces_from_source(source)
            traces.extend(source_traces)

        return traces

    async def collect_traces_from_source(self, source: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Collect traces from source."""
        traces = []

        # Implementation would connect to tracing backend

        return traces


class NetworkMetricCollector(MetricCollector):
    """Network metrics collector."""

    async def collect_from_source(self, source: Dict[str, Any]) -> List[Metric]:
        """Collect network metrics."""
        metrics = []

        # Collect interface statistics
        interface_metrics = await self.collect_interface_metrics(source)
        metrics.extend(interface_metrics)

        # Collect bandwidth utilization
        bandwidth_metrics = await self.collect_bandwidth_metrics(source)
        metrics.extend(bandwidth_metrics)

        # Collect latency metrics
        latency_metrics = await self.collect_latency_metrics(source)
        metrics.extend(latency_metrics)

        return metrics

    async def collect_interface_metrics(self, source: Dict[str, Any]) -> List[Metric]:
        """Collect interface statistics."""
        metrics = []
        # Implementation would query device for interface stats
        return metrics

    async def collect_bandwidth_metrics(self, source: Dict[str, Any]) -> List[Metric]:
        """Collect bandwidth utilization."""
        metrics = []
        # Implementation would calculate bandwidth usage
        return metrics

    async def collect_latency_metrics(self, source: Dict[str, Any]) -> List[Metric]:
        """Collect network latency."""
        metrics = []
        # Implementation would measure latency
        return metrics


class CustomMetricCollector(MetricCollector):
    """Custom metrics collector."""

    def __init__(self):
        super().__init__()
        self.custom_collectors = {}

    def register_collector(self, name: str, collector_func):
        """Register custom collector function."""
        self.custom_collectors[name] = collector_func

    async def collect_from_source(self, source: Dict[str, Any]) -> List[Metric]:
        """Collect custom metrics."""
        collector_name = source.get('collector')

        if collector_name in self.custom_collectors:
            collector_func = self.custom_collectors[collector_name]
            return await collector_func(source)
        else:
            logger.warning(f"Unknown custom collector: {collector_name}")
            return []


class SNMPCollector(MetricCollector):
    """SNMP metrics collector."""

    def __init__(self):
        super().__init__()
        self.snmp_engine = SnmpEngine()
        self.oid_mappings = {
            '1.3.6.1.2.1.1.3.0': 'system_uptime',
            '1.3.6.1.4.1.9.9.109.1.1.1.1.5': 'cisco_cpu_5min',
            '1.3.6.1.4.1.9.9.48.1.1.1.5': 'cisco_memory_used',
            '1.3.6.1.4.1.9.9.48.1.1.1.6': 'cisco_memory_free',
            '1.3.6.1.2.1.2.2.1.10': 'if_in_octets',
            '1.3.6.1.2.1.2.2.1.16': 'if_out_octets',
        }

    async def collect_from_source(self, source: Dict[str, Any]) -> List[Metric]:
        """Collect SNMP metrics."""
        metrics = []
        host = source.get('host')
        port = source.get('port', 161)
        community = source.get('community', 'public')
        version = source.get('version', 2)  # SNMPv2c by default

        for oid, metric_name in self.oid_mappings.items():
            try:
                value = await self._get_snmp_value(
                    host, port, community, oid, version
                )
                if value is not None:
                    metric = Metric(
                        name=f"snmp_{metric_name}",
                        type=MetricType.GAUGE,
                        value=value,
                        labels={"host": host, "oid": oid},
                        source="snmp_collector"
                    )
                    metrics.append(metric)
            except Exception as e:
                logger.error(f"SNMP error for {host}:{oid} - {e}")

        return metrics

    async def _get_snmp_value(
        self,
        host: str,
        port: int,
        community: str,
        oid: str,
        version: int
    ) -> Optional[float]:
        """Get single SNMP value."""
        errorIndication, errorStatus, errorIndex, varBinds = await getCmd(
            self.snmp_engine,
            CommunityData(community, mpModel=version-1),
            UdpTransportTarget((host, port)),
            ContextData(),
            ObjectType(ObjectIdentity(oid))
        )

        if errorIndication:
            logger.error(f"SNMP error: {errorIndication}")
            return None
        elif errorStatus:
            logger.error(f"SNMP error: {errorStatus}")
            return None
        else:
            for varBind in varBinds:
                return float(varBind[1])

        return None

    async def walk_oid(
        self,
        host: str,
        port: int,
        community: str,
        base_oid: str,
        version: int = 2
    ) -> List[tuple]:
        """Walk SNMP OID tree."""
        results = []

        async for errorIndication, errorStatus, errorIndex, varBinds in nextCmd(
            self.snmp_engine,
            CommunityData(community, mpModel=version-1),
            UdpTransportTarget((host, port)),
            ContextData(),
            ObjectType(ObjectIdentity(base_oid))
        ):
            if errorIndication:
                logger.error(f"SNMP walk error: {errorIndication}")
                break
            elif errorStatus:
                logger.error(f"SNMP walk error: {errorStatus}")
                break
            else:
                for varBind in varBinds:
                    results.append((str(varBind[0]), varBind[1]))

        return results


class SyslogCollector:
    """Syslog message collector."""

    def __init__(self, bind_host: str = '0.0.0.0', bind_port: int = 514):
        self.bind_host = bind_host
        self.bind_port = bind_port
        self.socket = None
        self.running = False
        self.message_queue = asyncio.Queue()

    async def start(self):
        """Start syslog collector."""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((self.bind_host, self.bind_port))
        self.socket.setblocking(False)
        self.running = True

        asyncio.create_task(self._receive_messages())

    async def stop(self):
        """Stop syslog collector."""
        self.running = False
        if self.socket:
            self.socket.close()

    async def _receive_messages(self):
        """Receive syslog messages."""
        loop = asyncio.get_event_loop()

        while self.running:
            try:
                data, addr = await loop.sock_recvfrom(self.socket, 1024)
                message = self._parse_syslog_message(data.decode('utf-8'))
                if message:
                    message['source_ip'] = addr[0]
                    await self.message_queue.put(message)
            except Exception as e:
                logger.error(f"Syslog receive error: {e}")
                await asyncio.sleep(1)

    def _parse_syslog_message(self, data: str) -> Optional[Dict[str, Any]]:
        """Parse syslog message."""
        import re

        # Try RFC5424 format first
        rfc5424_pattern = r'^<(\d+)>(\d+) (\S+) (\S+) (\S+) (\S+) (\S+) - (.*)$'
        match = re.match(rfc5424_pattern, data)
        if match:
            return {
                'priority': int(match.group(1)),
                'version': int(match.group(2)),
                'timestamp': match.group(3),
                'hostname': match.group(4),
                'app_name': match.group(5),
                'proc_id': match.group(6),
                'msg_id': match.group(7),
                'message': match.group(8),
                'format': 'RFC5424'
            }

        # Try RFC3164 format
        rfc3164_pattern = r'^<(\d+)>([A-Z][a-z]{2} \d{1,2} \d{2}:\d{2}:\d{2}) (\S+) (\S+)\[(\d+)\]: (.*)$'
        match = re.match(rfc3164_pattern, data)
        if match:
            return {
                'priority': int(match.group(1)),
                'timestamp': match.group(2),
                'hostname': match.group(3),
                'app_name': match.group(4),
                'proc_id': match.group(5),
                'message': match.group(6),
                'format': 'RFC3164'
            }

        # Simple format fallback
        simple_pattern = r'^<(\d+)>(.*)$'
        match = re.match(simple_pattern, data)
        if match:
            return {
                'priority': int(match.group(1)),
                'message': match.group(2),
                'format': 'simple'
            }

        return None

    async def get_messages(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get queued syslog messages."""
        messages = []

        for _ in range(min(limit, self.message_queue.qsize())):
            try:
                message = await asyncio.wait_for(
                    self.message_queue.get(),
                    timeout=0.1
                )
                messages.append(message)
            except asyncio.TimeoutError:
                break

        return messages


class NetflowCollector:
    """Netflow/IPFIX collector."""

    def __init__(self, bind_host: str = '0.0.0.0', bind_port: int = 2055):
        self.bind_host = bind_host
        self.bind_port = bind_port
        self.socket = None
        self.running = False
        self.flow_cache = {}
        self.templates = {}

    async def start(self):
        """Start netflow collector."""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((self.bind_host, self.bind_port))
        self.socket.setblocking(False)
        self.running = True

        asyncio.create_task(self._receive_flows())

    async def stop(self):
        """Stop netflow collector."""
        self.running = False
        if self.socket:
            self.socket.close()

    async def _receive_flows(self):
        """Receive netflow data."""
        loop = asyncio.get_event_loop()

        while self.running:
            try:
                data, addr = await loop.sock_recvfrom(self.socket, 4096)
                flows = self._parse_netflow(data, addr[0])

                for flow in flows:
                    await self._process_flow(flow)

            except Exception as e:
                logger.error(f"Netflow receive error: {e}")
                await asyncio.sleep(1)

    def _parse_netflow(self, data: bytes, source_ip: str) -> List[Dict[str, Any]]:
        """Parse netflow packet."""
        flows = []

        # Parse netflow v5, v9, or IPFIX
        version = struct.unpack('!H', data[:2])[0]

        if version == 5:
            flows = self._parse_netflow_v5(data, source_ip)
        elif version == 9:
            flows = self._parse_netflow_v9(data, source_ip)
        elif version == 10:  # IPFIX
            flows = self._parse_ipfix(data, source_ip)

        return flows

    def _parse_netflow_v5(self, data: bytes, source_ip: str) -> List[Dict[str, Any]]:
        """Parse Netflow v5."""
        flows = []

        # Parse header
        header_fmt = '!HHIIIIBBH'
        header_size = struct.calcsize(header_fmt)
        header = struct.unpack(header_fmt, data[:header_size])

        version, count, sys_uptime, unix_secs, unix_nsecs, flow_seq, engine_type, engine_id, sampling = header

        # Parse flow records
        flow_fmt = '!IIIHHIIIIHHHHHHHBBBBHHBBH'
        flow_size = struct.calcsize(flow_fmt)

        offset = header_size
        for i in range(count):
            if offset + flow_size > len(data):
                break

            flow_data = struct.unpack(flow_fmt, data[offset:offset + flow_size])

            flow = {
                'version': 5,
                'source_ip': socket.inet_ntoa(struct.pack('!I', flow_data[0])),
                'dest_ip': socket.inet_ntoa(struct.pack('!I', flow_data[1])),
                'next_hop': socket.inet_ntoa(struct.pack('!I', flow_data[2])),
                'input_snmp': flow_data[3],
                'output_snmp': flow_data[4],
                'packets': flow_data[5],
                'bytes': flow_data[6],
                'start_time': flow_data[7],
                'end_time': flow_data[8],
                'src_port': flow_data[9],
                'dst_port': flow_data[10],
                'tcp_flags': flow_data[12],
                'protocol': flow_data[13],
                'tos': flow_data[14],
                'src_as': flow_data[15],
                'dst_as': flow_data[16],
                'src_mask': flow_data[17],
                'dst_mask': flow_data[18],
                'exporter': source_ip,
                'timestamp': unix_secs
            }

            flows.append(flow)
            offset += flow_size

        return flows

    def _parse_netflow_v9(self, data: bytes, source_ip: str) -> List[Dict[str, Any]]:
        """Parse Netflow v9."""
        flows = []

        # Parse header
        header_fmt = '!HHIIII'
        header_size = struct.calcsize(header_fmt)
        header = struct.unpack(header_fmt, data[:header_size])

        version, count, sys_uptime, unix_secs, sequence, source_id = header

        offset = header_size

        # Parse flowsets
        while offset < len(data):
            if offset + 4 > len(data):
                break

            flowset_id, flowset_length = struct.unpack('!HH', data[offset:offset+4])

            if flowset_id == 0:  # Template flowset
                # Store templates for later use
                self._parse_v9_template(data[offset:offset+flowset_length], source_id)
            elif flowset_id > 255:  # Data flowset
                # Parse data using stored template
                flowset_flows = self._parse_v9_data(
                    data[offset:offset+flowset_length],
                    flowset_id,
                    source_id,
                    source_ip,
                    unix_secs
                )
                flows.extend(flowset_flows)

            offset += flowset_length

        return flows

    def _parse_v9_template(self, data: bytes, source_id: int):
        """Parse and store Netflow v9 template."""
        if source_id not in self.templates:
            self.templates[source_id] = {}

        offset = 4  # Skip flowset header
        while offset < len(data) - 4:
            template_id, field_count = struct.unpack('!HH', data[offset:offset+4])
            offset += 4

            fields = []
            for i in range(field_count):
                field_type, field_length = struct.unpack('!HH', data[offset:offset+4])
                fields.append({'type': field_type, 'length': field_length})
                offset += 4

            self.templates[source_id][template_id] = fields

    def _parse_v9_data(self, data: bytes, template_id: int, source_id: int, source_ip: str, timestamp: int) -> List[Dict[str, Any]]:
        """Parse Netflow v9 data using template."""
        flows = []

        if source_id not in self.templates or template_id not in self.templates[source_id]:
            return flows

        template = self.templates[source_id][template_id]
        record_size = sum(f['length'] for f in template)

        offset = 4  # Skip flowset header
        while offset + record_size <= len(data):
            flow = {'exporter': source_ip, 'timestamp': timestamp}

            for field in template:
                # Map common field types
                field_mapping = {
                    8: 'source_ip',
                    12: 'dest_ip',
                    7: 'src_port',
                    11: 'dst_port',
                    4: 'protocol',
                    1: 'bytes',
                    2: 'packets'
                }

                field_name = field_mapping.get(field['type'], f"field_{field['type']}")

                if field['length'] == 4:
                    value = struct.unpack('!I', data[offset:offset+4])[0]
                    if field['type'] in [8, 12]:  # IP addresses
                        value = socket.inet_ntoa(struct.pack('!I', value))
                elif field['length'] == 2:
                    value = struct.unpack('!H', data[offset:offset+2])[0]
                elif field['length'] == 1:
                    value = struct.unpack('!B', data[offset:offset+1])[0]
                else:
                    value = data[offset:offset+field['length']].hex()

                flow[field_name] = value
                offset += field['length']

            flows.append(flow)

        return flows

    def _parse_ipfix(self, data: bytes, source_ip: str) -> List[Dict[str, Any]]:
        """Parse IPFIX."""
        flows = []

        # IPFIX is similar to Netflow v9 but with different header
        header_fmt = '!HHIII'
        header_size = struct.calcsize(header_fmt)
        header = struct.unpack(header_fmt, data[:header_size])

        version, length, export_time, sequence, observation_domain = header

        offset = header_size

        # Parse sets (similar to v9 flowsets)
        while offset < length:
            if offset + 4 > len(data):
                break

            set_id, set_length = struct.unpack('!HH', data[offset:offset+4])

            if set_id == 2:  # Template set
                self._parse_ipfix_template(data[offset:offset+set_length], observation_domain)
            elif set_id >= 256:  # Data set
                set_flows = self._parse_ipfix_data(
                    data[offset:offset+set_length],
                    set_id,
                    observation_domain,
                    source_ip,
                    export_time
                )
                flows.extend(set_flows)

            offset += set_length

        return flows

    def _parse_ipfix_template(self, data: bytes, domain: int):
        """Parse IPFIX template."""
        # Similar to v9 template parsing
        if domain not in self.templates:
            self.templates[domain] = {}

        offset = 4
        while offset < len(data) - 4:
            template_id, field_count = struct.unpack('!HH', data[offset:offset+4])
            offset += 4

            fields = []
            for i in range(field_count):
                info_element, field_length = struct.unpack('!HH', data[offset:offset+4])
                fields.append({'element': info_element, 'length': field_length})
                offset += 4

            self.templates[domain][template_id] = fields

    def _parse_ipfix_data(self, data: bytes, template_id: int, domain: int, source_ip: str, timestamp: int) -> List[Dict[str, Any]]:
        """Parse IPFIX data."""
        # Similar to v9 data parsing with IPFIX information elements
        flows = []

        if domain not in self.templates or template_id not in self.templates[domain]:
            return flows

        template = self.templates[domain][template_id]

        offset = 4
        while offset < len(data):
            flow = {'exporter': source_ip, 'export_time': timestamp}

            for field in template:
                # IPFIX information element mappings
                element_mapping = {
                    8: 'source_ipv4',
                    12: 'dest_ipv4',
                    7: 'src_port',
                    11: 'dst_port',
                    4: 'protocol',
                    1: 'bytes',
                    2: 'packets',
                    152: 'flow_start_ms',
                    153: 'flow_end_ms'
                }

                field_name = element_mapping.get(field['element'], f"element_{field['element']}")

                # Parse based on length
                if field['length'] == 4:
                    value = struct.unpack('!I', data[offset:offset+4])[0]
                    if field['element'] in [8, 12]:  # IPv4 addresses
                        value = socket.inet_ntoa(struct.pack('!I', value))
                elif field['length'] == 2:
                    value = struct.unpack('!H', data[offset:offset+2])[0]
                elif field['length'] == 1:
                    value = struct.unpack('!B', data[offset:offset+1])[0]
                elif field['length'] == 8:
                    value = struct.unpack('!Q', data[offset:offset+8])[0]
                else:
                    value = data[offset:offset+field['length']].hex()

                flow[field_name] = value
                offset += field['length']

            flows.append(flow)

        return flows

    async def _process_flow(self, flow: Dict[str, Any]):
        """Process flow record."""
        # Create flow key for aggregation
        flow_key = f"{flow.get('source_ip', '')}:{flow.get('src_port', 0)}-{flow.get('dest_ip', '')}:{flow.get('dst_port', 0)}-{flow.get('protocol', 0)}"

        # Update flow cache
        if flow_key not in self.flow_cache:
            self.flow_cache[flow_key] = {
                'first_seen': datetime.utcnow(),
                'last_seen': datetime.utcnow(),
                'packets': 0,
                'bytes': 0,
                'count': 0
            }

        cache_entry = self.flow_cache[flow_key]
        cache_entry['last_seen'] = datetime.utcnow()
        cache_entry['packets'] += flow.get('packets', 0)
        cache_entry['bytes'] += flow.get('bytes', 0)
        cache_entry['count'] += 1

        # Calculate rate
        duration = (cache_entry['last_seen'] - cache_entry['first_seen']).total_seconds()
        if duration > 0:
            cache_entry['bps'] = (cache_entry['bytes'] * 8) / duration
            cache_entry['pps'] = cache_entry['packets'] / duration

        # Detect anomalies
        if cache_entry.get('bps', 0) > 1000000000:  # > 1 Gbps
            logger.warning(f"High bandwidth flow detected: {flow_key} - {cache_entry['bps'] / 1000000:.2f} Mbps")

        # Clean old entries
        cutoff = datetime.utcnow() - timedelta(minutes=5)
        self.flow_cache = {
            k: v for k, v in self.flow_cache.items()
            if v['last_seen'] > cutoff
        }

    async def get_flow_statistics(self) -> Dict[str, Any]:
        """Get flow statistics."""
        return {
            'total_flows': len(self.flow_cache),
            'top_talkers': self._get_top_talkers(),
            'top_protocols': self._get_top_protocols(),
            'bandwidth_usage': self._calculate_bandwidth()
        }

    def _get_top_talkers(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get top talkers by bandwidth."""
        # Aggregate by source IP
        ip_stats = {}

        for flow_key, stats in self.flow_cache.items():
            # Extract source IP from flow key
            source_ip = flow_key.split(':')[0]

            if source_ip not in ip_stats:
                ip_stats[source_ip] = {'bytes': 0, 'packets': 0, 'flows': 0}

            ip_stats[source_ip]['bytes'] += stats['bytes']
            ip_stats[source_ip]['packets'] += stats['packets']
            ip_stats[source_ip]['flows'] += 1

        # Sort by bytes and return top N
        sorted_ips = sorted(
            ip_stats.items(),
            key=lambda x: x[1]['bytes'],
            reverse=True
        )

        return [
            {
                'ip': ip,
                'bytes': stats['bytes'],
                'packets': stats['packets'],
                'flows': stats['flows']
            }
            for ip, stats in sorted_ips[:limit]
        ]

    def _get_top_protocols(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get top protocols by volume."""
        protocol_stats = {}

        # Protocol number to name mapping
        protocol_names = {
            1: 'ICMP', 6: 'TCP', 17: 'UDP', 47: 'GRE',
            50: 'ESP', 51: 'AH', 89: 'OSPF', 103: 'PIM'
        }

        for flow_key, stats in self.flow_cache.items():
            # Extract protocol from flow key
            parts = flow_key.split('-')
            if len(parts) >= 3:
                protocol = int(parts[-1])
                protocol_name = protocol_names.get(protocol, f"Protocol-{protocol}")

                if protocol_name not in protocol_stats:
                    protocol_stats[protocol_name] = {'bytes': 0, 'packets': 0, 'flows': 0}

                protocol_stats[protocol_name]['bytes'] += stats['bytes']
                protocol_stats[protocol_name]['packets'] += stats['packets']
                protocol_stats[protocol_name]['flows'] += 1

        # Sort by bytes
        sorted_protocols = sorted(
            protocol_stats.items(),
            key=lambda x: x[1]['bytes'],
            reverse=True
        )

        return [
            {
                'protocol': proto,
                'bytes': stats['bytes'],
                'packets': stats['packets'],
                'flows': stats['flows']
            }
            for proto, stats in sorted_protocols[:limit]
        ]

    def _calculate_bandwidth(self) -> Dict[str, float]:
        """Calculate bandwidth usage."""
        total_bytes = sum(stats['bytes'] for stats in self.flow_cache.values())
        total_packets = sum(stats['packets'] for stats in self.flow_cache.values())

        # Calculate rates over last minute
        recent_flows = [
            stats for stats in self.flow_cache.values()
            if stats['last_seen'] > datetime.utcnow() - timedelta(minutes=1)
        ]

        if recent_flows:
            recent_bytes = sum(stats['bytes'] for stats in recent_flows)
            recent_packets = sum(stats['packets'] for stats in recent_flows)

            # Assume data collected over 1 minute
            bps = (recent_bytes * 8) / 60  # bits per second
            pps = recent_packets / 60  # packets per second
        else:
            bps = 0
            pps = 0

        return {
            'total_bytes': total_bytes,
            'total_packets': total_packets,
            'current_bps': bps,
            'current_pps': pps,
            'current_mbps': bps / 1000000,
            'active_flows': len(self.flow_cache)
        }


class StreamTelemetryCollector:
    """Streaming telemetry collector (gRPC/gNMI)."""

    def __init__(self):
        self.subscriptions = []
        self.channels = {}

    async def subscribe(
        self,
        device: str,
        paths: List[str],
        interval: int = 10
    ):
        """Subscribe to telemetry paths."""
        subscription = {
            'device': device,
            'paths': paths,
            'interval': interval,
            'active': True
        }
        self.subscriptions.append(subscription)

        # Start subscription task
        asyncio.create_task(self._handle_subscription(subscription))

    async def _handle_subscription(self, subscription: Dict[str, Any]):
        """Handle telemetry subscription."""
        device = subscription['device']

        while subscription['active']:
            try:
                # Connect to device via gNMI
                data = await self._get_telemetry_data(
                    device,
                    subscription['paths']
                )

                # Process telemetry data
                metrics = self._parse_telemetry_data(data)

                # Store metrics
                for metric in metrics:
                    await self._store_metric(metric)

                await asyncio.sleep(subscription['interval'])

            except Exception as e:
                logger.error(f"Telemetry error for {device}: {e}")
                await asyncio.sleep(60)

    async def _get_telemetry_data(
        self,
        device: str,
        paths: List[str]
    ) -> Dict[str, Any]:
        """Get telemetry data via gNMI."""
        # This would use a gNMI client library
        # Simulated implementation
        telemetry_data = {}

        for path in paths:
            # Simulate fetching data for each path
            if 'interface' in path:
                telemetry_data[path] = {
                    'in_octets': 1234567890,
                    'out_octets': 9876543210,
                    'in_packets': 1234567,
                    'out_packets': 7654321,
                    'operational_status': 'up'
                }
            elif 'cpu' in path:
                telemetry_data[path] = {
                    'usage_percent': 45.2,
                    'temperature': 55.0
                }
            elif 'memory' in path:
                telemetry_data[path] = {
                    'used_bytes': 2147483648,
                    'free_bytes': 2147483648,
                    'usage_percent': 50.0
                }

        return telemetry_data

    def _parse_telemetry_data(self, data: Dict[str, Any]) -> List[Metric]:
        """Parse telemetry data to metrics."""
        metrics = []
        # Implementation would parse gNMI response
        return metrics

    async def _store_metric(self, metric: Metric):
        """Store telemetry metric."""
        # This would store to a time series database like InfluxDB or TimescaleDB
        # For now, just log it
        logger.debug(f"Storing metric: {metric.name} = {metric.value} with labels {metric.labels}")

    async def unsubscribe(self, device: str):
        """Unsubscribe from device telemetry."""
        for sub in self.subscriptions:
            if sub['device'] == device:
                sub['active'] = False


class APIMetricCollector(MetricCollector):
    """API metrics collector for custom integrations."""

    def __init__(self):
        super().__init__()
        self.api_endpoints = {}

    def register_api(
        self,
        name: str,
        url: str,
        method: str = 'GET',
        headers: Optional[Dict] = None,
        auth: Optional[Dict] = None,
        parser: Optional[callable] = None
    ):
        """Register API endpoint for metric collection."""
        self.api_endpoints[name] = {
            'url': url,
            'method': method,
            'headers': headers or {},
            'auth': auth,
            'parser': parser or self._default_parser
        }

    async def collect_from_source(self, source: Dict[str, Any]) -> List[Metric]:
        """Collect metrics from API."""
        api_name = source.get('api')

        if api_name not in self.api_endpoints:
            logger.warning(f"Unknown API: {api_name}")
            return []

        api_config = self.api_endpoints[api_name]
        metrics = []

        async with aiohttp.ClientSession() as session:
            kwargs = {
                'headers': api_config['headers'],
                'timeout': aiohttp.ClientTimeout(total=self.timeout)
            }

            # Add authentication
            if api_config['auth']:
                if api_config['auth']['type'] == 'basic':
                    kwargs['auth'] = aiohttp.BasicAuth(
                        api_config['auth']['username'],
                        api_config['auth']['password']
                    )
                elif api_config['auth']['type'] == 'bearer':
                    kwargs['headers']['Authorization'] = f"Bearer {api_config['auth']['token']}"

            # Make request
            async with session.request(
                api_config['method'],
                api_config['url'],
                **kwargs
            ) as response:
                if response.status == 200:
                    data = await response.json()

                    # Parse response to metrics
                    parser = api_config['parser']
                    metrics = parser(data, source)

        return metrics

    def _default_parser(self, data: Dict[str, Any], source: Dict[str, Any]) -> List[Metric]:
        """Default API response parser."""
        metrics = []

        # Flatten nested dict and create metrics
        def flatten_dict(d, parent_key=''):
            items = []
            for k, v in d.items():
                new_key = f"{parent_key}.{k}" if parent_key else k
                if isinstance(v, dict):
                    items.extend(flatten_dict(v, new_key).items())
                elif isinstance(v, (int, float)):
                    items.append((new_key, v))
            return dict(items)

        flat_data = flatten_dict(data)

        for key, value in flat_data.items():
            metric = Metric(
                name=f"api_{key}",
                type=MetricType.GAUGE,
                value=value,
                labels={"api": source.get('api', 'unknown')},
                source="api_collector"
            )
            metrics.append(metric)

        return metrics
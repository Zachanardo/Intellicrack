"""
Network Behavior Analyzer - Advanced network activity monitoring and analysis.

This module provides comprehensive network behavior analysis for detecting
license server communications, C&C channels, and suspicious network patterns.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellicrack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack.  If not, see <https://www.gnu.org/licenses/>.
"""

import asyncio
import base64
import json
import psutil
import re
import socket
import ssl
import struct
import threading
import time
import urllib.parse
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from ipaddress import ip_address, ip_network
from typing import Any, Dict, List, Optional, Set, Tuple
import logging

try:
    import dpkt
    import pcap
    PACKET_CAPTURE_AVAILABLE = True
except ImportError:
    PACKET_CAPTURE_AVAILABLE = False

try:
    import dns.resolver
    import dns.reversename
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

from intellicrack.logger import logger


class NetworkEventType(Enum):
    """Types of network events."""
    CONNECTION_ESTABLISHED = auto()
    CONNECTION_CLOSED = auto()
    DNS_QUERY = auto()
    HTTP_REQUEST = auto()
    HTTPS_REQUEST = auto()
    SSL_HANDSHAKE = auto()
    DATA_TRANSFER = auto()
    SUSPICIOUS_TRAFFIC = auto()


class ProtocolType(Enum):
    """Network protocol types."""
    TCP = auto()
    UDP = auto()
    HTTP = auto()
    HTTPS = auto()
    DNS = auto()
    ICMP = auto()
    UNKNOWN = auto()


@dataclass
class NetworkConnection:
    """Represents a network connection."""
    process_id: int
    local_addr: str
    local_port: int
    remote_addr: str
    remote_port: int
    protocol: ProtocolType
    status: str
    start_time: float
    end_time: Optional[float] = None
    bytes_sent: int = 0
    bytes_received: int = 0
    packets_sent: int = 0
    packets_received: int = 0
    is_encrypted: bool = False
    ssl_info: Optional[Dict[str, Any]] = None
    http_requests: List[Dict[str, Any]] = field(default_factory=list)
    dns_queries: List[str] = field(default_factory=list)


@dataclass
class NetworkEvent:
    """Represents a network event."""
    timestamp: float
    event_type: NetworkEventType
    process_id: int
    connection: Optional[NetworkConnection] = None
    details: Dict[str, Any] = field(default_factory=dict)
    raw_data: Optional[bytes] = None
    confidence: float = 1.0
    tags: Set[str] = field(default_factory=set)


@dataclass
class LicenseServerProfile:
    """Profile of potential license server."""
    hostname: str
    ip_addresses: Set[str]
    ports: Set[int]
    protocols: Set[str]
    request_patterns: List[str]
    response_patterns: List[str]
    certificate_info: Optional[Dict[str, Any]] = None
    confidence_score: float = 0.0
    first_seen: float = 0.0
    last_seen: float = 0.0
    connection_count: int = 0


class NetworkBehaviorAnalyzer:
    """
    Advanced network behavior analyzer for security research.
    
    This analyzer monitors network activity to detect license server
    communications, command & control channels, and suspicious patterns.
    """

    def __init__(self, target_processes: Optional[List[int]] = None):
        """
        Initialize network behavior analyzer.
        
        Args:
            target_processes: Optional list of process IDs to monitor
        """
        self.target_processes = target_processes or []
        self.logger = logging.getLogger(__name__)
        
        # Monitoring state
        self.is_monitoring = False
        self.monitoring_threads: List[threading.Thread] = []
        self.stop_event = threading.Event()
        
        # Data storage
        self.connections: Dict[str, NetworkConnection] = {}
        self.events: deque = deque(maxlen=10000)
        self.dns_cache: Dict[str, Dict[str, Any]] = {}
        self.license_servers: Dict[str, LicenseServerProfile] = {}
        
        # Pattern detection
        self.license_patterns = self._load_license_patterns()
        self.suspicious_patterns = self._load_suspicious_patterns()
        
        # Network monitoring
        self.packet_capture: Optional[Any] = None
        self.connection_monitor: Optional[threading.Thread] = None
        
        # Performance settings
        self.analysis_interval = 2.0
        self.packet_buffer_size = 1000
        
        # Initialize components
        self._initialize_network_monitoring()

    def _initialize_network_monitoring(self):
        """Initialize network monitoring components."""
        try:
            # Initialize packet capture if available
            if PACKET_CAPTURE_AVAILABLE:
                self._initialize_packet_capture()
            
            # Initialize DNS monitoring
            if DNS_AVAILABLE:
                self._initialize_dns_monitoring()
            
            self.logger.info("Network behavior analyzer initialized")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize network monitoring: {e}")

    def _initialize_packet_capture(self):
        """Initialize packet capture for deep inspection."""
        try:
            # Find suitable network interface
            interfaces = pcap.findalldevs()
            
            if interfaces:
                # Use first available interface
                self.capture_interface = interfaces[0]
                self.logger.info(f"Packet capture initialized on interface: {self.capture_interface}")
            else:
                self.logger.warning("No network interfaces found for packet capture")
                
        except Exception as e:
            self.logger.error(f"Failed to initialize packet capture: {e}")

    def _initialize_dns_monitoring(self):
        """Initialize DNS query monitoring."""
        try:
            # Set up DNS resolver
            self.dns_resolver = dns.resolver.Resolver()
            self.dns_resolver.timeout = 5.0
            self.dns_resolver.lifetime = 10.0
            
            self.logger.info("DNS monitoring initialized")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize DNS monitoring: {e}")

    def start_monitoring(self) -> bool:
        """
        Start network behavior monitoring.
        
        Returns:
            True if monitoring started successfully
        """
        if self.is_monitoring:
            self.logger.warning("Network monitoring already active")
            return True

        try:
            self.stop_event.clear()
            self.is_monitoring = True
            
            # Start connection monitoring
            self._start_connection_monitoring()
            
            # Start packet capture if available
            if PACKET_CAPTURE_AVAILABLE:
                self._start_packet_capture()
            
            # Start DNS monitoring
            self._start_dns_monitoring()
            
            # Start analysis thread
            analysis_thread = threading.Thread(
                target=self._analysis_loop,
                daemon=True
            )
            analysis_thread.start()
            self.monitoring_threads.append(analysis_thread)
            
            self.logger.info("Network behavior monitoring started")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to start network monitoring: {e}")
            self.is_monitoring = False
            return False

    def stop_monitoring(self) -> Dict[str, Any]:
        """
        Stop network monitoring and return results.
        
        Returns:
            Dictionary containing analysis results
        """
        if not self.is_monitoring:
            return self._get_current_results()

        try:
            self.stop_event.set()
            self.is_monitoring = False
            
            # Wait for threads to finish
            for thread in self.monitoring_threads:
                if thread.is_alive():
                    thread.join(timeout=5.0)
            
            # Stop packet capture
            if self.packet_capture:
                try:
                    self.packet_capture.close()
                except:
                    pass
            
            results = self._get_current_results()
            self.logger.info("Network behavior monitoring stopped")
            
            return results
            
        except Exception as e:
            self.logger.error(f"Error stopping network monitoring: {e}")
            return self._get_current_results()

    def _start_connection_monitoring(self):
        """Start monitoring network connections."""
        def monitor_connections():
            """Monitor network connections for target processes."""
            try:
                last_connections = set()
                
                while not self.stop_event.is_set():
                    current_connections = set()
                    
                    # Get all network connections
                    for conn in psutil.net_connections(kind='inet'):
                        try:
                            # Filter by target processes if specified
                            if self.target_processes and conn.pid not in self.target_processes:
                                continue
                            
                            if conn.status == 'ESTABLISHED' and conn.raddr:
                                conn_key = f"{conn.pid}:{conn.laddr.ip}:{conn.laddr.port}->{conn.raddr.ip}:{conn.raddr.port}"
                                current_connections.add((conn_key, conn))
                                
                                # Check if this is a new connection
                                if conn_key not in self.connections:
                                    self._handle_new_connection(conn)
                                else:
                                    self._update_existing_connection(conn_key, conn)
                                    
                        except (AttributeError, psutil.AccessDenied):
                            continue
                    
                    # Detect closed connections
                    current_keys = {key for key, _ in current_connections}
                    closed_connections = set(self.connections.keys()) - current_keys
                    
                    for conn_key in closed_connections:
                        self._handle_connection_closed(conn_key)
                    
                    time.sleep(1.0)  # Check every second
                    
            except Exception as e:
                self.logger.error(f"Error in connection monitoring: {e}")
        
        thread = threading.Thread(target=monitor_connections, daemon=True)
        thread.start()
        self.monitoring_threads.append(thread)

    def _handle_new_connection(self, conn):
        """Handle new network connection."""
        try:
            conn_key = f"{conn.pid}:{conn.laddr.ip}:{conn.laddr.port}->{conn.raddr.ip}:{conn.raddr.port}"
            
            # Determine protocol
            protocol = ProtocolType.TCP if conn.type == socket.SOCK_STREAM else ProtocolType.UDP
            
            # Classify connection type
            if conn.raddr.port in [80, 8080]:
                protocol = ProtocolType.HTTP
            elif conn.raddr.port in [443, 8443]:
                protocol = ProtocolType.HTTPS
            elif conn.raddr.port == 53:
                protocol = ProtocolType.DNS
            
            connection = NetworkConnection(
                process_id=conn.pid,
                local_addr=conn.laddr.ip,
                local_port=conn.laddr.port,
                remote_addr=conn.raddr.ip,
                remote_port=conn.raddr.port,
                protocol=protocol,
                status=conn.status,
                start_time=time.time(),
                is_encrypted=(protocol == ProtocolType.HTTPS)
            )
            
            self.connections[conn_key] = connection
            
            # Create connection event
            event = NetworkEvent(
                timestamp=time.time(),
                event_type=NetworkEventType.CONNECTION_ESTABLISHED,
                process_id=conn.pid,
                connection=connection,
                details={
                    'remote_host': conn.raddr.ip,
                    'remote_port': conn.raddr.port,
                    'protocol': protocol.name
                }
            )
            
            # Analyze for license server patterns
            if self._is_potential_license_server(connection):
                event.tags.add('license_server')
                event.confidence = 0.8
            
            # Check for suspicious patterns
            if self._is_suspicious_connection(connection):
                event.tags.add('suspicious')
                event.confidence = 0.9
            
            self.events.append(event)
            
            # Resolve hostname if possible
            self._resolve_hostname_async(conn.raddr.ip, conn_key)
            
        except Exception as e:
            self.logger.error(f"Error handling new connection: {e}")

    def _handle_connection_closed(self, conn_key: str):
        """Handle closed network connection."""
        try:
            if conn_key in self.connections:
                connection = self.connections[conn_key]
                connection.end_time = time.time()
                
                event = NetworkEvent(
                    timestamp=time.time(),
                    event_type=NetworkEventType.CONNECTION_CLOSED,
                    process_id=connection.process_id,
                    connection=connection,
                    details={
                        'duration': connection.end_time - connection.start_time,
                        'bytes_sent': connection.bytes_sent,
                        'bytes_received': connection.bytes_received
                    }
                )
                
                self.events.append(event)
                
                # Keep connection for analysis but mark as closed
                connection.status = 'CLOSED'
                
        except Exception as e:
            self.logger.error(f"Error handling connection close: {e}")

    def _update_existing_connection(self, conn_key: str, conn):
        """Update existing connection with current statistics."""
        try:
            if conn_key in self.connections:
                connection = self.connections[conn_key]
                
                # Update connection statistics if available
                # Note: psutil doesn't provide byte counts, would need packet capture
                connection.status = conn.status
                
        except Exception as e:
            self.logger.error(f"Error updating connection: {e}")

    def _start_packet_capture(self):
        """Start packet capture for deep inspection."""
        if not PACKET_CAPTURE_AVAILABLE:
            return
        
        def capture_packets():
            """Capture and analyze network packets."""
            try:
                # Initialize packet capture
                pc = pcap.pcap(name=self.capture_interface, promisc=True, immediate=True)
                pc.setfilter('tcp or udp')
                
                self.packet_capture = pc
                
                for timestamp, raw_packet in pc:
                    if self.stop_event.is_set():
                        break
                    
                    try:
                        self._analyze_packet(timestamp, raw_packet)
                    except Exception as e:
                        self.logger.debug(f"Error analyzing packet: {e}")
                        
            except Exception as e:
                self.logger.error(f"Error in packet capture: {e}")
        
        thread = threading.Thread(target=capture_packets, daemon=True)
        thread.start()
        self.monitoring_threads.append(thread)

    def _analyze_packet(self, timestamp: float, raw_packet: bytes):
        """Analyze captured network packet."""
        try:
            # Parse Ethernet frame
            eth = dpkt.ethernet.Ethernet(raw_packet)
            
            # Check if IP packet
            if not isinstance(eth.data, dpkt.ip.IP):
                return
            
            ip = eth.data
            src_ip = socket.inet_ntoa(ip.src)
            dst_ip = socket.inet_ntoa(ip.dst)
            
            # Analyze based on protocol
            if isinstance(ip.data, dpkt.tcp.TCP):
                self._analyze_tcp_packet(timestamp, ip, src_ip, dst_ip)
            elif isinstance(ip.data, dpkt.udp.UDP):
                self._analyze_udp_packet(timestamp, ip, src_ip, dst_ip)
                
        except Exception as e:
            self.logger.debug(f"Error parsing packet: {e}")

    def _analyze_tcp_packet(self, timestamp: float, ip, src_ip: str, dst_ip: str):
        """Analyze TCP packet."""
        try:
            tcp = ip.data
            src_port = tcp.sport
            dst_port = tcp.dport
            
            # Check for HTTP traffic
            if dst_port in [80, 8080] or src_port in [80, 8080]:
                self._analyze_http_traffic(timestamp, tcp.data, src_ip, dst_ip, src_port, dst_port)
            
            # Check for HTTPS traffic
            elif dst_port in [443, 8443] or src_port in [443, 8443]:
                self._analyze_https_traffic(timestamp, tcp.data, src_ip, dst_ip, src_port, dst_port)
            
            # Check for other protocols
            else:
                self._analyze_generic_tcp(timestamp, tcp.data, src_ip, dst_ip, src_port, dst_port)
                
        except Exception as e:
            self.logger.debug(f"Error analyzing TCP packet: {e}")

    def _analyze_http_traffic(self, timestamp: float, data: bytes, src_ip: str, dst_ip: str, src_port: int, dst_port: int):
        """Analyze HTTP traffic."""
        try:
            if not data:
                return
            
            # Try to parse HTTP request/response
            try:
                http_data = data.decode('utf-8', errors='ignore')
                
                # Check for HTTP request
                if http_data.startswith(('GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS')):
                    self._process_http_request(timestamp, http_data, src_ip, dst_ip, dst_port)
                
                # Check for HTTP response
                elif http_data.startswith('HTTP/'):
                    self._process_http_response(timestamp, http_data, src_ip, dst_ip, src_port)
                    
            except UnicodeDecodeError:
                # Binary data, skip
                pass
                
        except Exception as e:
            self.logger.debug(f"Error analyzing HTTP traffic: {e}")

    def _process_http_request(self, timestamp: float, http_data: str, src_ip: str, dst_ip: str, dst_port: int):
        """Process HTTP request."""
        try:
            lines = http_data.split('\r\n')
            if not lines:
                return
            
            # Parse request line
            request_parts = lines[0].split(' ', 2)
            if len(request_parts) >= 3:
                method = request_parts[0]
                path = request_parts[1]
                version = request_parts[2]
                
                # Parse headers
                headers = {}
                for line in lines[1:]:
                    if ':' in line:
                        key, value = line.split(':', 1)
                        headers[key.strip().lower()] = value.strip()
                
                # Create HTTP request event
                event = NetworkEvent(
                    timestamp=timestamp,
                    event_type=NetworkEventType.HTTP_REQUEST,
                    process_id=0,  # Would need to correlate with connection
                    details={
                        'method': method,
                        'path': path,
                        'host': headers.get('host', dst_ip),
                        'user_agent': headers.get('user-agent', ''),
                        'headers': headers
                    }
                )
                
                # Check for license-related patterns
                if self._is_license_related_http(method, path, headers):
                    event.tags.add('license')
                    event.confidence = 0.9
                
                self.events.append(event)
                
        except Exception as e:
            self.logger.debug(f"Error processing HTTP request: {e}")

    def _analyze_https_traffic(self, timestamp: float, data: bytes, src_ip: str, dst_ip: str, src_port: int, dst_port: int):
        """Analyze HTTPS traffic (TLS inspection)."""
        try:
            if not data or len(data) < 5:
                return
            
            # Check for TLS handshake
            if data[0] == 0x16:  # TLS Handshake
                self._analyze_tls_handshake(timestamp, data, src_ip, dst_ip, dst_port)
                
        except Exception as e:
            self.logger.debug(f"Error analyzing HTTPS traffic: {e}")

    def _analyze_tls_handshake(self, timestamp: float, data: bytes, src_ip: str, dst_ip: str, dst_port: int):
        """Analyze TLS handshake for certificate information."""
        try:
            # Basic TLS parsing - would need more sophisticated parser for full analysis
            if len(data) > 43 and data[5] == 0x01:  # Client Hello
                # Extract SNI if present
                sni = self._extract_sni_from_client_hello(data)
                
                if sni:
                    event = NetworkEvent(
                        timestamp=timestamp,
                        event_type=NetworkEventType.SSL_HANDSHAKE,
                        process_id=0,
                        details={
                            'server_name': sni,
                            'destination_ip': dst_ip,
                            'destination_port': dst_port
                        }
                    )
                    
                    # Check if SNI suggests license server
                    if self._is_license_server_hostname(sni):
                        event.tags.add('license_server')
                        event.confidence = 0.85
                    
                    self.events.append(event)
                    
        except Exception as e:
            self.logger.debug(f"Error analyzing TLS handshake: {e}")

    def _extract_sni_from_client_hello(self, data: bytes) -> Optional[str]:
        """Extract Server Name Indication from TLS Client Hello."""
        try:
            # Simplified SNI extraction - production code would need full TLS parser
            offset = 43  # Skip to extensions
            
            if len(data) <= offset:
                return None
            
            # Look for SNI extension (type 0x0000)
            while offset < len(data) - 4:
                if data[offset:offset+2] == b'\x00\x00':  # SNI extension type
                    # Extract server name
                    length = struct.unpack('>H', data[offset+2:offset+4])[0]
                    if offset + 4 + length <= len(data):
                        sni_data = data[offset+4:offset+4+length]
                        if len(sni_data) > 5:
                            name_length = struct.unpack('>H', sni_data[3:5])[0]
                            if 5 + name_length <= len(sni_data):
                                return sni_data[5:5+name_length].decode('utf-8', errors='ignore')
                offset += 1
            
            return None
            
        except Exception as e:
            self.logger.debug(f"Error extracting SNI: {e}")
            return None

    def _start_dns_monitoring(self):
        """Start DNS query monitoring."""
        def monitor_dns():
            """Monitor DNS queries."""
            try:
                while not self.stop_event.is_set():
                    # Monitor DNS connections
                    for conn in psutil.net_connections(kind='inet'):
                        try:
                            if (conn.raddr and conn.raddr.port == 53 and 
                                (not self.target_processes or conn.pid in self.target_processes)):
                                
                                # Record DNS query
                                event = NetworkEvent(
                                    timestamp=time.time(),
                                    event_type=NetworkEventType.DNS_QUERY,
                                    process_id=conn.pid,
                                    details={
                                        'dns_server': conn.raddr.ip,
                                        'local_port': conn.laddr.port
                                    }
                                )
                                
                                self.events.append(event)
                                
                        except (AttributeError, psutil.AccessDenied):
                            continue
                    
                    time.sleep(2.0)  # Check every 2 seconds
                    
            except Exception as e:
                self.logger.error(f"Error in DNS monitoring: {e}")
        
        thread = threading.Thread(target=monitor_dns, daemon=True)
        thread.start()
        self.monitoring_threads.append(thread)

    def _analysis_loop(self):
        """Main analysis loop for pattern detection."""
        try:
            while not self.stop_event.is_set():
                # Perform periodic analysis
                self._analyze_license_server_patterns()
                self._analyze_suspicious_patterns()
                self._update_server_profiles()
                
                time.sleep(self.analysis_interval)
                
        except Exception as e:
            self.logger.error(f"Error in analysis loop: {e}")

    def _analyze_license_server_patterns(self):
        """Analyze patterns to identify license servers."""
        try:
            # Group events by destination
            destination_events = defaultdict(list)
            
            for event in list(self.events):
                if event.connection:
                    dest_key = f"{event.connection.remote_addr}:{event.connection.remote_port}"
                    destination_events[dest_key].append(event)
            
            # Analyze each destination for license server patterns
            for dest_key, events in destination_events.items():
                if len(events) >= 3:  # Minimum events for pattern analysis
                    self._evaluate_license_server_candidate(dest_key, events)
                    
        except Exception as e:
            self.logger.error(f"Error analyzing license server patterns: {e}")

    def _evaluate_license_server_candidate(self, dest_key: str, events: List[NetworkEvent]):
        """Evaluate if destination is likely a license server."""
        try:
            ip, port = dest_key.split(':')
            port = int(port)
            
            # Calculate confidence score
            confidence_score = 0.0
            
            # Check for license-related tags
            license_events = [e for e in events if 'license' in e.tags]
            if license_events:
                confidence_score += 0.4
            
            # Check for HTTPS traffic (license servers often use encryption)
            https_events = [e for e in events if e.connection and e.connection.protocol == ProtocolType.HTTPS]
            if https_events:
                confidence_score += 0.2
            
            # Check for periodic communication patterns
            if self._has_periodic_pattern(events):
                confidence_score += 0.3
            
            # Check for specific ports commonly used by license servers
            if port in [443, 80, 7070, 8080, 8443, 9000, 27000]:
                confidence_score += 0.1
            
            # Update or create server profile
            if confidence_score > 0.3:
                hostname = self._resolve_hostname(ip)
                
                if hostname not in self.license_servers:
                    self.license_servers[hostname] = LicenseServerProfile(
                        hostname=hostname,
                        ip_addresses={ip},
                        ports={port},
                        protocols=set(),
                        request_patterns=[],
                        response_patterns=[],
                        confidence_score=confidence_score,
                        first_seen=min(e.timestamp for e in events),
                        last_seen=max(e.timestamp for e in events),
                        connection_count=len(events)
                    )
                else:
                    profile = self.license_servers[hostname]
                    profile.ip_addresses.add(ip)
                    profile.ports.add(port)
                    profile.confidence_score = max(profile.confidence_score, confidence_score)
                    profile.last_seen = max(profile.last_seen, max(e.timestamp for e in events))
                    profile.connection_count += len(events)
                    
        except Exception as e:
            self.logger.error(f"Error evaluating license server candidate: {e}")

    def _has_periodic_pattern(self, events: List[NetworkEvent]) -> bool:
        """Check if events show periodic communication pattern."""
        try:
            if len(events) < 5:
                return False
            
            # Sort events by timestamp
            sorted_events = sorted(events, key=lambda e: e.timestamp)
            
            # Calculate intervals between events
            intervals = []
            for i in range(1, len(sorted_events)):
                interval = sorted_events[i].timestamp - sorted_events[i-1].timestamp
                intervals.append(interval)
            
            # Check for consistent intervals (license checks often periodic)
            if intervals:
                avg_interval = sum(intervals) / len(intervals)
                consistent_intervals = sum(1 for i in intervals if abs(i - avg_interval) < avg_interval * 0.3)
                
                # If 70% of intervals are consistent, consider it periodic
                return consistent_intervals / len(intervals) > 0.7
            
            return False
            
        except Exception as e:
            self.logger.debug(f"Error checking periodic pattern: {e}")
            return False

    def _resolve_hostname_async(self, ip: str, conn_key: str):
        """Asynchronously resolve hostname for IP address."""
        def resolve():
            try:
                hostname = self._resolve_hostname(ip)
                if hostname != ip and conn_key in self.connections:
                    # Update connection with hostname information
                    self.connections[conn_key].details = {'hostname': hostname}
                    
            except Exception as e:
                self.logger.debug(f"Error resolving hostname for {ip}: {e}")
        
        threading.Thread(target=resolve, daemon=True).start()

    def _resolve_hostname(self, ip: str) -> str:
        """Resolve hostname for IP address."""
        try:
            if ip in self.dns_cache:
                cache_entry = self.dns_cache[ip]
                if time.time() - cache_entry['timestamp'] < 3600:  # 1-hour cache
                    return cache_entry['hostname']
            
            # Perform reverse DNS lookup
            import socket
            hostname = socket.gethostbyaddr(ip)[0]
            
            # Cache result
            self.dns_cache[ip] = {
                'hostname': hostname,
                'timestamp': time.time()
            }
            
            return hostname
            
        except Exception:
            return ip  # Return IP if resolution fails

    def _is_potential_license_server(self, connection: NetworkConnection) -> bool:
        """Check if connection is potentially to a license server."""
        try:
            # Check common license server ports
            license_ports = [7070, 8080, 9000, 27000, 443, 80]
            if connection.remote_port in license_ports:
                return True
            
            # Check for HTTPS on non-standard ports (often license servers)
            if connection.protocol == ProtocolType.HTTPS and connection.remote_port not in [443, 8443]:
                return True
            
            # Check IP ranges commonly used by license services
            # (This would be enhanced with actual known license server ranges)
            try:
                ip = ip_address(connection.remote_addr)
                # Example: Some commercial license servers use specific ranges
                commercial_ranges = [
                    ip_network('172.16.0.0/12'),  # Private range often used
                    ip_network('10.0.0.0/8'),    # Private range
                ]
                
                for network in commercial_ranges:
                    if ip in network:
                        return True
                        
            except Exception:
                pass
            
            return False
            
        except Exception as e:
            self.logger.debug(f"Error checking license server potential: {e}")
            return False

    def _is_suspicious_connection(self, connection: NetworkConnection) -> bool:
        """Check if connection appears suspicious."""
        try:
            # Check for suspicious ports
            suspicious_ports = [1337, 31337, 4444, 5555, 6666, 666]
            if connection.remote_port in suspicious_ports:
                return True
            
            # Check for non-standard protocols on standard ports
            if (connection.remote_port == 80 and connection.protocol != ProtocolType.HTTP):
                return True
            
            # Check for connections to suspicious IP ranges
            try:
                ip = ip_address(connection.remote_addr)
                
                # Check for connections to Tor exit nodes (simplified check)
                # In production, this would use updated Tor exit node lists
                if str(ip).startswith('127.'):  # Example placeholder
                    return True
                    
            except Exception:
                pass
            
            return False
            
        except Exception as e:
            self.logger.debug(f"Error checking suspicious connection: {e}")
            return False

    def _is_license_related_http(self, method: str, path: str, headers: Dict[str, str]) -> bool:
        """Check if HTTP request is license-related."""
        try:
            # Check path for license keywords
            license_keywords = ['license', 'activation', 'validate', 'auth', 'register', 'trial']
            path_lower = path.lower()
            
            if any(keyword in path_lower for keyword in license_keywords):
                return True
            
            # Check User-Agent for license-related software
            user_agent = headers.get('user-agent', '').lower()
            license_agents = ['license', 'activation', 'flexlm', 'rlm']
            
            if any(agent in user_agent for agent in license_agents):
                return True
            
            # Check for specific API endpoints
            api_patterns = [
                r'/api/v\d+/license',
                r'/license/check',
                r'/activation/',
                r'/validate'
            ]
            
            for pattern in api_patterns:
                if re.search(pattern, path_lower):
                    return True
            
            return False
            
        except Exception as e:
            self.logger.debug(f"Error checking license-related HTTP: {e}")
            return False

    def _is_license_server_hostname(self, hostname: str) -> bool:
        """Check if hostname suggests a license server."""
        try:
            hostname_lower = hostname.lower()
            
            # Common license server hostname patterns
            patterns = [
                'license',
                'activation',
                'auth',
                'validate',
                'flexlm',
                'rlm',
                'sentinel',
                'hasp',
                'dongle'
            ]
            
            return any(pattern in hostname_lower for pattern in patterns)
            
        except Exception as e:
            self.logger.debug(f"Error checking license server hostname: {e}")
            return False

    def _load_license_patterns(self) -> List[Dict[str, Any]]:
        """Load license-related network patterns."""
        return [
            {
                'name': 'flexlm_communication',
                'description': 'FlexLM license manager communication',
                'port_ranges': [(27000, 27009)],
                'protocols': ['TCP'],
                'patterns': [b'FLEXLM', b'INCREMENT', b'FEATURE']
            },
            {
                'name': 'rlm_communication',
                'description': 'RLM license manager communication',
                'port_ranges': [(5053, 5053)],
                'protocols': ['TCP', 'UDP'],
                'patterns': [b'RLM', b'license']
            },
            {
                'name': 'sentinel_hasp',
                'description': 'Sentinel HASP license protection',
                'port_ranges': [(1947, 1947), (475, 475)],
                'protocols': ['TCP', 'UDP'],
                'patterns': [b'HASP', b'Sentinel']
            },
            {
                'name': 'software_activation',
                'description': 'Generic software activation',
                'port_ranges': [(80, 80), (443, 443)],
                'protocols': ['HTTP', 'HTTPS'],
                'patterns': [b'activation', b'validate', b'license']
            }
        ]

    def _load_suspicious_patterns(self) -> List[Dict[str, Any]]:
        """Load suspicious network patterns."""
        return [
            {
                'name': 'reverse_shell',
                'description': 'Potential reverse shell connection',
                'port_ranges': [(4444, 4444), (1337, 1337), (31337, 31337)],
                'protocols': ['TCP'],
                'severity': 'high'
            },
            {
                'name': 'c2_communication',
                'description': 'Command and control communication',
                'port_ranges': [(80, 80), (443, 443), (8080, 8080)],
                'protocols': ['HTTP', 'HTTPS'],
                'patterns': [b'cmd=', b'exec=', b'shell='],
                'severity': 'critical'
            }
        ]

    def get_license_server_report(self) -> Dict[str, Any]:
        """Generate comprehensive license server analysis report."""
        try:
            report = {
                'detected_servers': [],
                'communication_patterns': [],
                'suspicious_activity': [],
                'statistics': {}
            }
            
            # Compile detected license servers
            for hostname, profile in self.license_servers.items():
                server_info = {
                    'hostname': hostname,
                    'ip_addresses': list(profile.ip_addresses),
                    'ports': list(profile.ports),
                    'confidence_score': profile.confidence_score,
                    'first_seen': datetime.fromtimestamp(profile.first_seen).isoformat(),
                    'last_seen': datetime.fromtimestamp(profile.last_seen).isoformat(),
                    'connection_count': profile.connection_count,
                    'classification': self._classify_license_server(profile)
                }
                report['detected_servers'].append(server_info)
            
            # Analyze communication patterns
            license_events = [e for e in self.events if 'license' in e.tags]
            if license_events:
                pattern_analysis = self._analyze_communication_patterns(license_events)
                report['communication_patterns'] = pattern_analysis
            
            # Compile statistics
            total_connections = len(self.connections)
            license_connections = len([c for c in self.connections.values() 
                                     if any('license' in tag for tag in getattr(c, 'tags', []))])
            
            report['statistics'] = {
                'total_connections': total_connections,
                'license_related_connections': license_connections,
                'unique_remote_hosts': len(set(c.remote_addr for c in self.connections.values())),
                'monitoring_duration': max(e.timestamp for e in self.events) - min(e.timestamp for e in self.events) if self.events else 0
            }
            
            return report
            
        except Exception as e:
            self.logger.error(f"Error generating license server report: {e}")
            return {}

    def _classify_license_server(self, profile: LicenseServerProfile) -> str:
        """Classify type of license server based on profile."""
        try:
            # Check for known license manager patterns
            if any(port in [27000, 27001, 27002] for port in profile.ports):
                return 'FlexLM'
            elif 5053 in profile.ports:
                return 'RLM'
            elif 1947 in profile.ports or 475 in profile.ports:
                return 'Sentinel HASP'
            elif any(port in [80, 443, 8080, 8443] for port in profile.ports):
                return 'Web-based Activation'
            else:
                return 'Unknown'
                
        except Exception:
            return 'Unknown'

    def _analyze_communication_patterns(self, events: List[NetworkEvent]) -> List[Dict[str, Any]]:
        """Analyze communication patterns in license-related events."""
        patterns = []
        
        try:
            # Group events by connection
            connection_events = defaultdict(list)
            for event in events:
                if event.connection:
                    conn_key = f"{event.connection.remote_addr}:{event.connection.remote_port}"
                    connection_events[conn_key].append(event)
            
            # Analyze each connection's pattern
            for conn_key, conn_events in connection_events.items():
                if len(conn_events) >= 3:
                    pattern = {
                        'connection': conn_key,
                        'event_count': len(conn_events),
                        'time_span': max(e.timestamp for e in conn_events) - min(e.timestamp for e in conn_events),
                        'is_periodic': self._has_periodic_pattern(conn_events),
                        'event_types': list(set(e.event_type.name for e in conn_events))
                    }
                    patterns.append(pattern)
            
        except Exception as e:
            self.logger.error(f"Error analyzing communication patterns: {e}")
        
        return patterns

    def _get_current_results(self) -> Dict[str, Any]:
        """Get current analysis results."""
        try:
            return {
                'connections': {
                    'total': len(self.connections),
                    'active': len([c for c in self.connections.values() if c.status != 'CLOSED']),
                    'license_related': len([c for c in self.connections.values() 
                                          if any('license' in str(getattr(c, 'tags', [])))])
                },
                'events': {
                    'total': len(self.events),
                    'by_type': dict(defaultdict(int, 
                        [(e.event_type.name, 1) for e in self.events]
                    ))
                },
                'license_servers': len(self.license_servers),
                'dns_cache_size': len(self.dns_cache),
                'monitoring_active': self.is_monitoring
            }
            
        except Exception as e:
            self.logger.error(f"Error getting current results: {e}")
            return {}
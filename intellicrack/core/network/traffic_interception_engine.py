"""
Traffic Interception Engine for Real License Server Communications

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

import logging
import os
import socket
import struct
import sys
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple

try:
    import scapy.all as scapy
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

try:
    import pcap
    HAS_PCAP = True
except ImportError:
    HAS_PCAP = False

try:
    import netfilterqueue
    HAS_NETFILTER = True
except ImportError:
    HAS_NETFILTER = False


@dataclass
class InterceptedPacket:
    """Container for intercepted network packet data"""
    source_ip: str
    dest_ip: str
    source_port: int
    dest_port: int
    protocol: str
    data: bytes
    timestamp: float
    packet_size: int
    flags: Dict[str, bool]

    def __post_init__(self):
        """Initialize flags if not provided"""
        if not self.flags:
            self.flags = {'syn': False, 'ack': False, 'fin': False, 'rst': False}


@dataclass
class AnalyzedTraffic:
    """Container for analyzed traffic data"""
    packet: InterceptedPacket
    is_license_related: bool
    protocol_type: str
    confidence: float
    patterns_matched: List[str]
    analysis_metadata: Dict[str, Any]

from .base_network_analyzer import BaseNetworkAnalyzer


class TrafficInterceptionEngine(BaseNetworkAnalyzer):
    """
    Real-time traffic interception engine for license server communications.
    
    This engine intercepts actual network traffic to and from license servers,
    analyzes the protocols, and enables real-time response generation.
    """

    def __init__(self, bind_interface: str = "127.0.0.1"):
        """
        Initialize the traffic interception engine.
        
        Args:
            bind_interface: Network interface to bind to
        """
        super().__init__()
        self.logger = logging.getLogger("IntellicrackLogger.TrafficEngine")
        self.bind_interface = bind_interface
        self.running = False

        # Statistics
        self.stats = {
            'packets_captured': 0,
            'license_packets_detected': 0,
            'protocols_detected': set(),
            'total_bytes': 0,
            'start_time': None
        }

        # Configuration
        self.capture_config = {
            'promiscuous_mode': False,
            'buffer_size': 65536,
            'timeout_ms': 100,
            'filter_expression': None
        }

        # Protocol patterns for license detection
        self.license_patterns = {
            'flexlm': [
                b'VENDOR_STRING',
                b'FEATURE',
                b'INCREMENT',
                b'SERVER',
                b'HOSTID',
                b'SIGN='
            ],
            'hasp': [
                b'hasp',
                b'HASP',
                b'sentinel',
                b'SENTINEL',
                b'Aladdin'
            ],
            'adobe': [
                b'adobe',
                b'ADOBE',
                b'lcsap',
                b'LCSAP',
                b'activation',
                b'serial'
            ],
            'autodesk': [
                b'adsk',
                b'ADSK',
                b'autodesk',
                b'AUTODESK',
                b'AdskNetworkLicenseManager'
            ],
            'microsoft': [
                b'kms',
                b'KMS',
                b'microsoft',
                b'MICROSOFT',
                b'activation'
            ],
            'generic_license': [
                b'license',
                b'LICENSE',
                b'activation',
                b'ACTIVATION',
                b'checkout',
                b'CHECKOUT',
                b'verify',
                b'VERIFY'
            ]
        }

        # Known license server ports
        self.license_ports = {
            27000, 27001, 27002, 27003, 27004, 27005, 27006, 27007, 27008, 27009,  # FlexLM
            1947,  # HASP/Sentinel
            443, 80, 8080, 8443,  # HTTPS/HTTP license servers
            1688,  # Microsoft KMS
            2080,  # Autodesk Network License Manager
            7788, 7789  # Other common license ports
        }

        # Active connections tracking
        self.active_connections: Dict[str, Dict[str, Any]] = {}
        self.connection_lock = threading.Lock()

        # Analysis callbacks
        self.analysis_callbacks: List[Callable[[AnalyzedTraffic], None]] = []

        # Transparent proxy settings
        self.proxy_mappings: Dict[str, Tuple[str, int]] = {}
        self.dns_redirections: Dict[str, str] = {}

        # Threading
        self.capture_thread: Optional[threading.Thread] = None
        self.analysis_thread: Optional[threading.Thread] = None
        self.packet_queue: List[InterceptedPacket] = []
        self.queue_lock = threading.Lock()

        # Initialize capture backend
        self.capture_backend = self._initialize_capture_backend()
    def _initialize_capture_backend(self) -> str:
        """Initialize the best available packet capture backend"""
        # Check platform and available libraries
        if sys.platform == "win32":
            if HAS_SCAPY:
                self.logger.info("Using Scapy for Windows packet capture")
                return "scapy"
            else:
                self.logger.warning("Scapy not available, using socket-based capture")
                return "socket"
        elif sys.platform.startswith("linux"):
            # Check if running as root (geteuid only available on Unix-like systems)
            is_root = hasattr(os, 'geteuid') and os.geteuid() == 0  # pylint: disable=no-member
            if HAS_SCAPY and is_root:
                self.logger.info("Using Scapy for Linux packet capture (root required)")
                return "scapy"
            elif HAS_PCAP:
                self.logger.info("Using libpcap for packet capture")
                return "pcap"
            else:
                self.logger.warning("Limited capture capabilities, using socket-based capture")
                return "socket"
        else:
            if HAS_SCAPY:
                self.logger.info("Using Scapy for packet capture")
                return "scapy"
            else:
                self.logger.warning("Using socket-based capture")
                return "socket"

    def start_interception(self, ports: List[int] = None) -> bool:
        """
        Start traffic interception on specified ports.
        
        Args:
            ports: List of ports to monitor, or None for all license ports
            
        Returns:
            bool: True if started successfully
        """
        try:
            if self.running:
                self.logger.warning("Traffic interception already running")
                return True

            if ports:
                self.license_ports.update(ports)

            self.running = True
            self.stats['start_time'] = time.time()

            # Start capture thread
            self.capture_thread = threading.Thread(
                target=self._capture_loop,
                daemon=True
            )
            self.capture_thread.start()

            # Start analysis thread
            self.analysis_thread = threading.Thread(
                target=self._analysis_loop,
                daemon=True
            )
            self.analysis_thread.start()

            self.logger.info(f"Traffic interception started using {self.capture_backend} backend")
            self.logger.info(f"Monitoring {len(self.license_ports)} license server ports")

            return True

        except Exception as e:
            self.logger.error(f"Failed to start traffic interception: {e}")
            self.running = False
            return False

    def stop_interception(self) -> bool:
        """Stop traffic interception"""
        try:
            self.running = False

            # Wait for threads to finish
            if self.capture_thread and self.capture_thread.is_alive():
                self.capture_thread.join(timeout=5.0)

            if self.analysis_thread and self.analysis_thread.is_alive():
                self.analysis_thread.join(timeout=5.0)

            self.logger.info("Traffic interception stopped")
            return True

        except Exception as e:
            self.logger.error(f"Error stopping traffic interception: {e}")
            return False

    def _capture_loop(self):
        """Main packet capture loop"""
        try:
            if self.capture_backend == "scapy":
                self._scapy_capture()
            elif self.capture_backend == "pcap":
                self._pcap_capture()
            else:
                self._socket_capture()

        except Exception as e:
            self.logger.error(f"Capture loop error: {e}")

    def _scapy_capture(self):
        """Packet capture using Scapy"""
        if not HAS_SCAPY:
            return

        try:
            # Build filter for license server ports
            port_filter = " or ".join([f"port {port}" for port in self.license_ports])
            filter_expr = f"tcp and ({port_filter})"

            self.logger.info(f"Starting Scapy capture with filter: {filter_expr}")

            # Define packet processing function
            def process_license_packet(packet, IP, TCP):
                """Process packets for license interception."""
                if TCP in packet:
                        tcp_layer = packet[TCP]
                        ip_layer = packet[IP]

                        # Extract packet data
                        intercepted = InterceptedPacket(
                            source_ip=ip_layer.src,
                            dest_ip=ip_layer.dst,
                            source_port=tcp_layer.sport,
                            dest_port=tcp_layer.dport,
                            protocol='tcp',
                            data=bytes(tcp_layer.payload) if tcp_layer.payload else b'',
                            timestamp=time.time(),
                            packet_size=len(packet),
                            flags={
                                'syn': bool(tcp_layer.flags & 0x02),
                                'ack': bool(tcp_layer.flags & 0x10),
                                'fin': bool(tcp_layer.flags & 0x01),
                                'rst': bool(tcp_layer.flags & 0x04)
                            }
                        )

                        self._queue_packet(intercepted)

            # Create packet handler using base class
            packet_handler = self.create_packet_handler(
                scapy,
                lambda: self.running,
                process_license_packet
            )

            # Start capture
            scapy.sniff(
                filter=filter_expr,
                prn=packet_handler,
                stop_filter=lambda x: not self.running,
                timeout=1
            )

        except Exception as e:
            self.logger.error(f"Scapy capture error: {e}")
    def _pcap_capture(self):
        """Packet capture using libpcap"""
        if not HAS_PCAP:
            return

        try:
            # Create pcap handle
            pc = pcap.pcap(
                name=None,  # Default interface
                promisc=self.capture_config['promiscuous_mode'],
                immediate=True,
                timeout_ms=self.capture_config['timeout_ms']
            )

            # Build filter
            port_filter = " or ".join([f"port {port}" for port in self.license_ports])
            filter_expr = f"tcp and ({port_filter})"
            pc.setfilter(filter_expr)

            self.logger.info(f"Starting libpcap capture with filter: {filter_expr}")

            for timestamp, raw_packet in pc:
                if not self.running:
                    break

                try:
                    # Parse Ethernet header (14 bytes)
                    if len(raw_packet) < 14:
                        continue

                    eth_header = raw_packet[:14]
                    eth_protocol = struct.unpack('!H', eth_header[12:14])[0]

                    # Check for IPv4 (0x0800)
                    if eth_protocol != 0x0800:
                        continue

                    # Parse IP header
                    ip_header = raw_packet[14:34]
                    if len(ip_header) < 20:
                        continue

                    ip_data = struct.unpack('!BBHHHBBH4s4s', ip_header)
                    protocol = ip_data[6]

                    # Check for TCP (6)
                    if protocol != 6:
                        continue

                    source_ip = socket.inet_ntoa(ip_data[8])
                    dest_ip = socket.inet_ntoa(ip_data[9])

                    # Parse TCP header
                    tcp_header = raw_packet[34:54]
                    if len(tcp_header) < 20:
                        continue

                    tcp_data = struct.unpack('!HHLLBBHHH', tcp_header)
                    source_port = tcp_data[0]
                    dest_port = tcp_data[1]
                    flags = tcp_data[5]

                    # Extract payload
                    tcp_header_length = (tcp_data[4] >> 4) * 4
                    payload_start = 34 + tcp_header_length
                    payload = raw_packet[payload_start:] if payload_start < len(raw_packet) else b''

                    # Create intercepted packet
                    intercepted = InterceptedPacket(
                        source_ip=source_ip,
                        dest_ip=dest_ip,
                        source_port=source_port,
                        dest_port=dest_port,
                        protocol='tcp',
                        data=payload,
                        timestamp=timestamp,
                        packet_size=len(raw_packet),
                        flags={
                            'syn': bool(flags & 0x02),
                            'ack': bool(flags & 0x10),
                            'fin': bool(flags & 0x01),
                            'rst': bool(flags & 0x04)
                        }
                    )

                    self._queue_packet(intercepted)

                except Exception as e:
                    self.logger.debug(f"Error processing packet: {e}")

        except Exception as e:
            self.logger.error(f"libpcap capture error: {e}")

    def _socket_capture(self):
        """Basic socket-based capture for localhost traffic"""
        try:
            # Create raw socket for local traffic monitoring
            if sys.platform == "win32":
                # Windows raw socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
                sock.bind((self.bind_interface, 0))
                sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            else:
                # Unix raw socket (requires root)
                try:
                    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
                except (AttributeError, OSError):
                    # Fallback to standard socket monitoring
                    self._monitor_local_connections()
                    return

            self.logger.info("Starting socket-based capture")

            while self.running:
                try:
                    raw_packet = sock.recv(65535)
                    self._parse_raw_packet(raw_packet)

                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        self.logger.debug(f"Socket capture error: {e}")

            if sys.platform == "win32":
                sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            sock.close()

        except Exception as e:
            self.logger.warning(f"Raw socket capture failed, using connection monitoring: {e}")
            self._monitor_local_connections()
    def _monitor_local_connections(self):
        """Monitor local connections when raw sockets aren't available"""
        self.logger.info("Monitoring localhost connections for license traffic")

        while self.running:
            try:
                # Monitor connections to license server ports
                for port in self.license_ports:
                    try:
                        # Attempt connection to detect active servers
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(0.1)
                        result = sock.connect_ex((self.bind_interface, port))

                        if result == 0:
                            # Port is open, there's a license server
                            connection_key = f"{self.bind_interface}:{port}"

                            with self.connection_lock:
                                if connection_key not in self.active_connections:
                                    self.active_connections[connection_key] = {
                                        'first_seen': time.time(),
                                        'last_activity': time.time(),
                                        'packet_count': 0
                                    }

                                    self.logger.info(f"License server detected on port {port}")

                        sock.close()

                    except Exception:
                        pass

                time.sleep(1.0)

            except Exception as e:
                self.logger.debug(f"Connection monitoring error: {e}")

    def _parse_raw_packet(self, raw_packet: bytes):
        """Parse raw network packet"""
        try:
            if len(raw_packet) < 20:
                return

            # Parse IP header
            ip_header = struct.unpack('!BBHHHBBH4s4s', raw_packet[:20])
            protocol = ip_header[6]

            # Only process TCP packets
            if protocol != 6:
                return

            source_ip = socket.inet_ntoa(ip_header[8])
            dest_ip = socket.inet_ntoa(ip_header[9])

            # Parse TCP header
            if len(raw_packet) < 40:
                return

            tcp_header = struct.unpack('!HHLLBBHHH', raw_packet[20:40])
            source_port = tcp_header[0]
            dest_port = tcp_header[1]
            flags = tcp_header[5]

            # Check if this is license server traffic
            if dest_port not in self.license_ports and source_port not in self.license_ports:
                return

            # Extract payload
            tcp_header_length = (tcp_header[4] >> 4) * 4
            payload_start = 20 + tcp_header_length
            payload = raw_packet[payload_start:] if payload_start < len(raw_packet) else b''

            # Create intercepted packet
            intercepted = InterceptedPacket(
                source_ip=source_ip,
                dest_ip=dest_ip,
                source_port=source_port,
                dest_port=dest_port,
                protocol='tcp',
                data=payload,
                timestamp=time.time(),
                packet_size=len(raw_packet),
                flags={
                    'syn': bool(flags & 0x02),
                    'ack': bool(flags & 0x10),
                    'fin': bool(flags & 0x01),
                    'rst': bool(flags & 0x04)
                }
            )

            self._queue_packet(intercepted)

        except Exception as e:
            self.logger.debug(f"Error parsing packet: {e}")

    def _queue_packet(self, packet: InterceptedPacket):
        """Add packet to analysis queue"""
        with self.queue_lock:
            self.packet_queue.append(packet)

            # Update statistics
            self.stats['packets_captured'] += 1
            self.stats['total_bytes'] += packet.packet_size

            # Limit queue size
            if len(self.packet_queue) > 10000:
                self.packet_queue.pop(0)
    def _analysis_loop(self):
        """Main packet analysis loop"""
        while self.running:
            try:
                packets_to_analyze = []

                with self.queue_lock:
                    if self.packet_queue:
                        packets_to_analyze = self.packet_queue.copy()
                        self.packet_queue.clear()

                for packet in packets_to_analyze:
                    analysis = self._analyze_packet(packet)
                    if analysis:
                        # Call analysis callbacks
                        for callback in self.analysis_callbacks:
                            try:
                                callback(analysis)
                            except Exception as e:
                                self.logger.error(f"Analysis callback error: {e}")

                time.sleep(0.1)

            except Exception as e:
                self.logger.error(f"Analysis loop error: {e}")

    def _analyze_packet(self, packet: InterceptedPacket) -> Optional[AnalyzedTraffic]:
        """Analyze packet for license-related content"""
        try:
            is_license_related = False
            protocol_type = "unknown"
            confidence = 0.0
            patterns_matched = []

            # Check if packet has data
            if not packet.data:
                return None

            # Check port-based detection
            if packet.dest_port in self.license_ports or packet.source_port in self.license_ports:
                confidence += 0.3
                is_license_related = True

            # Pattern matching
            for proto, patterns in self.license_patterns.items():
                matches = 0
                for pattern in patterns:
                    if pattern in packet.data:
                        matches += 1
                        patterns_matched.append(pattern.decode('utf-8', errors='ignore'))

                if matches > 0:
                    pattern_confidence = min(matches / len(patterns), 1.0) * 0.7
                    if pattern_confidence > confidence:
                        confidence = pattern_confidence
                        protocol_type = proto
                        is_license_related = True

            # Additional heuristics
            if packet.data:
                data_lower = packet.data.lower()

                # Look for license-related keywords
                license_keywords = [b'license', b'activation', b'checkout', b'verify', b'serial']
                keyword_matches = sum(1 for keyword in license_keywords if keyword in data_lower)

                if keyword_matches > 0:
                    confidence += min(keyword_matches * 0.1, 0.3)
                    is_license_related = True

            # Only return analysis if confidence is high enough
            if confidence < 0.2:
                return None

            # Update statistics
            if is_license_related:
                self.stats['license_packets_detected'] += 1
                self.stats['protocols_detected'].add(protocol_type)

            analysis_metadata = {
                'keywords_found': patterns_matched,
                'port_based_detection': packet.dest_port in self.license_ports or packet.source_port in self.license_ports,
                'data_size': len(packet.data),
                'connection_flags': packet.flags
            }

            return AnalyzedTraffic(
                packet=packet,
                is_license_related=is_license_related,
                protocol_type=protocol_type,
                confidence=confidence,
                patterns_matched=patterns_matched,
                analysis_metadata=analysis_metadata
            )

        except Exception as e:
            self.logger.error(f"Packet analysis error: {e}")
            return None

    def add_analysis_callback(self, callback: Callable[[AnalyzedTraffic], None]):
        """Add callback for analyzed traffic"""
        self.analysis_callbacks.append(callback)

    def remove_analysis_callback(self, callback: Callable[[AnalyzedTraffic], None]):
        """Remove analysis callback"""
        if callback in self.analysis_callbacks:
            self.analysis_callbacks.remove(callback)

    def set_dns_redirection(self, hostname: str, target_ip: str) -> bool:
        """Setup DNS redirection for hostname"""
        try:
            self.dns_redirections[hostname.lower()] = target_ip
            self.logger.info(f"DNS redirection setup: {hostname} -> {target_ip}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to setup DNS redirection: {e}")
            return False

    def setup_transparent_proxy(self, target_host: str, target_port: int) -> bool:
        """Setup transparent proxy for target server"""
        try:
            proxy_key = f"{target_host}:{target_port}"
            self.proxy_mappings[proxy_key] = (self.bind_interface, target_port)
            self.logger.info(f"Transparent proxy setup: {proxy_key} -> {self.bind_interface}:{target_port}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to setup transparent proxy: {e}")
            return False

    def get_statistics(self) -> Dict[str, Any]:
        """Get traffic interception statistics"""
        current_time = time.time()
        uptime = current_time - self.stats['start_time'] if self.stats['start_time'] else 0

        stats = self.stats.copy()
        stats['protocols_detected'] = list(stats['protocols_detected'])
        stats['uptime_seconds'] = uptime
        stats['packets_per_second'] = stats['packets_captured'] / max(uptime, 1)
        stats['active_connections'] = len(self.active_connections)
        stats['capture_backend'] = self.capture_backend
        stats['dns_redirections'] = len(self.dns_redirections)
        stats['proxy_mappings'] = len(self.proxy_mappings)

        return stats

    def get_active_connections(self) -> List[Dict[str, Any]]:
        """Get list of active connections"""
        connections = []
        current_time = time.time()

        with self.connection_lock:
            for connection_key, info in self.active_connections.items():
                connections.append({
                    'endpoint': connection_key,
                    'duration': current_time - info['first_seen'],
                    'last_activity': info['last_activity'],
                    'packet_count': info['packet_count']
                })

        return connections


__all__ = ['TrafficInterceptionEngine', 'InterceptedPacket', 'AnalyzedTraffic']

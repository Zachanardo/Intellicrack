"""Traffic interception engine for capturing and analyzing network traffic."""

import logging
import os
import socket
import struct
import sys
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from intellicrack.utils.logger import logger

from .base_network_analyzer import BaseNetworkAnalyzer


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
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""


try:
    import scapy.all as scapy

    HAS_SCAPY = True
except ImportError as e:
    logger.exception("Import error in traffic_interception_engine: %s", e)
    HAS_SCAPY = False

# Note: Removed pcap import - now using Scapy exclusively for packet capture
# Legacy pcap support removed in favor of superior Scapy implementation


@dataclass
class InterceptedPacket:
    """Container for intercepted network packet data."""

    source_ip: str
    dest_ip: str
    source_port: int
    dest_port: int
    protocol: str
    data: bytes
    timestamp: float
    packet_size: int
    flags: dict[str, bool]

    def __post_init__(self) -> None:
        """Initialize flags if not provided.

        Ensures the flags dictionary is properly initialized with default
        TCP flag values when not explicitly set during dataclass construction.

        """
        if not self.flags:
            self.flags = {"syn": False, "ack": False, "fin": False, "rst": False}


@dataclass
class AnalyzedTraffic:
    """Container for analyzed traffic data."""

    packet: InterceptedPacket
    is_license_related: bool
    protocol_type: str
    confidence: float
    patterns_matched: list[str]
    analysis_metadata: dict[str, Any]


class TrafficInterceptionEngine(BaseNetworkAnalyzer):
    """Real-time traffic interception engine for license server communications.

    This engine intercepts actual network traffic to and from license servers,
    analyzes the protocols, and enables real-time response generation.
    """

    def __init__(self, bind_interface: str | None = None) -> None:
        """Initialize the traffic interception engine.

        Args:
            bind_interface: Network interface to bind to

        """
        super().__init__()
        self.logger = logging.getLogger("IntellicrackLogger.TrafficEngine")

        # Use configuration for bind interface
        if bind_interface is None:
            # Lazy import to avoid circular dependency
            from intellicrack.utils.service_utils import get_service_url

            proxy_url = get_service_url("proxy_server")
            bind_interface = proxy_url.replace("http://", "").replace("https://", "").split(":")[0]

        self.bind_interface = bind_interface
        self.running = False

        # Statistics
        self.stats: dict[str, Any] = {
            "packets_captured": 0,
            "license_packets_detected": 0,
            "protocols_detected": set(),
            "total_bytes": 0,
            "start_time": None,
        }

        # Configuration
        self.capture_config = {
            "promiscuous_mode": False,
            "buffer_size": 65536,
            "timeout_ms": 100,
            "filter_expression": None,
        }

        # Protocol patterns for license detection
        self.license_patterns = {
            "flexlm": [
                b"VENDOR_STRING",
                b"FEATURE",
                b"INCREMENT",
                b"SERVER",
                b"HOSTID",
                b"SIGN=",
            ],
            "hasp": [
                b"hasp",
                b"HASP",
                b"sentinel",
                b"SENTINEL",
                b"Aladdin",
            ],
            "adobe": [
                b"adobe",
                b"ADOBE",
                b"lcsap",
                b"LCSAP",
                b"activation",
                b"serial",
            ],
            "autodesk": [
                b"adsk",
                b"ADSK",
                b"autodesk",
                b"AUTODESK",
                b"AdskNetworkLicenseManager",
            ],
            "microsoft": [
                b"kms",
                b"KMS",
                b"microsoft",
                b"MICROSOFT",
                b"activation",
            ],
            "generic_license": [
                b"license",
                b"LICENSE",
                b"activation",
                b"ACTIVATION",
                b"checkout",
                b"CHECKOUT",
                b"verify",
                b"VERIFY",
            ],
        }

        # Known license server ports
        self.license_ports = {
            27000,
            27001,
            27002,
            27003,
            27004,
            27005,
            27006,
            27007,
            27008,
            27009,  # FlexLM
            1947,  # HASP/Sentinel
            443,
            80,
            8080,
            8443,  # HTTPS/HTTP license servers
            1688,  # Microsoft KMS
            2080,  # Autodesk Network License Manager
            7788,
            7789,  # Other common license ports
        }

        # Active connections tracking
        self.active_connections: dict[str, dict[str, Any]] = {}
        self.connection_lock = threading.Lock()

        # Analysis callbacks
        self.analysis_callbacks: list[Callable[[AnalyzedTraffic], None]] = []

        # Transparent proxy settings
        self.proxy_mappings: dict[str, tuple[str, int]] = {}
        self.dns_redirections: dict[str, str] = {}

        # Threading
        self.capture_thread: threading.Thread | None = None
        self.analysis_thread: threading.Thread | None = None
        self.packet_queue: list[InterceptedPacket] = []
        self.queue_lock = threading.Lock()

        # Initialize capture backend
        self.capture_backend = self._initialize_capture_backend()

    def _initialize_capture_backend(self) -> str:
        """Initialize the best available packet capture backend.

        Detects the operating system and available dependencies to select
        the most appropriate packet capture implementation.

        Returns:
            str: Name of the selected capture backend ('scapy' or 'socket')

        """
        # Check platform and available libraries
        if sys.platform == "win32":
            if HAS_SCAPY:
                self.logger.info("Using Scapy for Windows packet capture")
                return "scapy"
            self.logger.warning("Scapy not available, using socket-based capture")
            return "socket"
        elif sys.platform.startswith("linux"):
            # Check if running as root (geteuid only available on Unix-like systems)
            is_root = hasattr(os, "geteuid") and os.geteuid() == 0  # pylint: disable=no-member
            if HAS_SCAPY and is_root:
                self.logger.info("Using Scapy for Linux packet capture (root required)")
                return "scapy"
            # Note: libpcap support removed - using Scapy for all packet capture
            self.logger.warning("Limited capture capabilities, using socket-based capture")
            return "socket"
        else:
            # Default for other platforms
            if HAS_SCAPY:
                self.logger.info("Using Scapy for packet capture")
                return "scapy"
            self.logger.warning("Using socket-based capture")
            return "socket"

    def start_interception(self, ports: list[int] | None = None) -> bool:
        """Start traffic interception on specified ports.

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
            self.stats["start_time"] = time.time()

            # Start capture thread
            self.capture_thread = threading.Thread(
                target=self._capture_loop,
                daemon=True,
            )
            self.capture_thread.start()

            # Start analysis thread
            self.analysis_thread = threading.Thread(
                target=self._analysis_loop,
                daemon=True,
            )
            self.analysis_thread.start()

            self.logger.info("Traffic interception started using %s backend", self.capture_backend)
            self.logger.info("Monitoring %d license server ports", len(self.license_ports))

            return True

        except Exception as e:
            self.logger.exception("Failed to start traffic interception: %s", e)
            self.running = False
            return False

    def stop_interception(self) -> bool:
        """Stop traffic interception.

        Gracefully halts all packet capture and analysis threads,
        cleaning up resources.

        Returns:
            bool: True if stopped successfully, False otherwise

        """
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
            self.logger.exception("Error stopping traffic interception: %s", e)
            return False

    def _capture_loop(self) -> None:
        """Run main packet capture loop.

        Orchestrates packet capture by delegating to the appropriate backend
        (Scapy or raw socket) based on the system configuration. Handles
        exceptions and continues loop execution.

        """
        try:
            if self.capture_backend == "scapy":
                self._scapy_capture()
            # Note: pcap backend removed - using Scapy exclusively
            else:
                self._socket_capture()

        except Exception as e:
            self.logger.exception("Capture loop error: %s", e)

    def _scapy_capture(self) -> None:
        """Capture network packets using Scapy library.

        Implements packet capture using the Scapy library with filtering for
        license server ports. Processes captured packets and queues them for
        analysis.

        """
        if not HAS_SCAPY:
            return

        try:
            # Build filter for license server ports
            port_filter = " or ".join([f"port {port}" for port in self.license_ports])
            filter_expr = f"tcp and ({port_filter})"

            self.logger.info("Starting Scapy capture with filter: %s", filter_expr)

            # Define packet processing function
            def process_license_packet(packet: Any, IP: Any, TCP: Any) -> None:
                """Process packets for license interception.

                Extracts license-related information from intercepted TCP packets
                and queues them for analysis.

                Args:
                    packet: Scapy packet object containing network data
                    IP: Scapy IP layer class for packet inspection
                    TCP: Scapy TCP layer class for packet inspection

                """
                if hasattr(packet, "__contains__") and TCP in packet:
                    tcp_layer = packet[TCP]
                    ip_layer = packet[IP]

                    # Extract packet data with safe attribute access
                    packet_data = bytes(tcp_layer.payload) if hasattr(tcp_layer, "payload") and tcp_layer.payload else b""
                    packet_len = len(packet) if hasattr(packet, "__len__") else 0

                    intercepted = InterceptedPacket(
                        source_ip=str(ip_layer.src),
                        dest_ip=str(ip_layer.dst),
                        source_port=int(tcp_layer.sport),
                        dest_port=int(tcp_layer.dport),
                        protocol="tcp",
                        data=packet_data,
                        timestamp=time.time(),
                        packet_size=packet_len,
                        flags={
                            "syn": bool(tcp_layer.flags & 0x02),
                            "ack": bool(tcp_layer.flags & 0x10),
                            "fin": bool(tcp_layer.flags & 0x01),
                            "rst": bool(tcp_layer.flags & 0x04),
                        },
                    )

                    self._queue_packet(intercepted)

            # Create packet handler using base class
            packet_handler = self.create_packet_handler(
                scapy,
                lambda: self.running,
                process_license_packet,
            )

            # Start capture
            def stop_filter_fn(x: Any) -> bool:
                """Stop filter function for scapy sniff.

                Determines whether to continue packet capture based on
                the engine's running state.

                Args:
                    x: Packet object from Scapy sniff

                Returns:
                    bool: True to stop sniffing, False to continue

                """
                logger.debug("Packet in stop_filter: %s", x)
                return not self.running

            scapy.sniff(
                filter=filter_expr,
                prn=packet_handler,
                stop_filter=stop_filter_fn,
                timeout=1,
            )

        except Exception as e:
            self.logger.exception("Scapy capture error: %s", e)

    # Note: _pcap_capture method removed - now using Scapy exclusively for packet capture
    # This provides better cross-platform compatibility and enhanced features

    def _socket_capture(self) -> None:
        """Capture network traffic using raw sockets.

        Establishes a raw socket for packet capture on Windows or Unix-like
        systems. Falls back to connection monitoring if raw socket access
        is not available.

        """
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
                except (AttributeError, OSError) as e:
                    self.logger.exception("Error in traffic_interception_engine: %s", e)
                    # Fallback to standard socket monitoring
                    self._monitor_local_connections()
                    return

            self.logger.info("Starting socket-based capture")

            while self.running:
                try:
                    raw_packet = sock.recv(65535)
                    self._parse_raw_packet(raw_packet)

                except TimeoutError as e:
                    logger.exception("socket.timeout in traffic_interception_engine: %s", e)
                    continue
                except Exception as e:
                    if self.running:
                        self.logger.debug("Socket capture error: %s", e)

            if sys.platform == "win32":
                sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            sock.close()

        except Exception as e:
            self.logger.warning("Raw socket capture failed, using connection monitoring: %s", e)
            self._monitor_local_connections()

    def _monitor_local_connections(self) -> None:
        """Monitor local connections when raw sockets are unavailable.

        Fallback monitoring mechanism that periodically checks for open
        connections on license server ports using socket connection attempts.

        """
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
                                        "first_seen": time.time(),
                                        "last_activity": time.time(),
                                        "packet_count": 0,
                                    }

                                    self.logger.info("License server detected on port %d", port)

                        sock.close()

                    except Exception as e:
                        logger.exception("Exception in traffic_interception_engine: %s", e)

                time.sleep(1.0)

            except Exception as e:
                self.logger.debug("Connection monitoring error: %s", e)

    def _parse_raw_packet(self, raw_packet: bytes) -> None:
        """Parse raw network packet.

        Extracts IP and TCP headers from raw socket data and creates
        InterceptedPacket objects for license-related traffic.

        Args:
            raw_packet: Raw packet bytes from socket recv()

        Raises:
            Exception: Logs debug messages for parsing errors, continues
                on failure.

        """
        try:
            if len(raw_packet) < 20:
                return

            # Parse IP header
            ip_header = struct.unpack("!BBHHHBBH4s4s", raw_packet[:20])
            protocol = ip_header[6]

            # Only process TCP packets
            if protocol != 6:
                return

            source_ip = socket.inet_ntoa(ip_header[8])
            dest_ip = socket.inet_ntoa(ip_header[9])

            # Parse TCP header
            if len(raw_packet) < 40:
                return

            tcp_header = struct.unpack("!HHLLBBHHH", raw_packet[20:40])
            source_port = tcp_header[0]
            dest_port = tcp_header[1]
            flags = tcp_header[5]

            # Check if this is license server traffic
            if dest_port not in self.license_ports and source_port not in self.license_ports:
                return

            # Extract payload
            tcp_header_length = (tcp_header[4] >> 4) * 4
            payload_start = 20 + tcp_header_length
            payload = raw_packet[payload_start:] if payload_start < len(raw_packet) else b""

            # Create intercepted packet
            intercepted = InterceptedPacket(
                source_ip=source_ip,
                dest_ip=dest_ip,
                source_port=source_port,
                dest_port=dest_port,
                protocol="tcp",
                data=payload,
                timestamp=time.time(),
                packet_size=len(raw_packet),
                flags={
                    "syn": bool(flags & 0x02),
                    "ack": bool(flags & 0x10),
                    "fin": bool(flags & 0x01),
                    "rst": bool(flags & 0x04),
                },
            )

            self._queue_packet(intercepted)

        except Exception as e:
            self.logger.debug("Error parsing packet: %s", e)

    def _queue_packet(self, packet: InterceptedPacket) -> None:
        """Add packet to analysis queue.

        Thread-safely appends packets to the analysis queue and updates
        packet capture statistics. Maintains a maximum queue size of 10000
        packets.

        Args:
            packet: InterceptedPacket object to queue for analysis

        """
        with self.queue_lock:
            self.packet_queue.append(packet)

            # Update statistics with type narrowing
            packets_captured = self.stats["packets_captured"]
            if isinstance(packets_captured, int):
                self.stats["packets_captured"] = packets_captured + 1

            total_bytes = self.stats["total_bytes"]
            if isinstance(total_bytes, int):
                self.stats["total_bytes"] = total_bytes + packet.packet_size

            # Limit queue size
            if len(self.packet_queue) > 10000:
                self.packet_queue.pop(0)

    def _analysis_loop(self) -> None:
        """Run main packet analysis loop.

        Continuously processes queued packets, invokes registered analysis
        callbacks for license-related traffic, and handles errors gracefully.

        """
        while self.running:
            try:
                packets_to_analyze = []

                with self.queue_lock:
                    if self.packet_queue:
                        packets_to_analyze = self.packet_queue.copy()
                        self.packet_queue.clear()

                for packet in packets_to_analyze:
                    if analysis := self._analyze_packet(packet):
                        # Call analysis callbacks
                        for callback in self.analysis_callbacks:
                            try:
                                callback(analysis)
                            except Exception as e:
                                self.logger.exception("Analysis callback error: %s", e)

                time.sleep(0.1)

            except Exception as e:
                self.logger.exception("Analysis loop error: %s", e)

    def _analyze_packet(self, packet: InterceptedPacket) -> AnalyzedTraffic | None:
        """Analyze packet for license-related content.

        Performs pattern matching, port-based detection, and heuristic analysis
        to determine if a packet contains license-related communications.

        Args:
            packet: InterceptedPacket object to analyze

        Returns:
            AnalyzedTraffic object if packet is license-related with sufficient
            confidence, None otherwise.

        Raises:
            Exception: Logs exception and returns None on analysis error.

        """
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
                        patterns_matched.append(pattern.decode("utf-8", errors="ignore"))

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
                license_keywords = [b"license", b"activation", b"checkout", b"verify", b"serial"]
                keyword_matches = sum(keyword in data_lower for keyword in license_keywords)

                if keyword_matches > 0:
                    confidence += min(keyword_matches * 0.1, 0.3)
                    is_license_related = True

            # Only return analysis if confidence is high enough
            if confidence < 0.2:
                return None

            # Update statistics with type narrowing
            if is_license_related:
                license_packets = self.stats["license_packets_detected"]
                if isinstance(license_packets, int):
                    self.stats["license_packets_detected"] = license_packets + 1

                protocols_detected = self.stats["protocols_detected"]
                if isinstance(protocols_detected, set):
                    protocols_detected.add(protocol_type)

            analysis_metadata = {
                "keywords_found": patterns_matched,
                "port_based_detection": packet.dest_port in self.license_ports or packet.source_port in self.license_ports,
                "data_size": len(packet.data),
                "connection_flags": packet.flags,
            }

            return AnalyzedTraffic(
                packet=packet,
                is_license_related=is_license_related,
                protocol_type=protocol_type,
                confidence=confidence,
                patterns_matched=patterns_matched,
                analysis_metadata=analysis_metadata,
            )

        except Exception as e:
            self.logger.exception("Packet analysis error: %s", e)
            return None

    def add_analysis_callback(self, callback: Callable[[AnalyzedTraffic], None]) -> None:
        """Add callback for analyzed traffic.

        Registers a callback function to be invoked when traffic is analyzed
        and identified as license-related.

        Args:
            callback: Callable that accepts AnalyzedTraffic and returns None.

        """
        self.analysis_callbacks.append(callback)

    def remove_analysis_callback(self, callback: Callable[[AnalyzedTraffic], None]) -> None:
        """Remove analysis callback.

        Deregisters a previously added callback function from the analysis
        callback list.

        Args:
            callback: Callable to remove from the callback list.

        """
        if callback in self.analysis_callbacks:
            self.analysis_callbacks.remove(callback)

    def set_dns_redirection(self, hostname: str, target_ip: str) -> bool:
        """Set up DNS redirection for hostname.

        Configures DNS resolution redirection to route hostname queries to
        a specified target IP address for traffic interception.

        Args:
            hostname: Hostname to redirect.
            target_ip: Target IP address for the redirection.

        Returns:
            True if redirection configured successfully, False otherwise.

        Raises:
            Exception: Logs exception and returns False on configuration error.

        """
        try:
            self.dns_redirections[hostname.lower()] = target_ip
            self.logger.info("DNS redirection setup: %s -> %s", hostname, target_ip)
            return True
        except Exception as e:
            self.logger.exception("Failed to setup DNS redirection: %s", e)
            return False

    def setup_transparent_proxy(self, target_host: str, target_port: int) -> bool:
        """Set up transparent proxy for target server.

        Configures transparent proxy routing to intercept traffic destined
        for a license server and redirect it through the interception engine.

        Args:
            target_host: Hostname or IP address of the target license server.
            target_port: Port number of the target license server.

        Returns:
            True if proxy configured successfully, False otherwise.

        Raises:
            Exception: Logs exception and returns False on configuration error.

        """
        try:
            proxy_key = f"{target_host}:{target_port}"
            self.proxy_mappings[proxy_key] = (self.bind_interface, target_port)
            self.logger.info("Transparent proxy setup: %s -> %s:%d", proxy_key, self.bind_interface, target_port)
            return True
        except Exception as e:
            self.logger.exception("Failed to setup transparent proxy: %s", e)
            return False

    def get_statistics(self) -> dict[str, Any]:
        """Get traffic interception statistics.

        Returns accumulated statistics about packet capture, license detection,
        and interception engine performance.

        Returns:
            Dictionary containing:

            - packets_captured: Total packets intercepted
            - license_packets_detected: Packets identified as license-related
            - protocols_detected: List of license protocols identified
            - total_bytes: Total bytes captured
            - uptime_seconds: Engine uptime in seconds
            - packets_per_second: Capture rate
            - active_connections: Count of active connections
            - capture_backend: Name of capture backend in use
            - dns_redirections: Count of DNS redirections
            - proxy_mappings: Count of proxy mappings

        """
        current_time = time.time()
        start_time = self.stats["start_time"]
        uptime = current_time - start_time if isinstance(start_time, (int, float)) else 0.0

        stats = self.stats.copy()

        # Convert protocols_detected set to list
        protocols_detected = stats["protocols_detected"]
        if isinstance(protocols_detected, set):
            stats["protocols_detected"] = list(protocols_detected)

        stats["uptime_seconds"] = uptime

        # Calculate packets per second with type narrowing
        packets_captured = stats["packets_captured"]
        if isinstance(packets_captured, int):
            stats["packets_per_second"] = float(packets_captured) / max(uptime, 1.0)
        else:
            stats["packets_per_second"] = 0.0

        stats["active_connections"] = len(self.active_connections)
        stats["capture_backend"] = self.capture_backend
        stats["dns_redirections"] = len(self.dns_redirections)
        stats["proxy_mappings"] = len(self.proxy_mappings)

        return stats

    def get_active_connections(self) -> list[dict[str, Any]]:
        """Get list of active connections.

        Retrieves information about currently tracked license server connections.

        Returns:
            List of connection dictionaries containing:

            - endpoint: Connection address (ip:port)
            - duration: Connection duration in seconds
            - last_activity: Timestamp of last activity
            - packet_count: Number of packets exchanged

        """
        connections: list[dict[str, Any]] = []
        current_time = time.time()

        with self.connection_lock:
            connections.extend(
                {
                    "endpoint": connection_key,
                    "duration": current_time - info["first_seen"],
                    "last_activity": info["last_activity"],
                    "packet_count": info["packet_count"],
                }
                for connection_key, info in self.active_connections.items()
            )
        return connections

    def send_protocol_command(
        self,
        protocol_name: str,
        host: str,
        port: int,
        command: bytes,
    ) -> bytes | None:
        """Send a protocol-specific command to a license server.

        This method establishes a connection to the specified license server
        and sends a protocol-appropriate command, returning the server's response.

        Args:
            protocol_name: Name of the license protocol (flexlm, hasp, adobe,
                etc.)
            host: Target server hostname or IP address.
            port: Target server port number.
            command: Raw command bytes to send.

        Returns:
            Server response bytes, or None if connection/send failed.

        Raises:
            TimeoutError: If connection or receive timeout occurs, caught and
                logged.
            OSError: If socket operations fail, caught and logged.
            Exception: Other exceptions caught and logged.

        """
        try:
            self.logger.info(
                "Sending %s protocol command to %s:%d",
                protocol_name,
                host,
                port,
            )

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10.0)

            try:
                sock.connect((host, port))
            except (TimeoutError, OSError) as e:
                self.logger.exception("Connection failed to %s:%d: %s", host, port, e)
                sock.close()
                return None

            protocol_lower = protocol_name.lower()
            wrapped_command = self._wrap_protocol_command(protocol_lower, command)

            try:
                sock.sendall(wrapped_command)
            except OSError as e:
                self.logger.exception("Send failed: %s", e)
                sock.close()
                return None

            response_chunks = []
            total_received = 0
            max_response_size = 65536

            try:
                while total_received < max_response_size:
                    sock.settimeout(5.0)
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response_chunks.append(chunk)
                    total_received += len(chunk)

                    if self._is_response_complete(protocol_lower, b"".join(response_chunks)):
                        break

            except TimeoutError:
                pass
            except OSError as e:
                self.logger.debug("Receive error: %s", e)

            sock.close()

            if response_chunks:
                response = b"".join(response_chunks)
                self.logger.info(
                    "Received %d bytes response from %s:%d",
                    len(response),
                    host,
                    port,
                )

                with self.connection_lock:
                    connection_key = f"{host}:{port}"
                    if connection_key not in self.active_connections:
                        self.active_connections[connection_key] = {
                            "first_seen": time.time(),
                            "last_activity": time.time(),
                            "packet_count": 1,
                            "protocol": protocol_name,
                        }
                    else:
                        self.active_connections[connection_key]["last_activity"] = time.time()
                        self.active_connections[connection_key]["packet_count"] += 1

                return response

            self.logger.warning("No response received from %s:%d", host, port)
            return None

        except Exception as e:
            self.logger.exception("Protocol command failed: %s", e)
            return None

    def _wrap_protocol_command(self, protocol_name: str, command: bytes) -> bytes:
        """Wrap command bytes in protocol-specific packet format.

        Adds protocol headers and formatting appropriate for the target
        license protocol (FlexLM, HASP, Adobe, Autodesk, Microsoft KMS).

        Args:
            protocol_name: Protocol identifier string.
            command: Raw command data bytes.

        Returns:
            Protocol-wrapped command bytes ready to send.

        """
        if protocol_name == "flexlm":
            header = struct.pack(">HH", 0x0001, len(command))
            return header + command

        if protocol_name == "hasp":
            header = b"\x00\x01\x02\x03"
            length = struct.pack("<H", len(command))
            return header + length + command

        if protocol_name in {"adobe", "autodesk"}:
            return command + b"\x00"

        if protocol_name == "microsoft":
            header = struct.pack("<I", len(command))
            return header + command

        return command

    def _is_response_complete(self, protocol_name: str, data: bytes) -> bool:
        """Check if received response is complete for the protocol.

        Analyzes protocol-specific data to determine if a complete response
        has been received based on length fields or termination patterns.

        Args:
            protocol_name: Protocol identifier string.
            data: Received data so far in bytes.

        Returns:
            True if response appears complete, False otherwise.

        """
        if not data:
            return False

        if protocol_name == "flexlm":
            if len(data) >= 4:
                flexlm_expected_len: int = struct.unpack(">H", data[2:4])[0]
                return bool(len(data) >= flexlm_expected_len + 4)
            return False

        if protocol_name == "hasp":
            if len(data) >= 6:
                hasp_expected_len: int = struct.unpack("<H", data[4:6])[0]
                return bool(len(data) >= hasp_expected_len + 6)
            return False

        if data.endswith(b"\x00") or data.endswith(b"\r\n"):
            return True

        return len(data) > 0

    def capture_license_traffic(self) -> list[dict[str, Any]]:
        """Capture and return recent license-related network traffic.

        This method returns accumulated license traffic data that has been
        captured during interception. It analyzes the packet queue for
        license-related communications and falls back to port scanning if
        no traffic has been captured.

        Returns:
            List of license traffic dictionaries containing:

            - protocol: Detected protocol name
            - server: Server address (ip:port)
            - timestamp: Time of capture
            - data_size: Size of captured data
            - direction: 'outbound' or 'inbound'
            - patterns: Matched license patterns

        """
        license_traffic = []

        with self.queue_lock:
            packets_to_analyze = list(self.packet_queue)

        for packet in packets_to_analyze:
            if not packet.data:
                continue

            is_license = False
            detected_protocol = "unknown"
            patterns_found = []

            if packet.dest_port in self.license_ports or packet.source_port in self.license_ports:
                is_license = True

            for proto, patterns in self.license_patterns.items():
                for pattern in patterns:
                    if pattern in packet.data:
                        is_license = True
                        detected_protocol = proto
                        patterns_found.append(pattern.decode("utf-8", errors="ignore"))

            if is_license:
                if packet.dest_port in self.license_ports:
                    server = f"{packet.dest_ip}:{packet.dest_port}"
                    direction = "outbound"
                else:
                    server = f"{packet.source_ip}:{packet.source_port}"
                    direction = "inbound"

                license_traffic.append({
                    "protocol": detected_protocol,
                    "server": server,
                    "timestamp": packet.timestamp,
                    "data_size": len(packet.data),
                    "direction": direction,
                    "patterns": patterns_found,
                    "source_ip": packet.source_ip,
                    "dest_ip": packet.dest_ip,
                    "source_port": packet.source_port,
                    "dest_port": packet.dest_port,
                })

        if not license_traffic:
            license_traffic = self._scan_for_active_license_servers()

        self.logger.info("Captured %d license traffic entries", len(license_traffic))
        return license_traffic

    def _scan_for_active_license_servers(self) -> list[dict[str, Any]]:
        """Scan for active license servers when no traffic is captured.

        Attempts to connect to known license server ports on localhost and
        the bind interface to detect active servers. Returns detected servers
        in the same format as capture_license_traffic.

        Returns:
            List of detected license server entries with protocol, server,
            and connection details.

        """
        detected = []
        scan_hosts = [self.bind_interface, "127.0.0.1"]

        for host in scan_hosts:
            for port in list(self.license_ports)[:10]:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.3)
                    result = sock.connect_ex((host, port))
                    sock.close()

                    if result == 0:
                        protocol = self._identify_protocol_by_port(port)
                        detected.append({
                            "protocol": protocol,
                            "server": f"{host}:{port}",
                            "timestamp": time.time(),
                            "data_size": 0,
                            "direction": "detected",
                            "patterns": [],
                            "source_ip": self.bind_interface,
                            "dest_ip": host,
                            "source_port": 0,
                            "dest_port": port,
                        })

                except (TimeoutError, OSError):
                    continue

        return detected

    def _identify_protocol_by_port(self, port: int) -> str:
        """Identify likely protocol based on port number.

        Maps port numbers to known license protocols based on industry-standard
        port assignments for FlexLM, HASP, Microsoft KMS, Autodesk, and HTTP(S).

        Args:
            port: Port number to identify.

        Returns:
            Protocol name string corresponding to the port, or 'unknown' if
            the port is not recognized.

        """
        port_protocols = {
            27000: "flexlm",
            27001: "flexlm",
            1947: "hasp",
            443: "https_license",
            80: "http_license",
            1688: "microsoft_kms",
            2080: "autodesk",
            8080: "http_license",
        }

        return port_protocols.get(port, "unknown")


__all__ = ["AnalyzedTraffic", "InterceptedPacket", "TrafficInterceptionEngine"]

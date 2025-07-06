"""Network traffic analyzer for monitoring and analyzing network communications."""
import datetime
import glob
import logging
import os
import select
import signal
import socket
import struct
import threading
import time
import traceback
from typing import Any, Dict, Optional

from intellicrack.logger import logger

from .base_network_analyzer import BaseNetworkAnalyzer

"""
Network Traffic Analyzer for License Communications

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



# Optional network capture dependencies - graceful fallback if not available
try:
    import pyshark
    PYSHARK_AVAILABLE = True
except ImportError as e:
    logger.error("Import error in traffic_analyzer: %s", e)
    PYSHARK_AVAILABLE = False

try:
    import scapy.all as scapy
    SCAPY_AVAILABLE = True
except ImportError as e:
    logger.error("Import error in traffic_analyzer: %s", e)
    SCAPY_AVAILABLE = False

# Visualization dependencies
try:
    import matplotlib.pyplot as plt
    MATPLOTLIB_AVAILABLE = True
except ImportError as e:
    logger.error("Import error in traffic_analyzer: %s", e)
    MATPLOTLIB_AVAILABLE = False

# Determine available packet capture library
if PYSHARK_AVAILABLE:
    PACKET_CAPTURE_LIB = "pyshark"
elif SCAPY_AVAILABLE:
    PACKET_CAPTURE_LIB = "scapy"
else:
    PACKET_CAPTURE_LIB = "socket"  # Fallback to raw sockets



class NetworkTrafficAnalyzer(BaseNetworkAnalyzer):
    """
    Visual network traffic analyzer for license communications.

    This system captures, analyzes, and visualizes network traffic related to
    license verification, providing insights into license check mechanisms.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the network traffic analyzer.

        Args:
            config: Configuration dictionary (optional)
        """
        super().__init__()
        self.logger = logging.getLogger(__name__)

        # Default configuration
        self.config = {
            'capture_file': 'license_traffic.pcap',
            'max_packets': 10000,
            'filter': 'tcp',
            'visualization_dir': 'visualizations',
            'auto_analyze': True
        }

        # Update with provided configuration
        if config:
            self.config.update(config)

        # Initialize components
        self.packets = []
        self.connections = {}
        self.license_servers = set()
        self.license_connections = []
        self.license_patterns = [
            b'license', b'activation', b'auth', b'key', b'valid',
            b'FEATURE', b'INCREMENT', b'VENDOR', b'SERVER',
            b'HASP', b'Sentinel', b'FLEXLM', b'LCSAP'
        ]

        # Capture control flag
        self.capturing = False

        # Common license server ports
        self.license_ports = [1111, 1234, 2222, 27000, 27001, 27002, 27003, 27004, 27005,
                             1947, 6001, 22350, 22351, 2080, 8224, 5093, 49684]

        # Local network detection (simplified)
        self.local_networks = ['192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.',
                              '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.',
                              '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.',
                              '127.', 'localhost']

        # Create visualization directory
        os.makedirs(self.config['visualization_dir'], exist_ok=True)

    def start_capture(self, interface: Optional[str] = None) -> bool:
        """
        Start capturing network traffic.

        Args:
            interface: Network interface to capture on (optional)

        Returns:
            bool: True if capture started successfully, False otherwise
        """
        try:
            # Set capturing flag
            self.capturing = True
            # Define capture thread function
            def capture_thread():
                """
                Thread function for packet capture operations.

                This function executes the packet capture operation in a separate thread,
                allowing the network monitoring to run concurrently with the main application.
                It calls the internal _capture_packets method with the specified interface
                and provides exception handling to prevent thread crashes.

                Args:
                    None: Uses the interface parameter from the parent function scope

                Returns:
                    None

                Raises:
                    No exceptions are propagated as they are caught and logged internally
                """
                try:
                    self._capture_packets(interface)
                except Exception as e:
                    self.logger.error("Error in capture thread: %s", e)

            # Start capture in a separate thread
            thread = threading.Thread(target=capture_thread)
            thread.daemon = True
            thread.start()

            self.logger.info(f"Started packet capture on {interface or 'default interface'}")
            return True

        except Exception as e:
            self.logger.error("Error starting capture: %s", e)
            self.logger.error(traceback.format_exc())
            return False

    def _capture_packets(self, interface: Optional[str] = None):
        """
        Capture packets using available libraries.

        Args:
            interface: Network interface to capture on (optional)
        """
        # Try different packet capture libraries
        # Use the detected library based on PACKET_CAPTURE_LIB global variable
        try:
            if PACKET_CAPTURE_LIB == "scapy":
                self._capture_with_scapy(interface)
                return
            elif PACKET_CAPTURE_LIB == "pyshark":
                self._capture_with_pyshark(interface)
                return
            elif PACKET_CAPTURE_LIB == "socket":
                self._capture_with_socket(interface)
                return
            else:
                self.logger.error("No packet capture library available")
        except Exception as e:
            self.logger.error(f"Packet capture failed: {str(e)}")

    def _capture_with_socket(self, interface: Optional[str] = None, capture_filter: Optional[str] = None,
                           output_file: Optional[str] = None, packet_count: Optional[int] = None,
                           timeout: Optional[int] = None) -> Dict[str, Any]:
        """
        Capture packets using Python's native socket library.
        This is a fallback method when specialized packet capture libraries are not available.

        Args:
            interface: Network interface to capture on (optional)
            capture_filter: Display filter (partially supported - only basic filtering possible)
            output_file: Path to save the capture (optional)
            packet_count: Maximum number of packets to capture (optional)
            timeout: Timeout in seconds (optional)
        """
        self.logger.info("Starting packet capture using native socket library")

        # Create a raw socket
        try:
            try:
                if os.name == "nt":  # Windows
                    # On Windows, socket.SOCK_RAW requires administrator privileges
                    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                    if interface:
                        # Try to bind to the specified interface
                        try:
                            s.bind((interface, 0))
                        except Exception as e:
                            self.logger.warning(f"Could not bind to interface {interface}, using default: {str(e)}")
                            # Get host name and attempt to bind to its IP
                            host = socket.gethostbyname(socket.gethostname())
                            s.bind((host, 0))
                    else:
                        # Get host name and bind to its IP
                        host = socket.gethostbyname(socket.gethostname())
                        s.bind((host, 0))

                    # Enable promiscuous mode
                    if hasattr(socket, 'SIO_RCVALL') and hasattr(socket, 'RCVALL_ON'):
                        s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
                else:  # Linux, macOS, etc.
                    if hasattr(socket, 'AF_PACKET'):
                        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
                    else:
                        # Fallback for systems without AF_PACKET
                        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                    if interface:
                        try:
                            s.bind((interface, 0))
                        except Exception as e:
                            self.logger.warning(f"Could not bind to interface {interface}: {str(e)}")
            except PermissionError:
                self.logger.error("Permission denied: Raw socket capture requires administrator/root privileges")
                raise
            except OSError as e:
                if "access" in str(e).lower() or "permission" in str(e).lower():
                    self.logger.error("Permission denied: Raw socket capture requires administrator/root privileges")
                raise

            # Set timeout if specified
            if timeout:
                s.settimeout(timeout)

            # Initialize capture statistics
            start_time = time.time()
            packets_captured = 0
            capture_stats = {
                'start_time': start_time,
                'packets_total': 0,
                'capture_time': 0
            }

            # Inner function to handle the main capture logic
            def perform_capture(out_file):
                """Perform the actual packet capture."""
                nonlocal packets_captured

                # Capture loop
                try:
                    while self.capturing:
                        # Break if we've captured enough packets
                        if packet_count and packets_captured >= packet_count:
                            break

                        # Check if overall timeout has elapsed before waiting for more packets
                        current_time = time.time()
                        if timeout and (current_time - start_time) > timeout:
                            self.logger.info(f"Capture timeout reached after {current_time - start_time:.2f} seconds")
                            break

                        # Wait for packets with timeout
                        ready, _, _ = select.select([s], [], [], 0.1)  # Short timeout for responsiveness

                        if not ready:
                            continue

                        # Receive packet
                        packet = s.recv(65535)
                        packets_captured += 1

                        # Apply very basic filtering if requested (exact string match only)
                        if capture_filter and capture_filter.encode() not in packet:
                            continue

                        # Write to output file if specified
                        if out_file:
                            timestamp = time.time()
                            # Write timestamp + packet size + packet data
                            header = struct.pack("!dI", timestamp, len(packet))
                            out_file.write(header)
                            out_file.write(packet)

                        # Display basic packet info (simplified)
                        if packets_captured % 10 == 0:  # Don't flood the logs
                            self.logger.info("Captured %s packets", packets_captured)

                        # Process the packet (simplified)
                        self._process_captured_packet(packet)

                except KeyboardInterrupt:
                    self.logger.info("Packet capture interrupted by user")
                except socket.timeout:
                    self.logger.info("Packet capture timeout reached")
                except Exception as e:
                    self.logger.error(f"Error during packet capture: {str(e)}")
                finally:
                    # Clean up
                    capture_stats['packets_total'] = packets_captured
                    capture_stats['capture_time'] = time.time() - start_time

                    if os.name == "nt":
                        # Disable promiscuous mode on Windows
                        try:
                            if hasattr(socket, 'SIO_RCVALL') and hasattr(socket, 'RCVALL_OFF'):
                                s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                        except (OSError, AttributeError) as e:
                            logger.error("Error in traffic_analyzer: %s", e)
                            pass

                    s.close()

                    self.logger.info(f"Socket-based packet capture completed: {packets_captured} packets in {capture_stats['capture_time']:.2f} seconds")

            # Main execution with optional file context
            if output_file:
                try:
                    with open(output_file, 'wb') as out_file:
                        # Write a simple header (not pcap format, just timestamped raw packets)
                        out_file.write(f"# Intellicrack socket capture started at {datetime.datetime.now()}\n".encode('utf-8'))
                        perform_capture(out_file)
                except Exception as e:
                    self.logger.error(f"Failed to open output file: {str(e)}")
                    # Continue capture without output file
                    perform_capture(None)
            else:
                # No output file specified
                perform_capture(None)

            return capture_stats

        except Exception as e:
            self.logger.error(f"Failed to initialize socket for packet capture: {str(e)}")
            raise

    def _process_captured_packet(self, packet_data: bytes):
        """
        Simple packet processor for socket-captured packets
        """
        try:
            # Very basic packet processing - extract IP header info
            if len(packet_data) >= 20:  # Minimum IP header size
                # Ensure we're working with bytes for consistent handling
                if not isinstance(packet_data, (bytes, bytearray)):
                    self.logger.warning("Unexpected packet_data type, expected bytes or bytearray")
                    return

                # Extract version and header length
                version_ihl = packet_data[0]
                version = version_ihl >> 4
                ihl = (version_ihl & 0xF) * 4

                # Log and validate IP version
                if version != 4:
                    self.logger.warning("Unexpected IP version: %s, expected IPv4", version)
                    return

                # Extract other IP header fields if needed
                if len(packet_data) >= 20:
                    # Protocol (TCP=6, UDP=17, ICMP=1, etc.)
                    protocol = packet_data[9]

                    # For license analysis, focus on common license server protocols
                    if protocol == 6:  # TCP
                        # Check for common license server ports
                        if len(packet_data) >= ihl + 4:  # Ensure we have TCP header
                            # Extract source and destination ports from TCP header using struct for proper byte handling
                            try:
                                src_port = (packet_data[ihl] << 8) | packet_data[ihl + 1]
                                dst_port = (packet_data[ihl + 2] << 8) | packet_data[ihl + 3]

                                # Common license server ports
                                if src_port in self.license_ports or dst_port in self.license_ports:
                                    self.logger.info("Potential license traffic detected: port %s->%s", src_port, dst_port)
                            except Exception as e:
                                self.logger.debug(f"Error extracting TCP ports: {str(e)}")
        except Exception as e:
            # Just log the error and continue
            self.logger.error(f"Error processing packet: {str(e)}")

    def _capture_with_pyshark(self, interface: Optional[str] = None, capture_filter: Optional[str] = None,
                            output_file: Optional[str] = None, packet_count: Optional[int] = None,
                            timeout: Optional[int] = None):
        """
        Capture packets using pyshark with enhanced functionality for license traffic analysis.

        Args:
            interface: Network interface to capture on (optional)
            capture_filter: Custom display filter to override default license filter (optional)
            output_file: Path to save the capture in pcapng format (optional)
            packet_count: Maximum number of packets to capture before stopping (optional)
            timeout: Timeout in seconds after which to stop capturing (optional)
        """
        if not PYSHARK_AVAILABLE:
            self.logger.error("pyshark not available - please install pyshark")
            return

        try:
            # Initialize capture statistics
            start_time = time.time()
            packets_captured = 0
            packets_analyzed = 0
            capture_stats = {
                'start_time': start_time,
                'packets_total': 0,
                'packets_analyzed': 0,
                'errors': 0
            }

            # Prepare capture options
            capture_options = {}
            if interface:
                capture_options['interface'] = interface
            if output_file:
                capture_options['output_file'] = output_file

            # Create capture object
            # Use either custom filter or the one from config
            display_filter = capture_filter if capture_filter else self.config['filter']

            # If no filter is specified, use comprehensive license-related traffic filter
            if not display_filter:
                display_filter = (
                    # FlexLM ports
                    'tcp.port == 27000-27009 or tcp.port == 2080 or tcp.port == 8224 or '
                    # HASP/Sentinel ports
                    'tcp.port == 1947 or tcp.port == 6001 or '
                    # CodeMeter ports
                    'tcp.port == 22350 or tcp.port == 22351 or '
                    # Common web license ports
                    'tcp.port == 80 or tcp.port == 443 or tcp.port == 8080 or '
                    # Known application license ports
                    'tcp.port == 1234 or tcp.port == 5093 or tcp.port == 49684 or '
                    # DNS lookups for license validation
                    'dns.qry.name contains "license" or dns.qry.name contains "activation" or '
                    # HTTP license-related requests
                    '(http and (http.request.uri contains "license" or http.request.uri contains "activation" or '
                    'http.request.uri contains "validate" or http.request.uri contains "auth"))'
                )

            capture_options['display_filter'] = display_filter
            capture = pyshark.LiveCapture(**capture_options)

            # Log capture start
            self.logger.info(f"Starting packet capture on {'all interfaces' if not interface else interface}")
            self.logger.info("Using filter: %s", display_filter)

            # Define signal handler for graceful exit
            original_sigint_handler = signal.getsignal(signal.SIGINT)

            def signal_handler(sig, frame):
                """
                Handle SIGINT for graceful packet capture termination.

                Logs the interrupt and restores the original signal handler.
                """
                self.logger.info("Received interrupt signal %d, stopping capture...", sig)
                if frame:
                    self.logger.debug("Signal received at frame: %s", frame.f_code.co_filename if hasattr(frame, 'f_code') else 'unknown')
                signal.signal(signal.SIGINT, original_sigint_handler)

            signal.signal(signal.SIGINT, signal_handler)

            # Start capturing with appropriate method based on parameters
            max_packets = packet_count if packet_count else self.config.get('max_packets', float('inf'))
            capture_start_time = time.time()

            # Process packets
            for packet in capture.sniff_continuously():
                # Check if capture should stop
                if not self.capturing:
                    self.logger.info("Capture stopped by user")
                    break

                # Check for timeout
                if timeout and time.time() - capture_start_time > timeout:
                    self.logger.info("Capture timeout reached (%ss), stopping...", timeout)
                    break

                # Process the packet
                try:
                    if self._process_pyshark_packet(packet):
                        # Increment analyzed packets count when processing is successful
                        packets_analyzed += 1
                        capture_stats['packets_analyzed'] = packets_analyzed

                    packets_captured += 1
                    capture_stats['packets_total'] = packets_captured

                    # Check if we've reached the max packet count
                    if len(self.packets) >= max_packets:
                        self.logger.info("Reached maximum packet count (%s), stopping capture", max_packets)
                        capture.close()
                        break

                    # Log progress periodically
                    if packets_captured % 100 == 0:
                        elapsed = time.time() - start_time
                        rate = packets_captured / elapsed if elapsed > 0 else 0
                        self.logger.info(f"Captured {packets_captured} packets ({rate:.2f} packets/sec), " +
                                        f"analyzed {len(self.packets)} license-related packets")

                except Exception as packet_ex:
                    self.logger.error(f"Error processing packet: {str(packet_ex)}")
                    capture_stats['errors'] += 1
                    # Continue capturing despite errors in individual packets
                    continue

            # Capture complete, log statistics
            end_time = time.time()
            duration = end_time - start_time
            packet_rate = packets_captured / duration if duration > 0 else 0

            summary_msg = (
                f"Capture complete. Duration: {duration:.2f}s, "
                f"Total packets: {packets_captured}, "
                f"Analyzed packets: {packets_analyzed}, "
                f"License-related packets: {len(self.packets)}, "
                f"Errors: {capture_stats['errors']}, "
                f"Rate: {packet_rate:.2f} packets/sec"
            )
            self.logger.info(summary_msg)

            # If output file was specified, verify it was saved
            if output_file and os.path.exists(output_file):
                self.logger.info("Capture saved to file: %s", output_file)

        except Exception as e:
            self.logger.error(f"Failed to capture packets: {str(e)}")
            self.logger.error(traceback.format_exc())
            raise

    def _process_pyshark_packet(self, packet) -> bool:
        """
        Process a captured packet from pyshark.

        Args:
            packet: Captured packet

        Returns:
            bool: True if packet was processed successfully, False otherwise
        """
        try:
            # Check if it's a TCP packet
            if hasattr(packet, 'tcp') and hasattr(packet, 'ip'):
                # Extract connection information
                src_ip = packet.ip.src
                dst_ip = packet.ip.dst
                src_port = packet.tcp.srcport
                dst_port = packet.tcp.dstport

                # Create connection key for tracking connections
                conn_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"

                # Store connection direction information
                is_outbound = any(src_ip.startswith(net) for net in self.local_networks)
                direction = "outbound" if is_outbound else "inbound"

                # Track unique connections with enhanced metadata
                if conn_key not in self.connections:
                    # Initialize new connection with detailed tracking info
                    self.connections[conn_key] = {
                        'first_seen': float(packet.sniff_timestamp),
                        'last_seen': float(packet.sniff_timestamp),
                        'packets': [],
                        'bytes_sent': 0,
                        'bytes_received': 0,
                        'start_time': float(packet.sniff_timestamp),
                        'last_time': float(packet.sniff_timestamp),
                        'is_license': False,
                        'status': 'active',
                        'direction': direction,
                        'src_ip': src_ip,
                        'src_port': int(src_port),
                        'dst_ip': dst_ip,
                        'dst_port': int(dst_port),
                        'protocol': 'TCP'
                    }

                    # Analyze connection pattern
                    if int(dst_port) in self.license_ports or int(src_port) in self.license_ports:
                        self.connections[conn_key]['type'] = 'license'
                        self.license_connections.append(conn_key)
                        self.logger.info("Potential license traffic detected: %s", conn_key)

                    self.logger.debug("New %s connection detected: %s", direction, conn_key)

                # Check for payload
                payload = None
                if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'payload'):
                    try:
                        payload = bytes.fromhex(packet.tcp.payload.replace(':', ''))
                    except ValueError as e:
                        logger.error("Value error in traffic_analyzer: %s", e)
                        payload = None

                    # Look for license-related strings in payload
                    if payload and len(payload) > 10:
                        if self._check_payload_for_license_content(payload, conn_key):
                            # Mark as potential license traffic
                            self.connections[conn_key]['license_related'] = True

                # Create packet info
                packet_info = {
                    'timestamp': float(packet.sniff_timestamp),
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'src_port': int(src_port),
                    'dst_port': int(dst_port),
                    'payload': payload,
                    'size': int(packet.length),
                    'connection_id': conn_key
                }

                # Update connection stats
                conn = self.connections[conn_key]
                conn['packets'].append(packet_info)
                conn['last_time'] = float(packet.sniff_timestamp)

                if src_ip == conn['src_ip']:
                    conn['bytes_sent'] += int(packet.length)
                else:
                    conn['bytes_received'] += int(packet.length)

                # Check if this is a license-related connection
                if payload:
                    for pattern in self.license_patterns:
                        if pattern in payload:
                            conn['is_license'] = True

                            # Add to license servers
                            if int(dst_port) > 1024:
                                self.license_servers.add(dst_ip)
                            else:
                                self.license_servers.add(src_ip)

                            break

                # Add to packets list
                self.packets.append(packet_info)

                # Auto-analyze if enabled
                if self.config['auto_analyze'] and len(self.packets) % 100 == 0:
                    self.analyze_traffic()

                return True

        except Exception as e:
            self.logger.error("Error processing packet: %s", e)
            return False

        return False

    def _check_payload_for_license_content(self, payload: bytes, conn_key: str) -> bool:
        """
        Check if payload contains license-related content.

        Args:
            payload: Packet payload data
            conn_key: Connection key for logging

        Returns:
            bool: True if license content detected, False otherwise
        """
        try:
            for pattern in self.license_patterns:
                if pattern in payload:
                    self.logger.debug(f"License pattern '{pattern.decode('utf-8', errors='ignore')}' found in {conn_key}")
                    return True
            return False
        except Exception as e:
            self.logger.debug("Error checking payload for license content: %s", e)
            return False

    def _capture_with_scapy(self, interface: Optional[str] = None):
        """
        Capture packets using scapy.

        Args:
            interface: Network interface to capture on (optional)
        """
        if not SCAPY_AVAILABLE:
            self.logger.error("scapy not available - please install scapy")
            return

        self.logger.info("Starting packet capture using Scapy...")

        try:
            # Build filter for license-related traffic
            bpf_filter = (
                "tcp and ("
                "port 27000 or port 27001 or port 27002 or port 27003 or "  # FlexLM
                "port 1947 or port 6001 or "  # HASP/Sentinel
                "port 22350 or port 22351 or "  # CodeMeter
                "port 2080 or port 8224 or port 5093 or "  # Other license ports
                "port 80 or port 443"  # Web-based licensing
                ")"
            )

            # Define packet processing function
            def process_tcp_packet(packet, IP, TCP):
                """Process TCP packets for analysis."""
                if IP in packet and TCP in packet:
                        # Extract packet info
                        src_ip = packet[IP].src
                        dst_ip = packet[IP].dst
                        src_port = packet[TCP].sport
                        dst_port = packet[TCP].dport

                        # Create connection key
                        conn_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"

                        # Check if this is a new connection
                        if conn_key not in self.connections:
                            self.connections[conn_key] = {
                                'first_seen': time.time(),
                                'last_seen': time.time(),
                                'packets': [],
                                'bytes_sent': 0,
                                'bytes_received': 0,
                                'start_time': time.time(),
                                'last_time': time.time(),
                                'is_license': False,
                                'src_ip': src_ip,
                                'src_port': src_port,
                                'dst_ip': dst_ip,
                                'dst_port': dst_port,
                                'protocol': 'TCP'
                            }

                            # Check if it's license-related
                            if dst_port in self.license_ports or src_port in self.license_ports:
                                self.connections[conn_key]['is_license'] = True
                                self.license_connections.append(conn_key)
                                self.logger.info("Potential license traffic: %s", conn_key)

                        # Extract payload if available
                        payload = None
                        if hasattr(scapy, 'Raw') and scapy.Raw in packet:
                            payload = bytes(packet[scapy.Raw])

                            # Check for license patterns
                            if payload:
                                for pattern in self.license_patterns:
                                    if pattern in payload:
                                        self.connections[conn_key]['is_license'] = True
                                        if dst_port > 1024:
                                            self.license_servers.add(dst_ip)
                                        else:
                                            self.license_servers.add(src_ip)
                                        break

                        # Create packet info
                        packet_info = {
                            'timestamp': time.time(),
                            'src_ip': src_ip,
                            'dst_ip': dst_ip,
                            'src_port': src_port,
                            'dst_port': dst_port,
                            'payload': payload,
                            'size': len(packet),
                            'connection_id': conn_key
                        }

                        # Update connection stats
                        conn = self.connections[conn_key]
                        conn['packets'].append(packet_info)
                        conn['last_time'] = time.time()

                        if src_ip == conn['src_ip']:
                            conn['bytes_sent'] += len(packet)
                        else:
                            conn['bytes_received'] += len(packet)

                        # Add to packets list
                        self.packets.append(packet_info)

                        # Auto-analyze if enabled
                        if self.config['auto_analyze'] and len(self.packets) % 100 == 0:
                            self.analyze_traffic()

            # Create packet handler using base class
            packet_handler = self.create_packet_handler(
                scapy,
                lambda: self.capturing,
                process_tcp_packet
            )

            # Start sniffing
            self.logger.info("Starting Scapy sniffer with filter: %s", bpf_filter)

            # Use sniff with a stop filter
            def stop_filter(packet):
                self.logger.debug("Checking stop condition for packet: %s", type(packet).__name__)
                return not self.capturing

            # Start capture
            scapy.sniff(
                iface=interface,
                filter=bpf_filter,
                prn=packet_handler,
                stop_filter=stop_filter,
                store=0  # Don't store packets in memory
            )

            self.logger.info("Scapy capture completed")

        except Exception as e:
            self.logger.error("Scapy capture failed: %s", e)
            self.logger.info("Falling back to socket capture")
            self._capture_with_socket(interface)

    def analyze_traffic(self) -> Optional[Dict[str, Any]]:
        """
        Analyze captured traffic for license communications.

        Returns:
            dict: Analysis results
        """
        try:
            # Count packets and connections
            total_packets = len(self.packets)
            total_connections = len(self.connections)
            license_connections = sum(1 for conn in self.connections.values() if conn['is_license'])

            # Identify license servers
            license_servers = list(self.license_servers)

            # Analyze license connections
            license_conn_details = []
            for conn_key, conn in self.connections.items():
                if conn['is_license']:
                    # Extract connection details
                    conn_details = {
                        'conn_id': conn_key,
                        'src_ip': conn['src_ip'],
                        'dst_ip': conn['dst_ip'],
                        'src_port': conn['src_port'],
                        'dst_port': conn['dst_port'],
                        'packets': len(conn['packets']),
                        'bytes_sent': conn['bytes_sent'],
                        'bytes_received': conn['bytes_received'],
                        'duration': conn['last_time'] - conn['start_time']
                    }

                    # Extract license patterns
                    patterns_found = set()
                    for packet in conn['packets']:
                        if packet['payload']:
                            for pattern in self.license_patterns:
                                if pattern in packet['payload']:
                                    patterns_found.add(pattern.decode('utf-8', errors='ignore'))

                    conn_details['patterns'] = list(patterns_found)
                    license_conn_details.append(conn_details)

            # Create analysis results
            results = {
                'total_packets': total_packets,
                'total_connections': total_connections,
                'license_connections': license_connections,
                'license_servers': license_servers,
                'license_conn_details': license_conn_details
            }

            # Generate visualizations
            if MATPLOTLIB_AVAILABLE:
                self._generate_visualizations(results)

            return results

        except Exception as e:
            self.logger.error("Error analyzing traffic: %s", e)
            return None

    def _generate_visualizations(self, results: Dict[str, Any]):
        """
        Generate visualizations of license traffic.

        Args:
            results: Analysis results
        """
        if not MATPLOTLIB_AVAILABLE:
            self.logger.warning("matplotlib not available - skipping visualizations")
            return

        try:
            # Create timestamp for visualizations
            timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')

            # 1. Connection graph
            plt.figure(figsize=(10, 6))
            plt.title('License Connections')

            # Extract data
            ips = set()
            for conn in results['license_conn_details']:
                ips.add(conn['src_ip'])
                ips.add(conn['dst_ip'])

            if not ips:
                self.logger.info("No license connections to visualize")
                plt.close()
                return

            # Create positions
            pos = {}
            client_x = 0.2
            server_x = 0.8

            client_ips = [ip for ip in ips if ip not in results['license_servers']]
            server_ips = results['license_servers']

            for i, ip in enumerate(client_ips):
                pos[ip] = (client_x, (i + 1) / (len(client_ips) + 1))

            for i, ip in enumerate(server_ips):
                pos[ip] = (server_x, (i + 1) / (len(server_ips) + 1))

            # Draw nodes
            for ip in client_ips:
                plt.plot(pos[ip][0], pos[ip][1], 'bo', markersize=10)
                plt.text(pos[ip][0] - 0.05, pos[ip][1], ip, ha='right', va='center')

            for ip in server_ips:
                plt.plot(pos[ip][0], pos[ip][1], 'rs', markersize=10)
                plt.text(pos[ip][0] + 0.05, pos[ip][1], ip, ha='left', va='center')

            # Draw edges
            for conn in results['license_conn_details']:
                if conn['src_ip'] in pos and conn['dst_ip'] in pos:
                    src_pos = pos[conn['src_ip']]
                    dst_pos = pos[conn['dst_ip']]

                    # Calculate edge width based on bytes
                    total_bytes = conn['bytes_sent'] + conn['bytes_received']
                    width = 0.5 + min(2.0, total_bytes / 1000)

                    plt.plot([src_pos[0], dst_pos[0]], [src_pos[1], dst_pos[1]], 'g-', linewidth=width)

            plt.xlim(0, 1)
            plt.ylim(0, 1)
            plt.axis('off')

            # Add legend
            plt.plot([], [], 'bo', markersize=10, label='Clients')
            plt.plot([], [], 'rs', markersize=10, label='License Servers')
            plt.plot([], [], 'g-', linewidth=2, label='Connections')
            plt.legend(loc='upper center', bbox_to_anchor=(0.5, 0.05), ncol=3)

            # Save figure
            plt.savefig(f"{self.config['visualization_dir']}/license_connections_{timestamp}.png",
                       dpi=300, bbox_inches='tight')
            plt.close()

            self.logger.info(f"Generated visualizations in {self.config['visualization_dir']}")

        except Exception as e:
            self.logger.error("Error generating visualizations: %s", e)

    def get_results(self) -> Dict[str, Any]:
        """
        Get network analysis results.

        This method returns comprehensive results from the network traffic analysis,
        including packet statistics, protocol detection, license server identification,
        and suspicious traffic patterns.

        Returns:
            Dictionary containing:
            - packets_analyzed: Total number of packets analyzed
            - protocols_detected: List of detected protocols
            - suspicious_traffic: List of suspicious traffic patterns
            - statistics: Detailed traffic statistics
        """
        # Analyze traffic if not already done
        if not hasattr(self, '_last_analysis_results'):
            self._last_analysis_results = self.analyze_traffic()

        # Get base analysis results
        analysis = self._last_analysis_results or {
            'total_packets': 0,
            'total_connections': 0,
            'license_connections': 0,
            'license_servers': [],
            'license_conn_details': []
        }

        # Detect protocols used
        protocols_detected = []
        port_protocol_map = {
            80: 'HTTP',
            443: 'HTTPS',
            27000: 'FlexLM',
            27001: 'FlexLM',
            1947: 'HASP/Sentinel',
            6001: 'HASP/Sentinel',
            22350: 'CodeMeter',
            2080: 'License Manager',
            8224: 'License Server',
            5093: 'Sentinel RMS'
        }

        detected_ports = set()
        for conn in self.connections.values():
            detected_ports.add(conn['dst_port'])
            detected_ports.add(conn['src_port'])

        for port in detected_ports:
            if port in port_protocol_map:
                protocol = port_protocol_map[port]
                if protocol not in protocols_detected:
                    protocols_detected.append(protocol)

        # Add generic TCP if no specific protocols detected
        if not protocols_detected and self.connections:
            protocols_detected.append('TCP')

        # Identify suspicious traffic patterns
        suspicious_traffic = []

        for conn_key, conn in self.connections.items():
            # Check for suspicious patterns
            suspicious_indicators = []

            # 1. Unusual license server ports
            if conn['dst_port'] > 40000 and conn.get('is_license'):
                suspicious_indicators.append('High port number for license traffic')

            # 2. Excessive data transfer
            total_bytes = conn['bytes_sent'] + conn['bytes_received']
            if total_bytes > 1000000:  # 1MB
                suspicious_indicators.append(f'Large data transfer: {total_bytes} bytes')

            # 3. Long-duration connections
            if 'duration' in conn or ('last_time' in conn and 'start_time' in conn):
                duration = conn.get('duration', conn['last_time'] - conn['start_time'])
                if duration > 3600:  # 1 hour
                    suspicious_indicators.append(f'Long connection duration: {duration:.0f}s')

            # 4. Potential data exfiltration
            if conn['bytes_sent'] > conn['bytes_received'] * 10:
                suspicious_indicators.append('Asymmetric data flow (potential exfiltration)')

            # 5. Non-standard license protocols
            if conn.get('is_license') and conn['dst_port'] not in self.license_ports:
                suspicious_indicators.append(f'Non-standard license port: {conn["dst_port"]}')

            if suspicious_indicators:
                suspicious_traffic.append({
                    'connection': conn_key,
                    'src_ip': conn['src_ip'],
                    'dst_ip': conn['dst_ip'],
                    'src_port': conn['src_port'],
                    'dst_port': conn['dst_port'],
                    'indicators': suspicious_indicators,
                    'severity': self._assess_threat_level(suspicious_indicators)
                })

        # Calculate comprehensive statistics
        statistics = {
            'capture_duration': self._calculate_capture_duration(),
            'packets_per_second': self._calculate_packet_rate(),
            'total_bytes': sum(conn['bytes_sent'] + conn['bytes_received'] for conn in self.connections.values()),
            'unique_ips': len(set(conn['src_ip'] for conn in self.connections.values()) |
                              set(conn['dst_ip'] for conn in self.connections.values())),
            'protocol_distribution': self._calculate_protocol_distribution(),
            'port_distribution': self._calculate_port_distribution(),
            'license_traffic_percentage': self._calculate_license_traffic_percentage(),
            'peak_traffic_time': self._identify_peak_traffic_time(),
            'connection_durations': self._analyze_connection_durations()
        }

        # Compile final results
        results = {
            'packets_analyzed': analysis['total_packets'],
            'protocols_detected': protocols_detected,
            'suspicious_traffic': suspicious_traffic,
            'statistics': statistics,
            'license_analysis': {
                'license_servers': analysis['license_servers'],
                'license_connections': analysis['license_connections'],
                'license_connection_details': analysis['license_conn_details']
            },
            'summary': {
                'total_connections': analysis['total_connections'],
                'suspicious_connections': len(suspicious_traffic),
                'identified_license_servers': len(analysis['license_servers']),
                'analysis_timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
            }
        }

        return results

    def _assess_threat_level(self, indicators: list) -> str:
        """Assess threat level based on suspicious indicators."""
        if len(indicators) >= 3:
            return 'high'
        elif len(indicators) >= 2:
            return 'medium'
        else:
            return 'low'

    def _calculate_capture_duration(self) -> float:
        """Calculate total capture duration in seconds."""
        if not self.packets:
            return 0.0

        timestamps = [pkt['timestamp'] for pkt in self.packets]
        if timestamps:
            return max(timestamps) - min(timestamps)
        return 0.0

    def _calculate_packet_rate(self) -> float:
        """Calculate average packets per second."""
        duration = self._calculate_capture_duration()
        if duration > 0:
            return len(self.packets) / duration
        return 0.0

    def _calculate_protocol_distribution(self) -> Dict[str, int]:
        """Calculate distribution of protocols."""
        distribution = {}

        port_protocol_map = {
            80: 'HTTP', 443: 'HTTPS', 27000: 'FlexLM', 27001: 'FlexLM',
            1947: 'HASP', 6001: 'HASP', 22350: 'CodeMeter'
        }

        for conn in self.connections.values():
            protocol = port_protocol_map.get(conn['dst_port'], 'Other')
            distribution[protocol] = distribution.get(protocol, 0) + len(conn['packets'])

        return distribution

    def _calculate_port_distribution(self) -> Dict[int, int]:
        """Calculate distribution of destination ports."""
        distribution = {}

        for conn in self.connections.values():
            port = conn['dst_port']
            distribution[port] = distribution.get(port, 0) + 1

        return dict(sorted(distribution.items(), key=lambda x: x[1], reverse=True)[:10])

    def _calculate_license_traffic_percentage(self) -> float:
        """Calculate percentage of traffic that is license-related."""
        if not self.packets:
            return 0.0

        license_packets = sum(len(conn['packets']) for conn in self.connections.values()
                            if conn.get('is_license', False))

        return (license_packets / len(self.packets)) * 100 if self.packets else 0.0

    def _identify_peak_traffic_time(self) -> Optional[str]:
        """Identify time period with peak traffic."""
        if not self.packets:
            return None

        # Group packets by minute
        minute_counts = {}
        for pkt in self.packets:
            minute = int(pkt['timestamp'] / 60) * 60
            minute_counts[minute] = minute_counts.get(minute, 0) + 1

        if minute_counts:
            peak_minute = max(minute_counts.items(), key=lambda x: x[1])[0]
            return time.strftime('%Y-%m-%d %H:%M', time.localtime(peak_minute))

        return None

    def _analyze_connection_durations(self) -> Dict[str, float]:
        """Analyze connection duration statistics."""
        durations = []

        for conn in self.connections.values():
            if 'last_time' in conn and 'start_time' in conn:
                duration = conn['last_time'] - conn['start_time']
                durations.append(duration)

        if not durations:
            return {'min': 0, 'max': 0, 'avg': 0, 'total': 0}

        return {
            'min': min(durations),
            'max': max(durations),
            'avg': sum(durations) / len(durations),
            'total': len(durations)
        }

    def stop_capture(self) -> bool:
        """
        Stop the packet capture process.

        Returns:
            bool: True if capture was stopped successfully, False otherwise
        """
        try:
            # Set flag to stop capture threads
            self.capturing = False

            self.logger.info("Stopping packet capture...")

            # Give capture threads time to finish gracefully
            time.sleep(0.5)

            # Log final statistics
            total_packets = len(self.packets)
            total_connections = len(self.connections)
            license_connections = sum(1 for conn in self.connections.values() if conn.get('is_license', False))

            self.logger.info(
                "Packet capture stopped. Total packets: %d, Total connections: %d, License connections: %d",
                total_packets, total_connections, license_connections
            )

            # Auto-analyze if configured
            if self.config.get('auto_analyze', True) and total_packets > 0:
                self.analyze_traffic()

            return True

        except Exception as e:
            self.logger.error("Error stopping capture: %s", e)
            return False

    def generate_report(self, filename: Optional[str] = None) -> bool:
        """
        Generate an HTML report of license traffic analysis.

        Args:
            filename: Output filename (optional)

        Returns:
            bool: True if generated successfully, False otherwise
        """
        try:
            # Analyze traffic
            results = self.analyze_traffic()

            if not results:
                self.logger.error("No analysis results available")
                return False

            # Use default filename if not provided
            if not filename:
                timestamp = time.strftime('%Y%m%d_%H%M%S')
                filename = f"{self.config['visualization_dir']}/license_report_{timestamp}.html"

            from ...utils.reporting.html_templates import close_html, get_traffic_html_template

            # Create HTML report using common template
            html = get_traffic_html_template() + f"""
                <h1>License Traffic Analysis Report</h1>
                <p>Generated on {time.strftime('%Y-%m-%d %H:%M:%S')}</p>

                <div class="summary">
                    <h2>Summary</h2>
                    <p>Total Packets: {results['total_packets']}</p>
                    <p>Total Connections: {results['total_connections']}</p>
                    <p>License-related Connections: {results['license_connections']}</p>
                    <p>License Servers: {', '.join(results['license_servers']) if results['license_servers'] else 'None detected'}</p>
                </div>

                <h2>License Connections</h2>
            """

            if results['license_conn_details']:
                html += """
                <table>
                    <tr>
                        <th>Source</th>
                        <th>Destination</th>
                        <th>Packets</th>
                        <th>Bytes Sent</th>
                        <th>Bytes Received</th>
                        <th>Duration (s)</th>
                        <th>License Patterns</th>
                    </tr>
                """

                for conn in results['license_conn_details']:
                    html += f"""
                    <tr>
                        <td>{conn['src_ip']}:{conn['src_port']}</td>
                        <td>{conn['dst_ip']}:{conn['dst_port']}</td>
                        <td>{conn['packets']}</td>
                        <td>{conn['bytes_sent']}</td>
                        <td>{conn['bytes_received']}</td>
                        <td>{conn['duration']:.2f}</td>
                        <td>{', '.join(conn['patterns']) if conn['patterns'] else 'N/A'}</td>
                    </tr>
                    """

                html += "</table>"
            else:
                html += "<p>No license connections detected.</p>"

            # Add visualizations
            html += """
                <h2>Visualizations</h2>
            """

            # Find visualization files
            visualization_files = glob.glob(f"{self.config['visualization_dir']}/*.png")
            if visualization_files:
                visualization_files.sort(key=os.path.getmtime, reverse=True)

                for vis_file in visualization_files[:3]:  # Show latest 3 visualizations
                    vis_name = os.path.basename(vis_file).replace('.png', '').replace('_', ' ').title()
                    # Use relative path for HTML
                    relative_path = os.path.relpath(vis_file, os.path.dirname(filename))
                    html += f"""
                    <div class="visualization">
                        <h3>{vis_name}</h3>
                        <img src="{relative_path}" alt="{vis_name}">
                    </div>
                    """
            else:
                html += "<p>No visualizations available.</p>"

            html += close_html()

            # Write HTML file
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(html)

            self.logger.info("Generated HTML report: %s", filename)
            return True

        except Exception as e:
            self.logger.error("Error generating report: %s", e)
            self.logger.error(traceback.format_exc())
            return False


__all__ = ['NetworkTrafficAnalyzer']

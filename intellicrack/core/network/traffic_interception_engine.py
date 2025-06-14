"""
Real Traffic Interception and Analysis Engine

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

import socket
import threading
import time
import ssl
import struct
import queue
import hashlib
import json
from typing import Dict, List, Optional, Tuple, Any, Callable
from dataclasses import dataclass
from ...utils.logger import get_logger

# Import protocol parsers
try:
    from .protocols.flexlm_parser import FlexLMProtocolParser
    from .protocols.hasp_parser import HASPSentinelParser
    from .protocols.codemeter_parser import CodeMeterProtocolParser
    from .protocols.adobe_parser import AdobeLicensingParser
    from .protocols.autodesk_parser import AutodeskLicensingParser
    HAS_PROTOCOL_PARSERS = True
except ImportError:
    HAS_PROTOCOL_PARSERS = False

logger = get_logger(__name__)

@dataclass
class InterceptedPacket:
    """Structure for intercepted network packet"""
    timestamp: float
    source_ip: str
    dest_ip: str
    source_port: int
    dest_port: int
    protocol: str
    data: bytes
    is_request: bool
    connection_id: str

@dataclass
class AnalyzedTraffic:
    """Structure for analyzed license traffic"""
    packet: InterceptedPacket
    protocol_type: str
    parsed_data: Optional[Any]
    is_license_related: bool
    confidence: float
    analysis_notes: List[str]

class TrafficInterceptionEngine:
    """Real network traffic interception and license protocol analysis engine"""
    
    # Common license server ports
    LICENSE_PORTS = {
        27000: "FlexLM",
        27001: "FlexLM_Vendor",
        1947: "HASP_LM",
        22350: "CodeMeter",
        443: "HTTPS_License",
        80: "HTTP_License",
        7788: "Adobe_License",
        2080: "Autodesk_License",
        4085: "Wibu_License",
        6789: "RLM_License",
        5093: "Sentinel_LM"
    }
    
    # Known license server hostnames
    LICENSE_HOSTNAMES = [
        "license.autodesk.com",
        "activate.adobe.com",
        "lm.mathworks.com",
        "flexnet.bentley.com",
        "licensing.ansys.com",
        "lmgrd",
        "flexlm",
        "hasplms",
        "codemeter",
        "rlm",
        "sentinel"
    ]
    
    def __init__(self, interface: str = "0.0.0.0"):
        self.logger = get_logger(__name__)
        self.interface = interface
        self.is_running = False
        self.capture_threads = []
        self.packet_queue = queue.Queue(maxsize=10000)
        self.analysis_callbacks = []
        self.intercepted_connections = {}
        self.protocol_parsers = {}
        self.traffic_statistics = {
            "packets_captured": 0,
            "license_packets": 0,
            "protocols_detected": set(),
            "start_time": None
        }
        
        # Initialize protocol parsers
        self._initialize_protocol_parsers()
        
        # Create SSL context for HTTPS interception
        self._setup_ssl_context()
        
    def _initialize_protocol_parsers(self):
        """Initialize available protocol parsers"""
        if not HAS_PROTOCOL_PARSERS:
            self.logger.warning("Protocol parsers not available")
            return
            
        try:
            self.protocol_parsers = {
                "flexlm": FlexLMProtocolParser(),
                "hasp": HASPSentinelParser(),
                "codemeter": CodeMeterProtocolParser(),
                "adobe": AdobeLicensingParser(),
                "autodesk": AutodeskLicensingParser()
            }
            self.logger.info(f"Initialized {len(self.protocol_parsers)} protocol parsers")
        except Exception as e:
            self.logger.error(f"Failed to initialize protocol parsers: {e}")
            
    def _setup_ssl_context(self):
        """Setup SSL context for HTTPS traffic interception"""
        try:
            self.ssl_context = ssl.create_default_context()
            self.ssl_context.check_hostname = False
            self.ssl_context.verify_mode = ssl.CERT_NONE
            
            # Create self-signed certificate for MITM
            self.ssl_cert_path = self._generate_ssl_certificate()
            
        except Exception as e:
            self.logger.error(f"Failed to setup SSL context: {e}")
            self.ssl_context = None
            
    def _generate_ssl_certificate(self) -> str:
        """Generate self-signed SSL certificate for traffic interception"""
        try:
            # This is a simplified implementation
            # In production, you'd use proper certificate generation
            import tempfile
            import os
            
            cert_dir = tempfile.mkdtemp()
            cert_path = os.path.join(cert_dir, "intercept.pem")
            
            # Generate a basic self-signed certificate
            # This is a placeholder - real implementation would use cryptography library
            with open(cert_path, 'w') as f:
                f.write("-----BEGIN CERTIFICATE-----\n")
                f.write("MIICpjCCAY4CAQAwDQYJKoZIhvcNAQELBQAwDTELMAkGA1UEBhMCVVMwHhcNMjUw\n")
                f.write("-----END CERTIFICATE-----\n")
                
            return cert_path
            
        except Exception as e:
            self.logger.error(f"Failed to generate SSL certificate: {e}")
            return None
            
    def start_interception(self, target_ports: Optional[List[int]] = None):
        """
        Start real network traffic interception
        
        Args:
            target_ports: Specific ports to monitor, None for all license ports
        """
        if self.is_running:
            self.logger.warning("Traffic interception already running")
            return
            
        self.is_running = True
        self.traffic_statistics["start_time"] = time.time()
        
        # Determine ports to monitor
        if target_ports is None:
            target_ports = list(self.LICENSE_PORTS.keys())
            
        self.logger.info(f"Starting traffic interception on ports: {target_ports}")
        
        # Start packet capture threads for each port
        for port in target_ports:
            thread = threading.Thread(
                target=self._capture_port_traffic,
                args=(port,),
                daemon=True
            )
            thread.start()
            self.capture_threads.append(thread)
            
        # Start raw packet capture thread
        raw_thread = threading.Thread(
            target=self._capture_raw_traffic,
            daemon=True
        )
        raw_thread.start()
        self.capture_threads.append(raw_thread)
        
        # Start analysis thread
        analysis_thread = threading.Thread(
            target=self._analyze_captured_traffic,
            daemon=True
        )
        analysis_thread.start()
        self.capture_threads.append(analysis_thread)
        
        self.logger.info("Traffic interception started successfully")
        
    def stop_interception(self):
        """Stop traffic interception"""
        if not self.is_running:
            return
            
        self.is_running = False
        self.logger.info("Stopping traffic interception...")
        
        # Wait for threads to finish
        for thread in self.capture_threads:
            if thread.is_alive():
                thread.join(timeout=2.0)
                
        self.capture_threads.clear()
        self.logger.info("Traffic interception stopped")
        
    def _capture_port_traffic(self, port: int):
        """Capture traffic on a specific port"""
        try:
            # Create listening socket for the port
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(1.0)
            
            try:
                sock.bind((self.interface, port))
                sock.listen(5)
                self.logger.info(f"Listening on port {port} for {self.LICENSE_PORTS.get(port, 'Unknown')}")
                
                while self.is_running:
                    try:
                        client_socket, client_addr = sock.accept()
                        # Handle connection in separate thread
                        conn_thread = threading.Thread(
                            target=self._handle_intercepted_connection,
                            args=(client_socket, client_addr, port),
                            daemon=True
                        )
                        conn_thread.start()
                        
                    except socket.timeout:
                        continue
                    except Exception as e:
                        if self.is_running:
                            self.logger.debug(f"Port {port} accept error: {e}")
                        
            finally:
                sock.close()
                
        except Exception as e:
            self.logger.error(f"Failed to capture traffic on port {port}: {e}")
            
    def _capture_raw_traffic(self):
        """Capture raw network traffic using packet sniffing"""
        try:
            # This requires raw socket privileges
            try:
                # Create raw socket for packet capture
                raw_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
                raw_sock.settimeout(1.0)
                
                self.logger.info("Started raw packet capture")
                
                while self.is_running:
                    try:
                        packet_data, addr = raw_sock.recvfrom(65535)
                        self._process_raw_packet(packet_data, addr)
                        
                    except socket.timeout:
                        continue
                    except Exception as e:
                        if self.is_running:
                            self.logger.debug(f"Raw capture error: {e}")
                            
            except PermissionError:
                self.logger.warning("Raw socket requires administrator privileges")
                # Fallback to alternative capture methods
                self._capture_with_fallback()
                
        except Exception as e:
            self.logger.error(f"Raw traffic capture failed: {e}")
            
    def _capture_with_fallback(self):
        """Fallback capture method when raw sockets not available"""
        try:
            # Use alternative capture methods
            # This could integrate with pcap libraries if available
            
            self.logger.info("Using fallback capture method")
            
            while self.is_running:
                # Monitor network connections via system APIs
                connections = self._get_network_connections()
                
                for conn in connections:
                    if self._is_license_connection(conn):
                        self._monitor_connection(conn)
                        
                time.sleep(1.0)
                
        except Exception as e:
            self.logger.error(f"Fallback capture failed: {e}")
            
    def _process_raw_packet(self, packet_data: bytes, addr: Tuple[str, int]):
        """Process raw network packet"""
        try:
            # Parse IP header
            ip_header = struct.unpack('!BBHHHBBH4s4s', packet_data[:20])
            src_ip = socket.inet_ntoa(ip_header[8])
            dest_ip = socket.inet_ntoa(ip_header[9])
            
            # Parse TCP header if it's TCP
            if ip_header[6] == 6:  # TCP protocol
                tcp_header = struct.unpack('!HHLLBBHHH', packet_data[20:40])
                src_port = tcp_header[0]
                dest_port = tcp_header[1]
                
                # Check if this looks like license traffic
                if self._is_license_port(src_port) or self._is_license_port(dest_port):
                    payload = packet_data[40:]
                    
                    if payload:
                        packet = InterceptedPacket(
                            timestamp=time.time(),
                            source_ip=src_ip,
                            dest_ip=dest_ip,
                            source_port=src_port,
                            dest_port=dest_port,
                            protocol="TCP",
                            data=payload,
                            is_request=dest_port in self.LICENSE_PORTS,
                            connection_id=f"{src_ip}:{src_port}-{dest_ip}:{dest_port}"
                        )
                        
                        self.packet_queue.put(packet)
                        self.traffic_statistics["packets_captured"] += 1
                        
        except Exception as e:
            self.logger.debug(f"Failed to process raw packet: {e}")
            
    def _handle_intercepted_connection(self, client_socket: socket.socket, 
                                     client_addr: Tuple[str, int], port: int):
        """Handle an intercepted connection"""
        try:
            connection_id = f"{client_addr[0]}:{client_addr[1]}-{self.interface}:{port}"
            self.logger.info(f"Intercepted connection: {connection_id}")
            
            # Store connection info
            self.intercepted_connections[connection_id] = {
                "client_addr": client_addr,
                "port": port,
                "start_time": time.time(),
                "protocol_type": self.LICENSE_PORTS.get(port, "Unknown"),
                "data_exchanged": 0
            }
            
            client_socket.settimeout(30.0)
            
            while self.is_running:
                try:
                    # Receive data from client
                    data = client_socket.recv(4096)
                    if not data:
                        break
                        
                    # Create packet record
                    packet = InterceptedPacket(
                        timestamp=time.time(),
                        source_ip=client_addr[0],
                        dest_ip=self.interface,
                        source_port=client_addr[1],
                        dest_port=port,
                        protocol="TCP",
                        data=data,
                        is_request=True,
                        connection_id=connection_id
                    )
                    
                    # Queue for analysis
                    self.packet_queue.put(packet)
                    self.traffic_statistics["packets_captured"] += 1
                    
                    # Update connection stats
                    self.intercepted_connections[connection_id]["data_exchanged"] += len(data)
                    
                    # Attempt to forward to real server or generate response
                    response = self._handle_license_request(packet)
                    if response:
                        client_socket.send(response)
                        
                except socket.timeout:
                    break
                except Exception as e:
                    self.logger.debug(f"Connection handling error: {e}")
                    break
                    
        finally:
            try:
                client_socket.close()
            except:
                pass
            if connection_id in self.intercepted_connections:
                del self.intercepted_connections[connection_id]
                
    def _analyze_captured_traffic(self):
        """Analyze captured traffic for license protocols"""
        while self.is_running:
            try:
                # Get packet from queue with timeout
                try:
                    packet = self.packet_queue.get(timeout=1.0)
                except queue.Empty:
                    continue
                    
                # Analyze the packet
                analysis = self._analyze_packet(packet)
                
                if analysis.is_license_related:
                    self.traffic_statistics["license_packets"] += 1
                    self.traffic_statistics["protocols_detected"].add(analysis.protocol_type)
                    
                    # Notify analysis callbacks
                    for callback in self.analysis_callbacks:
                        try:
                            callback(analysis)
                        except Exception as e:
                            self.logger.error(f"Analysis callback error: {e}")
                            
                self.packet_queue.task_done()
                
            except Exception as e:
                self.logger.error(f"Traffic analysis error: {e}")
                
    def _analyze_packet(self, packet: InterceptedPacket) -> AnalyzedTraffic:
        """Analyze a single packet for license protocol content"""
        analysis = AnalyzedTraffic(
            packet=packet,
            protocol_type="unknown",
            parsed_data=None,
            is_license_related=False,
            confidence=0.0,
            analysis_notes=[]
        )
        
        try:
            # Check if port suggests license traffic
            if self._is_license_port(packet.dest_port):
                analysis.is_license_related = True
                analysis.protocol_type = self.LICENSE_PORTS.get(packet.dest_port, "unknown")
                analysis.confidence += 0.3
                analysis.analysis_notes.append(f"Known license port: {packet.dest_port}")
                
            # Analyze packet content with protocol parsers
            for parser_name, parser in self.protocol_parsers.items():
                try:
                    if hasattr(parser, 'parse_request'):
                        parsed = parser.parse_request(packet.data)
                        if parsed:
                            analysis.parsed_data = parsed
                            analysis.protocol_type = parser_name
                            analysis.is_license_related = True
                            analysis.confidence += 0.7
                            analysis.analysis_notes.append(f"Parsed as {parser_name} protocol")
                            break
                except Exception as e:
                    self.logger.debug(f"Parser {parser_name} failed: {e}")
                    
            # Check for license-related keywords in data
            if self._contains_license_keywords(packet.data):
                analysis.is_license_related = True
                analysis.confidence += 0.2
                analysis.analysis_notes.append("Contains license keywords")
                
            # Check for SSL/TLS traffic that might be license-related
            if self._is_ssl_traffic(packet.data):
                if self._is_license_hostname(packet.dest_ip):
                    analysis.is_license_related = True
                    analysis.protocol_type = "https_license"
                    analysis.confidence += 0.4
                    analysis.analysis_notes.append("SSL/TLS to license server")
                    
        except Exception as e:
            analysis.analysis_notes.append(f"Analysis error: {e}")
            
        return analysis        
    def _handle_license_request(self, packet: InterceptedPacket) -> Optional[bytes]:
        """Handle intercepted license request and generate appropriate response"""
        try:
            # Analyze packet to determine protocol
            analysis = self._analyze_packet(packet)
            
            if not analysis.is_license_related:
                return None
                
            # Generate response using appropriate parser
            if analysis.protocol_type in self.protocol_parsers:
                parser = self.protocol_parsers[analysis.protocol_type]
                
                if analysis.parsed_data:
                    # Generate response using parsed data
                    if hasattr(parser, 'generate_response'):
                        response_obj = parser.generate_response(analysis.parsed_data)
                        
                        # Serialize response back to bytes
                        if hasattr(parser, 'serialize_response'):
                            return parser.serialize_response(response_obj)
                            
            # Generate generic success response if no specific parser available
            return self._generate_generic_response(packet)
            
        except Exception as e:
            self.logger.error(f"Failed to handle license request: {e}")
            return None
            
    def _generate_generic_response(self, packet: InterceptedPacket) -> bytes:
        """Generate generic license response"""
        try:
            # Check if this looks like HTTP traffic
            if b'HTTP' in packet.data[:100] or b'GET' in packet.data[:10] or b'POST' in packet.data[:10]:
                # Generate HTTP response
                response_body = json.dumps({
                    "status": "success",
                    "license_valid": True,
                    "expiry_date": "2025-12-31",
                    "features_enabled": ["full_access"]
                })
                
                http_response = (
                    f"HTTP/1.1 200 OK\r\n"
                    f"Content-Type: application/json\r\n"
                    f"Content-Length: {len(response_body)}\r\n"
                    f"Server: intellicrack-license-interceptor\r\n"
                    f"\r\n"
                    f"{response_body}"
                )
                
                return http_response.encode()
                
            else:
                # Generate binary response (success status)
                return b'\x00\x00\x00\x00'  # Generic success
                
        except Exception as e:
            self.logger.error(f"Failed to generate generic response: {e}")
            return b'\xFF\xFF\xFF\xFF'  # Generic error
            
    def _is_license_port(self, port: int) -> bool:
        """Check if port is commonly used for license servers"""
        return port in self.LICENSE_PORTS
        
    def _is_license_hostname(self, hostname: str) -> bool:
        """Check if hostname is license-related"""
        hostname_lower = hostname.lower()
        return any(license_host in hostname_lower for license_host in self.LICENSE_HOSTNAMES)
        
    def _contains_license_keywords(self, data: bytes) -> bool:
        """Check if data contains license-related keywords"""
        try:
            # Convert to string for keyword searching
            text = data.decode('utf-8', errors='ignore').lower()
            
            license_keywords = [
                'license', 'activation', 'checkout', 'flexlm', 'hasp', 'sentinel',
                'codemeter', 'entitlement', 'subscription', 'validate', 'authenticate',
                'vendor_code', 'feature_id', 'product_key', 'serial_number',
                'machine_id', 'hostid', 'dongle', 'hardlock', 'wibu', 'rlm'
            ]
            
            return any(keyword in text for keyword in license_keywords)
            
        except:
            return False
            
    def _is_ssl_traffic(self, data: bytes) -> bool:
        """Check if data appears to be SSL/TLS traffic"""
        try:
            # Check for SSL/TLS handshake patterns
            if len(data) < 6:
                return False
                
            # TLS record types: 22=handshake, 23=application_data, 21=alert, 20=change_cipher_spec
            if data[0] in [20, 21, 22, 23] and data[1] == 3:  # TLS version starts with 3
                return True
                
            # Check for SSL v2 patterns
            if len(data) >= 2:
                record_length = struct.unpack('>H', data[:2])[0]
                if 0x8000 <= record_length <= 0xFFFF:  # SSL v2 record length pattern
                    return True
                    
            return False
            
        except:
            return False
            
    def _get_network_connections(self) -> List[Dict[str, Any]]:
        """Get current network connections (fallback method)"""
        connections = []
        try:
            # This would use system APIs to get network connections
            # Placeholder implementation
            import psutil
            
            for conn in psutil.net_connections():
                if conn.status == 'ESTABLISHED':
                    connections.append({
                        'local_addr': conn.laddr,
                        'remote_addr': conn.raddr,
                        'pid': conn.pid,
                        'status': conn.status
                    })
                    
        except ImportError:
            # Fallback if psutil not available
            self.logger.debug("psutil not available for connection monitoring")
        except Exception as e:
            self.logger.debug(f"Failed to get network connections: {e}")
            
        return connections
        
    def _is_license_connection(self, connection: Dict[str, Any]) -> bool:
        """Check if network connection is license-related"""
        try:
            if connection.get('remote_addr'):
                remote_port = connection['remote_addr'][1]
                return self._is_license_port(remote_port)
        except:
            pass
        return False
        
    def _monitor_connection(self, connection: Dict[str, Any]):
        """Monitor a specific network connection"""
        try:
            # This would set up monitoring for the specific connection
            self.logger.debug(f"Monitoring connection: {connection}")
        except Exception as e:
            self.logger.debug(f"Failed to monitor connection: {e}")
            
    def add_analysis_callback(self, callback: Callable[[AnalyzedTraffic], None]):
        """Add callback function to be called when license traffic is analyzed"""
        self.analysis_callbacks.append(callback)
        
    def remove_analysis_callback(self, callback: Callable[[AnalyzedTraffic], None]):
        """Remove analysis callback"""
        if callback in self.analysis_callbacks:
            self.analysis_callbacks.remove(callback)
            
    def get_statistics(self) -> Dict[str, Any]:
        """Get traffic interception statistics"""
        stats = self.traffic_statistics.copy()
        stats["protocols_detected"] = list(stats["protocols_detected"])
        stats["active_connections"] = len(self.intercepted_connections)
        stats["is_running"] = self.is_running
        
        if stats["start_time"]:
            stats["uptime_seconds"] = time.time() - stats["start_time"]
            
        return stats
        
    def get_active_connections(self) -> Dict[str, Dict[str, Any]]:
        """Get currently active intercepted connections"""
        return self.intercepted_connections.copy()
        
    def set_dns_redirection(self, hostname: str, redirect_ip: str = "127.0.0.1"):
        """Set up DNS redirection for license server hostnames"""
        try:
            # This would modify system DNS or hosts file
            import platform
            
            if platform.system() == "Windows":
                hosts_file = r"C:\Windows\System32\drivers\etc\hosts"
            else:
                hosts_file = "/etc/hosts"
                
            # Read current hosts file
            try:
                with open(hosts_file, 'r') as f:
                    hosts_content = f.read()
            except PermissionError:
                self.logger.error("DNS redirection requires administrator privileges")
                return False
                
            # Add redirection entry
            redirect_entry = f"\n{redirect_ip}\t{hostname}\t# Intellicrack license interception"
            
            if redirect_entry not in hosts_content:
                with open(hosts_file, 'a') as f:
                    f.write(redirect_entry)
                    
                self.logger.info(f"Added DNS redirection: {hostname} -> {redirect_ip}")
                return True
                
        except Exception as e:
            self.logger.error(f"Failed to set DNS redirection: {e}")
            
        return False
        
    def remove_dns_redirection(self, hostname: str):
        """Remove DNS redirection for hostname"""
        try:
            import platform
            
            if platform.system() == "Windows":
                hosts_file = r"C:\Windows\System32\drivers\etc\hosts"
            else:
                hosts_file = "/etc/hosts"
                
            # Read and filter hosts file
            try:
                with open(hosts_file, 'r') as f:
                    lines = f.readlines()
                    
                # Remove lines containing the hostname and Intellicrack comment
                filtered_lines = [
                    line for line in lines 
                    if not (hostname in line and "Intellicrack license interception" in line)
                ]
                
                with open(hosts_file, 'w') as f:
                    f.writelines(filtered_lines)
                    
                self.logger.info(f"Removed DNS redirection for {hostname}")
                
            except PermissionError:
                self.logger.error("DNS redirection removal requires administrator privileges")
                
        except Exception as e:
            self.logger.error(f"Failed to remove DNS redirection: {e}")
            
    def setup_transparent_proxy(self, target_host: str, target_port: int, 
                               local_port: Optional[int] = None):
        """Set up transparent proxy for license server traffic"""
        try:
            if local_port is None:
                local_port = target_port
                
            # Create proxy socket
            proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            proxy_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            proxy_socket.bind((self.interface, local_port))
            proxy_socket.listen(5)
            
            self.logger.info(f"Started transparent proxy: localhost:{local_port} -> {target_host}:{target_port}")
            
            # Handle proxy connections
            def proxy_handler():
                while self.is_running:
                    try:
                        client_socket, client_addr = proxy_socket.accept()
                        
                        # Start proxy thread
                        proxy_thread = threading.Thread(
                            target=self._handle_proxy_connection,
                            args=(client_socket, client_addr, target_host, target_port),
                            daemon=True
                        )
                        proxy_thread.start()
                        
                    except Exception as e:
                        if self.is_running:
                            self.logger.debug(f"Proxy accept error: {e}")
                            
            proxy_thread = threading.Thread(target=proxy_handler, daemon=True)
            proxy_thread.start()
            self.capture_threads.append(proxy_thread)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to setup transparent proxy: {e}")
            return False
            
    def _handle_proxy_connection(self, client_socket: socket.socket, 
                                client_addr: Tuple[str, int],
                                target_host: str, target_port: int):
        """Handle transparent proxy connection"""
        target_socket = None
        try:
            # Connect to target server
            target_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            target_socket.connect((target_host, target_port))
            
            # Start bidirectional forwarding
            def forward_data(src_socket, dst_socket, direction):
                try:
                    while self.is_running:
                        data = src_socket.recv(4096)
                        if not data:
                            break
                            
                        # Intercept and analyze data
                        packet = InterceptedPacket(
                            timestamp=time.time(),
                            source_ip=client_addr[0] if direction == "request" else target_host,
                            dest_ip=target_host if direction == "request" else client_addr[0],
                            source_port=client_addr[1] if direction == "request" else target_port,
                            dest_port=target_port if direction == "request" else client_addr[1],
                            protocol="TCP_PROXY",
                            data=data,
                            is_request=direction == "request",
                            connection_id=f"proxy_{client_addr[0]}:{client_addr[1]}"
                        )
                        
                        self.packet_queue.put(packet)
                        
                        # Forward data
                        dst_socket.send(data)
                        
                except Exception as e:
                    self.logger.debug(f"Proxy forwarding error ({direction}): {e}")
                    
            # Start forwarding threads
            request_thread = threading.Thread(
                target=forward_data,
                args=(client_socket, target_socket, "request"),
                daemon=True
            )
            response_thread = threading.Thread(
                target=forward_data,
                args=(target_socket, client_socket, "response"),
                daemon=True
            )
            
            request_thread.start()
            response_thread.start()
            
            # Wait for threads to complete
            request_thread.join()
            response_thread.join()
            
        except Exception as e:
            self.logger.debug(f"Proxy connection error: {e}")
        finally:
            try:
                client_socket.close()
            except:
                pass
            try:
                if target_socket:
                    target_socket.close()
            except:
                pass
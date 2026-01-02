"""Network analysis plugin for Intellicrack.

This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see https://www.gnu.org/licenses/.
"""

import logging
import queue
import socket
import threading
import time
from typing import Any


"""
Network Analysis Plugin Template
Specialized template for network traffic analysis
"""

logger = logging.getLogger(__name__)


class NetworkAnalysisPlugin:
    """Plugin for network traffic analysis and security assessment."""

    def __init__(self) -> None:
        """Initialize the network analysis plugin."""
        super().__init__()
        self.capture_thread: threading.Thread | None = None
        self.packet_queue: queue.Queue[Any] = queue.Queue()
        self.filter_expression: str = ""
        self.logger: logging.Logger = logging.getLogger(__name__)
        self.is_capturing: bool = False
        self.monitoring: bool = False
        self.active_sockets: dict[str, socket.socket] = {}
        self.socket_monitor_thread: threading.Thread | None = None

    def analyze(self, binary_path: str) -> list[str]:
        """Analyze binary for network-related functionality.

        Scans a binary file for network-related indicators such as protocol
        strings (HTTP, HTTPS, FTP) and Windows socket API references that
        suggest network communication capabilities.

        Args:
            binary_path: Path to the binary file to analyze.

        Returns:
            list[str]: A list of analysis results including detected network
                indicators and error messages if the analysis fails.

        Raises:
            Exception: If an error occurs during binary file reading.

        """
        results = [f"Analyzing network capabilities of: {binary_path}"]
        # Check for network-related strings
        network_indicators = [
            b"http://",
            b"https://",
            b"ftp://",
            b"socket",
            b"connect",
            b"bind",
            b"listen",
            b"send",
            b"recv",
            b"WSAStartup",
        ]

        try:
            with open(binary_path, "rb") as f:
                data = f.read()

                if found_indicators := [
                    indicator.decode("utf-8", errors="ignore") for indicator in network_indicators if indicator in data
                ]:
                    results.append("Network indicators found:")
                    results.extend(f"  - {indicator}" for indicator in found_indicators)
                else:
                    results.append("No obvious network indicators found")

        except Exception as e:
            logger.exception("Binary network analysis failed: %s", e)
            results.append(f"Analysis error: {e}")

        return results

    def detect_socket_apis(self, binary_path: str) -> list[str]:
        """Detect socket API usage in binary.

        Scans a binary file for references to socket API functions including
        Windows socket APIs (WSA*), standard socket operations, and SSL/TLS APIs.

        Args:
            binary_path: Path to the binary file to scan.

        Returns:
            list[str]: A list of strings describing detected socket API
                references and any errors encountered during scanning.

        Raises:
            Exception: If an error occurs during binary file reading or API
                detection.

        """
        results = []

        # Socket API function names to search for
        socket_apis = {
            # Windows socket APIs
            b"WSAStartup": "Windows Sockets initialization",
            b"WSACleanup": "Windows Sockets cleanup",
            b"WSASocketA": "Windows async socket creation",
            b"WSAConnect": "Windows async connect",
            b"WSASend": "Windows async send",
            b"WSARecv": "Windows async receive",
            b"WSAAccept": "Windows async accept",
            b"WSAIoctl": "Windows socket I/O control",
            # Standard socket APIs
            b"socket": "Socket creation",
            b"connect": "Socket connection",
            b"bind": "Socket binding",
            b"listen": "Socket listening",
            b"accept": "Socket accept connections",
            b"send": "Socket send data",
            b"recv": "Socket receive data",
            b"sendto": "UDP send",
            b"recvfrom": "UDP receive",
            b"shutdown": "Socket shutdown",
            b"closesocket": "Close socket",
            b"gethostbyname": "DNS hostname resolution",
            b"getaddrinfo": "Address information",
            b"inet_addr": "IP address conversion",
            b"inet_ntoa": "IP address to string",
            b"htons": "Host to network byte order (short)",
            b"htonl": "Host to network byte order (long)",
            b"ntohs": "Network to host byte order (short)",
            b"ntohl": "Network to host byte order (long)",
            # SSL/TLS APIs
            b"SSL_connect": "SSL connection",
            b"SSL_read": "SSL read",
            b"SSL_write": "SSL write",
            b"SSL_CTX_new": "SSL context creation",
        }

        try:
            with open(binary_path, "rb") as f:
                data = f.read()

            if found_apis := [f"{api.decode('ascii')} - {description}" for api, description in socket_apis.items() if api in data]:
                results.append(f"Found {len(found_apis)} socket API references:")
                results.extend(f"   {api}" for api in found_apis)
            else:
                results.append("No socket API references found")

        except Exception as e:
            logger.exception("Socket API detection failed: %s", e)
            results.append(f"Error detecting socket APIs: {e}")

        return results

    def create_socket_server(self, host: str = "127.0.0.1", port: int = 0) -> dict[str, Any]:
        """Create a socket server for testing.

        Creates a TCP socket server bound to the specified host and port. If port
        is 0, the OS will assign an available port. The server is configured to
        listen for incoming connections and socket information is stored for
        later cleanup.

        Args:
            host: IP address to bind the server to. Defaults to "127.0.0.1"
                (localhost).
            port: Port number to bind to. Use 0 to let the OS assign an
                available port. Defaults to 0.

        Returns:
            dict[str, Any]: A dictionary with keys 'success' (bool), 'host',
                'port', 'socket_info' (containing family, type, protocol,
                address, state), 'message', and 'error' (if an exception
                occurred).

        Raises:
            Exception: If socket creation, binding, or listening fails.

        """
        result = {
            "success": False,
            "host": host,
            "port": port,
            "socket_info": {},
        }

        try:
            # Create TCP socket
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            # Bind to address
            server_socket.bind((host, port))

            # Get actual port if 0 was specified
            actual_host, actual_port = server_socket.getsockname()
            result["port"] = actual_port

            # Start listening
            server_socket.listen(5)

            result["success"] = True
            result["socket_info"] = {
                "family": "AF_INET",
                "type": "SOCK_STREAM",
                "protocol": "TCP",
                "address": f"{actual_host}:{actual_port}",
                "state": "LISTENING",
            }

            # Store socket for later use
            self.active_sockets[f"server_{actual_port}"] = server_socket

            result["message"] = f"Server listening on {actual_host}:{actual_port}"

        except Exception as e:
            logger.exception("Socket server creation failed: %s", e)
            result["error"] = str(e)
            result["message"] = f"Failed to create server: {e}"

        return result

    def scan_ports(self, target_host: str, start_port: int = 1, end_port: int = 1000, timeout: float = 0.5) -> list[dict[str, Any]]:
        """Scan ports on target host using sockets.

        Performs a TCP port scan on the target host, attempting to connect to each
        port in the specified range. Open ports are identified and mapped to known
        service names using the socket library and a fallback mapping for common
        ports.

        Args:
            target_host: IP address or hostname of the target to scan.
            start_port: Starting port number for the scan range. Defaults to 1.
            end_port: Ending port number for the scan range (inclusive).
                Defaults to 1000.
            timeout: Socket connection timeout in seconds. Defaults to 0.5.

        Returns:
            list[dict[str, Any]]: A list of dictionaries, each containing
                'port' (int), 'service' (str), 'state' ('open'), and
                'protocol' ('tcp') for each open port found.

        Raises:
            TimeoutError: If socket connection times out during port scanning.
            Exception: If an error occurs during port scanning operations.

        """
        open_ports = []

        for port in range(start_port, end_port + 1):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)

            try:
                result = sock.connect_ex((target_host, port))
                if result == 0:
                    # Port is open
                    service_name = "unknown"
                    try:
                        service_name = socket.getservbyport(port)
                    except Exception as e:
                        logger.debug("Could not resolve service name for port %d: %s", port, e, exc_info=True)
                        # Common port services
                        common_ports = {
                            21: "ftp",
                            22: "ssh",
                            23: "telnet",
                            25: "smtp",
                            53: "dns",
                            80: "http",
                            110: "pop3",
                            143: "imap",
                            443: "https",
                            445: "smb",
                            3306: "mysql",
                            3389: "rdp",
                            5432: "postgresql",
                            6379: "redis",
                            8080: "http-alt",
                            8443: "https-alt",
                            27017: "mongodb",
                        }
                        service_name = common_ports.get(port, "unknown")

                    open_ports.append(
                        {
                            "port": port,
                            "service": service_name,
                            "state": "open",
                            "protocol": "tcp",
                        },
                    )
            except TimeoutError:
                # Port is filtered or host is down
                pass
            except Exception as e:
                # Other errors
                logger.debug("Port scan error on %d: %s", port, e, exc_info=True)
            finally:
                sock.close()

        return open_ports

    def monitor_socket_activity(self, duration: int = 60) -> dict[str, Any]:
        """Monitor real-time socket activity.

        Starts a background thread to monitor established network connections for
        the specified duration. Tracks new connections and closed connections,
        recording timestamps and connection details (local address, remote address,
        PID).

        Args:
            duration: Duration in seconds to monitor socket activity. Defaults
                to 60.

        Returns:
            dict[str, Any]: A dictionary with 'monitoring_started' (timestamp),
                'duration', 'connections' (list of connection events), and
                'statistics' (containing total_events, new_connections, and
                closed_connections counts). Returns error dict if monitoring
                is already in progress.

        Raises:
            Exception: If socket monitoring thread encounters an error during
                execution.

        """
        result = {
            "monitoring_started": time.time(),
            "duration": duration,
            "connections": [],
            "statistics": {},
        }

        if self.monitoring:
            return {"error": "Monitoring already in progress"}

        def monitor_thread() -> None:
            """Monitor socket activity in background thread.

            Tracks established network connections, detecting new connections
            and closed connections, and recording connection details including
            timestamps, local addresses, remote addresses, and process IDs.

            """
            self.monitoring = True
            start_time = time.time()
            connection_log = []

            try:
                from intellicrack.handlers.psutil_handler import psutil

                initial_connections = set()
                for conn in psutil.net_connections(kind="inet"):
                    if conn.status == psutil.CONN_ESTABLISHED:
                        conn_id = f"{conn.laddr}:{conn.raddr}"
                        initial_connections.add(conn_id)

                while self.monitoring and (time.time() - start_time) < duration:
                    current_connections = set()

                    for conn in psutil.net_connections(kind="inet"):
                        if conn.status == psutil.CONN_ESTABLISHED:
                            conn_id = f"{conn.laddr}:{conn.raddr}"
                            current_connections.add(conn_id)

                            # New connection detected
                            if conn_id not in initial_connections:
                                connection_log.append(
                                    {
                                        "timestamp": time.time(),
                                        "type": "new_connection",
                                        "local": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A",
                                        "remote": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A",
                                        "pid": conn.pid if hasattr(conn, "pid") else "N/A",
                                    },
                                )

                    # Check for closed connections
                    closed_connections = initial_connections - current_connections
                    for conn_id in closed_connections:
                        connection_log.append(
                            {
                                "timestamp": time.time(),
                                "type": "closed_connection",
                                "connection": conn_id,
                            },
                        )

                    initial_connections = current_connections
                    time.sleep(1)  # Check every second

            except Exception as e:
                logger.exception("Socket monitoring error: %s", e)
            finally:
                self.monitoring = False

            result["connections"] = connection_log
            result["statistics"] = {
                "total_events": len(connection_log),
                "new_connections": sum(c["type"] == "new_connection" for c in connection_log),
                "closed_connections": sum(c["type"] == "closed_connection" for c in connection_log),
            }

        # Start monitoring in a separate thread
        monitor_thread_obj = threading.Thread(target=monitor_thread)
        monitor_thread_obj.daemon = True
        monitor_thread_obj.start()
        self.socket_monitor_thread = monitor_thread_obj

        return result

    def analyze_socket_traffic(self, capture_file: str | None = None) -> dict[str, Any]:
        """Analyze socket traffic patterns.

        Examines current network connections and identifies usage patterns such as
        frequently used ports and most frequently connected IPs. Detects suspicious
        activity including connections to known malicious ports and possible port
        scanning behavior.

        Args:
            capture_file: Optional path to a capture file. Currently unused but
                available for future integration with packet capture analysis.
                Defaults to None.

        Returns:
            dict[str, Any]: A dictionary with 'analysis_time' (timestamp),
                'patterns' (list of identified patterns with type, description,
                and data), 'suspicious_activity' (list of suspicious items with
                type, details, and severity), and 'error' (if an exception
                occurred).

        Raises:
            Exception: If an error occurs during network connection analysis.

        """
        result: dict[str, Any] = {
            "analysis_time": time.time(),
            "patterns": [],
            "suspicious_activity": [],
        }

        try:
            from intellicrack.handlers.psutil_handler import psutil

            # Get current network connections
            connections = psutil.net_connections(kind="inet")

            # Analyze connection patterns
            port_frequency: dict[int, int] = {}
            ip_frequency: dict[str, int] = {}
            suspicious_ports = [22, 23, 135, 139, 445, 1433, 3389, 4444, 5555, 8080]

            for conn in connections:
                if conn.status in [psutil.CONN_ESTABLISHED, psutil.CONN_LISTEN]:
                    # Track port usage
                    if conn.laddr:
                        port = conn.laddr.port
                        port_frequency[port] = port_frequency.get(port, 0) + 1

                    # Track IP connections
                    if conn.raddr:
                        ip = conn.raddr.ip
                        ip_frequency[ip] = ip_frequency.get(ip, 0) + 1

                        # Check for suspicious ports
                        if conn.raddr.port in suspicious_ports:
                            result["suspicious_activity"].append(
                                {
                                    "type": "suspicious_port",
                                    "details": f"Connection to suspicious port {conn.raddr.port} at {ip}",
                                    "severity": "medium",
                                },
                            )

            # Identify patterns
            if port_frequency:
                most_used_ports = sorted(port_frequency.items(), key=lambda x: x[1], reverse=True)[:5]
                result["patterns"].append(
                    {
                        "type": "port_usage",
                        "description": "Most frequently used ports",
                        "data": most_used_ports,
                    },
                )

            if ip_frequency:
                most_connected_ips = sorted(ip_frequency.items(), key=lambda x: x[1], reverse=True)[:5]
                result["patterns"].append(
                    {
                        "type": "ip_connections",
                        "description": "Most frequently connected IPs",
                        "data": most_connected_ips,
                    },
                )

            # Check for potential port scanning
            if len(port_frequency) > 50:
                result["suspicious_activity"].append(
                    {
                        "type": "possible_port_scan",
                        "details": f"Large number of different ports in use: {len(port_frequency)}",
                        "severity": "high",
                    },
                )

        except Exception as e:
            logger.exception("Socket traffic analysis failed: %s", e)
            result["error"] = str(e)

        return result

    def cleanup_sockets(self) -> None:
        """Clean up any active sockets.

        Closes all active sockets stored in the active_sockets dictionary and
        stops the socket monitoring thread if it is running. This method should
        be called during application shutdown or when sockets are no longer
        needed.

        Raises:
            OSError: If an error occurs while closing a socket.

        """
        for socket_name, sock in self.active_sockets.items():
            try:
                sock.close()
                logger.info("Closed socket: %s", socket_name)
            except OSError as e:
                logger.debug("Error closing socket %s: %s", socket_name, e)
        self.active_sockets.clear()

        if self.monitoring:
            self.monitoring = False

        if self.socket_monitor_thread and self.socket_monitor_thread.is_alive():
            self.socket_monitor_thread.join(timeout=2)

    def monitor_traffic(self, target_process: int | None = None) -> list[str]:
        """Monitor network traffic and connections.

        Monitors active network connections and listening ports, optionally
        filtered by a specific process. Resolves remote hostnames and displays
        network I/O statistics. Supports targeting specific processes on
        Windows platforms.

        Args:
            target_process: Optional process ID to filter connections for.
                If provided, only connections from this process are monitored.
                Defaults to None, which monitors all system connections.

        Returns:
            list[str]: A list of formatted strings containing connection
                details, listening ports, and network I/O statistics.

        Raises:
            ImportError: If psutil library is not available.
            Exception: If an error occurs during network monitoring or hostname
                resolution.

        """
        results = [f"Starting network monitoring{f' for process: {target_process!s}' if target_process else ''}..."]
        try:
            import socket

            from intellicrack.handlers.psutil_handler import psutil

            # Get network connections
            connections = psutil.net_connections(kind="inet")
            if target_process:
                # Filter connections for specific process
                try:
                    proc = psutil.Process(target_process)
                    connections = proc.connections(kind="inet")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    results.append(f"Error: Cannot access process {target_process}")
                    return results

            active_connections = []
            for conn in connections:
                if conn.status == psutil.CONN_ESTABLISHED:
                    local_addr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
                    remote_addr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"

                    # Use socket to resolve hostnames
                    remote_host = None
                    if conn.raddr:
                        try:
                            remote_host = socket.gethostbyaddr(conn.raddr.ip)[0]
                        except (socket.herror, socket.gaierror, OSError):
                            remote_host = conn.raddr.ip

                    active_connections.append(
                        {
                            "local": local_addr,
                            "remote": remote_addr,
                            "remote_host": remote_host,
                            "status": conn.status,
                            "pid": conn.pid if hasattr(conn, "pid") else "N/A",
                        },
                    )

            if active_connections:
                results.append(f"Found {len(active_connections)} active network connections:")
                for i, conn in enumerate(active_connections[:10]):  # Show max 10
                    host_info = f" [{conn['remote_host']}]" if conn["remote_host"] else ""
                    results.append(f"  {i + 1}. {conn['local']} -> {conn['remote']}{host_info} (PID: {conn['pid']})")
                if len(active_connections) > 10:
                    results.append(f"  ... and {len(active_connections) - 10} more connections")
            else:
                results.append("No active network connections found")

            # Check for listening ports
            listening_ports = []
            for conn in psutil.net_connections(kind="inet"):
                if conn.status == psutil.CONN_LISTEN:
                    local_addr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
                    listening_ports.append(
                        {
                            "address": local_addr,
                            "pid": conn.pid if hasattr(conn, "pid") else "N/A",
                        },
                    )

            if listening_ports:
                results.append(f"\nListening ports ({len(listening_ports)}):")
                for i, port in enumerate(listening_ports[:5]):  # Show max 5
                    results.append(f"  {i + 1}. {port['address']} (PID: {port['pid']})")
                if len(listening_ports) > 5:
                    results.append(f"  ... and {len(listening_ports) - 5} more listening ports")

            if net_io := psutil.net_io_counters():
                results.extend((
                    "\nNetwork I/O Statistics:",
                    f"  Bytes sent: {net_io.bytes_sent:,}",
                    f"  Bytes received: {net_io.bytes_recv:,}",
                    f"  Packets sent: {net_io.packets_sent:,}",
                    f"  Packets received: {net_io.packets_recv:,}",
                ))
        except ImportError as e:
            logger.debug("psutil not available: %s", e, exc_info=True)
            results.extend((
                "Error: psutil library not available for network monitoring",
                "Install with: pip install psutil",
            ))
        except Exception as e:
            logger.exception("Network monitoring error: %s", e)
            results.append(f"Network monitoring error: {e}")

        return results

    def get_socket_info(self, sock: socket.socket) -> dict[str, Any]:
        """Get detailed information about a socket.

        Retrieves comprehensive information about a socket including family,
        type, protocol, local address, peer address, and socket options
        (SO_REUSEADDR, SO_KEEPALIVE, receive buffer, send buffer). Handles
        exceptions gracefully if socket information cannot be retrieved.

        Args:
            sock: Socket object to retrieve information from.

        Returns:
            dict[str, Any]: A dictionary containing socket metadata with keys:
                'family', 'type', 'proto', 'local_address', 'remote_address',
                'reuse_addr', 'keep_alive', 'recv_buffer' (if available), and
                'send_buffer' (if available).

        Raises:
            OSError: If an error occurs while retrieving socket options or
                addresses.

        """
        info = {
            "family": sock.family.name if hasattr(sock.family, "name") else str(sock.family),
            "type": sock.type.name if hasattr(sock.type, "name") else str(sock.type),
            "proto": sock.proto,
        }

        try:
            # Get socket name (local address)
            local_addr = sock.getsockname()
            if len(local_addr) == 2:  # IPv4
                info["local_address"] = f"{local_addr[0]}:{local_addr[1]}"
            else:
                info["local_address"] = str(local_addr)
        except Exception as e:
            logger.debug("Could not get local address: %s", e, exc_info=True)
            info["local_address"] = "Not bound"

        try:
            # Get peer name (remote address)
            peer_addr = sock.getpeername()
            if len(peer_addr) == 2:  # IPv4
                info["remote_address"] = f"{peer_addr[0]}:{peer_addr[1]}"
            else:
                info["remote_address"] = str(peer_addr)
        except Exception as e:
            logger.debug("Could not get remote address: %s", e, exc_info=True)
            info["remote_address"] = "Not connected"

        # Get socket options
        try:
            info["reuse_addr"] = bool(sock.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR))
            info["keep_alive"] = bool(sock.getsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE))
            if hasattr(socket, "SO_RCVBUF"):
                info["recv_buffer"] = sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
            if hasattr(socket, "SO_SNDBUF"):
                info["send_buffer"] = sock.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF)
        except OSError as e:
            logger.debug("Could not get socket buffer info: %s", e)

        return info


def register() -> NetworkAnalysisPlugin:
    """Register and return an instance of the network analysis plugin.

    Creates a NetworkAnalysisPlugin instance and registers cleanup handlers
    to ensure all active sockets are properly closed when the program exits.
    This function is called by the plugin system during initialization.

    Returns:
        NetworkAnalysisPlugin: An initialized NetworkAnalysisPlugin instance
            with cleanup handlers registered via atexit.

    """
    plugin = NetworkAnalysisPlugin()
    # Register cleanup on exit
    import atexit

    atexit.register(plugin.cleanup_sockets)
    return plugin

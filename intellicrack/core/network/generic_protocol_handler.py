"""Provide protocol handler for network communication and data processing."""

import socket
import threading
import time
from typing import Any

from intellicrack.utils.logger import logger

from .license_protocol_handler import LicenseProtocolHandler

"""
Generic License Protocol Handler Implementation.

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


class GenericProtocolHandler(LicenseProtocolHandler):
    """Provide implementation of the LicenseProtocolHandler abstract class.

    This provides a working implementation that can handle basic TCP/UDP
    protocol interactions for license verification systems.
    """

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        """Initialize the generic protocol handler."""
        super().__init__(config)
        self.protocol = config.get("protocol", "tcp") if config else "tcp"
        self.captured_requests = []
        self.captured_responses = []
        self.active_connections = {}

    def _run_proxy(self, port: int) -> None:
        """Run the proxy server implementation.

        Args:
            port: Port number to bind to

        """
        if self.protocol.lower() == "udp":
            self._run_udp_proxy(port)
        else:
            self._run_tcp_proxy(port)

    def _run_tcp_proxy(self, port: int) -> None:
        """Run TCP proxy server."""
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            server_socket.bind((self.bind_host, port))
            server_socket.listen(5)
            server_socket.settimeout(1.0)

            self.logger.info("Generic TCP proxy listening on %s:%d", self.bind_host, port)

            while self.running:
                try:
                    client_socket, client_addr = server_socket.accept()
                    self.logger.info("TCP connection from %s:%s", client_addr[0], client_addr[1])

                    # Handle each connection in a separate thread
                    conn_thread = threading.Thread(
                        target=self._handle_tcp_connection,
                        args=(client_socket, client_addr),
                        daemon=True,
                    )
                    conn_thread.start()

                except TimeoutError as e:
                    logger.error("socket.timeout in generic_protocol_handler: %s", e)
                    continue
                except Exception as e:
                    if self.running:
                        self.logger.error("TCP proxy error: %s", e)

        finally:
            server_socket.close()
            self.logger.info("TCP proxy stopped")

    def _run_udp_proxy(self, port: int) -> None:
        """Run UDP proxy server."""
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            server_socket.bind((self.bind_host, port))
            server_socket.settimeout(1.0)

            self.logger.info("Generic UDP proxy listening on %s:%d", self.bind_host, port)

            while self.running:
                try:
                    data, client_addr = server_socket.recvfrom(4096)
                    if data:
                        self.logger.info("UDP packet from %s:%s", client_addr[0], client_addr[1])

                        # Handle UDP packet
                        response = self.generate_response(data)
                        if response:
                            server_socket.sendto(response, client_addr)

                except TimeoutError as e:
                    logger.error("socket.timeout in generic_protocol_handler: %s", e)
                    continue
                except Exception as e:
                    if self.running:
                        self.logger.error("UDP proxy error: %s", e)

        finally:
            server_socket.close()
            self.logger.info("UDP proxy stopped")

    def _handle_tcp_connection(self, client_socket: socket.socket, client_addr: tuple) -> None:
        """Handle individual TCP connection."""
        try:
            # Set timeout for client socket
            client_socket.settimeout(self.timeout)

            # Track connection
            conn_id = f"{client_addr[0]}:{client_addr[1]}_{time.time()}"
            self.active_connections[conn_id] = {
                "socket": client_socket,
                "address": client_addr,
                "start_time": time.time(),
            }

            # Receive initial data
            initial_data = client_socket.recv(4096)
            if initial_data:
                self.handle_connection(client_socket, initial_data)

            # Continue handling connection until closed
            while self.running:
                try:
                    more_data = client_socket.recv(4096)
                    if not more_data:
                        break
                    self.handle_connection(client_socket, more_data)
                except TimeoutError as e:
                    logger.error("socket.timeout in generic_protocol_handler: %s", e)
                    continue
                except Exception as e:
                    logger.error("Exception in generic_protocol_handler: %s", e)
                    break

        except Exception as e:
            self.logger.error("Error handling TCP connection from %s: %s", client_addr, e)
        finally:
            client_socket.close()
            # Remove from active connections
            if conn_id in self.active_connections:
                del self.active_connections[conn_id]

    def handle_connection(self, client_socket: Any, initial_data: bytes) -> None:
        """Handle a client connection with generic protocol processing.

        Args:
            client_socket: Client socket connection
            initial_data: Initial data received from client

        """
        # Log the request
        self.log_request(
            initial_data,
            str(client_socket.getpeername() if hasattr(client_socket, "getpeername") else "unknown"),
        )

        # Store request for analysis
        self.captured_requests.append(
            {
                "timestamp": time.time(),
                "data": initial_data,
                "hex": initial_data.hex(),
                "source": str(client_socket.getpeername() if hasattr(client_socket, "getpeername") else "unknown"),
            },
        )

        # Generate response
        response = self.generate_response(initial_data)

        # Send response
        if response:
            try:
                if hasattr(client_socket, "send"):
                    client_socket.send(response)
                elif hasattr(client_socket, "sendto"):
                    # For UDP-like sockets
                    client_socket.sendto(response, client_socket.getpeername())

                self.log_response(
                    response,
                    str(client_socket.getpeername() if hasattr(client_socket, "getpeername") else "unknown"),
                )

                # Store response
                self.captured_responses.append(
                    {
                        "timestamp": time.time(),
                        "data": response,
                        "hex": response.hex(),
                        "destination": str(client_socket.getpeername() if hasattr(client_socket, "getpeername") else "unknown"),
                    },
                )

            except Exception as e:
                self.logger.error("Failed to send response: %s", e)

    def generate_response(self, request_data: bytes) -> bytes:
        """Generate a generic protocol response.

        This implementation provides basic responses for common patterns.
        Subclasses should override for protocol-specific behavior.

        Args:
            request_data: Raw request data from client

        Returns:
            Generic response data

        """
        # Try to detect request type
        request_str = request_data.decode("utf-8", errors="ignore").lower()

        # Check for common license verification patterns
        if any(keyword in request_str for keyword in ["license", "verify", "check", "auth"]):
            # Generic success response
            return b"OK\x00LICENSE_VALID\x00"

        if any(keyword in request_str for keyword in ["status", "ping", "heartbeat"]):
            # Status/heartbeat response
            return b"OK\x00SERVER_ACTIVE\x00"

        if any(keyword in request_str for keyword in ["version", "info"]):
            # Version information
            return b"GENERIC_LICENSE_SERVER_V1.0\x00"

        if len(request_data) >= 4:
            # Binary protocol - check for common patterns
            if request_data[:4] == b"\x00\x00\x00\x01":  # Common init sequence
                return b"\x00\x00\x00\x00\x00\x00\x00\x01"  # Success + handle

            if request_data[:2] == b"\x02\x00":  # Common query
                return b"\x00\x00\xff\xff\xff\xff"  # Max licenses available

        # Default response for unknown requests
        return b"OK\x00"

    def clear_data(self) -> None:
        """Clear captured data and active connections."""
        super().clear_data()
        self.captured_requests.clear()
        self.captured_responses.clear()
        self.active_connections.clear()
        self.logger.debug("Cleared generic protocol handler data")

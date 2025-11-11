"""Cloud License Response Generator and Hooker.

This module provides sophisticated capabilities for intercepting and responding to
cloud-based license validation requests, enabling security researchers to test
software behavior under various license conditions.

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
along with Intellicrack. If not, see <https://www.gnu.org/licenses/>.
"""

import hashlib
import json
import logging
import socket
import struct
import threading
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class CloudLicenseResponseGenerator:
    """Advanced cloud license response generator for security research.

    Provides comprehensive functionality for generating, intercepting, and
    responding to cloud-based license validation requests with realistic
    authentication protocols and encryption.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        """Initialize the cloud license response generator.

        Args:
            config: Configuration dictionary with settings for:
                - target_ports: List of ports to monitor
                - response_templates: License response templates
                - intercept_mode: Active or passive interception
                - encryption_keys: Keys for encrypted communications

        """
        self.config = config or {}
        self.target_ports = self.config.get("target_ports", [443, 8443, 5000, 8080])
        self.response_templates = self.config.get("response_templates", {})
        self.intercept_mode = self.config.get("intercept_mode", "passive")
        self.encryption_keys = self.config.get("encryption_keys", {})

        self.active = False
        self.intercepted_requests = []
        self.generated_responses = []
        self.hooks_enabled = False
        self.listener_threads = []
        self.socket_hooks = {}

        self._init_response_templates()
        self._init_protocol_handlers()

    def _init_response_templates(self) -> None:
        """Initialize default license response templates."""
        if not self.response_templates:
            self.response_templates = {
                "valid_license": {
                    "status": "valid",
                    "license_type": "professional",
                    "expiry_date": (datetime.now() + timedelta(days=365)).isoformat(),
                    "features": ["all"],
                    "max_users": "unlimited",
                    "signature": None,
                },
                "trial_license": {
                    "status": "trial",
                    "license_type": "evaluation",
                    "expiry_date": (datetime.now() + timedelta(days=30)).isoformat(),
                    "features": ["basic"],
                    "max_users": 5,
                    "signature": None,
                },
                "expired_license": {
                    "status": "expired",
                    "license_type": "expired",
                    "expiry_date": (datetime.now() - timedelta(days=1)).isoformat(),
                    "features": [],
                    "max_users": 0,
                    "signature": None,
                },
            }

    def _init_protocol_handlers(self) -> None:
        """Initialize protocol-specific handlers."""
        self.protocol_handlers = {
            "http": self._handle_http_request,
            "https": self._handle_https_request,
            "websocket": self._handle_websocket_request,
            "grpc": self._handle_grpc_request,
            "custom": self._handle_custom_protocol,
        }

    def enable_network_api_hooks(self) -> None:
        """Enable network API hooks for intercepting license requests."""
        if self.hooks_enabled:
            logger.warning("Network hooks already enabled")
            return

        try:
            # Start listener threads for target ports
            for port in self.target_ports:
                thread = threading.Thread(target=self._port_listener, args=(port,), daemon=True)
                thread.start()
                self.listener_threads.append(thread)

            # Hook socket functions for active interception
            if self.intercept_mode == "active":
                self._install_socket_hooks()

            self.hooks_enabled = True
            self.active = True
            logger.info(f"Network API hooks enabled on ports: {self.target_ports}")

        except Exception as e:
            logger.error(f"Failed to enable network hooks: {e}")

    def disable_network_api_hooks(self) -> None:
        """Disable network API hooks."""
        if not self.hooks_enabled:
            return

        self.active = False
        self.hooks_enabled = False

        # Remove socket hooks
        if self.intercept_mode == "active":
            self._remove_socket_hooks()

        logger.info("Network API hooks disabled")

    def _port_listener(self, port: int) -> None:
        """Listen on a specific port for incoming connections.

        Args:
            port: Port number to listen on

        """
        try:
            listener_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener_socket.bind(("0.0.0.0", port))
            listener_socket.listen(5)
            listener_socket.settimeout(1.0)

            logger.info(f"Listening on port {port}")

            while self.active:
                try:
                    client_socket, address = listener_socket.accept()
                    # Handle connection in separate thread
                    threading.Thread(target=self._handle_connection, args=(client_socket, address, port), daemon=True).start()
                except TimeoutError:
                    continue
                except Exception as e:
                    if self.active:
                        logger.error(f"Error accepting connection on port {port}: {e}")

            listener_socket.close()

        except Exception as e:
            logger.error(f"Failed to start listener on port {port}: {e}")

    def _handle_connection(self, client_socket: socket.socket, address: Tuple[str, int], port: int) -> None:
        """Handle an incoming connection.

        Args:
            client_socket: Connected client socket
            address: Client address tuple
            port: Port the connection was received on

        """
        try:
            # Record connection start time for performance metrics
            connection_start = time.time()

            # Receive request data
            request_data = client_socket.recv(4096)

            if request_data:
                # Match actual license server response timing characteristics
                network_delay = self.config.get("network_delay", 0.1)
                if network_delay > 0:
                    time.sleep(network_delay)

                # Log intercepted request with timing information
                request_info = {
                    "timestamp": datetime.now().isoformat(),
                    "source": f"{address[0]}:{address[1]}",
                    "port": port,
                    "data": request_data,
                    "protocol": self._detect_protocol(request_data),
                    "connection_time": connection_start,
                    "processing_delay": network_delay,
                }
                self.intercepted_requests.append(request_info)

                # Generate and send response
                response = self._generate_response(request_info)
                if response:
                    # Add response transmission delay for realism
                    response_delay = self.config.get("response_delay", 0.05)
                    if response_delay > 0:
                        time.sleep(response_delay)

                    client_socket.send(response)

                    # Log total processing time
                    total_time = time.time() - connection_start
                    logger.debug(f"Connection processed in {total_time:.3f}s with {network_delay:.3f}s network delay")

                    # Log generated response
                    self.generated_responses.append(
                        {"timestamp": datetime.now().isoformat(), "request": request_info, "response": response},
                    )

        except Exception as e:
            logger.error(f"Error handling connection from {address}: {e}")
        finally:
            client_socket.close()

    def _detect_protocol(self, data: bytes) -> str:
        """Detect the protocol of the incoming request.

        Args:
            data: Raw request data

        Returns:
            Detected protocol name

        """
        # Check for HTTP/HTTPS
        if data.startswith(b"GET ") or data.startswith(b"POST ") or data.startswith(b"PUT "):
            return "http"

        # Check for TLS/SSL handshake
        if len(data) > 5 and data[0] == 0x16 and data[1:3] in [b"\x03\x01", b"\x03\x03"]:
            return "https"

        # Check for WebSocket upgrade
        if b"Upgrade: websocket" in data:
            return "websocket"

        # Check for gRPC (HTTP/2)
        if data.startswith(b"PRI * HTTP/2"):
            return "grpc"

        return "custom"

    def _generate_response(self, request_info: Dict[str, Any]) -> Optional[bytes]:
        """Generate a license validation response.

        Args:
            request_info: Information about the intercepted request

        Returns:
            Generated response bytes or None

        """
        protocol = request_info["protocol"]

        if protocol in self.protocol_handlers:
            return self.protocol_handlers[protocol](request_info)

        return None

    def _handle_http_request(self, request_info: Dict[str, Any]) -> bytes:
        """Handle HTTP license validation request.

        Args:
            request_info: Request information

        Returns:
            HTTP response bytes

        """
        # Parse HTTP request
        request_data = request_info["data"]

        # Analyze request data to determine license type
        license_type = "valid_license"
        if request_data:
            # Look for common license request patterns
            request_str = request_data.decode("utf-8", errors="ignore")
            if "premium" in request_str.lower():
                license_type = "premium_license"
            elif "trial" in request_str.lower():
                license_type = "trial_license"
            elif "enterprise" in request_str.lower():
                license_type = "enterprise_license"

        # Generate license response based on analyzed request
        license_data = self._create_license_response(license_type)
        response_body = json.dumps(license_data).encode()

        # Build HTTP response
        response = b"HTTP/1.1 200 OK\r\n"
        response += b"Content-Type: application/json\r\n"
        response += f"Content-Length: {len(response_body)}\r\n".encode()
        response += b"Connection: close\r\n"
        response += b"\r\n"
        response += response_body

        return response

    def _handle_https_request(self, request_info: Dict[str, Any]) -> bytes:
        """Handle HTTPS license validation request.

        Args:
            request_info: Request information

        Returns:
            HTTPS response bytes

        """
        # For HTTPS, we would need to handle TLS handshake
        # This is a simplified version
        return self._handle_http_request(request_info)

    def _handle_websocket_request(self, request_info: Dict[str, Any]) -> bytes:
        """Handle WebSocket license validation request.

        Args:
            request_info: Request information

        Returns:
            WebSocket response bytes

        """
        # Generate WebSocket frame with license data
        license_data = self._create_license_response("valid_license")
        payload = json.dumps(license_data).encode()

        # Simple WebSocket frame (no masking)
        frame = bytearray()
        frame.append(0x81)  # FIN + text frame

        if len(payload) < 126:
            frame.append(len(payload))
        elif len(payload) < 65536:
            frame.append(126)
            frame.extend(struct.pack(">H", len(payload)))
        else:
            frame.append(127)
            frame.extend(struct.pack(">Q", len(payload)))

        frame.extend(payload)

        return bytes(frame)

    def _handle_grpc_request(self, request_info: Dict[str, Any]) -> bytes:
        """Handle gRPC license validation request.

        Args:
            request_info: Request information

        Returns:
            gRPC response bytes

        """
        # Generate gRPC response with license data
        license_data = self._create_license_response("valid_license")

        # Simplified gRPC response (would need proper HTTP/2 framing)
        payload = json.dumps(license_data).encode()

        # gRPC message format: [compression flag][length][data]
        message = bytearray()
        message.append(0x00)  # No compression
        message.extend(struct.pack(">I", len(payload)))
        message.extend(payload)

        return bytes(message)

    def _handle_custom_protocol(self, request_info: Dict[str, Any]) -> bytes:
        """Handle custom protocol license validation request.

        Args:
            request_info: Request information

        Returns:
            Custom protocol response bytes

        """
        # Generate generic license response
        license_data = self._create_license_response("valid_license")

        # Simple custom protocol: [magic][version][length][data]
        magic = b"LICR"
        version = struct.pack(">H", 0x0001)
        payload = json.dumps(license_data).encode()
        length = struct.pack(">I", len(payload))

        response = magic + version + length + payload

        return response

    def _create_license_response(self, template_name: str) -> Dict[str, Any]:
        """Create a license response from template.

        Args:
            template_name: Name of the template to use

        Returns:
            License response dictionary

        """
        template = self.response_templates.get(template_name, self.response_templates["valid_license"])

        response = template.copy()

        # Generate signature
        response["signature"] = self._generate_signature(response)

        # Add timestamp
        response["timestamp"] = datetime.now().isoformat()

        # Add server info
        response["server"] = {"name": "License Server", "version": "2.0.0", "region": "us-west-1"}

        return response

    def _generate_signature(self, data: Dict[str, Any]) -> str:
        """Generate a signature for license data.

        Args:
            data: License data to sign

        Returns:
            Signature string

        """
        # Create signing string
        signing_data = json.dumps(data, sort_keys=True).encode()

        # Generate SHA256 signature
        signature = hashlib.sha256(signing_data).hexdigest()

        return signature

    def _install_socket_hooks(self) -> None:
        """Install hooks on socket functions for active interception."""
        # This would require more advanced hooking techniques
        # such as using ctypes or system-specific APIs
        pass

    def _remove_socket_hooks(self) -> None:
        """Remove installed socket hooks."""
        # Remove any installed hooks
        pass

    def get_intercepted_requests(self) -> List[Dict[str, Any]]:
        """Get list of intercepted license requests.

        Returns:
            List of intercepted request information

        """
        return self.intercepted_requests

    def get_generated_responses(self) -> List[Dict[str, Any]]:
        """Get list of generated license responses.

        Returns:
            List of generated response information

        """
        return self.generated_responses

    def set_response_template(self, name: str, template: Dict[str, Any]) -> None:
        """Set a custom response template.

        Args:
            name: Template name
            template: Template dictionary

        """
        self.response_templates[name] = template

    def clear_logs(self) -> None:
        """Clear intercepted requests and generated responses."""
        self.intercepted_requests.clear()
        self.generated_responses.clear()


def run_cloud_license_hooker(app_instance=None) -> None:
    """Initialize and run the cloud license hooker.

    Args:
        app_instance: The main application instance (optional, for logging/context).

    """
    hooker = CloudLicenseResponseGenerator()
    hooker.enable_network_api_hooks()
    logger.info("Cloud license hooker initialized and running.")

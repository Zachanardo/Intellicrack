"""Remote plugin executor for running plugins on remote systems.

Copyright (C) 2025 Zachary Flint

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

import base64
import hashlib
import hmac
import json
import logging
import os
import socket
import sys
import tempfile
import threading
from typing import Any

from intellicrack.logger import logger
from intellicrack.utils.service_health_checker import get_service_url

from ..utils.secrets_manager import get_secret

"""
Remote Plugin Executor

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


__all__ = ["RemotePluginExecutor"]


class RemotePluginExecutor:
    """Execute plugins on remote systems.

    Provides secure remote plugin execution capabilities with serialization
    and network communication for distributed analysis tasks.
    """

    def __init__(self, remote_host: str | None = None, remote_port: int | None = None):
        """Initialize the remote plugin executor.

        Args:
            remote_host: Remote host to connect to (default: from config)
            remote_port: Remote port to connect to (default: from config)

        """
        # Get WebSocket server URL from configuration
        if remote_host is None or remote_port is None:
            ws_url = get_service_url("websocket_server")
            default_host = ws_url.replace("ws://", "").replace("wss://", "").split(":")[0]
            default_port = int(ws_url.split(":")[-1].replace("/", "")) if ":" in ws_url else 8765

            self.remote_host = remote_host or default_host
            self.remote_port = remote_port or default_port
        else:
            self.remote_host = remote_host
            self.remote_port = remote_port
        self.logger = logging.getLogger(__name__)

        # Security: Shared secret for HMAC validation (should be configured securely)
        secret = get_secret("INTELLICRACK_REMOTE_SECRET", None)
        if not secret:
            # Generate a random secret if not configured
            import secrets

            secret = secrets.token_hex(32)
            # Try to store it for future use
            from ..utils.secrets_manager import store_secret

            try:
                store_secret("INTELLICRACK_REMOTE_SECRET", secret)
                self.logger.info("Generated and stored new secure remote execution secret")
            except Exception as e:
                self.logger.warning(f"Could not store generated secret: {e}")
        self.shared_secret = secret.encode()

    def _serialize_safe(self, data: Any) -> str:
        """Safely serialize data to JSON only - no pickle allowed for security.

        Args:
            data: Data to serialize

        Returns:
            Base64-encoded serialized data

        """
        try:
            # Try JSON serialization
            json_str = json.dumps(data)
            return base64.b64encode(json_str.encode("utf-8")).decode("ascii")
        except (TypeError, ValueError):
            # Convert non-serializable objects to string representation
            self.logger.debug(f"Converting non-JSON-serializable data to string: {type(data)}")
            # Attempt to make data JSON-serializable
            if hasattr(data, "__dict__"):
                # Convert objects to their dict representation
                try:
                    json_str = json.dumps(data.__dict__)
                    return base64.b64encode(json_str.encode("utf-8")).decode("ascii")
                except:
                    pass
            # Last resort: convert to string
            json_str = json.dumps(str(data))
            return base64.b64encode(json_str.encode("utf-8")).decode("ascii")

    def _deserialize_safe(self, encoded_data: str, expected_type: str = "json") -> Any:
        """Safely deserialize data - only JSON allowed for security.

        Args:
            encoded_data: Base64-encoded data
            expected_type: Expected serialization type (only 'json' supported)

        Returns:
            Deserialized data

        """
        if expected_type != "json":
            raise ValueError(
                f"Unsupported serialization type: {expected_type}. Only JSON is allowed for security."
            )

        decoded = base64.b64decode(encoded_data)

        try:
            return json.loads(decoded.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            self.logger.error(f"Failed to deserialize as JSON: {e}")
            raise ValueError("Invalid JSON data")

    def execute_plugin(self, plugin_path: str, method_name: str, *args, **kwargs) -> list[str]:
        """Execute a plugin on a remote system.

        Args:
            plugin_path: Path to the plugin file
            method_name: Method name to call
            *args: Arguments to pass to the method
            **kwargs: Keyword arguments to pass to the method

        Returns:
            Results from the plugin method, or error messages

        """
        try:
            # Read plugin file
            with open(plugin_path, "rb") as f:
                plugin_code = f.read()

            # Encode plugin code and arguments
            encoded_plugin = base64.b64encode(plugin_code).decode("utf-8")
            encoded_args = self._serialize_safe(args)
            encoded_kwargs = self._serialize_safe(kwargs)

            # Create request with signature
            request = {
                "plugin_code": encoded_plugin,
                "method_name": method_name,
                "args": encoded_args,
                "kwargs": encoded_kwargs,
                "serialization": "json",  # Indicate serialization method
            }

            # Add HMAC signature for authentication
            request_json = json.dumps(request, sort_keys=True)
            signature = hmac.new(
                self.shared_secret, request_json.encode("utf-8"), hashlib.sha256
            ).hexdigest()
            request["signature"] = signature

            # Connect to remote server
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                # Set timeout for connection
                s.settimeout(30)
                s.connect((self.remote_host, self.remote_port))

                # Send request
                request_data = json.dumps(request).encode("utf-8") + b"\n"
                s.sendall(request_data)

                # Receive response
                response = b""
                while True:
                    data = s.recv(4096)
                    if not data:
                        break
                    response += data

                    # Check for end of response
                    if response.endswith(b"\n"):
                        break

            # Parse response
            response_data = json.loads(response.decode("utf-8"))

            if response_data.get("status") == "success":
                # Decode results safely
                encoded_results = response_data.get("results", "")
                serialization_type = response_data.get("serialization", "json")

                try:
                    results = self._deserialize_safe(
                        encoded_results, expected_type=serialization_type
                    )
                    return results
                except Exception as e:
                    self.logger.error("Failed to deserialize results: %s", e)
                    return [f"Deserialization error: {e}"]
            else:
                error = response_data.get("error", "Unknown error")
                self.logger.error("Remote execution error: %s", error)
                return [f"Remote execution error: {error}"]

        except ConnectionError as e:
            error_msg = f"Connection error: {e}"
            self.logger.error(error_msg)
            return [error_msg]
        except TimeoutError:
            error_msg = "Connection timeout"
            self.logger.error(error_msg)
            return [error_msg]
        except (OSError, ValueError, RuntimeError) as e:
            error_msg = f"Error executing remote plugin: {e}"
            self.logger.error(error_msg)
            return [error_msg]

    @staticmethod
    def start_server(host: str | None = None, port: int | None = None) -> None:
        """Start a remote plugin execution server.

        Args:
            host: Host to bind to (default: from config)
            port: Port to bind to

        """
        logger = logging.getLogger(__name__)

        def handle_client(client_socket: socket.socket) -> None:
            """Handle a client connection.

            Args:
                client_socket: Client socket connection

            """
            try:
                # Set timeout for client operations
                client_socket.settimeout(60)

                # Receive request
                request_data = b""
                while True:
                    data = client_socket.recv(4096)
                    if not data:
                        break
                    request_data += data

                    # Check for end of request
                    if request_data.endswith(b"\n"):
                        break

                # Parse request
                request = json.loads(request_data.decode("utf-8"))

                # Verify HMAC signature (if present)
                signature = request.pop("signature", None)
                if signature:
                    # Get shared secret
                    secret = get_secret("INTELLICRACK_REMOTE_SECRET", None)
                    if not secret:
                        logger.error("No remote execution secret configured - rejecting request")
                        response = {"status": "error", "error": "Server not configured"}
                        client_socket.sendall(json.dumps(response).encode("utf-8") + b"\n")
                        return
                    shared_secret = secret.encode()

                    # Verify signature
                    request_json = json.dumps(request, sort_keys=True)
                    expected_sig = hmac.new(
                        shared_secret, request_json.encode("utf-8"), hashlib.sha256
                    ).hexdigest()

                    if not hmac.compare_digest(signature, expected_sig):
                        logger.error("Invalid HMAC signature in request")
                        response = {"status": "error", "error": "Authentication failed"}
                        client_socket.sendall(json.dumps(response).encode("utf-8") + b"\n")
                        return

                # Extract plugin code and arguments
                plugin_code = base64.b64decode(request.get("plugin_code", ""))
                method_name = request.get("method_name", "")
                serialization_type = request.get("serialization", "json")

                # Deserialize arguments based on type
                executor = RemotePluginExecutor()
                try:
                    args = executor._deserialize_safe(
                        request.get("args", ""), expected_type=serialization_type
                    )
                    kwargs = executor._deserialize_safe(
                        request.get("kwargs", ""), expected_type=serialization_type
                    )
                except Exception as e:
                    logger.error("Failed to deserialize arguments: %s", e)
                    response = {"status": "error", "error": f"Deserialization failed: {e}"}
                    client_socket.sendall(json.dumps(response).encode("utf-8") + b"\n")
                    return

                # Write plugin code to temporary file
                with tempfile.NamedTemporaryFile(suffix=".py", delete=False) as f:
                    plugin_path = f.name
                    f.write(plugin_code)

                try:
                    # Import plugin
                    sys.path.insert(0, os.path.dirname(plugin_path))
                    plugin_module_name = os.path.basename(plugin_path)[:-3]
                    plugin_module = __import__(plugin_module_name)

                    # Create plugin instance
                    if hasattr(plugin_module, "Plugin"):
                        plugin_class = plugin_module.Plugin
                        plugin_instance = plugin_class()
                    else:
                        # Look for common plugin class names
                        for class_name in ["DemoPlugin", "CustomPlugin", "AnalysisPlugin"]:
                            if hasattr(plugin_module, class_name):
                                plugin_class = getattr(plugin_module, class_name)
                                plugin_instance = plugin_class()
                                break
                        else:
                            raise AttributeError("No suitable plugin class found")

                    # Execute plugin method with sandbox protection
                    results = _run_plugin_in_sandbox(plugin_instance, method_name, *args, **kwargs)

                    # Encode results using safe serialization
                    encoded_results = executor._serialize_safe(results)

                    # Create response
                    response = {
                        "status": "success",
                        "results": encoded_results,
                        "serialization": "json",  # Indicate serialization type
                    }

                except (OSError, ValueError, RuntimeError) as e:
                    # Create error response
                    logger.error("Plugin execution error: %s", e)
                    response = {
                        "status": "error",
                        "error": str(e),
                    }

                finally:
                    # Clean up
                    try:
                        os.unlink(plugin_path)
                    except OSError as e:
                        logger.error("OS error in remote_executor: %s", e)

                    # Remove plugin path from sys.path
                    plugin_dir = os.path.dirname(plugin_path)
                    if plugin_dir in sys.path:
                        sys.path.remove(plugin_dir)

                # Send response
                response_data = json.dumps(response).encode("utf-8") + b"\n"
                client_socket.sendall(response_data)

            except (OSError, ValueError, RuntimeError) as e:
                logger.error("Error handling client: %s", e)

                # Send error response
                try:
                    response = {
                        "status": "error",
                        "error": str(e),
                    }
                    response_data = json.dumps(response).encode("utf-8") + b"\n"
                    client_socket.sendall(response_data)
                except (OSError, ValueError, RuntimeError) as e:
                    logger.error("Error in remote_executor: %s", e)
                    # Client may have disconnected

            finally:
                try:
                    client_socket.close()
                except (OSError, ValueError, RuntimeError) as e:
                    logger.error("Error in remote_executor: %s", e)

        # Get configuration if not provided
        if host is None or port is None:
            ws_url = get_service_url("websocket_server")
            default_host = ws_url.replace("ws://", "").replace("wss://", "").split(":")[0]
            default_port = int(ws_url.split(":")[-1].replace("/", "")) if ":" in ws_url else 8765
            host = host or default_host
            port = port or default_port

        # Create server socket
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            # Bind and listen
            server_socket.bind((host, port))
            server_socket.listen(5)

            logger.info("Remote plugin execution server started on %s:%s", host, port)

            # Accept connections
            while True:
                try:
                    client_socket, addr = server_socket.accept()
                    logger.info("Accepted connection from %s", addr)

                    # Handle client in a new thread
                    client_thread = threading.Thread(
                        target=handle_client,
                        args=(client_socket,),
                        daemon=True,
                    )
                    client_thread.start()

                except KeyboardInterrupt:
                    logger.info("Server shutting down")
                    break
                except (OSError, ValueError, RuntimeError) as e:
                    logger.error("Error accepting connection: %s", e)

        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Server error: %s", e)
        finally:
            try:
                server_socket.close()
            except (OSError, ValueError, RuntimeError) as e:
                logger.error("Error in remote_executor: %s", e)

    def test_connection(self) -> bool:
        """Test connection to the remote server.

        Returns:
            True if connection successful, False otherwise

        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(5)
                s.connect((self.remote_host, self.remote_port))
                return True
        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("Connection test failed: %s", e)
            return False


def _run_plugin_in_sandbox(plugin_instance: Any, method_name: str, *args, **kwargs) -> list[str]:
    """Run plugin method in a sandboxed environment.

    Args:
        plugin_instance: Plugin instance to execute
        method_name: Method name to call
        *args: Method arguments
        **kwargs: Method keyword arguments

    Returns:
        Results from plugin method execution

    """
    try:
        # Check if method exists
        if not hasattr(plugin_instance, method_name):
            return [f"Method '{method_name}' not found in plugin"]

        # Get the method
        method = getattr(plugin_instance, method_name)

        # Execute the method
        if callable(method):
            result = method(*args, **kwargs)

            # Ensure result is a list of strings
            if isinstance(result, list):
                return [str(item) for item in result]
            if isinstance(result, str):
                return [result]
            return [str(result)]
        return [f"'{method_name}' is not callable"]

    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error in remote_executor: %s", e)
        return [f"Plugin execution error: {e}"]


def create_remote_executor(
    host: str | None = None, port: int | None = None
) -> RemotePluginExecutor:
    """Factory function to create a RemotePluginExecutor.

    Args:
        host: Remote host address (default: from config)
        port: Remote port number (default: from config)

    Returns:
        Configured RemotePluginExecutor instance

    """
    return RemotePluginExecutor(host, port)

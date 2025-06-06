"""
Remote Plugin Executor

This module provides functionality to execute plugins on remote systems,
enabling distributed plugin execution and analysis across multiple machines.
"""

import base64
import json
import logging
import os
import pickle
import socket
import sys
import tempfile
import threading
from typing import Any, List, Optional

__all__ = ['RemotePluginExecutor']


class RemotePluginExecutor:
    """
    Execute plugins on remote systems.

    Provides secure remote plugin execution capabilities with serialization
    and network communication for distributed analysis tasks.
    """

    def __init__(self, remote_host: Optional[str] = None, remote_port: Optional[int] = None):
        """
        Initialize the remote plugin executor.

        Args:
            remote_host: Remote host to connect to (default: localhost)
            remote_port: Remote port to connect to (default: 8765)
        """
        self.remote_host = remote_host or "localhost"
        self.remote_port = remote_port or 8765
        self.logger = logging.getLogger(__name__)

    def execute_plugin(self, plugin_path: str, method_name: str, *args, **kwargs) -> List[str]:
        """
        Execute a plugin on a remote system.

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
            with open(plugin_path, 'rb') as f:
                plugin_code = f.read()

            # Encode plugin code and arguments
            encoded_plugin = base64.b64encode(plugin_code).decode('utf-8')
            encoded_args = base64.b64encode(pickle.dumps(args)).decode('utf-8')
            encoded_kwargs = base64.b64encode(pickle.dumps(kwargs)).decode('utf-8')

            # Create request
            request = {
                "plugin_code": encoded_plugin,
                "method_name": method_name,
                "args": encoded_args,
                "kwargs": encoded_kwargs
            }

            # Connect to remote server
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                # Set timeout for connection
                s.settimeout(30)
                s.connect((self.remote_host, self.remote_port))

                # Send request
                request_data = json.dumps(request).encode('utf-8') + b'\n'
                s.sendall(request_data)

                # Receive response
                response = b''
                while True:
                    data = s.recv(4096)
                    if not data:
                        break
                    response += data

                    # Check for end of response
                    if response.endswith(b'\n'):
                        break

            # Parse response
            response_data = json.loads(response.decode('utf-8'))

            if response_data.get("status") == "success":
                # Decode results
                encoded_results = response_data.get("results", "")
                results = pickle.loads(base64.b64decode(encoded_results))
                return results
            else:
                error = response_data.get("error", "Unknown error")
                self.logger.error("Remote execution error: %s", error)
                return [f"Remote execution error: {error}"]

        except ConnectionError as e:
            error_msg = f"Connection error: {e}"
            self.logger.error(error_msg)
            return [error_msg]
        except socket.timeout:
            error_msg = "Connection timeout"
            self.logger.error(error_msg)
            return [error_msg]
        except Exception as e:
            error_msg = f"Error executing remote plugin: {e}"
            self.logger.error(error_msg)
            return [error_msg]

    @staticmethod
    def start_server(host: str = "localhost", port: int = 8765) -> None:
        """
        Start a remote plugin execution server.

        Args:
            host: Host to bind to
            port: Port to bind to
        """
        logger = logging.getLogger(__name__)

        def handle_client(client_socket: socket.socket) -> None:
            """
            Handle a client connection.

            Args:
                client_socket: Client socket connection
            """
            try:
                # Set timeout for client operations
                client_socket.settimeout(60)

                # Receive request
                request_data = b''
                while True:
                    data = client_socket.recv(4096)
                    if not data:
                        break
                    request_data += data

                    # Check for end of request
                    if request_data.endswith(b'\n'):
                        break

                # Parse request
                request = json.loads(request_data.decode('utf-8'))

                # Extract plugin code and arguments
                plugin_code = base64.b64decode(request.get("plugin_code", ""))
                method_name = request.get("method_name", "")
                args = pickle.loads(base64.b64decode(request.get("args", "")))
                kwargs = pickle.loads(base64.b64decode(request.get("kwargs", "")))

                # Write plugin code to temporary file
                with tempfile.NamedTemporaryFile(suffix='.py', delete=False) as f:
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

                    # Encode results
                    encoded_results = base64.b64encode(pickle.dumps(results)).decode('utf-8')

                    # Create response
                    response = {
                        "status": "success",
                        "results": encoded_results
                    }

                except Exception as e:
                    # Create error response
                    logger.error("Plugin execution error: %s", e)
                    response = {
                        "status": "error",
                        "error": str(e)
                    }

                finally:
                    # Clean up
                    try:
                        os.unlink(plugin_path)
                    except OSError:
                        pass

                    # Remove plugin path from sys.path
                    plugin_dir = os.path.dirname(plugin_path)
                    if plugin_dir in sys.path:
                        sys.path.remove(plugin_dir)

                # Send response
                response_data = json.dumps(response).encode('utf-8') + b'\n'
                client_socket.sendall(response_data)

            except Exception as e:
                logger.error("Error handling client: %s", e)

                # Send error response
                try:
                    response = {
                        "status": "error",
                        "error": str(e)
                    }
                    response_data = json.dumps(response).encode('utf-8') + b'\n'
                    client_socket.sendall(response_data)
                except Exception:
                    pass  # Client may have disconnected

            finally:
                try:
                    client_socket.close()
                except Exception:
                    pass

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
                        daemon=True
                    )
                    client_thread.start()

                except KeyboardInterrupt:
                    logger.info("Server shutting down")
                    break
                except Exception as e:
                    logger.error("Error accepting connection: %s", e)

        except Exception as e:
            logger.error("Server error: %s", e)
        finally:
            try:
                server_socket.close()
            except Exception:
                pass

    def test_connection(self) -> bool:
        """
        Test connection to the remote server.

        Returns:
            True if connection successful, False otherwise
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(5)
                s.connect((self.remote_host, self.remote_port))
                return True
        except Exception as e:
            self.logger.error("Connection test failed: %s", e)
            return False


def _run_plugin_in_sandbox(plugin_instance: Any, method_name: str, *args, **kwargs) -> List[str]:
    """
    Run plugin method in a sandboxed environment.

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
            elif isinstance(result, str):
                return [result]
            else:
                return [str(result)]
        else:
            return [f"'{method_name}' is not callable"]

    except Exception as e:
        return [f"Plugin execution error: {e}"]


def create_remote_executor(host: str = "localhost", port: int = 8765) -> RemotePluginExecutor:
    """
    Factory function to create a RemotePluginExecutor.

    Args:
        host: Remote host address
        port: Remote port number

    Returns:
        Configured RemotePluginExecutor instance
    """
    return RemotePluginExecutor(host, port)

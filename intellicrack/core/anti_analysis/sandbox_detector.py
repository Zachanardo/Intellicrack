"""
Sandbox Detection

Implements techniques to detect analysis sandboxes including
Cuckoo, VMRay, Joe Sandbox, and others.
"""

import ctypes
import logging
import os
import platform
import socket
import subprocess
import time
from typing import Any, Dict, List, Tuple

from .base_detector import BaseDetector


class SandboxDetector(BaseDetector):
    """
    Comprehensive sandbox detection using behavioral and environmental checks.
    """

    def __init__(self):
        super().__init__()
        self.logger = logging.getLogger("IntellicrackLogger.SandboxDetector")

        self.detection_methods = {
            'environment_checks': self._check_environment,
            'behavioral_detection': self._check_behavioral,
            'resource_limits': self._check_resource_limits,
            'network_connectivity': self._check_network,
            'user_interaction': self._check_user_interaction,
            'file_system': self._check_file_system_artifacts,
            'process_monitoring': self._check_process_monitoring,
            'time_acceleration': self._check_time_acceleration,
            'api_hooks': self._check_api_hooks,
            'mouse_movement': self._check_mouse_movement
        }

        # Known sandbox signatures
        self.sandbox_signatures = {
            'cuckoo': {
                'files': [os.path.join(os.environ.get('SystemDrive', 'C:'), 'analyzer'), os.path.join(os.environ.get('SystemDrive', 'C:'), 'sandbox'), '/tmp/.cuckoo-*'],
                'processes': ['python.exe', 'analyzer.py'],
                'network': ['192.168.56.0/24'],  # Common Cuckoo network
                'artifacts': ['cuckoo', 'analyzer', 'auxiliary']
            },
            'vmray': {
                'files': [os.path.join(os.environ.get('SystemDrive', 'C:'), 'vmray')],
                'processes': ['vmray_controller.exe'],
                'artifacts': ['vmray', 'controller']
            },
            'joe_sandbox': {
                'files': [os.path.join(os.environ.get('SystemDrive', 'C:'), 'joe')],
                'processes': ['joeboxcontrol.exe', 'joeboxserver.exe'],
                'artifacts': ['joe', 'joebox']
            },
            'threatgrid': {
                'artifacts': ['threatgrid', 'tgrid'],
                'network': ['192.168.2.0/24']
            },
            'hybrid_analysis': {
                'artifacts': ['falcon', 'hybrid-analysis'],
                'files': [os.path.join(os.environ.get('SystemDrive', 'C:'), 'falcon')]
            }
        }

        # Sandbox behavioral patterns
        self.behavioral_patterns = {
            'no_user_files': {
                'paths': [
                    os.path.expanduser('~/Documents'),
                    os.path.expanduser('~/Desktop'),
                    os.path.expanduser('~/Downloads')
                ],
                'min_files': 5  # Real systems have user files
            },
            'limited_processes': {
                'min_processes': 50,  # Real systems run many processes
                'common_processes': ['explorer.exe', 'svchost.exe', 'chrome.exe', 'firefox.exe']
            },
            'fast_boot': {
                'max_uptime': 300  # 5 minutes - sandboxes often have fresh boots
            },
            'limited_network': {
                'min_connections': 5  # Real systems have network activity
            }
        }

    def detect_sandbox(self, aggressive: bool = False) -> Dict[str, Any]:
        """
        Perform sandbox detection using multiple techniques.

        Args:
            aggressive: Use aggressive detection that might affect analysis

        Returns:
            Detection results with confidence scores
        """
        results = {
            'is_sandbox': False,
            'confidence': 0.0,
            'sandbox_type': None,
            'detections': {},
            'evasion_difficulty': 0
        }

        try:
            self.logger.info("Starting sandbox detection...")

            # Run detection methods using base class functionality
            detection_results = self.run_detection_loop(aggressive, self.get_aggressive_methods())

            # Merge results
            results.update(detection_results)

            # Calculate overall results
            if detection_results['detection_count'] > 0:
                results['is_sandbox'] = True
                results['confidence'] = min(1.0, detection_results['average_confidence'])
                results['sandbox_type'] = self._identify_sandbox_type(results['detections'])

            # Calculate evasion difficulty
            results['evasion_difficulty'] = self._calculate_evasion_difficulty(results['detections'])

            self.logger.info(f"Sandbox detection complete: {results['is_sandbox']} (confidence: {results['confidence']:.2f})")
            return results

        except Exception as e:
            self.logger.error(f"Sandbox detection failed: {e}")
            return results

    def _check_environment(self) -> Tuple[bool, float, Dict]:
        """Check for sandbox-specific environment variables and settings."""
        details = {'suspicious_env': [], 'username': None, 'computername': None}

        try:
            # Check username
            username = os.environ.get('USERNAME', os.environ.get('USER', '')).lower()
            details['username'] = username

            suspicious_users = ['sandbox', 'malware', 'virus', 'maltest', 'test',
                              'john', 'user', 'analyst', 'analysis']
            if any(user in username for user in suspicious_users):
                details['suspicious_env'].append(f'username: {username}')

            # Check computer name
            computername = os.environ.get('COMPUTERNAME', socket.gethostname()).lower()
            details['computername'] = computername

            # Get suspicious computer names from environment or use defaults
            suspicious_computers_env = os.environ.get('SANDBOX_SUSPICIOUS_COMPUTERS', '')
            if suspicious_computers_env:
                suspicious_computers = [name.strip().lower() for name in suspicious_computers_env.split(',')]
            else:
                suspicious_computers = ['sandbox', 'malware', 'virus', 'test', 'vmware',
                                      'virtualbox', 'qemu', 'analysis']
            if any(comp in computername for comp in suspicious_computers):
                details['suspicious_env'].append(f'computername: {computername}')

            # Check for sandbox-specific environment variables
            sandbox_env_vars = [
                'CUCKOO', 'CUCKOO_ROOT', 'CUCKOO_ANALYSIS',
                'VMRAY', 'VMRAY_ANALYSIS',
                'JOEBOX', 'JOESANDBOX',
                'SANDBOX', 'SANDBOXIE'
            ]

            for var in sandbox_env_vars:
                if var in os.environ:
                    details['suspicious_env'].append(f'env: {var}')

            if details['suspicious_env']:
                confidence = min(0.9, len(details['suspicious_env']) * 0.3)
                return True, confidence, details

        except Exception as e:
            self.logger.debug(f"Environment check failed: {e}")

        return False, 0.0, details

    def _check_behavioral(self) -> Tuple[bool, float, Dict]:
        """Check for behavioral indicators of sandbox environment."""
        details = {'anomalies': []}

        try:
            # Check user files
            user_file_count = 0
            for path in self.behavioral_patterns['no_user_files']['paths']:
                if os.path.exists(path):
                    try:
                        files = os.listdir(path)
                        user_file_count += len(files)
                    except Exception as e:
                        self.logger.debug(f"Error accessing {path}: {e}")

            if user_file_count < self.behavioral_patterns['no_user_files']['min_files']:
                details['anomalies'].append(f'Few user files: {user_file_count}')

            # Check process count
            if platform.system() == 'Windows':
                result = subprocess.run(['tasklist'], capture_output=True, text=True)
                process_count = len(result.stdout.strip().split('\n')) - 3  # Header lines
            else:
                result = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
                process_count = len(result.stdout.strip().split('\n')) - 1  # Header line

            if process_count < self.behavioral_patterns['limited_processes']['min_processes']:
                details['anomalies'].append(f'Few processes: {process_count}')

            # Check system uptime
            uptime = self._get_system_uptime()
            if uptime and uptime < self.behavioral_patterns['fast_boot']['max_uptime']:
                details['anomalies'].append(f'Low uptime: {uptime}s')

            if details['anomalies']:
                confidence = min(0.8, len(details['anomalies']) * 0.25)
                return True, confidence, details

        except Exception as e:
            self.logger.debug(f"Behavioral check failed: {e}")

        return False, 0.0, details

    def _check_resource_limits(self) -> Tuple[bool, float, Dict]:
        """Check for resource limitations typical of sandboxes."""
        details = {'limitations': []}

        try:
            # Check CPU cores
            cpu_count = os.cpu_count()
            if cpu_count and cpu_count <= 2:
                details['limitations'].append(f'Low CPU count: {cpu_count}')

            # Check memory
            if platform.system() == 'Windows':
                try:
                    import psutil
                    mem = psutil.virtual_memory()
                    total_gb = mem.total / (1024**3)
                    if total_gb < 4:
                        details['limitations'].append(f'Low memory: {total_gb:.1f}GB')
                except ImportError as e:
                    self.logger.error("Import error in sandbox_detector: %s", e)
            else:
                try:
                    with open('/proc/meminfo', 'r') as f:
                        for line in f:
                            if line.startswith('MemTotal:'):
                                total_kb = int(line.split()[1])
                                total_gb = total_kb / (1024**2)
                                if total_gb < 4:
                                    details['limitations'].append(f'Low memory: {total_gb:.1f}GB')
                                break
                except Exception as e:
                    self.logger.debug(f"Error reading memory info: {e}")

            # Check disk space
            if platform.system() == 'Windows':
                free_bytes = ctypes.c_ulonglong(0)
                total_bytes = ctypes.c_ulonglong(0)
                ctypes.windll.kernel32.GetDiskFreeSpaceExW(
                    'C:\\', ctypes.byref(free_bytes), ctypes.byref(total_bytes), None
                )
                total_gb = total_bytes.value / (1024**3)
                if total_gb < 60:
                    details['limitations'].append(f'Small disk: {total_gb:.1f}GB')
            else:
                if hasattr(os, 'statvfs'):
                    stat = os.statvfs('/')
                    total_gb = (stat.f_blocks * stat.f_frsize) / (1024**3)
                    if total_gb < 60:
                        details['limitations'].append(f'Small disk: {total_gb:.1f}GB')

            if details['limitations']:
                confidence = min(0.7, len(details['limitations']) * 0.25)
                return True, confidence, details

        except Exception as e:
            self.logger.debug(f"Resource limits check failed: {e}")

        return False, 0.0, details

    def _check_network(self) -> Tuple[bool, float, Dict]:
        """Check network connectivity and configuration."""
        details = {'network_anomalies': [], 'connections': 0}

        try:
            # Check network connections
            if platform.system() == 'Windows':
                result = subprocess.run(['netstat', '-an'], capture_output=True, text=True)
            else:
                result = subprocess.run(['ss', '-an'], capture_output=True, text=True)

            connections = len([l for l in result.stdout.split('\n') if 'ESTABLISHED' in l])
            details['connections'] = connections

            if connections < self.behavioral_patterns['limited_network']['min_connections']:
                details['network_anomalies'].append(f'Few connections: {connections}')

            # Check for sandbox networks
            try:
                hostname = socket.gethostname()
                local_ip = socket.gethostbyname(hostname)

                for sandbox_type, sigs in self.sandbox_signatures.items():
                    for network in sigs.get('network', []):
                        if self._ip_in_network(local_ip, network):
                            details['network_anomalies'].append(f'Sandbox network: {network} ({sandbox_type})')

            except Exception as e:
                self.logger.debug(f"Error checking network configuration: {e}")

            # Check DNS resolution
            try:
                # Try to resolve common domains
                test_domains = ['google.com', 'microsoft.com', 'amazon.com']
                resolved = 0

                for domain in test_domains:
                    try:
                        socket.gethostbyname(domain)
                        resolved += 1
                    except Exception as e:
                        self.logger.debug(f"DNS resolution failed for {domain}: {e}")

                if resolved == 0:
                    details['network_anomalies'].append('No DNS resolution')

            except Exception as e:
                self.logger.debug(f"Error in DNS resolution test: {e}")

            if details['network_anomalies']:
                confidence = min(0.8, len(details['network_anomalies']) * 0.3)
                return True, confidence, details

        except Exception as e:
            self.logger.debug(f"Network check failed: {e}")

        return False, 0.0, details

    def _check_user_interaction(self) -> Tuple[bool, float, Dict]:
        """Check for signs of user interaction."""
        details = {'interaction_signs': []}

        try:
            # Check recently used files (Windows)
            if platform.system() == 'Windows':
                recent_path = os.path.join(os.environ['APPDATA'],
                                         'Microsoft\\Windows\\Recent')
                if os.path.exists(recent_path):
                    recent_files = os.listdir(recent_path)
                    if len(recent_files) < 5:
                        details['interaction_signs'].append(f'Few recent files: {len(recent_files)}')

            # Check browser history/cookies
            browser_paths = {
                'chrome': os.path.join(os.environ.get('LOCALAPPDATA', ''),
                                     'Google\\Chrome\\User Data\\Default\\History'),
                'firefox': os.path.join(os.environ.get('APPDATA', ''),
                                      'Mozilla\\Firefox\\Profiles')
            }

            browser_found = False
            found_browsers = []
            for browser, path in browser_paths.items():
                if os.path.exists(path):
                    browser_found = True
                    found_browsers.append(browser)

            if not browser_found:
                details['interaction_signs'].append('No browser data found')
            else:
                details['found_browsers'] = found_browsers

            # Check for running user applications
            user_apps = ['chrome.exe', 'firefox.exe', 'outlook.exe', 'spotify.exe',
                        'discord.exe', 'slack.exe']

            if platform.system() == 'Windows':
                result = subprocess.run(['tasklist'], capture_output=True, text=True)
                processes = result.stdout.lower()

                running_apps = [app for app in user_apps if app in processes]
                if len(running_apps) == 0:
                    details['interaction_signs'].append('No user applications running')

            if details['interaction_signs']:
                confidence = min(0.7, len(details['interaction_signs']) * 0.25)
                return True, confidence, details

        except Exception as e:
            self.logger.debug(f"User interaction check failed: {e}")

        return False, 0.0, details

    def _check_file_system_artifacts(self) -> Tuple[bool, float, Dict]:
        """Check for sandbox-specific files and directories."""
        details = {'artifacts_found': []}

        try:
            # Check for sandbox files
            for sandbox_type, sigs in self.sandbox_signatures.items():
                for file_path in sigs.get('files', []):
                    if os.path.exists(file_path):
                        details['artifacts_found'].append(f'{sandbox_type}: {file_path}')

            # Check for analysis artifacts
            suspicious_paths = [
                os.path.join(os.environ.get('SystemDrive', 'C:'), 'analysis'),
                os.path.join(os.environ.get('SystemDrive', 'C:'), 'analyzer'),
                os.path.join(os.environ.get('SystemDrive', 'C:'), 'sandbox'),
                os.path.join(os.environ.get('SystemDrive', 'C:'), 'malware'),
                '/tmp/analysis/',
                '/tmp/cuckoo/',
                '/opt/sandbox/'
            ]

            for path in suspicious_paths:
                if os.path.exists(path):
                    details['artifacts_found'].append(f'Suspicious path: {path}')

            # Check for monitoring tools
            monitoring_files = [
                'C:\\\\Windows\\\\System32\\\\drivers\\\\monitor.sys',
                'C:\\\\Windows\\\\System32\\\\api_monitor.dll',
                'C:\\\\hook.dll',
                'C:\\\\inject.dll'
            ]

            for file_path in monitoring_files:
                if os.path.exists(file_path):
                    details['artifacts_found'].append(f'Monitoring file: {file_path}')

            if details['artifacts_found']:
                confidence = min(0.9, len(details['artifacts_found']) * 0.3)
                return True, confidence, details

        except Exception as e:
            self.logger.debug(f"File system check failed: {e}")

        return False, 0.0, details

    def _check_process_monitoring(self) -> Tuple[bool, float, Dict]:
        """Check for process monitoring and injection."""
        details = {'monitoring_signs': []}

        try:
            # Check for monitoring processes
            monitoring_processes = [
                'procmon.exe', 'procexp.exe', 'apimonitor.exe',
                'wireshark.exe', 'tcpdump', 'strace', 'ltrace',
                'sysmon.exe', 'autoruns.exe'
            ]

            # Use base class method to get process list
            processes, process_list = self.get_running_processes()

            for monitor in monitoring_processes:
                if monitor.lower() in processes:
                    details['monitoring_signs'].append(f'Monitoring process: {monitor}')

            # Check for injected DLLs (Windows)
            if platform.system() == 'Windows':
                try:
                    # Check for sandbox monitoring processes
                    sandbox_processes = ['procmon', 'dbgview', 'filemon', 'regmon',
                                       'wireshark', 'tcpdump', 'netmon', 'apimonitor']

                    for proc in sandbox_processes:
                        if proc in processes or any(proc in p for p in process_list):
                            details['monitoring_signs'].append(f'Monitor process: {proc}')

                    # Check current process for suspicious DLLs
                    import psutil
                    current_proc = psutil.Process()

                    suspicious_dlls = ['hook', 'inject', 'monitor', 'sandbox', 'api']

                    for dll in current_proc.memory_maps():
                        dll_name = os.path.basename(dll.path).lower()
                        if any(susp in dll_name for susp in suspicious_dlls):
                            details['monitoring_signs'].append(f'Suspicious DLL: {dll_name}')

                except Exception as e:
                    self.logger.debug(f"Error checking loaded DLLs: {e}")

            if details['monitoring_signs']:
                confidence = min(0.8, len(details['monitoring_signs']) * 0.3)
                return True, confidence, details

        except Exception as e:
            self.logger.debug(f"Process monitoring check failed: {e}")

        return False, 0.0, details

    def _check_time_acceleration(self) -> Tuple[bool, float, Dict]:
        """Check for time acceleration used by sandboxes."""
        details = {'time_anomaly': False, 'drift': 0}

        try:
            # Measure time drift
            # Get initial time
            start_real = time.time()
            start_perf = time.perf_counter()

            # Sleep for a short period
            time.sleep(2)

            # Check time drift
            end_real = time.time()
            end_perf = time.perf_counter()

            real_elapsed = end_real - start_real
            perf_elapsed = end_perf - start_perf

            drift = abs(real_elapsed - perf_elapsed)
            details['drift'] = drift

            # Significant drift indicates time manipulation
            if drift > 0.1:  # 100ms drift
                details['time_anomaly'] = True
                return True, 0.7, details

            # Check for GetTickCount acceleration
            if platform.system() == 'Windows':
                kernel32 = ctypes.windll.kernel32

                tick1 = kernel32.GetTickCount()
                time.sleep(1)
                tick2 = kernel32.GetTickCount()

                tick_elapsed = (tick2 - tick1) / 1000.0
                if abs(tick_elapsed - 1.0) > 0.1:
                    details['time_anomaly'] = True
                    return True, 0.7, details

        except Exception as e:
            self.logger.debug(f"Time acceleration check failed: {e}")

        return False, 0.0, details

    def _check_api_hooks(self) -> Tuple[bool, float, Dict]:
        """Check for API hooking commonly used by sandboxes."""
        details = {'hooked_apis': []}

        try:
            if platform.system() == 'Windows':
                # Check common hooked APIs
                apis_to_check = [
                    ('kernel32.dll', 'CreateFileW'),
                    ('kernel32.dll', 'WriteFile'),
                    ('kernel32.dll', 'ReadFile'),
                    ('ws2_32.dll', 'send'),
                    ('ws2_32.dll', 'recv'),
                    ('ntdll.dll', 'NtCreateFile'),
                    ('ntdll.dll', 'NtOpenProcess')
                ]

                kernel32 = ctypes.windll.kernel32

                for dll_name, api_name in apis_to_check:
                    try:
                        dll = ctypes.windll.LoadLibrary(dll_name)
                        api_addr = kernel32.GetProcAddress(dll._handle, api_name.encode())

                        if api_addr:
                            # Read first bytes of API
                            first_byte = ctypes.c_ubyte.from_address(api_addr).value

                            # Check for common hook patterns
                            if first_byte == 0xE9:  # JMP
                                details['hooked_apis'].append(f'{dll_name}!{api_name}')
                            elif first_byte == 0x68:  # PUSH
                                details['hooked_apis'].append(f'{dll_name}!{api_name}')

                    except Exception as e:
                        self.logger.debug(f"Error checking API hook for {dll_name}!{api_name}: {e}")

            if details['hooked_apis']:
                confidence = min(0.8, len(details['hooked_apis']) * 0.15)
                return True, confidence, details

        except Exception as e:
            self.logger.debug(f"API hook check failed: {e}")

        return False, 0.0, details

    def _check_mouse_movement(self) -> Tuple[bool, float, Dict]:
        """Check for human-like mouse movement."""
        details = {'mouse_active': False, 'movement_count': 0}

        try:
            if platform.system() == 'Windows':
                try:
                    from ctypes import wintypes

                    # Check if POINT is available
                    if not hasattr(wintypes, 'POINT'):
                        # Create mock POINT structure
                        class MockPOINT(ctypes.Structure):
                            """Mock POINT structure for Windows API compatibility."""
                            _fields_ = [("x", ctypes.c_long), ("y", ctypes.c_long)]
                        wintypes.POINT = MockPOINT
                except (ImportError, AttributeError) as e:
                    self.logger.error("Error in sandbox_detector: %s", e)
                    # Fallback if wintypes is not available
                    class MockWintypes:
                        """Mock wintypes implementation for compatibility."""
                        class POINT(ctypes.Structure):
                            """Mock POINT structure definition."""
                            _fields_ = [("x", ctypes.c_long), ("y", ctypes.c_long)]
                    from types import SimpleNamespace
                    wintypes = SimpleNamespace()
                    wintypes.POINT = MockWintypes.POINT

                user32 = ctypes.windll.user32

                # Track mouse position over time
                positions = []

                for _ in range(10):
                    point = wintypes.POINT()
                    user32.GetCursorPos(ctypes.byref(point))
                    positions.append((point.x, point.y))
                    time.sleep(0.5)

                # Check for movement
                unique_positions = len(set(positions))
                details['movement_count'] = unique_positions

                if unique_positions > 1:
                    details['mouse_active'] = True
                else:
                    # No mouse movement in 5 seconds is suspicious
                    return True, 0.6, details

        except Exception as e:
            self.logger.debug(f"Mouse movement check failed: {e}")

        return False, 0.0, details

    def _get_system_uptime(self) -> int:
        """Get system uptime in seconds."""
        try:
            if platform.system() == 'Windows':
                kernel32 = ctypes.windll.kernel32
                return kernel32.GetTickCount64() // 1000
            else:
                with open('/proc/uptime', 'r') as f:
                    uptime = float(f.readline().split()[0])
                    return int(uptime)
        except:
            return None

    def _ip_in_network(self, ip: str, network: str) -> bool:
        """Check if IP is in network range."""
        try:
            import ipaddress
            return ipaddress.ip_address(ip) in ipaddress.ip_network(network)
        except:
            # Simple check for common cases
            network_parts = network.split('/')[0].split('.')
            ip_parts = ip.split('.')

            # Check if first 3 octets match (assuming /24)
            return ip_parts[:3] == network_parts[:3]

    def _identify_sandbox_type(self, detections: Dict[str, Any]) -> str:
        """Identify specific sandbox based on detections."""
        sandbox_scores = {}

        # Analyze all detection details
        for method, result in detections.items():
            if result['detected']:
                details_str = str(result['details']).lower()
                self.logger.debug(f"Analyzing sandbox type from method: {method}")

                # Check for sandbox signatures
                for sandbox_type, sigs in self.sandbox_signatures.items():
                    score = 0

                    # Check artifacts
                    for artifact in sigs.get('artifacts', []):
                        if artifact.lower() in details_str:
                            score += 1

                    # Check processes
                    for process in sigs.get('processes', []):
                        if process.lower() in details_str:
                            score += 2

                    # Check files
                    for file_path in sigs.get('files', []):
                        if file_path.lower() in details_str:
                            score += 2

                    if score > 0:
                        sandbox_scores[sandbox_type] = sandbox_scores.get(sandbox_type, 0) + score

        # Return sandbox with highest score
        if sandbox_scores:
            return max(sandbox_scores, key=sandbox_scores.get)

        # Generic sandbox if no specific type identified
        return 'Generic Sandbox'

    def _calculate_evasion_difficulty(self, detections: Dict[str, Any]) -> int:
        """Calculate how difficult it is to evade sandbox detection."""
        # Methods that are hard to evade
        hard_methods = ['file_system', 'process_monitoring', 'api_hooks']
        medium_methods = ['environment_checks', 'network_connectivity']

        return self.calculate_detection_score(detections, hard_methods, medium_methods)

    def generate_sandbox_evasion(self) -> str:
        """Generate code to evade sandbox detection."""
        code = """
// Sandbox Evasion Code
#include <windows.h>
#include <time.h>

bool IsSandbox() {
    // 1. Check username and computer name
    char username[256], computername[256];
    DWORD size = 256;

    GetUserName(username, &size);
    size = 256;
    GetComputerName(computername, &size);

    // Common sandbox names
    const char* bad_names[] = {"sandbox", "malware", "virus", "test", "analyst"};
    for (int i = 0; i < 5; i++) {
        if (strstr(username, bad_names[i]) || strstr(computername, bad_names[i])) {
            return true;
        }
    }

    // 2. Check for user files
    WIN32_FIND_DATA findData;
    HANDLE hFind = FindFirstFile("C:\\\\Users\\\\*\\\\Documents\\\\*", &findData);
    int fileCount = 0;

    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            fileCount++;
        } while (FindNextFile(hFind, &findData) && fileCount < 10);
        FindClose(hFind);
    }

    if (fileCount < 5) {
        return true;  // Too few user files
    }

    // 3. Check system uptime
    DWORD uptime = GetTickCount64() / 1000;  // Seconds
    if (uptime < 300) {  // Less than 5 minutes
        return true;
    }

    // 4. Mouse movement check
    POINT pt1, pt2;
    GetCursorPos(&pt1);
    Sleep(1000);
    GetCursorPos(&pt2);

    if (pt1.x == pt2.x && pt1.y == pt2.y) {
        // No mouse movement
        return true;
    }

    // 5. Check for sandbox artifacts
    if (GetModuleHandle("SbieDll.dll") != NULL) {  // Sandboxie
        return true;
    }

    return false;
}

// Evasive execution
if (IsSandbox()) {
    // Appear benign
    MessageBox(NULL, "This application is not compatible with your system", "Error", MB_OK);

    // Sleep to waste sandbox time
    Sleep(120000);  // 2 minutes

    ExitProcess(0);
}

// Delay execution to bypass automated analysis
Sleep(30000);  // 30 seconds

// Continue with malicious payload...
"""
        return code

    def get_aggressive_methods(self) -> List[str]:
        """Get list of method names that are considered aggressive."""
        return ['time_acceleration', 'mouse_movement']

    def get_detection_type(self) -> str:
        """Get the type of detection this class performs."""
        return 'sandbox'

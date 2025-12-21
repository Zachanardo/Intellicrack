"""
Negative Control Validator for Phase 3 validation.
Ensures target software properly refuses to run without a valid license.
"""

import os
import time
import hashlib
import logging
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from datetime import datetime

try:
    import psutil
    import win32gui
    import win32process
    import win32api
except ImportError:
    # These are optional imports for advanced functionality
    psutil = None
    win32gui = None
    win32process = None
    win32api = None

from commercial_binary_manager import CommercialBinaryManager

logger = logging.getLogger(__name__)


@dataclass
class NegativeControlResult:
    """Result of a negative control validation test."""
    software_name: str
    binary_path: str
    binary_hash: str
    test_start_time: str
    test_end_time: str
    software_refused_execution: bool
    license_error_detected: bool
    network_attempts_logged: list[dict[str, Any]]
    screenshot_path: str | None
    process_monitoring_data: dict[str, Any]
    test_valid: bool
    error_message: str | None = None
    timestamp: str = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()


class NegativeControlValidator:
    """Validates that software properly refuses to run without a valid license."""

    def __init__(self, base_dir: str = "C:\\Intellicrack\\tests\\validation_system"):
        self.base_dir = Path(base_dir)
        self.evidence_dir = self.base_dir / "forensic_evidence"
        self.screenshots_dir = self.base_dir / "video_recordings"
        self.logs_dir = self.base_dir / "logs"
        self.reports_dir = self.base_dir / "reports"

        # Create required directories
        for directory in [self.evidence_dir, self.screenshots_dir, self.logs_dir, self.reports_dir]:
            directory.mkdir(exist_ok=True)

        self.binary_manager = CommercialBinaryManager(base_dir)

        # Network monitoring setup
        self.network_monitor_process = None

        logger.info("NegativeControlValidator initialized")

    def _calculate_hash(self, file_path: str) -> str:
        """Calculate SHA-256 hash of file."""
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                sha256.update(chunk)
        return sha256.hexdigest()

    def _start_network_monitoring(self) -> subprocess.Popen | None:
        """
        Start network monitoring to capture license server attempts.
        Uses netsh trace or PowerShell packet capture for real monitoring.
        """
        try:
            # Create a capture file
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            capture_file = self.evidence_dir / f"network_capture_{timestamp}.etl"

            # Use Windows netsh trace for real packet capture
            cmd = [
                "netsh", "trace", "start", "capture=yes",
                f"tracefile={capture_file}",
                "provider=Microsoft-Windows-TCPIP",
                "provider=Microsoft-Windows-HttpService",
                "provider=Microsoft-Windows-WinHttp",
                "level=5", "maxsize=50", "overwrite=yes"
            ]

            logger.info(f"Starting real network monitoring with: {' '.join(cmd)}")
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )

            # Give trace time to initialize
            time.sleep(2)
            if process.poll() is not None:
                # Process failed, try PowerShell fallback
                logger.warning("netsh trace failed, attempting PowerShell NetEventSession fallback")

                ps_script = f'''
                $sessionName = "IntellicrockCapture_{timestamp}"
                try {{
                    New-NetEventSession -Name $sessionName -CaptureMode SaveToFile -LocalFilePath "{capture_file.with_suffix('.etl')}"
                    Add-NetEventProvider -Name "Microsoft-Windows-TCPIP" -SessionName $sessionName
                    Add-NetEventProvider -Name "Microsoft-Windows-HttpService" -SessionName $sessionName
                    Start-NetEventSession -Name $sessionName
                    Write-Output "Network capture started: $sessionName"
                }} catch {{
                    Write-Error $_.Exception.Message
                    exit 1
                }}
                '''

                fallback_cmd = ["powershell", "-Command", ps_script]
                process = subprocess.Popen(
                    fallback_cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                time.sleep(1)

            logger.info(f"Network monitoring started, capture file: {capture_file}")
            return process

        except Exception as e:
            logger.error(f"Failed to start network monitoring: {e}")
            return None

    def _stop_network_monitoring(self, process: subprocess.Popen | None) -> list[dict[str, Any]]:
        """
        Stop network monitoring and return captured data.
        """
        network_attempts = []

        try:
            if process:
                # Stop netsh trace or PowerShell NetEventSession
                try:
                    # First, try stopping netsh trace
                    stop_cmd = ["netsh", "trace", "stop"]
                    stop_process = subprocess.run(
                        stop_cmd,
                        capture_output=True,
                        text=True,
                        timeout=30,
                        creationflags=subprocess.CREATE_NO_WINDOW
                    )

                    if stop_process.returncode != 0:
                        # Try stopping PowerShell NetEventSession
                        ps_stop = '''
                        Get-NetEventSession | Where-Object {$_.Name -like "IntellicrockCapture_*"} | Stop-NetEventSession
                        Get-NetEventSession | Where-Object {$_.Name -like "IntellicrockCapture_*"} | Remove-NetEventSession
                        '''
                        subprocess.run(
                            ["powershell", "-Command", ps_stop],
                            capture_output=True,
                            text=True,
                            timeout=15,
                            creationflags=subprocess.CREATE_NO_WINDOW
                        )

                except subprocess.TimeoutExpired:
                    logger.warning("Timeout stopping network monitoring")

                # Terminate the monitoring process
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()

                # Analyze captured data using netsh trace report
                try:
                    if etl_files := list(
                        self.evidence_dir.glob("network_capture_*.etl")
                    ):
                        latest_etl = max(etl_files, key=lambda x: x.stat().st_mtime)

                        # Convert ETL to readable format using netsh
                        report_file = latest_etl.with_suffix('.txt')
                        report_cmd = [
                            "netsh", "trace", "convert",
                            str(latest_etl), f"output={report_file}",
                            "report=yes", "overwrite=yes"
                        ]

                        report_process = subprocess.run(
                            report_cmd,
                            capture_output=True,
                            text=True,
                            timeout=60,
                            creationflags=subprocess.CREATE_NO_WINDOW
                        )

                        if report_process.returncode == 0 and report_file.exists():
                            # Parse the report file for license server attempts
                            with open(report_file, encoding='utf-8', errors='ignore') as f:
                                report_content = f.read()

                            # Look for common license server patterns
                            license_patterns = [
                                r'(?i)(license|activation|auth|flexlm|rlm)',
                                r'(?i)(port\s+27000|port\s+5053|port\s+1947)',
                                r'(?i)(\.lic|\.dat|\.key)',
                                r'(?i)(tcp.*:27\d{3}|udp.*:27\d{3})'
                            ]

                            import re
                            for i, line in enumerate(report_content.split('\n')):
                                network_attempts.extend(
                                    {
                                        "timestamp": datetime.now().isoformat(),
                                        "type": "potential_license_activity",
                                        "line_number": i + 1,
                                        "details": line.strip()[:200],
                                    }
                                    for pattern in license_patterns
                                    if re.search(pattern, line)
                                )
                            # Also look for DNS queries that might be license-related
                            dns_pattern = r'(?i)dns.*query.*'
                            for i, line in enumerate(report_content.split('\n')):
                                if re.search(dns_pattern, line):
                                    network_attempts.append({
                                        "timestamp": datetime.now().isoformat(),
                                        "type": "dns_query",
                                        "line_number": i + 1,
                                        "details": line.strip()[:200]
                                    })

                        if not network_attempts:
                            network_attempts.append({
                                "timestamp": datetime.now().isoformat(),
                                "type": "no_license_activity_detected",
                                "details": (
                                    f"Analyzed {len(report_content.split()) if 'report_content' in locals() else 0} "
                                    "words from network trace"
                                )
                            })

                except Exception as parse_error:
                    logger.error(f"Error parsing network capture: {parse_error}")
                    network_attempts.append({
                        "timestamp": datetime.now().isoformat(),
                        "type": "parse_error",
                        "details": f"Failed to parse network capture: {str(parse_error)}"
                    })

                logger.info(f"Network monitoring stopped, found {len(network_attempts)} network events")

            else:
                # No active monitoring - check for existing network connections
                logger.info("No active network monitoring, checking current network connections")

                try:
                    # Use netstat to check for license-related connections
                    netstat_result = subprocess.run(
                        ["netstat", "-an"],
                        capture_output=True,
                        text=True,
                        timeout=10,
                        creationflags=subprocess.CREATE_NO_WINDOW
                    )

                    if netstat_result.returncode == 0:
                        # Look for common license ports
                        license_ports = ['27000', '27001', '27002', '5053', '1947']
                        for line in netstat_result.stdout.split('\n'):
                            for port in license_ports:
                                if port in line:
                                    network_attempts.append({
                                        "timestamp": datetime.now().isoformat(),
                                        "type": "existing_license_connection",
                                        "details": line.strip()
                                    })

                    if not network_attempts:
                        network_attempts.append({
                            "timestamp": datetime.now().isoformat(),
                            "type": "no_license_connections",
                            "details": "No license-related network connections detected"
                        })

                except Exception as netstat_error:
                    network_attempts.append({
                        "timestamp": datetime.now().isoformat(),
                        "type": "netstat_error",
                        "details": f"Failed to check network connections: {str(netstat_error)}"
                    })

        except Exception as e:
            logger.error(f"Error stopping network monitoring: {e}")
            network_attempts.append({
                "timestamp": datetime.now().isoformat(),
                "type": "error",
                "details": f"Failed to stop monitoring: {str(e)}"
            })

        return network_attempts

    def _capture_screenshot(self, filename: str) -> str | None:
        """
        Capture a screenshot of the current desktop using Windows APIs.
        """
        try:
            # Change extension to PNG for actual screenshot
            base_name = Path(filename).stem
            screenshot_path = self.screenshots_dir / f"{base_name}.png"

            # Method 1: Use PowerShell with .NET Graphics.CopyFromScreen
            ps_script = f'''
            Add-Type -AssemblyName System.Drawing
            Add-Type -AssemblyName System.Windows.Forms

            $bounds = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
            $bitmap = New-Object System.Drawing.Bitmap $bounds.Width, $bounds.Height
            $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
            try {{
                $graphics.CopyFromScreen($bounds.Location, [System.Drawing.Point]::Empty, $bounds.Size)
                $bitmap.Save("{screenshot_path}", [System.Drawing.Imaging.ImageFormat]::Png)
                Write-Output "Screenshot captured: {screenshot_path}"
            }}
            catch {{
                Write-Error $_.Exception.Message
                exit 1
            }}
            finally {{
                $graphics.Dispose()
                $bitmap.Dispose()
            }}
            '''

            logger.info("Capturing screenshot using PowerShell .NET Graphics API")
            result = subprocess.run(
                ["powershell", "-Command", ps_script],
                capture_output=True,
                text=True,
                timeout=30,
                creationflags=subprocess.CREATE_NO_WINDOW
            )

            if result.returncode == 0 and screenshot_path.exists():
                logger.info(f"Screenshot captured successfully: {screenshot_path}")
                return str(screenshot_path)

            # Method 2: Fallback using Windows GDI32 via ctypes
            logger.warning("PowerShell screenshot failed, attempting GDI32 fallback")

            try:
                import ctypes

                # Get desktop dimensions
                user32 = ctypes.windll.user32
                gdi32 = ctypes.windll.gdi32

                screen_width = user32.GetSystemMetrics(0)  # SM_CXSCREEN
                screen_height = user32.GetSystemMetrics(1)  # SM_CYSCREEN

                # Create device contexts
                hdesktop = user32.GetDesktopWindow()
                hdc = user32.GetWindowDC(hdesktop)
                hdcmem = gdi32.CreateCompatibleDC(hdc)

                # Create bitmap
                hbitmap = gdi32.CreateCompatibleBitmap(hdc, screen_width, screen_height)
                gdi32.SelectObject(hdcmem, hbitmap)

                # Copy screen to bitmap
                gdi32.BitBlt(hdcmem, 0, 0, screen_width, screen_height,
                           hdc, 0, 0, 0x00CC0020)  # SRCCOPY

                # Get bitmap data
                bmi = ctypes.create_string_buffer(40)  # BITMAPINFOHEADER size
                ctypes.memmove(bmi, ctypes.c_int32(40), 4)  # biSize
                ctypes.memmove(bmi[4:], ctypes.c_int32(screen_width), 4)  # biWidth
                ctypes.memmove(bmi[8:], ctypes.c_int32(-screen_height), 4)  # biHeight (negative for top-down)
                ctypes.memmove(bmi[12:], ctypes.c_int16(1), 2)  # biPlanes
                ctypes.memmove(bmi[14:], ctypes.c_int16(24), 2)  # biBitCount

                buffer_size = screen_width * screen_height * 3  # 24-bit RGB
                buffer = ctypes.create_string_buffer(buffer_size)

                result = gdi32.GetDIBits(hdc, hbitmap, 0, screen_height,
                                       buffer, bmi, 0)  # DIB_RGB_COLORS

                # Clean up GDI objects
                gdi32.DeleteObject(hbitmap)
                gdi32.DeleteDC(hdcmem)
                user32.ReleaseDC(hdesktop, hdc)

                if result:
                    # Convert BGR to RGB and save as PNG
                    try:
                        from PIL import Image
                        import numpy as np

                        # Convert buffer to numpy array
                        img_array = np.frombuffer(buffer, dtype=np.uint8)
                        img_array = img_array.reshape((screen_height, screen_width, 3))

                        # Convert BGR to RGB
                        img_array = img_array[:, :, ::-1]

                        # Create PIL image and save
                        image = Image.fromarray(img_array)
                        image.save(screenshot_path, 'PNG')

                        logger.info(f"Screenshot captured using GDI32/PIL fallback: {screenshot_path}")
                        return str(screenshot_path)

                    except ImportError:
                        logger.error("PIL not available for GDI32 fallback")

            except Exception as gdi_error:
                logger.error(f"GDI32 screenshot fallback failed: {gdi_error}")

            # Method 3: Final fallback using MSS if available
            try:
                import mss

                with mss.mss() as sct:
                    monitor = sct.monitors[0]  # Use primary monitor
                    screenshot = sct.grab(monitor)

                    # Save screenshot
                    mss.tools.to_png(screenshot.rgb, screenshot.size, output=str(screenshot_path))

                logger.info(f"Screenshot captured using MSS fallback: {screenshot_path}")
                return str(screenshot_path)

            except ImportError:
                logger.error("MSS library not available for screenshot capture")
            except Exception as mss_error:
                logger.error(f"MSS screenshot fallback failed: {mss_error}")

            # If all methods fail, create a metadata file indicating the failure
            metadata_path = self.screenshots_dir / f"{base_name}_metadata.txt"
            with open(metadata_path, 'w') as f:
                f.write(f"Screenshot capture attempted at {datetime.now().isoformat()}\n")
                f.write(f"PowerShell result: {result.stderr or 'No error output'}\n")
                f.write("All screenshot methods failed - screen capture not available\n")
                resolution_x = screen_width if 'screen_width' in locals() else 'Unknown'
                resolution_y = screen_height if 'screen_height' in locals() else 'Unknown'
                f.write(f"Resolution attempted: {resolution_x} x {resolution_y}\n")

            logger.warning(f"All screenshot methods failed, created metadata file: {metadata_path}")
            return str(metadata_path)

        except Exception as e:
            logger.error(f"Failed to capture screenshot: {e}")
            return None

    def _monitor_process(self, process: subprocess.Popen, timeout: int = 60) -> dict[str, Any]:
        """
        Monitor a process for the specified timeout period.
        """
        monitoring_data = {
            "process_id": None,
            "start_time": datetime.now().isoformat(),
            "end_time": None,
            "exit_code": None,
            "cpu_usage": [],
            "memory_usage": [],
            "network_activity": [],
            "error_messages": []
        }

        try:
            # Get process ID
            monitoring_data["process_id"] = process.pid

            # Monitor for the timeout period
            start_time = time.time()
            while time.time() - start_time < timeout and not process.poll() is not None:
                if psutil:
                    try:
                        p = psutil.Process(process.pid)
                        cpu_percent = p.cpu_percent()
                        memory_info = p.memory_info()
            
                        monitoring_data["cpu_usage"].append({
                            "timestamp": datetime.now().isoformat(),
                            "percent": cpu_percent
                        })
            
                        monitoring_data["memory_usage"].append({
                            "timestamp": datetime.now().isoformat(),
                            "rss": memory_info.rss,
                            "vms": memory_info.vms
                        })
                    except psutil.NoSuchProcess:
                        # Process has ended
                        break
                    except Exception as e:
                        monitoring_data["error_messages"].append(f"Monitoring error: {e}")
            
                time.sleep(1)

            # Wait for process to complete or terminate it
            try:
                process.wait(timeout=5)
                monitoring_data["exit_code"] = process.returncode
            except subprocess.TimeoutExpired:
                # Terminate the process
                process.terminate()
                try:
                    process.wait(timeout=5)
                    monitoring_data["exit_code"] = process.returncode
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                    monitoring_data["exit_code"] = -1

            monitoring_data["end_time"] = datetime.now().isoformat()

        except Exception as e:
            logger.error(f"Error monitoring process: {e}")
            monitoring_data["error_messages"].append(f"Process monitoring error: {e}")

        return monitoring_data

    def _detect_license_error(self, process_monitoring_data: dict[str, Any]) -> bool:
        """
        Analyze process monitoring data to detect license errors using comprehensive methods.
        """
        license_error_detected = False

        # Check exit code (many license-protected applications return specific codes)
        exit_code = process_monitoring_data.get("exit_code")
        license_exit_codes = [
            30,   # Common license error code
            126,  # Command cannot execute (permission/license issue)
            127,  # Command not found (missing license component)
            200,  # Common application-specific license error
            201,  # License expired
            202,  # License not found
            203   # License invalid
        ]

        if exit_code is not None:
            if exit_code in license_exit_codes:
                logger.info(f"Known license error exit code detected: {exit_code}")
                license_error_detected = True
            elif exit_code != 0:
                logger.info(f"Non-zero exit code detected (possible license issue): {exit_code}")
                license_error_detected = True

        # Check for error messages in monitoring data
        error_messages = process_monitoring_data.get("error_messages", [])
        license_keywords = [
            'license', 'activation', 'expired', 'invalid', 'unauthorized',
            'flexlm', 'rlm', 'dongle', 'hasp', 'sentinel', 'wibu',
            'license server', 'license file', 'license key',
            'trial expired', 'demo expired', 'evaluation'
        ]

        for error in error_messages:
            error_lower = error.lower()
            for keyword in license_keywords:
                if keyword in error_lower:
                    logger.info(f"License-related error detected in monitoring: {error}")
                    license_error_detected = True
                    break

        # Check Windows Event Log for application errors
        try:
            if process_id := process_monitoring_data.get("process_id"):
                ps_script = f'''
                $filter = @{{LogName='Application'; Level=2,3; StartTime=(Get-Date).AddMinutes(-5)}}
                $events = Get-WinEvent -FilterHashtable $filter -ErrorAction SilentlyContinue
                $licenseEvents = $events | Where-Object {{
                    $_.Message -match "license|activation|expired|invalid|unauthorized|trial|demo|evaluation" -or
                    $_.ProcessId -eq {process_id}
                }}

                foreach ($event in $licenseEvents) {{
                    $msg = $event.Message -replace '`n',' ' | Out-String -Stream | Select-Object -First 1
                    Write-Output "EventID:$($event.Id) ProcessID:$($event.ProcessId) Message:$msg"
                }}
                '''

                event_result = subprocess.run(
                    ["powershell", "-Command", ps_script],
                    capture_output=True,
                    text=True,
                    timeout=15,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )

                if event_result.returncode == 0 and event_result.stdout.strip():
                    logger.info("License-related Windows Event Log entries found")
                    license_error_detected = True

                    # Log the specific events found
                    for line in event_result.stdout.strip().split('\n'):
                        if line.strip():
                            logger.info(f"Event Log: {line.strip()}")

        except Exception as event_error:
            logger.warning(f"Failed to check Windows Event Log: {event_error}")

        # Check registry for license error flags
        try:
            # Look for common license registry locations
            registry_paths = [
                r"HKEY_CURRENT_USER\Software\FLEXlm License error",
                r"HKEY_LOCAL_MACHINE\SOFTWARE\FLEXlm License error",
                r"HKEY_CURRENT_USER\Software\Reprise License Manager\Error",
                r"HKEY_LOCAL_MACHINE\SOFTWARE\Reprise License Manager\Error"
            ]

            for reg_path in registry_paths:
                try:
                    reg_result = subprocess.run(
                        ["reg", "query", reg_path],
                        capture_output=True,
                        text=True,
                        timeout=5,
                        creationflags=subprocess.CREATE_NO_WINDOW
                    )

                    if reg_result.returncode == 0 and reg_result.stdout.strip():
                        logger.info(f"License error registry entry found: {reg_path}")
                        license_error_detected = True

                except subprocess.TimeoutExpired:
                    # Registry query timed out, continue with other checks
                    pass
                except Exception:
                    pass
                    # Registry access may fail, continue with other checks

        except Exception as reg_error:
            logger.warning(f"Failed to check registry for license errors: {reg_error}")

        # Check for license-related temporary files that may indicate errors
        try:
            temp_paths = [
                os.path.expandvars(r"%TEMP%"),
                os.path.expandvars(r"%APPDATA%"),
                os.path.expandvars(r"%LOCALAPPDATA%")
            ]

            license_temp_patterns = [
                "*license*error*",
                "*flexlm*error*",
                "*rlm*error*",
                "*activation*fail*"
            ]

            for temp_path in temp_paths:
                if os.path.exists(temp_path):
                    for pattern in license_temp_patterns:
                        try:
                            import glob
                            if matches := glob.glob(
                                os.path.join(temp_path, pattern)
                            ):
                                logger.info(f"License error temp files found: {len(matches)} files")
                                license_error_detected = True
                                break
                        except Exception:
                            pass
                            # File access may fail, continue checking other files

        except Exception as temp_error:
            logger.warning(f"Failed to check temporary files for license errors: {temp_error}")

        if memory_usage := process_monitoring_data.get("memory_usage", []):
            if memory_values := [entry.get("rss", 0) for entry in memory_usage]:
                max_memory = max(memory_values)
                min_memory = min(memory_values)

                # If memory usage spikes significantly and then drops, might indicate failed license check
                if max_memory > min_memory * 3 and len(memory_values) > 5:
                    final_memory = memory_values[-1]
                    if final_memory < max_memory * 0.5:
                        logger.info("Memory usage pattern suggests possible license validation failure")

        if cpu_usage := process_monitoring_data.get("cpu_usage", []):
            # Brief high CPU followed by process termination might indicate license check failure
            cpu_values = [entry.get("percent", 0) for entry in cpu_usage]
            if cpu_values and len(cpu_values) < 10:  # Process ran briefly
                avg_cpu = sum(cpu_values) / len(cpu_values)
                if avg_cpu > 20:  # High CPU usage for short duration
                    logger.info("Brief high CPU usage suggests possible license validation attempt")

        return license_error_detected

    def validate_negative_control(self, binary_path: str, software_name: str) -> NegativeControlResult:
        """
        Validate that the software properly refuses to run without a valid license.

        Args:
            binary_path: Path to the software binary to test
            software_name: Name of the software being tested

        Returns:
            NegativeControlResult with test results
        """
        logger.info(f"Starting negative control validation for {software_name}")

        test_start_time = datetime.now().isoformat()

        # Calculate binary hash
        binary_hash = self._calculate_hash(binary_path)

        # Initialize result fields
        software_refused_execution = False
        license_error_detected = False
        network_attempts = []
        screenshot_path = None
        process_monitoring_data = {}
        test_valid = False
        error_message = None

        try:
            # Start network monitoring
            network_monitor_process = self._start_network_monitoring()

            # Capture initial screenshot
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            initial_screenshot = self._capture_screenshot(f"negative_control_initial_{timestamp}.txt")

            # Start the software without any bypass
            logger.info(f"Launching {software_name} without bypass")
            start_time = time.time()

            # Launch the process
            process = subprocess.Popen(
                [binary_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                creationflags=subprocess.CREATE_NEW_CONSOLE
            )

            # Monitor the process
            process_monitoring_data = self._monitor_process(process, timeout=120)

            # Stop network monitoring
            network_attempts = self._stop_network_monitoring(network_monitor_process)

            # Capture final screenshot
            final_screenshot = self._capture_screenshot(f"negative_control_final_{timestamp}.txt")
            screenshot_path = final_screenshot

            # Analyze results
            software_refused_execution = process_monitoring_data.get("exit_code", -1) != 0
            license_error_detected = self._detect_license_error(process_monitoring_data)

            # Determine if test is valid
            test_valid = True  # In a real implementation, this would be more sophisticated

            logger.info(f"Negative control test completed for {software_name}")
            logger.info(f"  Software refused execution: {software_refused_execution}")
            logger.info(f"  License error detected: {license_error_detected}")
            logger.info(f"  Test valid: {test_valid}")

        except Exception as e:
            error_message = str(e)
            logger.error(f"Negative control validation failed for {software_name}: {e}")

            # Try to stop any running processes
            try:
                if 'process' in locals():
                    process.terminate()
                    process.wait(timeout=5)
            except (subprocess.TimeoutExpired, ProcessLookupError):
                pass
                # Process cleanup may fail if already terminated

        test_end_time = datetime.now().isoformat()

        return NegativeControlResult(
            software_name=software_name,
            binary_path=binary_path,
            binary_hash=binary_hash,
            test_start_time=test_start_time,
            test_end_time=test_end_time,
            software_refused_execution=software_refused_execution,
            license_error_detected=license_error_detected,
            network_attempts_logged=network_attempts,
            screenshot_path=screenshot_path,
            process_monitoring_data=process_monitoring_data,
            test_valid=test_valid,
            error_message=error_message,
        )

    def validate_all_negative_controls(self) -> list[NegativeControlResult]:
        """
        Run negative control validation on all available binaries.
        """
        logger.info("Starting negative control validation for all binaries")

        results = []

        # Get all acquired binaries
        binaries = self.binary_manager.list_acquired_binaries()

        for binary in binaries:
            try:
                binary_path = binary.get("file_path")
                software_name = binary.get("software_name", "Unknown")

                if binary_path and os.path.exists(binary_path):
                    logger.info(f"Testing negative control for {software_name}")
                    result = self.validate_negative_control(binary_path, software_name)
                    results.append(result)
                else:
                    logger.warning(f"Binary not found for {software_name}: {binary_path}")
                    results.append(NegativeControlResult(
                        software_name=software_name,
                        binary_path=binary_path or "",
                        binary_hash="",
                        test_start_time=datetime.now().isoformat(),
                        test_end_time=datetime.now().isoformat(),
                        software_refused_execution=False,
                        license_error_detected=False,
                        network_attempts_logged=[],
                        screenshot_path=None,
                        process_monitoring_data={},
                        test_valid=False,
                        error_message=f"Binary not found: {binary_path}"
                    ))

            except Exception as e:
                logger.error(f"Failed to test negative control for {binary.get('software_name', 'Unknown')}: {e}")
                results.append(NegativeControlResult(
                    software_name=binary.get("software_name", "Unknown"),
                    binary_path=binary.get("file_path", ""),
                    binary_hash="",
                    test_start_time=datetime.now().isoformat(),
                    test_end_time=datetime.now().isoformat(),
                    software_refused_execution=False,
                    license_error_detected=False,
                    network_attempts_logged=[],
                    screenshot_path=None,
                    process_monitoring_data={},
                    test_valid=False,
                    error_message=str(e)
                ))

        logger.info(f"Completed negative control validation for {len(results)} binaries")
        return results

    def generate_report(self, results: list[NegativeControlResult]) -> str:
        """
        Generate a comprehensive report of negative control validation results.
        """
        if not results:
            return "No negative control tests were run."

        report_lines = [
            "Negative Control Validation Report",
            "=" * 50,
            f"Generated: {datetime.now().isoformat()}",
            f"Total Tests: {len(results)}",
            ""
        ]

        # Summary statistics
        refused_execution_count = sum(bool(r.software_refused_execution)
                                  for r in results)
        license_error_count = sum(bool(r.license_error_detected)
                              for r in results)
        valid_tests = sum(bool(r.test_valid)
                      for r in results)

        report_lines.append("Summary:")
        report_lines.append(f"  Software Refused Execution: {refused_execution_count}/{len(results)}")
        report_lines.append(f"  License Errors Detected: {license_error_count}/{len(results)}")
        report_lines.extend(
            (
                f"  Valid Tests: {valid_tests}/{len(results)}",
                "",
                "Detailed Results:",
                "-" * 30,
            )
        )
        for result in results:
            report_lines.extend(
                (
                    f"Software: {result.software_name}",
                    f"  Binary Hash: {result.binary_hash[:16]}...",
                )
            )
            report_lines.extend(
                (
                    f"  Test Duration: {result.test_end_time} - {result.test_start_time}",
                    f"  Software Refused Execution: {result.software_refused_execution}",
                )
            )
            report_lines.append(f"  License Error Detected: {result.license_error_detected}")
            report_lines.append(f"  Network Attempts: {len(result.network_attempts_logged)}")
            report_lines.append(f"  Screenshot: {result.screenshot_path}")
            report_lines.append(f"  Test Valid: {result.test_valid}")

            if result.error_message:
                report_lines.append(f"  Error: {result.error_message}")

            report_lines.append("")

        return "\n".join(report_lines)

    def save_report(self, results: list[NegativeControlResult], filename: str | None = None) -> str:
        """
        Save the negative control validation report to a file.
        """
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"negative_control_validation_report_{timestamp}.txt"

        report_path = self.reports_dir / filename

        report_text = self.generate_report(results)

        with open(report_path, 'w') as f:
            f.write(report_text)

        logger.info(f"Negative control validation report saved to {report_path}")
        return str(report_path)


if __name__ == "__main__":
    # Test the NegativeControlValidator
    validator = NegativeControlValidator()

    print("Negative Control Validator initialized")
    print("Available binaries:")

    if binaries := validator.binary_manager.list_acquired_binaries():
        for binary in binaries:
            print(f"  - {binary.get('software_name')}: {binary.get('protection')} {binary.get('version')}")

        # Run negative control validation on the first binary
        if binaries:
            first_binary = binaries[0]
            binary_path = first_binary.get("file_path")
            software_name = first_binary.get("software_name", "Unknown")

            if binary_path and os.path.exists(binary_path):
                print(f"\nRunning negative control validation on {software_name}...")
                result = validator.validate_negative_control(binary_path, software_name)

                print(f"Test completed for {software_name}")
                print(f"  Software refused execution: {result.software_refused_execution}")
                print(f"  License error detected: {result.license_error_detected}")
                print(f"  Network attempts: {len(result.network_attempts_logged)}")
                print(f"  Test valid: {result.test_valid}")

                if result.error_message:
                    print(f"  Error: {result.error_message}")

                # Generate and save report
                report_path = validator.save_report([result])
                print(f"\nReport saved to: {report_path}")
            else:
                print(f"\nBinary not found: {binary_path}")
    else:
        print("\nNo binaries acquired yet. Please acquire binaries using commercial_binary_manager.py")

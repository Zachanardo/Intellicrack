"""Windows Activation Module.

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

import hashlib
import os
import platform
import subprocess
import tempfile
import uuid
import winreg
from collections.abc import Callable
from enum import Enum
from pathlib import Path
from typing import IO, Any


try:
    import wmi
except ImportError:
    wmi = None

from ...utils.logger import get_logger
from ...utils.system.system_utils import is_admin


try:
    from ...utils.system.subprocess_utils import run_subprocess_check
except ImportError:
    run_subprocess_check = None  # type: ignore[assignment]

logger = get_logger(__name__)


class ActivationMethod(Enum):
    """Windows activation methods."""

    HWID = "hwid"
    KMS38 = "kms38"
    ONLINE_KMS = "ohook"
    CHECK_ONLY = "check"


class ActivationStatus(Enum):
    """Activation status values."""

    ACTIVATED = "activated"
    NOT_ACTIVATED = "not_activated"
    GRACE_PERIOD = "grace_period"
    UNKNOWN = "unknown"
    ERROR = "error"


class WindowsActivator:
    """Windows Activation Manager.

    Provides a Python interface to Windows activation functionality
    using the MAS (Microsoft Activation Scripts) approach.
    """

    def __init__(self) -> None:
        """Initialize the Windows activator with script path and temporary directory setup."""
        self.script_path: Path = Path(__file__).parent.parent.parent / "ui" / "Windows_Patch" / "WindowsActivator.cmd"
        self.temp_dir: Path = Path(tempfile.gettempdir()) / "intellicrack_activation"
        self.logger = get_logger(__name__)
        self.last_validation_time: float | None = None
        self.last_validation_result: dict[str, Any] | None = None
        self.validation_cache_duration: int = 300

    def activate(self, method: str = "hwid") -> dict[str, Any]:
        """Activate Windows using specified method - alias for activate_windows.

        Args:
            method: Activation method ('hwid', 'kms38', 'ohook')

        Returns:
            Dictionary with activation results

        """
        method_enum = ActivationMethod.HWID
        if method.lower() == "kms38":
            method_enum = ActivationMethod.KMS38
        elif method.lower() == "ohook":
            method_enum = ActivationMethod.ONLINE_KMS
        return self.activate_windows(method_enum)

    def check_activation_status(self) -> dict[str, Any]:
        """Check current Windows activation status - alias for get_activation_status.

        Returns:
            Dictionary with activation status information

        """
        status = self.get_activation_status()
        result: dict[str, Any] = dict(status)
        if "status" in status:
            result["activated"] = status["status"] == "activated"
        return result

    def generate_hwid(self) -> str:
        """Generate Hardware ID for Windows activation.

        Returns:
            Hardware ID string for digital license activation

        """
        try:
            # Initialize WMI
            if wmi is None:
                raise ImportError("WMI module is not available")
            c = wmi.WMI()

            # Collect hardware information
            hardware_info: list[str] = []

            # CPU info
            for processor in c.Win32_Processor():
                hardware_info.extend((
                    (processor.ProcessorId.strip() if processor.ProcessorId else ""),
                    str(processor.NumberOfCores),
                    processor.Name.strip() if processor.Name else "",
                ))
            # Motherboard info
            for board in c.Win32_BaseBoard():
                hardware_info.extend((
                    board.SerialNumber.strip() if board.SerialNumber else "",
                    board.Manufacturer.strip() if board.Manufacturer else "",
                    board.Product.strip() if board.Product else "",
                ))
            # BIOS info
            for bios in c.Win32_BIOS():
                hardware_info.extend((
                    bios.SerialNumber.strip() if bios.SerialNumber else "",
                    bios.Manufacturer.strip() if bios.Manufacturer else "",
                ))
            # Network adapter MAC addresses (physical adapters only)
            hardware_info.extend(
                nic.MACAddress.replace(":", "")
                for nic in c.Win32_NetworkAdapterConfiguration(IPEnabled=True)
                if nic.MACAddress
            )
            # System UUID
            hardware_info.extend(
                system.UUID.strip() if system.UUID else ""
                for system in c.Win32_ComputerSystemProduct()
            )
            # Combine all hardware info
            combined_info = "|".join(filter(None, hardware_info))

            # Generate HWID hash
            hwid_hash = hashlib.sha256(combined_info.encode()).hexdigest()

            # Format as Windows-style HWID
            hwid = f"{hwid_hash[:8]}-{hwid_hash[8:12]}-{hwid_hash[12:16]}-{hwid_hash[16:20]}-{hwid_hash[20:32]}"

            self.logger.info("Generated HWID: %s...", hwid[:20])  # Log partial HWID for privacy
            return hwid.upper()

        except ImportError:
            # Fallback if WMI not available
            self.logger.warning("WMI not available, using fallback HWID generation")

            # Use platform info and MAC address as fallback
            machine_info = f"{platform.machine()}|{platform.processor()}|{platform.node()}"

            # Try to get MAC address
            try:
                mac = uuid.getnode()
                machine_info += f"|{mac:012X}"
            except OSError:
                self.logger.debug("Failed to get MAC address")

            # Generate fallback HWID
            fallback_hash = hashlib.sha256(machine_info.encode()).hexdigest()
            hwid = f"{fallback_hash[:8]}-{fallback_hash[8:12]}-{fallback_hash[12:16]}-{fallback_hash[16:20]}-{fallback_hash[20:32]}"

            return hwid.upper()

        except Exception as e:
            self.logger.exception("Error generating HWID: %s", e)
            basic_info = f"{os.environ.get('COMPUTERNAME', 'UNKNOWN')}|{platform.platform()}"
            basic_hash = hashlib.sha256(basic_info.encode()).hexdigest()
            return f"{basic_hash[:8]}-{basic_hash[8:12]}-{basic_hash[12:16]}-{basic_hash[16:20]}-{basic_hash[20:32]}".upper()

    def check_prerequisites(self) -> tuple[bool, list[str]]:
        """Check if prerequisites for Windows activation are met.

        Returns:
            Tuple of (success, list of issues)

        """
        issues = []

        # Check if script exists
        if not self.script_path.exists():
            issues.append("WindowsActivator.cmd script not found")

        # Check if running on Windows
        if os.name != "nt":
            issues.append("Windows activation only supported on Windows")

        # Check admin privileges
        if not is_admin():
            issues.append("Administrator privileges required for activation")

        return not issues, issues

    def get_activation_status(self) -> dict[str, Any]:
        """Get current Windows activation status.

        Returns:
            Dictionary with activation information

        """
        try:
            # Use slmgr to check activation status
            result = subprocess.run(
                ["cscript", "//nologo", "C:\\Windows\\System32\\slmgr.vbs", "/xpr"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            status_info: dict[str, Any] = {
                "status": ActivationStatus.UNKNOWN.value,
                "raw_output": result.stdout.strip(),
                "error": result.stderr.strip() if result.stderr else None,
            }

            if result.returncode == 0:
                output = result.stdout.lower()
                if "permanently activated" in output:
                    status_info["status"] = ActivationStatus.ACTIVATED.value
                elif "grace period" in output:
                    status_info["status"] = ActivationStatus.GRACE_PERIOD.value
                elif "not activated" in output:
                    status_info["status"] = ActivationStatus.NOT_ACTIVATED.value
            else:
                status_info["status"] = ActivationStatus.ERROR.value

            return status_info

        except (OSError, ValueError, RuntimeError) as e:
            logger.exception("Error checking activation status: %s", e)
            return {
                "status": ActivationStatus.ERROR.value,
                "error": str(e),
            }

    def activate_windows(self, method: ActivationMethod = ActivationMethod.HWID) -> dict[str, Any]:
        """Activate Windows using specified method.

        Args:
            method: Activation method to use

        Returns:
            Dictionary with activation result

        """
        prereq_ok, issues = self.check_prerequisites()
        if not prereq_ok:
            return {
                "success": False,
                "error": "Prerequisites not met",
                "issues": issues,
            }

        try:
            # Create command based on method
            if method == ActivationMethod.HWID:
                cmd_args = [str(self.script_path), "/HWID"]
            elif method == ActivationMethod.KMS38:
                cmd_args = [str(self.script_path), "/KMS38"]
            elif method == ActivationMethod.ONLINE_KMS:
                cmd_args = [str(self.script_path), "/Ohook"]
            else:
                return {
                    "success": False,
                    "error": f"Unsupported activation method: {method.value}",
                }

            logger.info("Starting Windows activation with method: %s", method.value)

            # Run the activation script
            result = subprocess.run(  # nosec S603 - Legitimate subprocess usage for security research and binary analysis
                cmd_args,
                capture_output=True,
                text=True,
                timeout=300,  # 5 minutes timeout
                cwd=self.script_path.parent,
                check=False,
            )

            success = result.returncode == 0

            activation_result = {
                "success": success,
                "method": method.value,
                "return_code": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
            }

            if success:
                logger.info("Windows activation completed successfully with %s", method.value)
                # Get updated status
                activation_result["post_activation_status"] = self.get_activation_status()
            else:
                logger.exception("Windows activation failed with %s: %s", method.value, result.stderr)

            return activation_result

        except subprocess.TimeoutExpired:
            logger.exception("Windows activation timed out")
            return {
                "success": False,
                "error": "Activation process timed out",
            }
        except (OSError, ValueError, RuntimeError) as e:
            logger.exception("Error during Windows activation: %s", e)
            return {
                "success": False,
                "error": str(e),
            }

    def reset_activation(self) -> dict[str, Any]:
        """Reset Windows activation state.

        Returns:
            Dictionary with reset result

        """
        try:
            # Reset activation using slmgr
            result = subprocess.run(
                ["cscript", "//nologo", "C:\\Windows\\System32\\slmgr.vbs", "/rearm"],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )

            return {
                "success": result.returncode == 0,
                "return_code": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
            }

        except (OSError, ValueError, RuntimeError) as e:
            logger.exception("Error resetting activation: %s", e)
            return {
                "success": False,
                "error": str(e),
            }

    def get_product_key_info(self) -> dict[str, Any]:
        """Get information about installed product keys.

        Returns:
            Dictionary with product key information

        """
        try:
            result = subprocess.run(
                ["cscript", "//nologo", "C:\\Windows\\System32\\slmgr.vbs", "/dli"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            return {
                "success": result.returncode == 0,
                "product_info": result.stdout.strip(),
                "error": result.stderr.strip() if result.stderr else None,
            }

        except (OSError, ValueError, RuntimeError) as e:
            logger.exception("Error getting product key info: %s", e)
            return {
                "success": False,
                "error": str(e),
            }

    def activate_windows_kms(self) -> dict[str, Any]:
        """Activate Windows using KMS method."""
        return self.activate_windows(ActivationMethod.KMS38)

    def activate_windows_digital(self) -> dict[str, Any]:
        """Activate Windows using HWID digital method."""
        return self.activate_windows(ActivationMethod.HWID)

    def activate_office(self, office_version: str = "auto") -> dict[str, Any]:
        """Activate Microsoft Office using Office-specific activation methods.

        Args:
            office_version: Office version ("2016", "2019", "2021", "365", "auto")

        Returns:
            Dictionary with activation result

        """
        prereq_ok, issues = self.check_prerequisites()
        if not prereq_ok:
            return {
                "success": False,
                "error": "Prerequisites not met for Office activation",
                "issues": issues,
            }

        try:
            # Detect Office installation if version is auto
            if office_version == "auto":
                office_version = self._detect_office_version()
                if not office_version:
                    return {
                        "success": False,
                        "error": "No Microsoft Office installation detected",
                    }

            logger.info("Starting Office activation for version: %s", office_version)

            # Try C2R (Click-to-Run) activation first, then MSI if needed
            result = self._activate_office_c2r(office_version)

            # If C2R failed, try MSI method
            if not result.get("success", False):
                logger.info("C2R activation failed, trying MSI method...")
                msi_result = self._activate_office_msi(office_version)
                if msi_result.get("success", False):
                    result = msi_result
                else:
                    result["msi_error"] = msi_result.get("error", "MSI activation also failed")

            # Get Office activation status after attempt
            if result.get("success", False):
                result["post_activation_status"] = self._get_office_status()
                logger.info("Office activation completed successfully")
            else:
                logger.exception("Office activation failed: %s", result.get("error", "Unknown error"))

            return result

        except (OSError, ValueError, RuntimeError) as e:
            logger.exception("Error during Office activation: %s", e)
            return {
                "success": False,
                "error": f"Office activation error: {e!s}",
            }

    def _detect_office_version(self) -> str:
        """Detect installed Office version.

        Returns:
            Detected Office version string or empty string if not found

        """
        try:
            # Check common Office installation paths
            office_paths = [
                r"C:\Program Files\Microsoft Office",
                r"C:\Program Files (x86)\Microsoft Office",
                r"C:\Program Files\Microsoft Office\root\Office16",
                r"C:\Program Files (x86)\Microsoft Office\root\Office16",
            ]

            detected_versions = []

            for base_path in office_paths:
                if os.path.exists(base_path):
                    # Look for version-specific folders
                    try:
                        for item in os.listdir(base_path):
                            item_path = os.path.join(base_path, item)
                            if Path(item_path).is_dir() and any(
                                os.path.exists(os.path.join(item_path, exe)) for exe in ["WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE"]
                            ):
                                if "Office16" in item or "16.0" in item:
                                    detected_versions.append("2016")
                                elif "Office15" in item or "15.0" in item:
                                    detected_versions.append("2013")
                                elif "Office14" in item or "14.0" in item:
                                    detected_versions.append("2010")
                    except OSError as e:
                        logger.exception("Error in windows_activator: %s", e)
                        continue

            # Also check registry for C2R installations
            try:
                registry_paths = [
                    r"SOFTWARE\Microsoft\Office\ClickToRun\Configuration",  # pragma: allowlist secret
                    r"SOFTWARE\WOW6432Node\Microsoft\Office\ClickToRun\Configuration",  # pragma: allowlist secret
                ]

                for reg_path in registry_paths:
                    try:
                        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path) as key:
                            try:
                                version_info, _ = winreg.QueryValueEx(key, "VersionToReport")
                                if version_info.startswith("16."):
                                    detected_versions.append("2016")
                                elif version_info.startswith("15."):
                                    detected_versions.append("2013")
                            except FileNotFoundError as e:
                                logger.exception("File not found in windows_activator: %s", e)
                    except FileNotFoundError as e:
                        logger.exception("File not found in windows_activator: %s", e)
                        continue

            except ImportError as e:
                logger.exception("Import error in windows_activator: %s", e)

            # Return most recent version detected
            if detected_versions:
                if "2021" in detected_versions:
                    return "2021"
                if "2019" in detected_versions:
                    return "2019"
                if "2016" in detected_versions:
                    return "2016"
                return "2013" if "2013" in detected_versions else detected_versions[0]
            return ""

        except (OSError, ValueError, RuntimeError) as e:
            logger.exception("Error detecting Office version: %s", e)
            return ""

    def _activate_office_c2r(self, office_version: str) -> dict[str, Any]:
        """Activate Office using Click-to-Run (C2R) method.

        Args:
            office_version: Office version to activate

        Returns:
            Dictionary with activation result

        """
        try:
            # Use office_script_path from script directory if available
            office_script = self.script_path.parent / "OfficeActivator.cmd"

            # If specific Office script doesn't exist, use main script with Office flag
            if not office_script.exists():
                office_script = self.script_path
                cmd_args = [str(office_script), "/Office"]
            else:
                cmd_args = [str(office_script), "/C2R", f"/Version:{office_version}"]

            logger.info("Running Office C2R activation: %s", " ".join(cmd_args))

            result = subprocess.run(  # nosec S603 - Legitimate subprocess usage for security research and binary analysis
                cmd_args,
                capture_output=True,
                text=True,
                timeout=300,  # 5 minutes timeout
                cwd=self.script_path.parent,
                check=False,
            )

            success = result.returncode == 0

            return {
                "success": success,
                "method": "C2R",
                "office_version": office_version,
                "return_code": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
            }

        except subprocess.TimeoutExpired as e:
            logger.exception("Subprocess timeout in windows_activator: %s", e)
            return {
                "success": False,
                "method": "C2R",
                "error": "Office C2R activation timed out",
            }
        except (OSError, ValueError, RuntimeError) as e:
            logger.exception("Error in windows_activator: %s", e)
            return {
                "success": False,
                "method": "C2R",
                "error": f"Office C2R activation error: {e!s}",
            }

    def _activate_office_msi(self, office_version: str) -> dict[str, Any]:
        """Activate Office using MSI (Windows Installer) method.

        Args:
            office_version: Office version to activate

        Returns:
            Dictionary with activation result

        """
        try:
            # Use OSPP.VBS script for Office activation
            ospp_paths = [
                r"C:\Program Files\Microsoft Office\Office16\OSPP.VBS",
                r"C:\Program Files (x86)\Microsoft Office\Office16\OSPP.VBS",
                r"C:\Program Files\Microsoft Office\Office15\OSPP.VBS",
                r"C:\Program Files (x86)\Microsoft Office\Office15\OSPP.VBS",
            ]

            ospp_script = next((path for path in ospp_paths if os.path.exists(path)), None)
            if not ospp_script:
                return {
                    "success": False,
                    "method": "MSI",
                    "error": "OSPP.VBS script not found - Office may not be installed",
                }

            # Try to activate using OSPP with generic volume license key
            volume_keys = {
                "2019": "NMMKJ-6RK4F-KMJVX-8D9MJ-6MWKP",  # Office Pro Plus 2019
                "2016": "XQNVK-8JYDB-WJ9W3-YJ8YR-WFG99",  # Office Pro Plus 2016
                "2013": "YC7DK-G2NP3-2QQC3-J6H88-GVGXT",  # Office Pro Plus 2013
                "2021": "FXYTK-NJJ8C-GB6DW-3DYQT-6F7TH",  # Office Pro Plus 2021
            }

            key = volume_keys.get(office_version, volume_keys.get("2016"))  # Default to 2016 key

            # Install the product key
            install_cmd = [
                "cscript",
                "//nologo",
                ospp_script,
                f"/inpkey:{key}",
            ]

            logger.info("Installing Office product key for version %s", office_version)

            result = subprocess.run(install_cmd, capture_output=True, text=True, timeout=60, check=False)

            if result.returncode != 0:
                return {
                    "success": False,
                    "method": "MSI",
                    "error": f"Failed to install product key: {result.stderr}",
                }

            # Activate the installed key
            activate_cmd = [
                "cscript",
                "//nologo",
                ospp_script,
                "/act",
            ]

            logger.info("Activating Office using MSI method")

            result = subprocess.run(  # nosec S603 - Legitimate subprocess usage for security research and binary analysis
                activate_cmd,
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )

            success = result.returncode == 0

            return {
                "success": success,
                "method": "MSI",
                "office_version": office_version,
                "product_key": key,
                "return_code": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
            }

        except subprocess.TimeoutExpired as e:
            logger.exception("Subprocess timeout in windows_activator: %s", e)
            return {
                "success": False,
                "method": "MSI",
                "error": "Office MSI activation timed out",
            }
        except (OSError, ValueError, RuntimeError) as e:
            logger.exception("Error in windows_activator: %s", e)
            return {
                "success": False,
                "method": "MSI",
                "error": f"Office MSI activation error: {e!s}",
            }

    def _get_office_status(self) -> dict[str, Any]:
        """Get Office activation status.

        Returns:
            Dictionary with Office activation status

        """
        try:
            # Find OSPP.VBS script
            ospp_paths = [
                r"C:\Program Files\Microsoft Office\Office16\OSPP.VBS",
                r"C:\Program Files (x86)\Microsoft Office\Office16\OSPP.VBS",
                r"C:\Program Files\Microsoft Office\Office15\OSPP.VBS",
                r"C:\Program Files (x86)\Microsoft Office\Office15\OSPP.VBS",
            ]

            ospp_script = next((path for path in ospp_paths if os.path.exists(path)), None)
            if not ospp_script:
                return {
                    "status": "unknown",
                    "error": "OSPP.VBS not found",
                }

            # Check activation status
            result = subprocess.run(  # nosec S603 - Legitimate subprocess usage for security research and binary analysis
                ["cscript", "//nologo", ospp_script, "/dstatus"],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )

            status_info: dict[str, Any] = {
                "raw_output": result.stdout.strip(),
                "error": result.stderr.strip() if result.stderr else None,
            }

            if result.returncode == 0:
                output = result.stdout.lower()
                if "license status: ---licensed---" in output:
                    status_info["status"] = "activated"
                elif "license status: ---grace---" in output:
                    status_info["status"] = "grace_period"
                elif "license status: ---notification---" in output:
                    status_info["status"] = "notification"
                else:
                    status_info["status"] = "not_activated"
            else:
                status_info["status"] = "error"

            return status_info

        except (OSError, ValueError, RuntimeError) as e:
            logger.exception("Error getting Office status: %s", e)
            return {
                "status": "error",
                "error": str(e),
            }

    def activate_windows_interactive(self, output_callback: Callable[[str, bool], None] | None = None) -> dict[str, Any]:
        """Activate Windows with interactive output streaming.

        Runs the Windows activation process with real-time output streaming
        to a callback function. Useful for GUI applications that need to
        display activation progress to users.

        Args:
            output_callback: Optional callback function that receives output lines.
                            Signature: callback(line: str, is_stderr: bool) -> None

        Returns:
            Dictionary with activation results including:
                - success: Boolean indicating if activation succeeded
                - method: Activation method used (hwid)
                - return_code: Process exit code
                - stdout: Complete stdout output
                - stderr: Complete stderr output
                - error: Error message if activation failed
                - post_activation_status: Current activation status after attempt

        """
        prereq_ok, issues = self.check_prerequisites()
        if not prereq_ok:
            if output_callback:
                for issue in issues:
                    output_callback(f"Prerequisite issue: {issue}", True)
            return {
                "success": False,
                "error": "Prerequisites not met",
                "issues": issues,
            }

        try:
            cmd_args = [str(self.script_path), "/HWID"]

            self.logger.info("Starting interactive Windows activation with HWID method")
            if output_callback:
                output_callback("Starting Windows activation (HWID method)...", False)

            import queue
            import threading
            import time as time_module

            result: dict[str, Any] = {
                "success": False,
                "method": "hwid",
                "return_code": -1,
                "stdout": "",
                "stderr": "",
                "error": None,
            }

            output_queue: queue.Queue[tuple[str, bool]] = queue.Queue()
            stdout_lines: list[str] = []
            stderr_lines: list[str] = []

            def reader_thread(pipe: IO[str], line_list: list[str], is_stderr: bool = False) -> None:
                try:
                    for line in iter(pipe.readline, ""):
                        if not line:
                            break
                        line = line.rstrip("\n\r")
                        line_list.append(line)
                        output_queue.put((line, is_stderr))
                except Exception as e:
                    self.logger.debug("Reader thread error: %s", e)
                finally:
                    pipe.close()

            process = subprocess.Popen(
                cmd_args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=self.script_path.parent,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
            )

            stdout_thread = threading.Thread(
                target=reader_thread,
                args=(process.stdout, stdout_lines, False),
            )
            stderr_thread = threading.Thread(
                target=reader_thread,
                args=(process.stderr, stderr_lines, True),
            )

            stdout_thread.start()
            stderr_thread.start()

            start_time = time_module.time()
            timeout = 300

            while process.poll() is None:
                if time_module.time() - start_time > timeout:
                    process.terminate()
                    result["error"] = "Activation process timed out"
                    if output_callback:
                        output_callback("ERROR: Activation process timed out", True)
                    break

                try:
                    line, is_stderr = output_queue.get(timeout=0.1)
                    if output_callback:
                        output_callback(line, is_stderr)
                except queue.Empty:
                    continue

            stdout_thread.join(timeout=2)
            stderr_thread.join(timeout=2)

            while not output_queue.empty():
                try:
                    line, is_stderr = output_queue.get_nowait()
                    if output_callback:
                        output_callback(line, is_stderr)
                except queue.Empty:
                    break

            result["return_code"] = process.returncode
            result["stdout"] = "\n".join(stdout_lines)
            result["stderr"] = "\n".join(stderr_lines)
            result["success"] = process.returncode == 0

            if result["success"]:
                self.logger.info("Interactive Windows activation completed successfully")
                result["post_activation_status"] = self.get_activation_status()
                if output_callback:
                    output_callback("Activation completed successfully!", False)
            else:
                self.logger.exception("Interactive Windows activation failed")
                if output_callback:
                    output_callback("Activation failed. Check output for details.", True)

            return result

        except subprocess.TimeoutExpired:
            self.logger.exception("Windows activation timed out")
            if output_callback:
                output_callback("ERROR: Activation timed out", True)
            return {
                "success": False,
                "error": "Activation process timed out",
            }
        except (OSError, ValueError, RuntimeError) as e:
            self.logger.exception("Error during Windows activation: %s", e)
            if output_callback:
                output_callback(f"ERROR: {e}", True)
            return {
                "success": False,
                "error": str(e),
            }

    def activate_windows_in_terminal(self) -> dict[str, Any]:
        """Activate Windows using an embedded terminal approach.

        Runs the Windows activation script in a new command prompt window
        for maximum compatibility with scripts that require user interaction
        or display colored console output.

        Returns:
            Dictionary with activation results including:
                - success: Boolean indicating if activation was initiated
                - method: Activation method used (terminal)
                - process_started: Boolean indicating if the process started
                - error: Error message if startup failed
                - post_activation_status: Status check result (may be delayed)

        """
        prereq_ok, issues = self.check_prerequisites()
        if not prereq_ok:
            return {
                "success": False,
                "error": "Prerequisites not met",
                "issues": issues,
            }

        try:
            self.logger.info("Starting Windows activation in terminal mode")

            if os.name != "nt":
                return {
                    "success": False,
                    "error": "Terminal activation only supported on Windows",
                }

            cmd_args = [
                "cmd.exe",
                "/c",
                "start",
                "Windows Activation",
                "/wait",
                str(self.script_path),
            ]

            process = subprocess.Popen(
                cmd_args,
                cwd=self.script_path.parent,
                creationflags=subprocess.CREATE_NEW_CONSOLE,
            )

            self.logger.info("Terminal activation window opened, waiting for completion...")

            try:
                return_code = process.wait(timeout=600)

                result = {
                    "success": return_code == 0,
                    "method": "terminal",
                    "return_code": return_code,
                    "process_started": True,
                }

                if return_code == 0:
                    self.logger.info("Terminal activation completed successfully")
                    result["post_activation_status"] = self.get_activation_status()
                else:
                    self.logger.warning("Terminal activation exited with code: %d", return_code)

                return result

            except subprocess.TimeoutExpired:
                self.logger.warning("Terminal activation window still open after timeout")
                return {
                    "success": False,
                    "method": "terminal",
                    "process_started": True,
                    "error": "Activation window remained open - user interaction may be required",
                }

        except FileNotFoundError:
            self.logger.exception("Activation script not found: %s", self.script_path)
            return {
                "success": False,
                "error": f"Activation script not found: {self.script_path}",
            }
        except PermissionError:
            self.logger.exception("Permission denied - administrator privileges required")
            return {
                "success": False,
                "error": "Administrator privileges required for activation",
            }
        except (OSError, ValueError, RuntimeError) as e:
            self.logger.exception("Error during terminal activation: %s", e)
            return {
                "success": False,
                "error": str(e),
            }


def create_windows_activator() -> WindowsActivator:
    """Create Windows activator instance.

    Returns:
        Configured WindowsActivator instance

    """
    return WindowsActivator()


# Convenience functions
def check_windows_activation() -> dict[str, Any]:
    """Quick check of Windows activation status.

    Returns:
        Dictionary with activation status

    """
    activator = create_windows_activator()
    return activator.get_activation_status()


def activate_windows_hwid() -> dict[str, Any]:
    """Activate Windows using HWID method.

    Returns:
        Dictionary with activation result

    """
    activator = create_windows_activator()
    return activator.activate_windows(ActivationMethod.HWID)


def activate_windows_kms() -> dict[str, Any]:
    """Activate Windows using KMS38 method.

    Returns:
        Dictionary with activation result

    """
    activator = create_windows_activator()
    return activator.activate_windows(ActivationMethod.KMS38)


class WindowsActivatorInteractive:
    """Interactive Windows activation with real-time output streaming."""

    def __init__(self, activator: WindowsActivator) -> None:
        """Initialize with a WindowsActivator instance."""
        self.activator = activator
        self.logger = get_logger(__name__)

    def run_with_callback(
        self,
        cmd_args: list[str],
        output_callback: Callable[[str, bool], None] | None = None,
        timeout: int = 300,
    ) -> dict[str, Any]:
        """Run activation command with real-time output streaming.

        Args:
            cmd_args: Command arguments to execute
            output_callback: Optional callback function to receive output lines
            timeout: Maximum execution time in seconds

        Returns:
            Dictionary with execution results

        """
        import queue
        import threading

        result: dict[str, Any] = {
            "success": False,
            "return_code": -1,
            "stdout": "",
            "stderr": "",
            "error": None,
        }

        output_queue: queue.Queue[tuple[str, bool]] = queue.Queue()
        stdout_lines: list[str] = []
        stderr_lines: list[str] = []

        def reader_thread(pipe: IO[str], line_list: list[str], is_stderr: bool = False) -> None:
            try:
                for line in iter(pipe.readline, ""):
                    if not line:
                        break
                    line = line.rstrip("\n\r")
                    line_list.append(line)
                    output_queue.put((line, is_stderr))
            except Exception as e:
                self.logger.debug("Reader thread error: %s", e)
            finally:
                pipe.close()

        try:
            process = subprocess.Popen(
                cmd_args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=self.activator.script_path.parent,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
            )

            stdout_thread = threading.Thread(
                target=reader_thread,
                args=(process.stdout, stdout_lines, False),
            )
            stderr_thread = threading.Thread(
                target=reader_thread,
                args=(process.stderr, stderr_lines, True),
            )

            stdout_thread.start()
            stderr_thread.start()

            import time as time_module

            start_time = time_module.time()

            while process.poll() is None:
                if time_module.time() - start_time > timeout:
                    process.terminate()
                    result["error"] = "Process timed out"
                    break

                try:
                    line, is_stderr = output_queue.get(timeout=0.1)
                    if output_callback:
                        output_callback(line, is_stderr)
                except queue.Empty:
                    continue

            stdout_thread.join(timeout=2)
            stderr_thread.join(timeout=2)

            while not output_queue.empty():
                try:
                    line, is_stderr = output_queue.get_nowait()
                    if output_callback:
                        output_callback(line, is_stderr)
                except queue.Empty:
                    break

            result["return_code"] = process.returncode
            result["stdout"] = "\n".join(stdout_lines)
            result["stderr"] = "\n".join(stderr_lines)
            result["success"] = process.returncode == 0

        except FileNotFoundError:
            result["error"] = "Activation script not found"
            self.logger.exception("Activation script not found")
        except PermissionError:
            result["error"] = "Permission denied - administrator privileges required"
            self.logger.exception("Permission denied for activation script")
        except Exception as e:
            result["error"] = str(e)
            self.logger.exception("Interactive activation error: %s", e)

        return result

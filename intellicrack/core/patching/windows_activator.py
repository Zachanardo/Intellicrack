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
from enum import Enum
from pathlib import Path

try:
    import wmi
except ImportError:
    wmi = None

from ...utils.logger import get_logger
from ...utils.system.system_utils import is_admin

try:
    from ...utils.system.subprocess_utils import run_subprocess_check
except ImportError:
    run_subprocess_check = None

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
        self.script_path = Path(__file__).parent.parent.parent / "ui" / "Windows_Patch" / "WindowsActivator.cmd"
        self.temp_dir = Path(tempfile.gettempdir()) / "intellicrack_activation"
        self.logger = get_logger(__name__)
        self.last_validation_time = None
        self.last_validation_result = None
        self.validation_cache_duration = 300  # 5 minutes

    def activate(self, method: str = "hwid") -> dict[str, any]:
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

    def check_activation_status(self) -> dict[str, str]:
        """Check current Windows activation status - alias for get_activation_status.

        Returns:
            Dictionary with activation status information

        """
        status = self.get_activation_status()
        # Add 'activated' key for compatibility
        if "status" in status:
            status["activated"] = status["status"] == "activated"
        return status

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
            hardware_info = []

            # CPU info
            for processor in c.Win32_Processor():
                hardware_info.append(processor.ProcessorId.strip() if processor.ProcessorId else "")
                hardware_info.append(str(processor.NumberOfCores))
                hardware_info.append(processor.Name.strip() if processor.Name else "")

            # Motherboard info
            for board in c.Win32_BaseBoard():
                hardware_info.append(board.SerialNumber.strip() if board.SerialNumber else "")
                hardware_info.append(board.Manufacturer.strip() if board.Manufacturer else "")
                hardware_info.append(board.Product.strip() if board.Product else "")

            # BIOS info
            for bios in c.Win32_BIOS():
                hardware_info.append(bios.SerialNumber.strip() if bios.SerialNumber else "")
                hardware_info.append(bios.Manufacturer.strip() if bios.Manufacturer else "")

            # Network adapter MAC addresses (physical adapters only)
            for nic in c.Win32_NetworkAdapterConfiguration(IPEnabled=True):
                if nic.MACAddress:
                    hardware_info.append(nic.MACAddress.replace(":", ""))

            # System UUID
            for system in c.Win32_ComputerSystemProduct():
                hardware_info.append(system.UUID.strip() if system.UUID else "")

            # Combine all hardware info
            combined_info = "|".join(filter(None, hardware_info))

            # Generate HWID hash
            hwid_hash = hashlib.sha256(combined_info.encode()).hexdigest()

            # Format as Windows-style HWID
            hwid = f"{hwid_hash[:8]}-{hwid_hash[8:12]}-{hwid_hash[12:16]}-{hwid_hash[16:20]}-{hwid_hash[20:32]}"

            self.logger.info(f"Generated HWID: {hwid[:20]}...")  # Log partial HWID for privacy
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
                pass

            # Generate fallback HWID
            fallback_hash = hashlib.sha256(machine_info.encode()).hexdigest()
            hwid = f"{fallback_hash[:8]}-{fallback_hash[8:12]}-{fallback_hash[12:16]}-{fallback_hash[16:20]}-{fallback_hash[20:32]}"

            return hwid.upper()

        except Exception as e:
            self.logger.error(f"Error generating HWID: {e}")
            # Return a deterministic but unique HWID based on available info
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

        return len(issues) == 0, issues

    def get_activation_status(self) -> dict[str, str]:
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

            status_info = {
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
            logger.error("Error checking activation status: %s", e)
            return {
                "status": ActivationStatus.ERROR.value,
                "error": str(e),
            }

    def activate_windows(self, method: ActivationMethod = ActivationMethod.HWID) -> dict[str, any]:
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
                logger.error("Windows activation failed with %s: %s", method.value, result.stderr)

            return activation_result

        except subprocess.TimeoutExpired:
            logger.error("Windows activation timed out")
            return {
                "success": False,
                "error": "Activation process timed out",
            }
        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Error during Windows activation: %s", e)
            return {
                "success": False,
                "error": str(e),
            }

    def reset_activation(self) -> dict[str, any]:
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
            logger.error("Error resetting activation: %s", e)
            return {
                "success": False,
                "error": str(e),
            }

    def get_product_key_info(self) -> dict[str, str]:
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
            logger.error("Error getting product key info: %s", e)
            return {
                "success": False,
                "error": str(e),
            }

    def activate_windows_kms(self) -> dict[str, any]:
        """Activate Windows using KMS method."""
        return self.activate_windows(ActivationMethod.KMS38)

    def activate_windows_digital(self) -> dict[str, any]:
        """Activate Windows using HWID digital method."""
        return self.activate_windows(ActivationMethod.HWID)

    def activate_office(self, office_version: str = "auto") -> dict[str, any]:
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
                    # Combine error information
                    result["msi_error"] = msi_result.get("error", "MSI activation also failed")

            # Get Office activation status after attempt
            if result.get("success", False):
                result["post_activation_status"] = self._get_office_status()
                logger.info("Office activation completed successfully")
            else:
                logger.error("Office activation failed: %s", result.get("error", "Unknown error"))

            return result

        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Error during Office activation: %s", e)
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
                            if os.path.isdir(item_path):
                                # Check for Office executables
                                if any(
                                    os.path.exists(os.path.join(item_path, exe)) for exe in ["WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE"]
                                ):
                                    if "Office16" in item or "16.0" in item:
                                        detected_versions.append("2016")
                                    elif "Office15" in item or "15.0" in item:
                                        detected_versions.append("2013")
                                    elif "Office14" in item or "14.0" in item:
                                        detected_versions.append("2010")
                    except (OSError, PermissionError) as e:
                        logger.error("Error in windows_activator: %s", e)
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
                                logger.error("File not found in windows_activator: %s", e)
                    except FileNotFoundError as e:
                        logger.error("File not found in windows_activator: %s", e)
                        continue

            except ImportError as e:
                logger.error("Import error in windows_activator: %s", e)
                # winreg not available (non-Windows)

            # Return most recent version detected
            if detected_versions:
                if "2021" in detected_versions:
                    return "2021"
                if "2019" in detected_versions:
                    return "2019"
                if "2016" in detected_versions:
                    return "2016"
                if "2013" in detected_versions:
                    return "2013"
                return detected_versions[0]

            return ""

        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Error detecting Office version: %s", e)
            return ""

    def _activate_office_c2r(self, office_version: str) -> dict[str, any]:
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
            logger.error("Subprocess timeout in windows_activator: %s", e)
            return {
                "success": False,
                "method": "C2R",
                "error": "Office C2R activation timed out",
            }
        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Error in windows_activator: %s", e)
            return {
                "success": False,
                "method": "C2R",
                "error": f"Office C2R activation error: {e!s}",
            }

    def _activate_office_msi(self, office_version: str) -> dict[str, any]:
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

            ospp_script = None
            for path in ospp_paths:
                if os.path.exists(path):
                    ospp_script = path
                    break

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

            if run_subprocess_check is None:
                # Fallback to subprocess.run if run_subprocess_check is not available
                result = subprocess.run(install_cmd, capture_output=True, text=True, timeout=60)
            else:
                result = run_subprocess_check(install_cmd, timeout=60)

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
                activate_cmd, capture_output=True, text=True, timeout=120, check=False,
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
            logger.error("Subprocess timeout in windows_activator: %s", e)
            return {
                "success": False,
                "method": "MSI",
                "error": "Office MSI activation timed out",
            }
        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Error in windows_activator: %s", e)
            return {
                "success": False,
                "method": "MSI",
                "error": f"Office MSI activation error: {e!s}",
            }

    def _get_office_status(self) -> dict[str, str]:
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

            ospp_script = None
            for path in ospp_paths:
                if os.path.exists(path):
                    ospp_script = path
                    break

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

            status_info = {
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
            logger.error("Error getting Office status: %s", e)
            return {
                "status": "error",
                "error": str(e),
            }


def create_windows_activator() -> WindowsActivator:
    """Create Windows activator instance.

    Returns:
        Configured WindowsActivator instance

    """
    return WindowsActivator()


# Convenience functions
def check_windows_activation() -> dict[str, str]:
    """Quick check of Windows activation status.

    Returns:
        Dictionary with activation status

    """
    activator = create_windows_activator()
    return activator.get_activation_status()


def activate_windows_hwid() -> dict[str, any]:
    """Activate Windows using HWID method.

    Returns:
        Dictionary with activation result

    """
    activator = create_windows_activator()
    return activator.activate_windows(ActivationMethod.HWID)


def activate_windows_kms() -> dict[str, any]:
    """Activate Windows using KMS38 method.

    Returns:
        Dictionary with activation result

    """
    activator = create_windows_activator()
    return activator.activate_windows(ActivationMethod.KMS38)

"""Process and system utilities for Intellicrack.

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
import logging
import os
import shlex
import subprocess
import sys
from typing import Any

logger = logging.getLogger(__name__)

try:
    from intellicrack.handlers.psutil_handler import psutil

    PSUTIL_AVAILABLE = True
except ImportError as e:
    logger.error("Import error in process_utils: %s", e)
    psutil = None
    PSUTIL_AVAILABLE = False


# Consolidated process iteration utilities to avoid code duplication


def find_process_by_name(process_name: str, exact_match: bool = False) -> int | None:
    """Find process PID by name with unified logic.

    Args:
        process_name: Name of process to find
        exact_match: If True, require exact name match; if False, allow partial match

    Returns:
        Process PID if found, None otherwise

    """
    if not PSUTIL_AVAILABLE:
        logger.warning("psutil not available for process search")
        return None

    try:
        target_name = process_name.lower()
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                if proc.info["name"]:
                    proc_name_lower = proc.info["name"].lower()
                    if exact_match:
                        if proc_name_lower == target_name:
                            logger.info(f"Found exact process match: {process_name} with PID: {proc.info['pid']}")
                            return proc.info["pid"]
                    elif target_name in proc_name_lower:
                        logger.info(f"Found process match: {process_name} with PID: {proc.info['pid']}")
                        return proc.info["pid"]
            except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                logger.error("Error in process_utils: %s", e)
                continue
    except Exception as e:
        logger.error(f"Error searching for process {process_name}: {e}")

    return None


def get_all_processes(fields: list[str] | None = None) -> list[dict[str, Any]]:
    """Get list of all processes with unified logic.

    Args:
        fields: List of fields to retrieve (default: ['pid', 'name', 'cpu_percent', 'memory_percent'])

    Returns:
        List of process information dictionaries

    """
    if not PSUTIL_AVAILABLE:
        logger.warning("psutil not available for process listing")
        return []

    if fields is None:
        fields = ["pid", "name", "cpu_percent", "memory_percent"]

    processes = []
    try:
        for proc in psutil.process_iter(fields):
            try:
                processes.append(proc.info)
            except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                logger.error("Error in process_utils: %s", e)
                continue
    except Exception as e:
        logger.error(f"Error getting process list: {e}")

    return processes


def find_processes_matching_names(target_names: list[str]) -> list[str]:
    """Find all running processes that match any of the target names.

    Args:
        target_names: List of process names to search for

    Returns:
        List of running process names that match targets

    """
    if not PSUTIL_AVAILABLE:
        logger.warning("psutil not available for process matching")
        return []

    try:
        running_processes = [p.info["name"] for p in psutil.process_iter(["name"]) if p.info["name"]]
        target_names_lower = [name.lower() for name in target_names]

        matches = []
        for proc_name in running_processes:
            proc_name_lower = proc_name.lower()
            for target in target_names_lower:
                if target in proc_name_lower:
                    matches.append(proc_name)
                    break

        return matches
    except Exception as e:
        logger.error(f"Error matching process names: {e}")
        return []


def _get_system_path(path_type: str) -> str | None:
    """Get system path dynamically."""
    try:
        from .core.path_discovery import get_system_path

        return get_system_path(path_type)
    except ImportError as e:
        logger.error("Import error in process_utils: %s", e)
        # Fallback
        if path_type == "windows_system":
            return os.environ.get("SystemRoot", r"C:\Windows")
        if path_type == "windows_system32":
            return os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32")
        if path_type == "windows_drivers":
            return os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "drivers")
        return None


def get_target_process_pid(process_name: str) -> int | None:
    """Get the process ID of a target process by name.

    Args:
        process_name: Name of the process to find

    Returns:
        Process ID if found, None otherwise

    """
    if not psutil:
        logger.warning("psutil not available - cannot get process PID")
        return None

    # Use the consolidated process finding function
    return find_process_by_name(process_name, exact_match=False)


def compute_file_hash(file_path: str, algorithm: str = "sha256") -> str | None:
    """Compute hash of a file.

    Args:
        file_path: Path to the file to hash
        algorithm: Hash algorithm to use (md5, sha1, sha256, etc.)

    Returns:
        Hex digest of the hash, or None if error

    """
    try:
        if not os.path.exists(file_path):
            logger.error("File not found: %s", file_path)
            return None

        hasher = hashlib.new(algorithm)

        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)

        hash_value = hasher.hexdigest()
        logger.info("Computed %s hash for %s: %s", algorithm, file_path, hash_value)
        return hash_value

    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error computing hash for %s: %s", file_path, e)
        return None


def detect_hardware_dongles(app=None) -> list[str]:
    """Detects hardware dongle drivers and APIs.
    Supports detection of SafeNet, HASP, CodeMeter, and other common dongles.

    Args:
        app: Application instance (for real-time updates)

    Returns:
        List of detection results

    """
    logger.info("Starting hardware dongle detection.")
    results = []

    # Update app instance with progress if provided
    if app and hasattr(app, "update_output"):
        progress_message = "Starting hardware dongle detection..."
        if hasattr(app.update_output, "emit"):
            app.update_output.emit(progress_message)
        elif callable(app.update_output):
            app.update_output(progress_message)

    # Known hardware dongle drivers and DLLs
    dongle_drivers = {
        "SafeNet": ["sentinel.sys", "sentinelkeyW.dll", "hasp_windows_x64_demo.dll"],
        "HASP": ["haspvb32.dll", "haspdos.sys", "haspds_windows.dll", "hasp_windows_demo.dll"],
        "CodeMeter": ["codemeter.exe", "wibukey.dll", "wibusys.dll"],
        "Rainbow": ["rainbow.dll", "rainbow.sys"],
        "ROCKEY": ["rockey.dll", "rockeydrv.sys"],
        "Hardlock": ["hlock.sys", "hlock.dll"],
        "Matrix": ["matrix.sys", "matrix.dll"],
        "Keylok": ["keylok.sys", "keylok3.sys"],
    }

    # Check installed drivers in system directories
    system_dirs = [
        _get_system_path("windows_system"),
        _get_system_path("windows_system32"),
        os.path.join(_get_system_path("windows_system") or "C:\\Windows", "SysWOW64"),
        _get_system_path("windows_drivers"),
    ]

    results.append("Scanning for hardware dongle drivers...")
    found_dongles = set()

    for dir_path in system_dirs:
        if not os.path.exists(dir_path):
            continue

        logger.debug("Scanning directory for dongle drivers: %s", dir_path)

        for dongle, files in dongle_drivers.items():
            for file in files:
                if os.path.exists(os.path.join(dir_path, file)):
                    found_dongles.add(dongle)
                    driver_path = os.path.join(dir_path, file)
                    logger.info("Found %s driver: %s", dongle, driver_path)
                    detection_message = f"Found {dongle} dongle driver: {driver_path}"
                    results.append(detection_message)

                    # Update app instance with real-time detection
                    if app and hasattr(app, "update_output"):
                        if hasattr(app.update_output, "emit"):
                            app.update_output.emit(f"DETECTED: {detection_message}")
                        elif callable(app.update_output):
                            app.update_output(f"DETECTED: {detection_message}")

    # Check running processes for dongle service processes
    dongle_processes = {
        "SafeNet": ["hasplmd.exe", "hasplms.exe", "aksmon.exe"],
        "CodeMeter": ["codemeter.exe", "CodeMeterCC.exe"],
        "HASP": ["nhsrvice.exe", "hasplms.exe"],
        "WibuKey": ["wibukey.exe", "WkSvc.exe"],
    }

    if psutil:
        results.append("Checking for dongle service processes...")
        try:
            # Get all process names
            all_processes = get_all_processes(["name"])
            running_processes = [p["name"] for p in all_processes if p.get("name")]

            for dongle, processes in dongle_processes.items():
                for process in processes:
                    if any(process.lower() in proc.lower() for proc in running_processes if proc):
                        found_dongles.add(dongle)
                        logger.info("Found %s service process: %s", dongle, process)
                        results.append(f"Found {dongle} service process: {process}")

        except Exception as e:
            logger.warning("Error checking dongle processes: %s", e)
            results.append(f"Error checking processes: {e}")
    else:
        results.append("psutil not available - cannot check running processes")

    # Check registry for dongle entries (Windows only)
    if sys.platform == "win32":
        try:
            import winreg

            dongle_registry_keys = [
                r"SOFTWARE\SafeNet",
                r"SOFTWARE\Aladdin Knowledge Systems",
                r"SOFTWARE\WIBU-SYSTEMS",
                r"SOFTWARE\CodeMeter",
                r"SYSTEM\CurrentControlSet\Services\Sentinel",
                r"SYSTEM\CurrentControlSet\Services\aksdf",
            ]

            results.append("Checking registry for dongle entries...")

            for key_path in dongle_registry_keys:
                try:
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
                    logger.info("Found dongle registry key: %s", key_path)
                    results.append(f"Found dongle registry key: {key_path}")
                    winreg.CloseKey(key)
                except FileNotFoundError as e:
                    logger.error("File not found in process_utils: %s", e)
                    # Key doesn't exist
                except (OSError, ValueError, RuntimeError) as e:
                    logger.debug("Error accessing registry key %s: %s", key_path, e)

        except ImportError as e:
            logger.error("Import error in process_utils: %s", e)
            results.append("winreg not available - cannot check registry")

    if found_dongles:
        results.append(f"\nSummary: Found {len(found_dongles)} dongle types: {', '.join(found_dongles)}")
    else:
        results.append("No hardware dongles detected")

    return results


def detect_tpm_protection() -> dict[str, Any]:
    """Detect TPM (Trusted Platform Module) protection mechanisms.

    Returns:
        Dictionary containing TPM detection results

    """
    results = {
        "tpm_present": False,
        "tpm_version": None,
        "tpm_enabled": False,
        "tpm_owned": False,
        "detection_methods": [],
        "error": None,
    }

    try:
        logger.info("Starting TPM detection")

        # Check for TPM device on Windows
        if sys.platform == "win32":
            try:
                # Check WMI for _TPM info
                import wmi

                c = wmi.WMI()

                tpm_instances = c.Win32_Tpm()
                if tpm_instances:
                    results["tpm_present"] = True
                    results["detection_methods"].append("WMI Win32_Tpm")

                    for tmp in tpm_instances:
                        if hasattr(tmp, "IsEnabled_InitialValue"):
                            results["tpm_enabled"] = bool(tmp.IsEnabled_InitialValue)
                        if hasattr(tmp, "IsOwned_InitialValue"):
                            results["tpm_owned"] = bool(tmp.IsOwned_InitialValue)
                        if hasattr(tmp, "SpecVersion"):
                            results["tpm_version"] = tmp.SpecVersion

            except ImportError:
                logger.debug("WMI not available for TPM detection")
            except (OSError, ValueError, RuntimeError) as e:
                logger.warning("WMI TPM detection failed: %s", e)

        # Check TPM device files on Linux
        elif sys.platform.startswith("linux"):
            tpm_devices = ["/dev/tpm0", "/dev/tpmrm0"]
            for device in tpm_devices:
                if os.path.exists(device):
                    results["tpm_present"] = True
                    results["detection_methods"].append(f"Device file: {device}")
                    break

        # Check for TPM-related processes
        if psutil:
            tpm_processes = ["tpm2-abrmd", "tcsd", "trousers"]
            for proc in psutil.process_iter(["name"]):
                if proc.info["name"] and any(tmp_proc_name in proc.info["name"].lower() for tmp_proc_name in tpm_processes):
                    results["detection_methods"].append(f"TPM process: {proc.info['name']}")

        # Check for TPM kernel modules on Linux
        if sys.platform.startswith("linux"):
            try:
                with open("/proc/modules", encoding="utf-8") as f:
                    modules = f.read()
                    tpm_modules = ["tpm", "tpm_tis", "tpm_crb", "tpm2"]
                    for module in tpm_modules:
                        if module in modules:
                            results["detection_methods"].append(f"Kernel module: {module}")
                            results["tpm_present"] = True
            except (OSError, ValueError, RuntimeError) as e:
                logger.debug("Could not check kernel modules: %s", e)

        logger.info("TPM detection completed: %s", results)

    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error in TPM detection: %s", e)
        results["error"] = str(e)

    return results


def get_system_processes() -> list[dict[str, Any]]:
    """Get list of running system processes.

    Returns:
        List of process information dictionaries

    """
    processes = []

    if not psutil:
        logger.warning("psutil not available - cannot get process list")
        return processes

    try:
        for proc in psutil.process_iter(["pid", "name", "cmdline", "create_time"]):
            try:
                processes.append(
                    {
                        "pid": proc.info["pid"],
                        "name": proc.info["name"],
                        "cmdline": " ".join(proc.info["cmdline"]) if proc.info["cmdline"] else "",
                        "create_time": proc.info["create_time"],
                    }
                )
            except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                logger.error("Error in process_utils: %s", e)
                # Process may have terminated or access denied

    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error getting process list: %s", e)

    return processes


def run_command(command: str, timeout: int = 30) -> dict[str, Any]:
    """Run a system command and return the result.

    Args:
        command: Command to execute
        timeout: Timeout in seconds

    Returns:
        Dictionary with command results

    """
    result = {
        "success": False,
        "stdout": "",
        "stderr": "",
        "return_code": None,
        "error": None,
    }

    try:
        logger.info("Running command: %s", command)

        process = subprocess.run(  # nosec S603 - Legitimate subprocess usage for security research and binary analysis  # noqa: S603
            shlex.split(command) if isinstance(command, str) else command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            shell=False,  # Explicitly secure - using list format prevents shell injection
        )

        result["success"] = process.returncode == 0
        result["stdout"] = process.stdout
        result["stderr"] = process.stderr
        result["return_code"] = process.returncode

        logger.info("Command completed with return code: %s", process.returncode)

    except subprocess.TimeoutExpired:
        result["error"] = f"Command timed out after {timeout} seconds"
        logger.error(result["error"])
    except (OSError, ValueError, RuntimeError) as e:
        result["error"] = str(e)
        logger.error("Error running command: %s", e)

    return result

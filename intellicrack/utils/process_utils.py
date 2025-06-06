"""
Process and system utilities for Intellicrack.

This module provides functions for process management, hardware detection,
and system-level operations.
"""

import hashlib
import logging
import os
import subprocess
import sys
from typing import Any, Dict, List, Optional

try:
    import psutil
except ImportError:
    psutil = None

logger = logging.getLogger(__name__)

def _get_system_path(path_type: str) -> Optional[str]:
    """Get system path dynamically."""
    try:
        from .path_discovery import get_system_path
        return get_system_path(path_type)
    except ImportError:
        # Fallback
        if path_type == 'windows_system':
            return os.environ.get('SystemRoot', r'C:\Windows')
        elif path_type == 'windows_system32':
            return os.path.join(os.environ.get('SystemRoot', r'C:\Windows'), 'System32')
        elif path_type == 'windows_drivers':
            return os.path.join(os.environ.get('SystemRoot', r'C:\Windows'), 'System32', 'drivers')
        return None


def get_target_process_pid(process_name: str) -> Optional[int]:
    """
    Get the process ID of a target process by name.

    Args:
        process_name: Name of the process to find

    Returns:
        Process ID if found, None otherwise
    """
    if not psutil:
        logger.warning("psutil not available - cannot get process PID")
        return None

    try:
        for proc in psutil.process_iter(['pid', 'name']):
            if proc.info['name'] and process_name.lower() in proc.info['name'].lower():
                logger.info(f"Found process {process_name} with PID: {proc.info['pid']}")
                return proc.info['pid']

        logger.warning(f"Process {process_name} not found")
        return None

    except Exception as e:
        logger.error(f"Error finding process {process_name}: {e}")
        return None


def compute_file_hash(file_path: str, algorithm: str = 'sha256') -> Optional[str]:
    """
    Compute hash of a file.

    Args:
        file_path: Path to the file to hash
        algorithm: Hash algorithm to use (md5, sha1, sha256, etc.)

    Returns:
        Hex digest of the hash, or None if error
    """
    try:
        if not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            return None

        hasher = hashlib.new(algorithm)

        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)

        hash_value = hasher.hexdigest()
        logger.info(f"Computed {algorithm} hash for {file_path}: {hash_value}")
        return hash_value

    except Exception as e:
        logger.error(f"Error computing hash for {file_path}: {e}")
        return None


def detect_hardware_dongles(app=None) -> List[str]:
    """
    Detects hardware dongle drivers and APIs.
    Supports detection of SafeNet, HASP, CodeMeter, and other common dongles.

    Args:
        app: Application instance (for compatibility)

    Returns:
        List of detection results
    """
    logger.info("Starting hardware dongle detection.")
    results = []

    # Known hardware dongle drivers and DLLs
    dongle_drivers = {
        "SafeNet": ["sentinel.sys", "sentinelkeyW.dll", "hasp_windows_x64_demo.dll"],
        "HASP": ["haspvb32.dll", "haspdos.sys", "haspds_windows.dll", "hasp_windows_demo.dll"],
        "CodeMeter": ["codemeter.exe", "wibukey.dll", "wibusys.dll"],
        "Rainbow": ["rainbow.dll", "rainbow.sys"],
        "ROCKEY": ["rockey.dll", "rockeydrv.sys"],
        "Hardlock": ["hlock.sys", "hlock.dll"],
        "Matrix": ["matrix.sys", "matrix.dll"],
        "Keylok": ["keylok.sys", "keylok3.sys"]
    }

    # Check installed drivers in system directories
    system_dirs = [
        _get_system_path('windows_system'),
        _get_system_path('windows_system32'),
        os.path.join(_get_system_path('windows_system') or "C:\\Windows", "SysWOW64"),
        _get_system_path('windows_drivers')
    ]

    results.append("Scanning for hardware dongle drivers...")
    found_dongles = set()

    for dir_path in system_dirs:
        if not os.path.exists(dir_path):
            continue

        logger.debug(f"Scanning directory for dongle drivers: {dir_path}")

        for dongle, files in dongle_drivers.items():
            for file in files:
                if os.path.exists(os.path.join(dir_path, file)):
                    found_dongles.add(dongle)
                    driver_path = os.path.join(dir_path, file)
                    logger.info(f"Found {dongle} driver: {driver_path}")
                    results.append(f"Found {dongle} dongle driver: {driver_path}")

    # Check running processes for dongle service processes
    dongle_processes = {
        "SafeNet": ["hasplmd.exe", "hasplms.exe", "aksmon.exe"],
        "CodeMeter": ["codemeter.exe", "CodeMeterCC.exe"],
        "HASP": ["nhsrvice.exe", "hasplms.exe"],
        "WibuKey": ["wibukey.exe", "WkSvc.exe"]
    }

    if psutil:
        results.append("Checking for dongle service processes...")
        try:
            running_processes = [p.info['name'] for p in psutil.process_iter(['name'])]

            for dongle, processes in dongle_processes.items():
                for process in processes:
                    if any(process.lower() in proc.lower() for proc in running_processes if proc):
                        found_dongles.add(dongle)
                        logger.info(f"Found {dongle} service process: {process}")
                        results.append(f"Found {dongle} service process: {process}")

        except Exception as e:
            logger.warning(f"Error checking dongle processes: {e}")
            results.append(f"Error checking processes: {e}")
    else:
        results.append("psutil not available - cannot check running processes")

    # Check registry for dongle entries (Windows only)
    if sys.platform == 'win32':
        try:
            import winreg

            dongle_registry_keys = [
                r"SOFTWARE\SafeNet",
                r"SOFTWARE\Aladdin Knowledge Systems",
                r"SOFTWARE\WIBU-SYSTEMS",
                r"SOFTWARE\CodeMeter",
                r"SYSTEM\CurrentControlSet\Services\Sentinel",
                r"SYSTEM\CurrentControlSet\Services\aksdf"
            ]

            results.append("Checking registry for dongle entries...")

            for key_path in dongle_registry_keys:
                try:
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
                    logger.info(f"Found dongle registry key: {key_path}")
                    results.append(f"Found dongle registry key: {key_path}")
                    winreg.CloseKey(key)
                except FileNotFoundError:
                    pass  # Key doesn't exist
                except Exception as e:
                    logger.debug(f"Error accessing registry key {key_path}: {e}")

        except ImportError:
            results.append("winreg not available - cannot check registry")

    if found_dongles:
        results.append(f"\nSummary: Found {len(found_dongles)} dongle types: {', '.join(found_dongles)}")
    else:
        results.append("No hardware dongles detected")

    return results


def detect_tpm_protection() -> Dict[str, Any]:
    """
    Detect TPM (Trusted Platform Module) protection mechanisms.

    Returns:
        Dictionary containing TPM detection results
    """
    results = {
        "tpm_present": False,
        "tpm_version": None,
        "tpm_enabled": False,
        "tpm_owned": False,
        "detection_methods": [],
        "error": None
    }

    try:
        logger.info("Starting TPM detection")

        # Check for TPM device on Windows
        if sys.platform == 'win32':
            try:
                # Check WMI for TPM info
                import wmi
                c = wmi.WMI()

                tpm_instances = c.Win32_Tpm()
                if tpm_instances:
                    results["tpm_present"] = True
                    results["detection_methods"].append("WMI Win32_Tpm")

                    for tpm in tpm_instances:
                        if hasattr(tpm, 'IsEnabled_InitialValue'):
                            results["tpm_enabled"] = bool(tpm.IsEnabled_InitialValue)
                        if hasattr(tpm, 'IsOwned_InitialValue'):
                            results["tpm_owned"] = bool(tpm.IsOwned_InitialValue)
                        if hasattr(tpm, 'SpecVersion'):
                            results["tpm_version"] = tpm.SpecVersion

            except ImportError:
                logger.debug("WMI not available for TPM detection")
            except Exception as e:
                logger.warning(f"WMI TPM detection failed: {e}")

        # Check TPM device files on Linux
        elif sys.platform.startswith('linux'):
            tpm_devices = ['/dev/tpm0', '/dev/tpmrm0']
            for device in tpm_devices:
                if os.path.exists(device):
                    results["tpm_present"] = True
                    results["detection_methods"].append(f"Device file: {device}")
                    break

        # Check for TPM-related processes
        if psutil:
            tpm_processes = ['tpm2-abrmd', 'tcsd', 'trousers']
            for proc in psutil.process_iter(['name']):
                if proc.info['name'] and any(tpm_proc in proc.info['name'].lower() for tpm_proc in tpm_processes):
                    results["detection_methods"].append(f"TPM process: {proc.info['name']}")

        # Check for TPM kernel modules on Linux
        if sys.platform.startswith('linux'):
            try:
                with open('/proc/modules', 'r') as f:
                    modules = f.read()
                    tpm_modules = ['tpm', 'tpm_tis', 'tpm_crb', 'tpm2']
                    for module in tpm_modules:
                        if module in modules:
                            results["detection_methods"].append(f"Kernel module: {module}")
                            results["tpm_present"] = True
            except Exception as e:
                logger.debug(f"Could not check kernel modules: {e}")

        logger.info(f"TPM detection completed: {results}")

    except Exception as e:
        logger.error(f"Error in TPM detection: {e}")
        results["error"] = str(e)

    return results


def get_system_processes() -> List[Dict[str, Any]]:
    """
    Get list of running system processes.

    Returns:
        List of process information dictionaries
    """
    processes = []

    if not psutil:
        logger.warning("psutil not available - cannot get process list")
        return processes

    try:
        for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'create_time']):
            try:
                processes.append({
                    'pid': proc.info['pid'],
                    'name': proc.info['name'],
                    'cmdline': ' '.join(proc.info['cmdline']) if proc.info['cmdline'] else '',
                    'create_time': proc.info['create_time']
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass  # Process may have terminated or access denied

    except Exception as e:
        logger.error(f"Error getting process list: {e}")

    return processes


def run_command(command: str, timeout: int = 30) -> Dict[str, Any]:
    """
    Run a system command and return the result.

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
        "error": None
    }

    try:
        logger.info(f"Running command: {command}")

        process = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout
        )

        result["success"] = process.returncode == 0
        result["stdout"] = process.stdout
        result["stderr"] = process.stderr
        result["return_code"] = process.returncode

        logger.info(f"Command completed with return code: {process.returncode}")

    except subprocess.TimeoutExpired:
        result["error"] = f"Command timed out after {timeout} seconds"
        logger.error(result["error"])
    except Exception as e:
        result["error"] = str(e)
        logger.error(f"Error running command: {e}")

    return result

"""Legacy process utilities - consolidated functions moved to utils.system.process_utils

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
along with Intellicrack.  If not, see <https://www.gnu.org/licenses/>.
"""

# Import consolidated functions from the new location
# Re-export for backward compatibility
import logging
import os
import platform
import signal
import subprocess
import sys
import time
from typing import Any

from .system.process_utils import (
    get_target_process_pid,
)

logger = logging.getLogger(__name__)

# Try to import psutil for enhanced process management
try:
    import psutil

    PSUTIL_AVAILABLE = True
except ImportError as e:
    logger.error("Import error in process_utils: %s", e)
    PSUTIL_AVAILABLE = False


# get_target_process_pid is imported from utils.system.process_utils above


def _get_process_pid_windows(process_name: str) -> int | None:
    """Get process PID on Windows using tasklist."""
    try:
        result = subprocess.run(  # nosec S603 - Legitimate subprocess usage for security research and binary analysis  # noqa: S603
            ["tasklist", "/fi", f"imagename eq {process_name}", "/fo", "csv"],  # noqa: S607
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )

        if result.returncode == 0:
            lines = result.stdout.strip().split("\n")
            if len(lines) > 1:  # Skip header
                # Parse CSV output
                for line in lines[1:]:
                    parts = line.split(",")
                    if len(parts) >= 2:
                        name = parts[0].strip('"')
                        pid_str = parts[1].strip('"')
                        if name.lower() == process_name.lower():
                            return int(pid_str)

    except Exception as e:
        logger.debug(f"Windows process lookup failed: {e}")

    return None


def _get_process_pid_unix(process_name: str) -> int | None:
    """Get process PID on Unix systems using ps."""
    try:
        result = subprocess.run(
            ["ps", "aux"],  # noqa: S607
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )

        if result.returncode == 0:
            for line in result.stdout.split("\n"):
                if process_name.lower() in line.lower():
                    parts = line.split()
                    if len(parts) >= 2:
                        return int(parts[1])  # PID is second column

    except Exception as e:
        logger.debug(f"Unix process lookup failed: {e}")

    return None


def get_process_list() -> list[dict[str, Any]]:
    """Get list of running processes.

    Returns:
        List of process dictionaries with pid, name, and other info

    """
    processes = []

    try:
        if PSUTIL_AVAILABLE:
            for proc in psutil.process_iter(["pid", "name", "cpu_percent", "memory_percent"]):
                try:
                    processes.append(proc.info)
                except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                    logger.error("Error in process_utils: %s", e)
                    continue
        # Fallback implementation
        elif platform.system() == "Windows":
            processes = _get_process_list_windows()
        else:
            processes = _get_process_list_unix()

    except Exception as e:
        logger.debug(f"Failed to get process list: {e}")

    return processes


def _get_process_list_windows() -> list[dict[str, Any]]:
    """Get process list on Windows."""
    processes = []

    try:
        result = subprocess.run(
            ["tasklist", "/fo", "csv"],  # noqa: S607
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )

        if result.returncode == 0:
            lines = result.stdout.strip().split("\n")
            if len(lines) > 1:  # Skip header
                for line in lines[1:]:
                    parts = [part.strip('"') for part in line.split(",")]
                    if len(parts) >= 2:
                        processes.append(
                            {
                                "name": parts[0],
                                "pid": int(parts[1]),
                                "cpu_percent": 0.0,  # Not available in tasklist
                                "memory_percent": 0.0,  # Not available in tasklist
                            }
                        )

    except Exception as e:
        logger.debug(f"Windows process list failed: {e}")

    return processes


def _get_process_list_unix() -> list[dict[str, Any]]:
    """Get process list on Unix systems."""
    processes = []

    try:
        result = subprocess.run(
            ["ps", "aux", "--no-headers"],  # noqa: S607
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )

        if result.returncode == 0:
            for line in result.stdout.split("\n"):
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 11:
                        try:
                            processes.append(
                                {
                                    "name": parts[10],  # Command name
                                    "pid": int(parts[1]),
                                    "cpu_percent": float(parts[2]),
                                    "memory_percent": float(parts[3]),
                                }
                            )
                        except (ValueError, IndexError) as e:
                            logger.error("Error in process_utils: %s", e)
                            continue

    except Exception as e:
        logger.debug(f"Unix process list failed: {e}")

    return processes


def kill_process(pid: int, force: bool = False) -> bool:
    """Kill a process by PID.

    Args:
        pid: Process ID to kill
        force: Whether to force kill (SIGKILL vs SIGTERM)

    Returns:
        True if process was killed successfully

    """
    try:
        if PSUTIL_AVAILABLE:
            proc = psutil.Process(pid)
            if force:
                proc.kill()
            else:
                proc.terminate()

            # Wait for process to terminate
            proc.wait(timeout=10)
            return True
        # Fallback to os.kill
        if platform.system() == "Windows":
            # Use taskkill on Windows
            result = subprocess.run(  # nosec S603 - Legitimate subprocess usage for security research and binary analysis  # noqa: S603
                ["taskkill", "/PID", str(pid), "/F" if force else "/T"],  # noqa: S607
                check=False,
                capture_output=True,
            )
            return result.returncode == 0
        # Use kill signal on Unix
        if force:
            sig = getattr(signal, "SIGKILL", 9)  # Fallback to 9 if SIGKILL not available
        else:
            sig = getattr(signal, "SIGTERM", 15)  # Fallback to 15 if SIGTERM not available
        os.kill(pid, sig)
        return True

    except Exception as e:
        logger.debug(f"Failed to kill process {pid}: {e}")
        return False


def is_process_running(pid: int) -> bool:
    """Check if a process is running.

    Args:
        pid: Process ID to check

    Returns:
        True if process is running

    """
    try:
        if PSUTIL_AVAILABLE:
            return psutil.pid_exists(pid)
        # Fallback method
        if platform.system() == "Windows":
            result = subprocess.run(  # nosec S603 - Legitimate subprocess usage for security research and binary analysis  # noqa: S603
                ["tasklist", "/fi", f"PID eq {pid}"],  # noqa: S607
                check=False,
                capture_output=True,
                text=True,
            )
            return str(pid) in result.stdout
        # Send signal 0 to check if process exists
        os.kill(pid, 0)
        return True

    except (OSError, subprocess.SubprocessError) as e:
        logger.error("Error in process_utils: %s", e)
        return False
    except Exception as e:
        logger.debug(f"Process check failed for PID {pid}: {e}")
        return False


def get_process_info(pid: int) -> dict[str, Any] | None:
    """Get detailed information about a process.

    Args:
        pid: Process ID

    Returns:
        Dictionary with process information or None if not found

    """
    try:
        if PSUTIL_AVAILABLE:
            proc = psutil.Process(pid)
            return {
                "pid": proc.pid,
                "name": proc.name(),
                "status": proc.status(),
                "cpu_percent": proc.cpu_percent(),
                "memory_percent": proc.memory_percent(),
                "memory_info": proc.memory_info()._asdict(),
                "create_time": proc.create_time(),
                "exe": proc.exe(),
                "cmdline": proc.cmdline(),
            }
        # Basic fallback information
        if is_process_running(pid):
            return {
                "pid": pid,
                "name": "unknown",
                "status": "running",
                "cpu_percent": 0.0,
                "memory_percent": 0.0,
            }

    except Exception as e:
        logger.debug(f"Failed to get process info for PID {pid}: {e}")

    return None


def wait_for_process(process_name: str, timeout: int = 30) -> int | None:
    """Wait for a process to start and return its PID.

    Args:
        process_name: Name of the process to wait for
        timeout: Maximum time to wait in seconds

    Returns:
        PID of the process if found within timeout

    """
    start_time = time.time()

    while time.time() - start_time < timeout:
        pid = get_target_process_pid(process_name)
        if pid is not None:
            return pid

        time.sleep(1)  # Check every second

    return None


def run_as_admin(command: list[str]) -> tuple[bool, str]:
    """Run a command with administrator privileges.

    Args:
        command: Command and arguments to run

    Returns:
        Tuple of (success, output_or_error)

    """
    try:
        if platform.system() == "Windows":
            # Use runas on Windows
            result = subprocess.run(  # nosec S603 - Legitimate subprocess usage for security research and binary analysis  # noqa: S603
                ["runas", "/user:Administrator"] + command,
                check=False,
                capture_output=True,
                text=True,
                timeout=60,
            )
        else:
            # Use sudo on Unix systems
            result = subprocess.run(  # nosec S603 - Legitimate subprocess usage for security research and binary analysis  # noqa: S603
                ["sudo"] + command,
                check=False,
                capture_output=True,
                text=True,
                timeout=60,
            )

        if result.returncode == 0:
            return True, result.stdout
        return False, result.stderr

    except subprocess.TimeoutExpired as e:
        logger.error("Subprocess timeout in process_utils: %s", e)
        return False, "Command timed out"
    except Exception as e:
        logger.error("Exception in process_utils: %s", e)
        return False, str(e)


def get_current_process_info() -> dict[str, Any]:
    """Get information about the current process.

    Returns:
        Dictionary with current process information

    """
    try:
        if PSUTIL_AVAILABLE:
            proc = psutil.Process()
            return {
                "pid": proc.pid,
                "name": proc.name(),
                "exe": proc.exe(),
                "cwd": proc.cwd(),
                "cmdline": proc.cmdline(),
                "cpu_percent": proc.cpu_percent(),
                "memory_percent": proc.memory_percent(),
                "create_time": proc.create_time(),
            }
        return {
            "pid": os.getpid(),
            "name": os.path.basename(sys.executable),
            "exe": sys.executable,
            "cwd": os.getcwd(),
            "cmdline": sys.argv,
        }

    except Exception as e:
        logger.debug(f"Failed to get current process info: {e}")
        return {
            "pid": os.getpid(),
            "name": "unknown",
            "exe": "unknown",
            "cwd": os.getcwd(),
            "cmdline": sys.argv,
        }


def monitor_process_cpu(pid: int, duration: int = 10) -> dict[str, float]:
    """Monitor CPU usage of a process for a given duration.

    Args:
        pid: Process ID to monitor
        duration: Duration to monitor in seconds

    Returns:
        Dictionary with CPU statistics

    """
    cpu_samples = []
    start_time = time.time()

    try:
        if PSUTIL_AVAILABLE:
            proc = psutil.Process(pid)

            while time.time() - start_time < duration:
                cpu_percent = proc.cpu_percent(interval=1)
                cpu_samples.append(cpu_percent)

        if cpu_samples:
            return {
                "avg_cpu": sum(cpu_samples) / len(cpu_samples),
                "max_cpu": max(cpu_samples),
                "min_cpu": min(cpu_samples),
                "samples": len(cpu_samples),
            }

    except Exception as e:
        logger.debug(f"CPU monitoring failed for PID {pid}: {e}")

    return {
        "avg_cpu": 0.0,
        "max_cpu": 0.0,
        "min_cpu": 0.0,
        "samples": 0,
    }


def find_processes_by_pattern(pattern: str) -> list[dict[str, Any]]:
    """Find processes whose names match a pattern.

    Args:
        pattern: Pattern to match (case-insensitive)

    Returns:
        List of matching process dictionaries

    """
    matching_processes = []

    try:
        all_processes = get_process_list()
        pattern_lower = pattern.lower()

        for proc in all_processes:
            if pattern_lower in proc.get("name", "").lower():
                matching_processes.append(proc)

    except Exception as e:
        logger.debug(f"Process pattern search failed: {e}")

    return matching_processes


def detect_hardware_dongles() -> list[dict[str, Any]]:
    """Detect hardware dongles connected to the system.

    Returns:
        List of detected hardware dongles with their information

    """
    dongles = []

    try:
        # Check for common dongle manufacturers in device list
        if platform.system() == "Windows":
            try:
                # Use WMI to query USB devices
                result = subprocess.run(
                    ["wmic", "path", "win32_usbhub", "get", "deviceid,description"],  # noqa: S607
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )

                if result.returncode == 0:
                    lines = result.stdout.strip().split("\n")[1:]  # Skip header
                    for line in lines:
                        if line.strip():
                            parts = line.strip().split()
                            if len(parts) >= 2:
                                device_id = parts[0]
                                description = " ".join(parts[1:])

                                # Check for known dongle manufacturers
                                dongle_vendors = ["Sentinel", "HASP", "Rainbow", "SafeNet", "Wibu"]
                                for vendor in dongle_vendors:
                                    if vendor.lower() in description.lower():
                                        dongles.append(
                                            {
                                                "vendor": vendor,
                                                "device_id": device_id,
                                                "description": description,
                                                "type": "USB",
                                            }
                                        )

            except Exception as e:
                logger.debug(f"Windows dongle detection failed: {e}")

        elif platform.system() == "Linux":
            try:
                # Use lsusb to list USB devices
                result = subprocess.run(
                    ["lsusb"], check=False, capture_output=True, text=True, timeout=10  # noqa: S607
                )

                if result.returncode == 0:
                    lines = result.stdout.strip().split("\n")
                    for line in lines:
                        # Check for known dongle manufacturers
                        dongle_vendors = ["Sentinel", "HASP", "Rainbow", "SafeNet", "Wibu"]
                        for vendor in dongle_vendors:
                            if vendor.lower() in line.lower():
                                dongles.append(
                                    {
                                        "vendor": vendor,
                                        "device_info": line.strip(),
                                        "type": "USB",
                                    }
                                )

            except Exception as e:
                logger.debug(f"Linux dongle detection failed: {e}")

    except Exception as e:
        logger.error(f"Hardware dongle detection failed: {e}")

    return dongles


def detect_tpm_protection() -> dict[str, Any]:
    """Detect TPM (Trusted Platform Module) protection on the system.

    Returns:
        Dictionary with TPM detection results

    """
    tpm_info = {
        "present": False,
        "version": None,
        "manufacturer": None,
        "enabled": False,
        "details": [],
    }

    try:
        if platform.system() == "Windows":
            try:
                # Check TPM using WMI
                result = subprocess.run(
                    [  # noqa: S607
                        "wmic",
                        "/namespace:\\\\root\\cimv2\\security\\microsofttpm",
                        "path",
                        "win32_tpm",
                        "get",
                        "IsEnabled_InitialValue,IsActivated_InitialValue,ManufacturerVersion",
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )

                if result.returncode == 0 and result.stdout.strip():
                    tpm_info["present"] = True
                    tpm_info["details"].append("TPM detected via WMI")

                    # Parse WMI output
                    lines = result.stdout.strip().split("\n")
                    for line in lines[1:]:  # Skip header
                        if line.strip():
                            parts = line.strip().split()
                            if len(parts) >= 3:
                                is_enabled = parts[1]
                                version = parts[2]

                                tpm_info["enabled"] = is_enabled.lower() == "true"
                                tpm_info["version"] = version

            except Exception as e:
                logger.debug(f"Windows TPM detection failed: {e}")

            # Alternative method - check registry
            try:
                result = subprocess.run(
                    ["reg", "query", "HKLM\\SYSTEM\\CurrentControlSet\\Services\\TPM"],  # noqa: S607
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if result.returncode == 0:
                    tpm_info["present"] = True
                    tpm_info["details"].append("TPM service found in registry")

            except Exception as e:
                logger.debug(f"TPM registry check failed: {e}")

        elif platform.system() == "Linux":
            try:
                # Check for TPM device files
                tpm_devices = ["/dev/tpm0", "/sys/class/tpm/tpm0"]
                for device in tpm_devices:
                    if os.path.exists(device):
                        tpm_info["present"] = True
                        tpm_info["details"].append(f"TPM device found: {device}")

                # Check dmesg for TPM messages
                result = subprocess.run(
                    ["dmesg"], check=False, capture_output=True, text=True, timeout=5  # noqa: S607
                )
                if result.returncode == 0:
                    tpm_lines = [
                        line for line in result.stdout.split("\n") if "tpm" in line.lower()
                    ]
                    if tpm_lines:
                        tpm_info["present"] = True
                        tpm_info["details"].extend(tpm_lines[:3])  # Add first 3 TPM-related lines

            except Exception as e:
                logger.debug(f"Linux TPM detection failed: {e}")

    except Exception as e:
        logger.error(f"TPM detection failed: {e}")
        tpm_info["details"].append(f"Detection error: {e}")

    return tpm_info


# Export commonly used functions
__all__ = [
    "PSUTIL_AVAILABLE",
    "detect_hardware_dongles",
    "detect_tpm_protection",
    "find_processes_by_pattern",
    "get_current_process_info",
    "get_process_info",
    "get_process_list",
    "get_target_process_pid",
    "is_process_running",
    "kill_process",
    "monitor_process_cpu",
    "run_as_admin",
    "wait_for_process",
]

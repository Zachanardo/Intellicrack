"""System utilities for the Intellicrack framework.

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

import logging
import os
import platform
import subprocess
import sys
from pathlib import Path
from typing import Any

# Import consolidated process utilities
from .process_utils import get_all_processes

# Module logger
logger = logging.getLogger(__name__)

try:
    import psutil
except ImportError as e:
    logger.error("Import error in system_utils: %s", e)
    psutil = None

try:
    from PIL import Image, ImageDraw

    PIL_AVAILABLE = True
except ImportError as e:
    logger.error("Import error in system_utils: %s", e)
    Image = None
    ImageDraw = None
    PIL_AVAILABLE = False


def get_targetprocess_pid(binary_path: str) -> int | None:
    """Gets PID of target process, handling multiple instances and partial matches.

    Searches for processes matching the given binary name and handles cases where
    multiple instances are found. In GUI mode, prompts the user to select the
    correct process.

    Args:
        binary_path: Path to the binary file

    Returns:
        Optional[int]: Process ID if found, None otherwise

    """
    if psutil is None:
        logger.error("psutil is not installed. Cannot search for processes.")
        return None

    target_name = os.path.basename(binary_path).lower()
    potential_pids = []

    logger.info(f"[PID Finder] Searching for process matching '{target_name}'...")

    # Find all matching processes (exact and partial)
    try:
        for proc in psutil.process_iter(["pid", "name", "create_time"]):
            if proc.info["name"]:
                proc_name_lower = proc.info["name"].lower()
                # Prioritize exact matches
                if proc_name_lower == target_name:
                    potential_pids.append(
                        {
                            "pid": proc.info["pid"],
                            "name": proc.info["name"],
                            "create_time": proc.info["create_time"],
                            "match": "exact",
                        }
                    )
                elif target_name in proc_name_lower:
                    potential_pids.append(
                        {
                            "pid": proc.info["pid"],
                            "name": proc.info["name"],
                            "create_time": proc.info["create_time"],
                            "match": "partial",
                        }
                    )
    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error iterating processes: %s", e)
        return None

    if not potential_pids:
        logger.warning(f"[PID Finder] No process found matching '{target_name}'.")
        return None

    # Sort by match type (exact first) and then by creation time (newest first)
    potential_pids.sort(key=lambda x: (x["match"] != "exact", -x["create_time"]))

    if len(potential_pids) == 1:
        pid_info = potential_pids[0]
        logger.info(
            f"[PID Finder] Found unique process: {pid_info['name']} "
            f"(PID: {pid_info['pid']}, Match: {pid_info['match']})",
        )
        return pid_info["pid"]
    # Multiple processes found - in a library context, just return the first
    # In the full application, this would prompt the user
    logger.warning(
        f"[PID Finder] Found {len(potential_pids)} potential processes. " f"Returning first match.",
    )
    return potential_pids[0]["pid"]


def get_system_info() -> dict[str, Any]:
    """Get comprehensive system information.

    Returns:
        dict: System information including OS, architecture, CPU, memory, etc.

    """
    info = {
        "platform": platform.system(),
        "platform_release": platform.release(),
        "platform_version": platform.version(),
        "architecture": platform.machine(),
        "processor": platform.processor(),
        "python_version": sys.version,
        "python_implementation": platform.python_implementation(),
    }

    # Add psutil information if available
    if psutil:
        try:
            info["cpu_count"] = psutil.cpu_count()
            info["cpu_count_logical"] = psutil.cpu_count(logical=True)
            info["memory_total"] = psutil.virtual_memory().total
            info["memory_available"] = psutil.virtual_memory().available
            info["memory_percent"] = psutil.virtual_memory().percent
        except (OSError, ValueError, RuntimeError) as e:
            logger.warning("Error getting psutil system info: %s", e)

    return info


def check_dependencies(dependencies: dict[str, str]) -> tuple[bool, dict[str, bool]]:
    """Check if Python dependencies are installed.

    Args:
        dependencies: Dict mapping module names to descriptions

    Returns:
        tuple: (all_satisfied, results) where results maps module names to availability

    """
    results = {}
    all_satisfied = True

    for module_name, description in dependencies.items():
        try:
            __import__(module_name)
            results[module_name] = True
            logger.debug("✓ %s: %s", module_name, description)
        except ImportError:
            results[module_name] = False
            all_satisfied = False
            logger.warning("✗ %s: %s - NOT INSTALLED", module_name, description)

    return all_satisfied, results


def run_command(
    command: str | list[str],
    shell: bool = False,
    capture_output: bool = True,
    timeout: int | None = None,
) -> subprocess.CompletedProcess:
    """Run a system command with proper error handling.

    Args:
        command: Command to run (string or list of arguments)
        shell: Whether to run through shell
        capture_output: Whether to capture stdout/stderr
        timeout: Command timeout in seconds

    Returns:
        subprocess.CompletedProcess: Command result

    Raises:
        subprocess.TimeoutExpired: If command times out
        subprocess.CalledProcessError: If command fails

    """
    try:
        logger.debug("Running command: %s", command)

        if isinstance(command, str) and not shell:
            command = command.split()

        result = subprocess.run(
            command,
            shell=shell,
            capture_output=capture_output,
            text=True,
            timeout=timeout,
            check=False,
        )

        if result.returncode != 0:
            logger.error("Command failed with return code %s", result.returncode)
            logger.error("stderr: %s", result.stderr)

        return result

    except subprocess.TimeoutExpired:
        logger.error("Command timed out after %s seconds: %s", timeout, command)
        raise
    except (OSError, ValueError, RuntimeError) as e:
        logger.error(f"Error running command '{command}': {e}")
        raise


def is_windows() -> bool:
    """Check if running on Windows."""
    return platform.system().lower() == "windows"


def is_linux() -> bool:
    """Check if running on Linux."""
    return platform.system().lower() == "linux"


def is_macos() -> bool:
    """Check if running on macOS."""
    return platform.system().lower() == "darwin"


def get_process_list() -> list[dict[str, Any]]:
    """Get list of running processes.

    Returns:
        list: List of process info dictionaries

    """
    # Use the consolidated process listing function
    return get_all_processes(["pid", "name", "cpu_percent", "memory_percent"])


def kill_process(pid: int, force: bool = False) -> bool:
    """Kill a process by PID.

    Args:
        pid: Process ID
        force: Whether to force kill (SIGKILL vs SIGTERM)

    Returns:
        bool: True if successful

    """
    if psutil is None:
        logger.error("psutil is not installed. Cannot kill process.")
        return False

    try:
        process = psutil.Process(pid)
        if force:
            process.kill()  # SIGKILL
        else:
            process.terminate()  # SIGTERM

        logger.info(f"Successfully {'killed' if force else 'terminated'} process {pid}")
        return True

    except psutil.NoSuchProcess:
        logger.warning("Process %s does not exist", pid)
        return False
    except psutil.AccessDenied:
        logger.error("Access denied when trying to kill process %s", pid)
        return False
    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error killing process %s: %s", pid, e)
        return False


def get_environment_variable(name: str, default: str | None = None) -> str | None:
    """Get environment variable with optional default.

    Args:
        name: Variable name
        default: Default value if not found

    Returns:
        Optional[str]: Variable value or default

    """
    return os.environ.get(name, default)


def set_environment_variable(name: str, value: str) -> None:
    """Set environment variable.

    Args:
        name: Variable name
        value: Variable value

    """
    os.environ[name] = value
    logger.debug("Set environment variable: %s=%s", name, value)


def get_temp_directory() -> Path:
    """Get system temporary directory.

    Returns:
        Path: Temporary directory path

    """
    import tempfile

    return Path(tempfile.gettempdir())


def get_home_directory() -> Path:
    """Get user's home directory.

    Returns:
        Path: Home directory path

    """
    return Path.home()


def check_admin_privileges() -> bool:
    """Check if running with administrator/root privileges.

    Returns:
        bool: True if running with elevated privileges

    """
    try:
        if is_windows():
            import ctypes

            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        # Unix-like systems
        return hasattr(os, "geteuid") and getattr(os, "geteuid", lambda: -1)() == 0
    except (OSError, ValueError, RuntimeError) as e:
        logger.warning("Could not check admin privileges: %s", e)
        return False


def is_admin() -> bool:
    """Alias for check_admin_privileges() for compatibility.

    Returns:
        bool: True if running with elevated privileges

    """
    return check_admin_privileges()


def run_as_admin(command: str | list[str], shell: bool = False) -> bool:
    """Run a command with elevated privileges.

    Args:
        command: Command to run
        shell: Whether to run through shell

    Returns:
        bool: True if command executed successfully

    """
    _ = shell
    try:
        if is_windows():
            # On Windows, use runas or PowerShell Start-Process -Verb RunAs
            if isinstance(command, list):
                command = " ".join(command)

            # Use PowerShell to run with elevated privileges
            ps_command = (
                f'Start-Process -FilePath "cmd" -ArgumentList "/c {command}" -Verb RunAs -Wait'
            )
            result = subprocess.run(
                ["powershell", "-Command", ps_command], capture_output=True, text=True, check=False
            )
            return result.returncode == 0
        # On Unix-like systems, use sudo
        if isinstance(command, str):
            command = command.split()

        sudo_command = ["sudo"] + command
        result = subprocess.run(sudo_command, capture_output=True, text=True, check=False)
        return result.returncode == 0

    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error running command as admin: %s", e)
        return False


def extract_executable_icon(exe_path: str, output_path: str = None) -> str | None:
    """Extract icon from an executable file.

    Args:
        exe_path: Path to the executable file
        output_path: Output path for the icon (optional)

    Returns:
        Optional[str]: Path to the extracted icon file, or None if failed

    """
    try:
        if not PIL_AVAILABLE:
            logger.warning("PIL not available for icon extraction")
            return None

        if not os.path.exists(exe_path):
            logger.error("Executable not found: %s", exe_path)
            return None

        # Default output path
        if output_path is None:
            output_path = os.path.splitext(exe_path)[0] + "_icon.png"

        if is_windows():
            try:
                # Windows-specific icon extraction using win32api
                import win32api
                import win32con
                import win32gui
                import win32ui

                # Extract icon
                ico_x = win32api.GetSystemMetrics(win32con.SM_CXICON)
                ico_y = win32api.GetSystemMetrics(win32con.SM_CYICON)

                large, small = win32gui.ExtractIconEx(exe_path, 0)
                if large:
                    win32gui.DestroyIcon(small[0])

                    # Convert to PIL Image
                    hdc = win32ui.CreateDCFromHandle(win32gui.GetDC(0))
                    hbmp = win32ui.CreateBitmap()
                    hbmp.CreateCompatibleBitmap(hdc, ico_x, ico_y)
                    hdc_mem = hdc.CreateCompatibleDC()
                    hdc_mem.SelectObject(hbmp)

                    win32gui.DrawIconEx(
                        hdc_mem.GetHandleOutput(),
                        0,
                        0,
                        large[0],
                        ico_x,
                        ico_y,
                        0,
                        None,
                        win32con.DI_NORMAL,
                    )

                    # Save to file
                    bmpinfo = hbmp.GetInfo()
                    bmpstr = hbmp.GetBitmapBits(True)

                    img = Image.frombuffer(
                        "RGB",
                        (bmpinfo["bmWidth"], bmpinfo["bmHeight"]),
                        bmpstr,
                        "raw",
                        "BGRX",
                        0,
                        1,
                    )

                    img.save(output_path, "PNG")
                    win32gui.DestroyIcon(large[0])

                    logger.info("Icon extracted to: %s", output_path)
                    return output_path

            except ImportError:
                logger.warning("win32api not available, trying alternative method")
            except (OSError, ValueError, RuntimeError) as e:
                logger.error("Windows icon extraction failed: %s", e)

        # Cross-platform fallback: Try to extract from PE file
        try:
            import pefile

            pe = pefile.PE(exe_path)

            # Look for RT_ICON resources
            if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
                for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    if resource_type.name and str(resource_type.name) == "RT_ICON":
                        for resource_id in resource_type.directory.entries:
                            for resource_lang in resource_id.directory.entries:
                                data = pe.get_data(
                                    resource_lang.data.struct.OffsetToData,
                                    resource_lang.data.struct.Size,
                                )

                                # Save as ICO file first
                                ico_path = output_path.replace(".png", ".ico")
                                with open(ico_path, "wb") as f:
                                    f.write(data)

                                # Convert ICO to PNG using PIL
                                try:
                                    img = Image.open(ico_path)
                                    img.save(output_path, "PNG")
                                    os.remove(ico_path)  # Clean up ICO file
                                    logger.info("Icon extracted to: %s", output_path)
                                    return output_path
                                except (OSError, ValueError, RuntimeError) as e:
                                    logger.error("Failed to convert ICO to PNG: %s", e)

        except ImportError:
            logger.error("pefile not available for icon extraction")
        except (OSError, ValueError, RuntimeError) as e:
            logger.error("PE icon extraction failed: %s", e)

        # If all methods fail, create a default icon
        logger.warning("All icon extraction methods failed, creating default icon")
        if PIL_AVAILABLE:
            try:
                # Create a simple default icon
                img = Image.new("RGBA", (64, 64), (100, 100, 100, 255))
                draw = ImageDraw.Draw(img)
                draw.rectangle([10, 10, 54, 54], outline=(200, 200, 200), width=2)
                draw.text((20, 25), "EXE", fill=(255, 255, 255))
                img.save(output_path, "PNG")
                return output_path
            except (OSError, ValueError, RuntimeError) as e:
                logger.error("Failed to create default icon: %s", e)

    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Icon extraction failed: %s", e)
        return None


# Backward compatibility aliases
getprocess_list = get_process_list
killprocess = kill_process
get_target_process_pid = get_targetprocess_pid


def optimize_memory_usage() -> dict[str, Any]:
    """Optimize system memory usage by clearing caches and garbage collection.

    Returns:
        Dict[str, Any]: Memory statistics before and after optimization

    """
    import gc

    stats = {
        "before": {},
        "after": {},
        "freed": 0,
    }

    # Get initial memory stats
    if psutil:
        mem = psutil.virtual_memory()
        stats["before"] = {
            "total": mem.total,
            "available": mem.available,
            "percent": mem.percent,
            "used": mem.used,
        }

    # Force garbage collection
    collected = gc.collect()
    logger.info("Garbage collector: collected %s objects", collected)

    # Clear Python's internal caches
    try:
        # Clear linecache
        import linecache

        linecache.clearcache()

        # Clear re cache
        import re

        re.purge()

        # Clear functools caches
        import functools

        if hasattr(functools, "lru_cache"):
            # Clear all lru_cache instances (Python 3.9+)
            cleared_count = 0
            failed_count = 0
            for obj in gc.get_objects():
                if hasattr(obj, "cache_clear"):
                    try:
                        obj.cache_clear()
                        cleared_count += 1
                    except Exception as e:
                        failed_count += 1
                        logger.debug("Failed to clear cache for %s: %s", type(obj).__name__, e)

            logger.debug("Cache clearing: %d successful, %d failed", cleared_count, failed_count)
    except (OSError, ValueError, RuntimeError) as e:
        logger.warning("Error clearing caches: %s", e)

    # Get final memory stats
    if psutil:
        mem = psutil.virtual_memory()
        stats["after"] = {
            "total": mem.total,
            "available": mem.available,
            "percent": mem.percent,
            "used": mem.used,
        }

        # Calculate freed memory
        stats["freed"] = stats["before"]["used"] - stats["after"]["used"]
        logger.info(f"Memory optimization freed: {stats['freed'] / 1024 / 1024:.2f} MB")

    return stats


# Exported functions
__all__ = [
    "get_targetprocess_pid",
    "get_system_info",
    "check_dependencies",
    "run_command",
    "is_windows",
    "is_linux",
    "is_macos",
    "get_process_list",
    "kill_process",
    "get_environment_variable",
    "set_environment_variable",
    "get_temp_directory",
    "get_home_directory",
    "check_admin_privileges",
    "is_admin",
    "run_as_admin",
    "extract_executable_icon",
    "optimize_memory_usage",
    # Backward compatibility aliases
    "getprocess_list",
    "killprocess",
    "get_target_process_pid",
]

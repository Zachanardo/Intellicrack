"""
System utilities for the Intellicrack framework.

This module provides system-level utilities including process management,
dependency checking, platform detection, and system information retrieval.
"""

import datetime
import logging
import os
import platform
import subprocess
import sys
from pathlib import Path
from typing import Optional, Dict, List, Tuple, Any, Union

try:
    import psutil
except ImportError:
    psutil = None

# Module logger
logger = logging.getLogger(__name__)


def get_target_process_pid(binary_path: str) -> Optional[int]:
    """
    Gets PID of target process, handling multiple instances and partial matches.
    
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
        for proc in psutil.process_iter(['pid', 'name', 'create_time']):
            if proc.info['name']:
                proc_name_lower = proc.info['name'].lower()
                # Prioritize exact matches
                if proc_name_lower == target_name:
                    potential_pids.append({
                        'pid': proc.info['pid'],
                        'name': proc.info['name'],
                        'create_time': proc.info['create_time'],
                        'match': 'exact'
                    })
                elif target_name in proc_name_lower:
                    potential_pids.append({
                        'pid': proc.info['pid'],
                        'name': proc.info['name'],
                        'create_time': proc.info['create_time'],
                        'match': 'partial'
                    })
    except Exception as e:
        logger.error(f"Error iterating processes: {e}")
        return None
    
    if not potential_pids:
        logger.warning(f"[PID Finder] No process found matching '{target_name}'.")
        return None
    
    # Sort by match type (exact first) and then by creation time (newest first)
    potential_pids.sort(key=lambda x: (x['match'] != 'exact', -x['create_time']))
    
    if len(potential_pids) == 1:
        pid_info = potential_pids[0]
        logger.info(
            f"[PID Finder] Found unique process: {pid_info['name']} "
            f"(PID: {pid_info['pid']}, Match: {pid_info['match']})"
        )
        return pid_info['pid']
    else:
        # Multiple processes found - in a library context, just return the first
        # In the full application, this would prompt the user
        logger.warning(
            f"[PID Finder] Found {len(potential_pids)} potential processes. "
            f"Returning first match."
        )
        return potential_pids[0]['pid']


def get_system_info() -> Dict[str, Any]:
    """
    Get comprehensive system information.
    
    Returns:
        dict: System information including OS, architecture, CPU, memory, etc.
    """
    info = {
        'platform': platform.system(),
        'platform_release': platform.release(),
        'platform_version': platform.version(),
        'architecture': platform.machine(),
        'processor': platform.processor(),
        'python_version': sys.version,
        'python_implementation': platform.python_implementation(),
    }
    
    # Add psutil information if available
    if psutil:
        try:
            info['cpu_count'] = psutil.cpu_count()
            info['cpu_count_logical'] = psutil.cpu_count(logical=True)
            info['memory_total'] = psutil.virtual_memory().total
            info['memory_available'] = psutil.virtual_memory().available
            info['memory_percent'] = psutil.virtual_memory().percent
        except Exception as e:
            logger.warning(f"Error getting psutil system info: {e}")
    
    return info


def check_dependencies(dependencies: Dict[str, str]) -> Tuple[bool, Dict[str, bool]]:
    """
    Check if Python dependencies are installed.
    
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
            logger.debug(f"✓ {module_name}: {description}")
        except ImportError:
            results[module_name] = False
            all_satisfied = False
            logger.warning(f"✗ {module_name}: {description} - NOT INSTALLED")
    
    return all_satisfied, results


def run_command(command: Union[str, List[str]], shell: bool = False, 
                capture_output: bool = True, timeout: Optional[int] = None) -> subprocess.CompletedProcess:
    """
    Run a system command with proper error handling.
    
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
        logger.debug(f"Running command: {command}")
        
        if isinstance(command, str) and not shell:
            command = command.split()
        
        result = subprocess.run(
            command,
            shell=shell,
            capture_output=capture_output,
            text=True,
            timeout=timeout
        )
        
        if result.returncode != 0:
            logger.error(f"Command failed with return code {result.returncode}")
            logger.error(f"stderr: {result.stderr}")
        
        return result
        
    except subprocess.TimeoutExpired as e:
        logger.error(f"Command timed out after {timeout} seconds: {command}")
        raise
    except Exception as e:
        logger.error(f"Error running command '{command}': {e}")
        raise


def is_windows() -> bool:
    """Check if running on Windows."""
    return platform.system().lower() == 'windows'


def is_linux() -> bool:
    """Check if running on Linux."""
    return platform.system().lower() == 'linux'


def is_macos() -> bool:
    """Check if running on macOS."""
    return platform.system().lower() == 'darwin'


def get_process_list() -> List[Dict[str, Any]]:
    """
    Get list of running processes.
    
    Returns:
        list: List of process info dictionaries
    """
    if psutil is None:
        logger.error("psutil is not installed. Cannot get process list.")
        return []
    
    processes = []
    try:
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
            try:
                processes.append(proc.info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
    except Exception as e:
        logger.error(f"Error getting process list: {e}")
    
    return processes


def kill_process(pid: int, force: bool = False) -> bool:
    """
    Kill a process by PID.
    
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
        logger.warning(f"Process {pid} does not exist")
        return False
    except psutil.AccessDenied:
        logger.error(f"Access denied when trying to kill process {pid}")
        return False
    except Exception as e:
        logger.error(f"Error killing process {pid}: {e}")
        return False


def get_environment_variable(name: str, default: Optional[str] = None) -> Optional[str]:
    """
    Get environment variable with optional default.
    
    Args:
        name: Variable name
        default: Default value if not found
        
    Returns:
        Optional[str]: Variable value or default
    """
    return os.environ.get(name, default)


def set_environment_variable(name: str, value: str) -> None:
    """
    Set environment variable.
    
    Args:
        name: Variable name
        value: Variable value
    """
    os.environ[name] = value
    logger.debug(f"Set environment variable: {name}={value}")


def get_temp_directory() -> Path:
    """
    Get system temporary directory.
    
    Returns:
        Path: Temporary directory path
    """
    import tempfile
    return Path(tempfile.gettempdir())


def get_home_directory() -> Path:
    """
    Get user's home directory.
    
    Returns:
        Path: Home directory path
    """
    return Path.home()


def check_admin_privileges() -> bool:
    """
    Check if running with administrator/root privileges.
    
    Returns:
        bool: True if running with elevated privileges
    """
    try:
        if is_windows():
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            # Unix-like systems
            return os.geteuid() == 0
    except Exception as e:
        logger.warning(f"Could not check admin privileges: {e}")
        return False


def is_admin() -> bool:
    """
    Alias for check_admin_privileges() for compatibility.
    
    Returns:
        bool: True if running with elevated privileges
    """
    return check_admin_privileges()


def run_as_admin(command: Union[str, List[str]], shell: bool = False) -> bool:
    """
    Run a command with elevated privileges.
    
    Args:
        command: Command to run
        shell: Whether to run through shell
        
    Returns:
        bool: True if command executed successfully
    """
    try:
        if is_windows():
            # On Windows, use runas or PowerShell Start-Process -Verb RunAs
            if isinstance(command, list):
                command = ' '.join(command)
            
            # Use PowerShell to run with elevated privileges
            ps_command = f'Start-Process -FilePath "cmd" -ArgumentList "/c {command}" -Verb RunAs -Wait'
            result = subprocess.run(
                ['powershell', '-Command', ps_command],
                capture_output=True,
                text=True
            )
            return result.returncode == 0
        else:
            # On Unix-like systems, use sudo
            if isinstance(command, str):
                command = command.split()
            
            sudo_command = ['sudo'] + command
            result = subprocess.run(sudo_command, capture_output=True, text=True)
            return result.returncode == 0
            
    except Exception as e:
        logger.error(f"Error running command as admin: {e}")
        return False


# Exported functions
__all__ = [
    'get_target_process_pid',
    'get_system_info',
    'check_dependencies',
    'run_command',
    'is_windows',
    'is_linux',
    'is_macos',
    'get_process_list',
    'kill_process',
    'get_environment_variable',
    'set_environment_variable',
    'get_temp_directory',
    'get_home_directory',
    'check_admin_privileges',
    'is_admin',
    'run_as_admin',
]
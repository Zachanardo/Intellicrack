"""Tool discovery utilities for security analysis and reverse engineering tools.

This module provides functions to locate common security analysis tools including
disassemblers, debuggers, and reverse engineering utilities across different
platforms. It searches standard installation paths and validates tool availability
for the Intellicrack framework.

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
import shutil
import sys
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


def find_tool(tool_name: str) -> Optional[str]:
    """
    Find a tool by searching common installation paths and PATH.

    Args:
        tool_name: Name of the tool to find

    Returns:
        Full path to the tool if found, None otherwise
    """
    # First check if it's in PATH
    tool_path = shutil.which(tool_name)
    if tool_path:
        return tool_path

    # Define common tool search paths based on platform
    search_paths = _get_tool_search_paths(tool_name)

    # Search in common paths
    for search_path in search_paths:
        if os.path.exists(search_path) and os.path.isfile(search_path):
            return search_path

    logger.debug(f"Tool '{tool_name}' not found in common locations")
    return None


def _get_tool_search_paths(tool_name: str) -> List[str]:
    """Get platform-specific search paths for a tool."""
    paths = []
    system = platform.system().lower()

    if tool_name.lower() == "ghidra":
        if system == "windows":
            paths.extend([
                r"C:\ghidra\ghidraRun.bat",
                r"C:\Program Files\ghidra\ghidraRun.bat",
                r"C:\Program Files (x86)\ghidra\ghidraRun.bat",
                r"C:\Tools\ghidra\ghidraRun.bat",
                r"D:\ghidra\ghidraRun.bat",
                r"E:\ghidra\ghidraRun.bat"
            ])
            # Add version-specific paths
            for version in ["10.4", "10.3", "10.2", "10.1", "10.0", "9.2"]:
                paths.extend([
                    rf"C:\ghidra_{version}_PUBLIC\ghidraRun.bat",
                    rf"C:\Program Files\ghidra_{version}_PUBLIC\ghidraRun.bat"
                ])
        else:
            paths.extend([
                "/opt/ghidra/ghidraRun",
                "/usr/local/ghidra/ghidraRun",
                "/home/ghidra/ghidraRun",
                "~/ghidra/ghidraRun",
                "/Applications/ghidra/ghidraRun"
            ])

    elif tool_name.lower() == "radare2" or tool_name.lower() == "r2":
        if system == "windows":
            paths.extend([
                r"C:\radare2\bin\radare2.exe",
                r"C:\Program Files\radare2\bin\radare2.exe",
                r"C:\Program Files (x86)\radare2\bin\radare2.exe",
                r"C:\Tools\radare2\bin\radare2.exe"
            ])
        else:
            paths.extend([
                "/usr/bin/radare2",
                "/usr/local/bin/radare2",
                "/opt/radare2/bin/radare2"
            ])

    elif tool_name.lower() == "ida" or tool_name.lower() == "ida64":
        if system == "windows":
            paths.extend([
                r"C:\Program Files\IDA Pro 7.7\ida64.exe",
                r"C:\Program Files\IDA Pro 7.6\ida64.exe",
                r"C:\Program Files\IDA Pro 7.5\ida64.exe",
                r"C:\Program Files (x86)\IDA Pro 7.7\ida64.exe",
                r"C:\IDA Pro\ida64.exe"
            ])
        else:
            paths.extend([
                "/opt/ida/ida64",
                "/usr/local/ida/ida64"
            ])

    elif tool_name.lower() == "x64dbg":
        if system == "windows":
            paths.extend([
                r"C:\x64dbg\x64dbg.exe",
                r"C:\Program Files\x64dbg\x64dbg.exe",
                r"C:\Program Files (x86)\x64dbg\x64dbg.exe",
                r"C:\Tools\x64dbg\x64dbg.exe"
            ])

    elif tool_name.lower() == "ollydbg":
        if system == "windows":
            paths.extend([
                r"C:\OllyDbg\OllyDbg.exe",
                r"C:\Program Files\OllyDbg\OllyDbg.exe",
                r"C:\Program Files (x86)\OllyDbg\OllyDbg.exe"
            ])

    elif tool_name.lower() == "windbg":
        if system == "windows":
            paths.extend([
                r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\windbg.exe",
                r"C:\Program Files\Windows Kits\10\Debuggers\x64\windbg.exe",
                r"C:\WinDbg\windbg.exe"
            ])

    elif tool_name.lower() == "gdb":
        if system != "windows":
            paths.extend([
                "/usr/bin/gdb",
                "/usr/local/bin/gdb"
            ])

    elif tool_name.lower() == "objdump":
        if system == "windows":
            paths.extend([
                r"C:\mingw64\bin\objdump.exe",
                r"C:\msys64\mingw64\bin\objdump.exe"
            ])
        else:
            paths.extend([
                "/usr/bin/objdump",
                "/usr/local/bin/objdump"
            ])

    elif tool_name.lower() == "strings":
        if system == "windows":
            paths.extend([
                r"C:\SysinternalsSuite\strings.exe",
                r"C:\Program Files\SysinternalsSuite\strings.exe"
            ])
        else:
            paths.extend([
                "/usr/bin/strings",
                "/usr/local/bin/strings"
            ])

    elif tool_name.lower() == "hexdump" or tool_name.lower() == "xxd":
        if system != "windows":
            paths.extend([
                "/usr/bin/hexdump",
                "/usr/bin/xxd",
                "/usr/local/bin/hexdump",
                "/usr/local/bin/xxd"
            ])

    return paths


def find_all_tools() -> Dict[str, Optional[str]]:
    """
    Find all common reverse engineering tools.

    Returns:
        Dictionary mapping tool names to their paths (or None if not found)
    """
    tools = [
        "ghidra", "radare2", "ida", "ida64", "x64dbg", "ollydbg", "windbg",
        "gdb", "objdump", "strings", "hexdump", "xxd"
    ]

    results = {}
    for tool in tools:
        results[tool] = find_tool(tool)

    return results


def get_common_installation_paths() -> Dict[str, List[str]]:
    """
    Get common installation paths for different types of software.

    Returns:
        Dictionary mapping software types to common installation paths
    """
    system = platform.system().lower()
    paths = {}

    if system == "windows":
        paths.update({
            "program_files": [
                r"C:\Program Files",
                r"C:\Program Files (x86)"
            ],
            "tools": [
                r"C:\Tools",
                r"C:\Utils",
                r"C:\Software"
            ],
            "dev_tools": [
                r"C:\msys64",
                r"C:\mingw64",
                r"C:\cygwin64"
            ],
            "portable": [
                r"C:\PortableApps",
                r"D:\PortableApps"
            ]
        })
    else:
        paths.update({
            "bin": [
                "/usr/bin",
                "/usr/local/bin",
                "/opt/bin"
            ],
            "opt": [
                "/opt",
                "/usr/local/opt"
            ],
            "applications": [
                "/Applications" if system == "darwin" else "/usr/share/applications"
            ],
            "home": [
                os.path.expanduser("~/bin"),
                os.path.expanduser("~/tools"),
                os.path.expanduser("~/Applications") if system == "darwin" else os.path.expanduser("~/.local/bin")
            ]
        })

    return paths


def find_python_installations() -> List[Dict[str, str]]:
    """
    Find Python installations on the system.

    Returns:
        List of dictionaries with Python installation info
    """
    installations = []

    # Check current Python
    current_python = {
        "path": os.path.abspath(sys.executable),
        "version": platform.python_version(),
        "type": "current"
    }
    installations.append(current_python)

    # Common Python installation paths
    system = platform.system().lower()
    search_paths = []

    if system == "windows":
        search_paths.extend([
            r"C:\Python*\python.exe",
            r"C:\Program Files\Python*\python.exe",
            r"C:\Program Files (x86)\Python*\python.exe",
            r"%LOCALAPPDATA%\Programs\Python\Python*\python.exe"
        ])
    else:
        search_paths.extend([
            "/usr/bin/python*",
            "/usr/local/bin/python*",
            "/opt/python*/bin/python*"
        ])

    # Use glob to find Python installations
    import glob
    for pattern in search_paths:
        expanded_pattern = os.path.expandvars(pattern)
        for path in glob.glob(expanded_pattern):
            if os.path.isfile(path) and os.access(path, os.X_OK):
                try:
                    # Get version
                    import subprocess
                    result = subprocess.run([path, "--version"],
                                          capture_output=True, text=True, timeout=5)
                    version = result.stdout.strip().split()[-1] if result.returncode == 0 else "unknown"

                    installation = {
                        "path": os.path.abspath(path),
                        "version": version,
                        "type": "system"
                    }

                    # Avoid duplicates
                    if installation not in installations:
                        installations.append(installation)

                except Exception as e:
                    logger.debug(f"Failed to get Python version for {path}: {e}")

    return installations


def find_java_installations() -> List[Dict[str, str]]:
    """
    Find Java installations on the system.

    Returns:
        List of dictionaries with Java installation info
    """
    installations = []
    system = platform.system().lower()

    # Check JAVA_HOME
    java_home = os.environ.get("JAVA_HOME")
    if java_home and os.path.exists(java_home):
        java_exe = os.path.join(java_home, "bin", "java.exe" if system == "windows" else "java")
        if os.path.exists(java_exe):
            installations.append({
                "path": java_exe,
                "java_home": java_home,
                "type": "JAVA_HOME"
            })

    # Check PATH
    java_path = shutil.which("java")
    if java_path:
        installations.append({
            "path": java_path,
            "java_home": os.path.dirname(os.path.dirname(java_path)),
            "type": "PATH"
        })

    # Common Java installation paths
    search_paths = []
    if system == "windows":
        search_paths.extend([
            r"C:\Program Files\Java\*\bin\java.exe",
            r"C:\Program Files (x86)\Java\*\bin\java.exe",
            r"C:\Program Files\Eclipse Adoptium\*\bin\java.exe"
        ])
    elif system == "darwin":
        search_paths.extend([
            "/Library/Java/JavaVirtualMachines/*/Contents/Home/bin/java",
            "/System/Library/Java/JavaVirtualMachines/*/Contents/Home/bin/java"
        ])
    else:
        search_paths.extend([
            "/usr/lib/jvm/*/bin/java",
            "/opt/java/*/bin/java"
        ])

    import glob
    for pattern in search_paths:
        for path in glob.glob(pattern):
            if os.path.isfile(path) and os.access(path, os.X_OK):
                java_home = os.path.dirname(os.path.dirname(path))
                installation = {
                    "path": os.path.abspath(path),
                    "java_home": java_home,
                    "type": "system"
                }

                # Avoid duplicates
                if installation not in installations:
                    installations.append(installation)

    return installations


def validate_tool_path(tool_path: str) -> Tuple[bool, str]:
    """
    Validate that a tool path is valid and executable.

    Args:
        tool_path: Path to the tool

    Returns:
        Tuple of (is_valid, error_message)
    """
    if not tool_path:
        return False, "Path is empty"

    if not os.path.exists(tool_path):
        return False, f"Path does not exist: {tool_path}"

    if not os.path.isfile(tool_path):
        return False, f"Path is not a file: {tool_path}"

    if not os.access(tool_path, os.X_OK):
        return False, f"Path is not executable: {tool_path}"

    return True, "Tool path is valid"


def get_tool_version(tool_path: str, version_arg: str = "--version") -> Optional[str]:
    """
    Get the version of a tool.

    Args:
        tool_path: Path to the tool
        version_arg: Argument to get version (default: --version)

    Returns:
        Version string if successful, None otherwise
    """
    try:
        import subprocess
        result = subprocess.run([tool_path, version_arg],
                              capture_output=True, text=True, timeout=10)

        if result.returncode == 0:
            # Extract version from output (first line usually contains version)
            first_line = result.stdout.strip().split("\n")[0]
            return first_line
        else:
            # Some tools output version to stderr
            first_line = result.stderr.strip().split("\n")[0]
            return first_line if first_line else None

    except Exception as e:
        logger.debug(f"Failed to get version for {tool_path}: {e}")
        return None


def create_tool_shortcuts(tools_dict: Dict[str, str], shortcuts_dir: str) -> bool:
    """
    Create shortcuts/symlinks for found tools.

    Args:
        tools_dict: Dictionary mapping tool names to paths
        shortcuts_dir: Directory to create shortcuts in

    Returns:
        True if shortcuts were created successfully
    """
    try:
        os.makedirs(shortcuts_dir, exist_ok=True)
        system = platform.system().lower()

        for tool_name, tool_path in tools_dict.items():
            if not tool_path or not os.path.exists(tool_path):
                continue

            if system == "windows":
                # Create batch file wrapper on Windows
                shortcut_path = os.path.join(shortcuts_dir, f"{tool_name}.bat")
                with open(shortcut_path, "w") as f:
                    f.write(f'@echo off\n"{tool_path}" %*\n')
            else:
                # Create symlink on Unix systems
                shortcut_path = os.path.join(shortcuts_dir, tool_name)
                if os.path.exists(shortcut_path):
                    os.remove(shortcut_path)
                os.symlink(tool_path, shortcut_path)

        return True

    except Exception as e:
        logger.error(f"Failed to create tool shortcuts: {e}")
        return False


def discover_analysis_environments() -> Dict[str, Dict[str, str]]:
    """
    Discover common analysis environments and their configurations.

    Returns:
        Dictionary with environment information
    """
    environments = {}

    # Check for virtual machines
    vm_indicators = {
        "vmware": ["vmware", "vmtoolsd"],
        "virtualbox": ["vboxservice", "vboxtray"],
        "qemu": ["qemu-ga"],
        "xen": ["xenservice"]
    }

    for vm_type, processes in vm_indicators.items():
        for process in processes:
            if shutil.which(process):
                environments[f"vm_{vm_type}"] = {
                    "type": "virtual_machine",
                    "platform": vm_type,
                    "indicator": process
                }
                break

    # Check for analysis tools
    analysis_tools = find_all_tools()
    available_tools = {name: path for name, path in analysis_tools.items() if path}

    if available_tools:
        environments["analysis_tools"] = {
            "type": "analysis_environment",
            "tools": available_tools
        }

    # Check for development environments
    dev_indicators = {
        "visual_studio": "devenv.exe" if platform.system() == "Windows" else None,
        "vscode": "code",
        "intellij": "idea",
        "eclipse": "eclipse"
    }

    for env_name, executable in dev_indicators.items():
        if executable and shutil.which(executable):
            environments[f"dev_{env_name}"] = {
                "type": "development_environment",
                "executable": executable
            }

    return environments


# Export commonly used functions
__all__ = [
    "find_tool",
    "find_all_tools",
    "get_common_installation_paths",
    "find_python_installations",
    "find_java_installations",
    "validate_tool_path",
    "get_tool_version",
    "create_tool_shortcuts",
    "discover_analysis_environments"
]

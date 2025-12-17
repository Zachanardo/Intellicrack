"""Dynamic path discovery system for tools and system resources.

This module provides comprehensive tool and resource discovery capabilities across
different platforms. It locates security analysis tools, development environments,
and system paths using multiple discovery strategies including environment variables,
registry searches, and common installation locations.

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

import logging
import os
import shutil
import subprocess
import sys
from pathlib import Path


logger = logging.getLogger(__name__)


class PathDiscovery:
    """Dynamic path discovery system for tools and resources."""

    def __init__(self, config_manager: object | None = None) -> None:
        """Initialize path discovery system.

        Args:
            config_manager: Optional config manager for persistence.

        """
        self.config_manager = config_manager
        self.cache = {}
        self.platform = sys.platform
        self.is_windows = self.platform.startswith("win")
        self.is_linux = self.platform.startswith("linux")
        self.is_mac = self.platform.startswith("darwin")

        # Define tool specifications
        self.tool_specs = {
            "ghidra": {
                "executables": {
                    "win32": ["ghidraRun.bat", "ghidra.bat"],
                    "linux": ["ghidra", "ghidraRun"],
                    "darwin": ["ghidra", "ghidraRun"],
                },
                "search_paths": {
                    "win32": [
                        r"C:\Program Files\Ghidra",
                        r"C:\ghidra",
                        r"C:\Tools\ghidra",
                        r"C:\ProgramData\chocolatey\lib\ghidra\tools",
                    ],
                    "linux": [
                        "/opt/ghidra",
                        "/usr/local/ghidra",
                        "/usr/share/ghidra",
                        os.path.expanduser("~/ghidra"),
                    ],
                    "darwin": [
                        "/Applications/ghidra",
                        "/opt/ghidra",
                        "/usr/local/ghidra",
                        os.path.expanduser("~/ghidra"),
                    ],
                },
                "env_vars": ["GHIDRA_HOME", "GHIDRA_PATH", "GHIDRA_INSTALL_DIR"],
                "validation": self._validate_ghidra,
            },
            "radare2": {
                "executables": {
                    "win32": ["radare2.exe", "r2.exe"],
                    "linux": ["radare2", "r2"],
                    "darwin": ["radare2", "r2"],
                },
                "search_paths": {
                    "win32": [
                        r"C:\Program Files\radare2",
                        r"C:\radare2",
                        r"C:\Tools\radare2",
                        os.path.join(
                            os.path.dirname(__file__ or str(Path.cwd())),
                            "..",
                            "..",
                            "radare2",
                            "radare2-5.9.8-w64",
                            "bin",
                        )
                        if __file__
                        else os.path.join(str(Path.cwd()), "radare2", "radare2-5.9.8-w64", "bin"),
                    ],
                    "linux": [
                        "/usr/bin",
                        "/usr/local/bin",
                        "/opt/radare2/bin",
                    ],
                    "darwin": [
                        "/usr/local/bin",
                        "/opt/homebrew/bin",
                        "/opt/radare2/bin",
                    ],
                },
                "env_vars": ["RADARE2_HOME", "RADARE2_PATH"],
                "validation": self._validate_radare2,
            },
            "frida": {
                "executables": {
                    "win32": ["frida.exe", "frida-server.exe"],
                    "linux": ["frida", "frida-server"],
                    "darwin": ["frida", "frida-server"],
                },
                "search_paths": {
                    "win32": [
                        os.path.join(sys.prefix, "Scripts"),
                        r"C:\Python\Scripts",
                        r"C:\Program Files\Python\Scripts",
                    ],
                    "linux": [
                        "/usr/local/bin",
                        "/usr/bin",
                        os.path.expanduser("~/.local/bin"),
                    ],
                    "darwin": [
                        "/usr/local/bin",
                        "/opt/homebrew/bin",
                        os.path.expanduser("~/.local/bin"),
                    ],
                },
                "env_vars": ["FRIDA_PATH"],
                "validation": self._validate_frida,
            },
            "python": {
                "executables": {
                    "win32": [
                        "python.exe",
                        "python3.exe",
                        "python311.exe",
                        "python310.exe",
                        "python39.exe",
                    ],
                    "linux": ["python3", "python", "python3.11", "python3.10", "python3.9"],
                    "darwin": ["python3", "python", "python3.11", "python3.10", "python3.9"],
                },
                "search_paths": {
                    "win32": [
                        r"C:\Program Files\Python311",
                        r"C:\Program Files\Python310",
                        r"C:\Program Files\Python39",
                        r"C:\Program Files (x86)\Python311",
                        r"C:\Python311",
                        r"C:\Python310",
                        r"C:\Python39",
                        os.path.join(sys.prefix),
                    ],
                    "linux": [
                        "/usr/bin",
                        "/usr/local/bin",
                        "/opt/python/bin",
                    ],
                    "darwin": [
                        "/usr/local/bin",
                        "/opt/homebrew/bin",
                        "/usr/bin",
                    ],
                },
                "env_vars": ["PYTHON_HOME", "PYTHON_PATH"],
                "validation": self._validate_python,
            },
            "wireshark": {
                "executables": {
                    "win32": ["Wireshark.exe", "tshark.exe"],
                    "linux": ["wireshark", "tshark"],
                    "darwin": ["wireshark", "tshark"],
                },
                "search_paths": {
                    "win32": [
                        r"C:\Program Files\Wireshark",
                        r"C:\Program Files (x86)\Wireshark",
                    ],
                    "linux": [
                        "/usr/bin",
                        "/usr/local/bin",
                    ],
                    "darwin": [
                        "/Applications/Wireshark.app/Contents/MacOS",
                        "/usr/local/bin",
                    ],
                },
                "env_vars": ["WIRESHARK_PATH"],
                "validation": self._validate_wireshark,
            },
            "qemu": {
                "executables": {
                    "win32": ["qemu-system-x86_64.exe", "qemu-system-i386.exe"],
                    "linux": ["qemu-system-x86_64", "qemu-system-i386"],
                    "darwin": ["qemu-system-x86_64", "qemu-system-i386"],
                },
                "search_paths": {
                    "win32": [
                        r"C:\Program Files\qemu",
                        r"C:\qemu",
                        r"C:\Tools\qemu",
                    ],
                    "linux": [
                        "/usr/bin",
                        "/usr/local/bin",
                    ],
                    "darwin": [
                        "/usr/local/bin",
                        "/opt/homebrew/bin",
                    ],
                },
                "env_vars": ["QEMU_PATH", "QEMU_HOME"],
                "validation": None,
            },
            "git": {
                "executables": {
                    "win32": ["git.exe"],
                    "linux": ["git"],
                    "darwin": ["git"],
                },
                "search_paths": {
                    "win32": [
                        r"C:\Program Files\Git\bin",
                        r"C:\Program Files (x86)\Git\bin",
                        r"C:\Program Files\Git\cmd",
                    ],
                    "linux": [
                        "/usr/bin",
                        "/usr/local/bin",
                    ],
                    "darwin": [
                        "/usr/bin",
                        "/usr/local/bin",
                        "/opt/homebrew/bin",
                    ],
                },
                "env_vars": ["GIT_PATH"],
                "validation": None,
            },
            "wkhtmltopdf": {
                "executables": {
                    "win32": ["wkhtmltopdf.exe"],
                    "linux": ["wkhtmltopdf"],
                    "darwin": ["wkhtmltopdf"],
                },
                "search_paths": {
                    "win32": [
                        r"C:\Program Files\wkhtmltopdf\bin",
                        r"C:\Program Files (x86)\wkhtmltopdf\bin",
                        r"C:\wkhtmltopdf\bin",
                    ],
                    "linux": [
                        "/usr/bin",
                        "/usr/local/bin",
                    ],
                    "darwin": [
                        "/usr/local/bin",
                        "/opt/homebrew/bin",
                    ],
                },
                "env_vars": ["WKHTMLTOPDF_PATH"],
                "validation": None,
            },
        }

        # System paths
        self.system_paths = {
            "windows_system": self._get_windows_system_dir,
            "windows_system32": self._get_windows_system32_dir,
            "windows_drivers": self._get_windows_drivers_dir,
            "program_files": self._get_program_files_dir,
            "program_files_x86": self._get_program_files_x86_dir,
            "appdata": self._get_appdata_dir,
            "localappdata": self._get_localappdata_dir,
            "programdata": self._get_programdata_dir,
            "user_home": self._get_user_home,
            "temp": self._get_temp_dir,
            "startup": self._get_startup_dir,
        }

    def find_tool(self, tool_name: str, required_executables: list[str] | None = None) -> str | None:
        """Find a tool using multiple discovery strategies.

        Args:
            tool_name: Name of the tool to find
            required_executables: Optional list of specific executables to search for

        Returns:
            Path to the tool executable or None if not found

        """
        # Check cache
        cache_key = f"{tool_name}:{','.join(required_executables or [])}"
        if cache_key in self.cache:
            cached_path = self.cache[cache_key]
            if os.path.exists(cached_path):
                return cached_path
            # Cache is stale
            del self.cache[cache_key]

        # Check config first
        if self.config_manager:
            config_path = self.config_manager.get(f"{tool_name}_path")
            if config_path and os.path.exists(config_path):
                self.cache[cache_key] = config_path
                return config_path

        # Get tool specification
        spec = self.tool_specs.get(tool_name.lower())
        if not spec:
            # Generic tool search
            return self._generic_tool_search(tool_name, required_executables)

        # Try discovery strategies
        strategies = [
            (self._search_env_vars, spec.get("env_vars", [])),
            (self._search_path, required_executables or spec["executables"].get(self.platform, [])),
            (self._search_common_locations, spec),
            (self._search_registry, tool_name) if self.is_windows else (None, None),
        ]

        for strategy, args in strategies:
            if strategy is None:
                continue

            if path := strategy(args):
                # Validate if validator exists
                validator = spec.get("validation")
                if validator and not validator(path):
                    continue

                # Cache and return
                self.cache[cache_key] = path
                if self.config_manager:
                    self.config_manager.set(f"{tool_name}_path", path)
                return path

        return None

    def _generic_tool_search(self, tool_name: str, executables: list[str] | None = None) -> str | None:
        """Provide search for tools not in specification."""
        if not executables:
            executables = [tool_name]
            if self.is_windows:
                executables.extend([f"{tool_name}.exe", f"{tool_name}.bat", f"{tool_name}.cmd"])

        # Search in PATH
        for exe in executables:
            if path := shutil.which(exe):
                return path

        # Search common locations
        search_dirs = []
        if self.is_windows:
            search_dirs.extend(
                [
                    os.path.join(self.get_system_path("program_files"), tool_name),
                    os.path.join(self.get_system_path("program_files_x86"), tool_name),
                    f"C:\\{tool_name}",
                    f"C:\\Tools\\{tool_name}",
                ],
            )
        else:
            search_dirs.extend(
                [
                    f"/opt/{tool_name}",
                    f"/usr/local/{tool_name}",
                    os.path.expanduser(f"~/.{tool_name}"),
                    os.path.expanduser(f"~/{tool_name}"),
                ],
            )

        for directory in search_dirs:
            if os.path.exists(directory):
                for exe in executables:
                    exe_path = os.path.join(directory, exe)
                    if os.path.isfile(exe_path):
                        return exe_path

                    # Check bin subdirectory
                    bin_path = os.path.join(directory, "bin", exe)
                    if os.path.isfile(bin_path):
                        return bin_path

        return None

    def _search_env_vars(self, env_vars: list[str]) -> str | None:
        """Search using environment variables."""
        for var in env_vars:
            path = os.environ.get(var)
            if path and os.path.exists(path):
                if os.path.isfile(path):
                    return path
                if Path(path).is_dir():
                    # Look for executable in directory
                    for file in os.listdir(path):
                        if os.path.isfile(os.path.join(path, file)) and os.access(os.path.join(path, file), os.X_OK):
                            return os.path.join(path, file)
        return None

    def _search_path(self, executables: list[str]) -> str | None:
        """Search in system PATH."""
        for exe in executables:
            if path := shutil.which(exe):
                return path
        return None

    def _search_common_locations(self, spec: dict) -> str | None:
        """Search in common installation locations."""
        search_paths = spec.get("search_paths", {}).get(self.platform, [])
        executables = spec.get("executables", {}).get(self.platform, [])

        for directory in search_paths:
            directory = os.path.expanduser(directory)
            if os.path.exists(directory):
                for exe in executables:
                    exe_path = os.path.join(directory, exe)
                    if os.path.isfile(exe_path):
                        return exe_path

                    # Check subdirectories
                    for subdir in ["bin", "scripts", "Scripts"]:
                        sub_path = os.path.join(directory, subdir, exe)
                        if os.path.isfile(sub_path):
                            return sub_path

        return None

    def _search_registry(self, tool_name: str) -> str | None:
        """Search Windows registry for installed software."""
        if not self.is_windows:
            return None

        try:
            import winreg

            registry_paths = [
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
                (
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
                ),
                (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            ]

            for hkey, path in registry_paths:
                try:
                    with winreg.OpenKey(hkey, path) as key:
                        for i in range(winreg.QueryInfoKey(key)[0]):
                            try:
                                subkey_name = winreg.EnumKey(key, i)
                                with winreg.OpenKey(key, subkey_name) as subkey:
                                    try:
                                        name = winreg.QueryValueEx(subkey, "DisplayName")[0]
                                        if tool_name.lower() in name.lower():
                                            install_location = winreg.QueryValueEx(subkey, "InstallLocation")[0]
                                            if install_location and os.path.exists(install_location):
                                                # Look for executable
                                                spec = self.tool_specs.get(tool_name.lower(), {})
                                                executables = spec.get("executables", {}).get("win32", [f"{tool_name}.exe"])

                                                for exe in executables:
                                                    exe_path = os.path.join(install_location, exe)
                                                    if os.path.isfile(exe_path):
                                                        return exe_path

                                                    # Check bin subdirectory
                                                    bin_path = os.path.join(install_location, "bin", exe)
                                                    if os.path.isfile(bin_path):
                                                        return bin_path
                                    except OSError as e:
                                        logger.error("OS error in path_discovery: %s", e, exc_info=True)
                            except OSError as e:
                                logger.error("OS error in path_discovery: %s", e, exc_info=True)
                except OSError as e:
                    logger.error("OS error in path_discovery: %s", e, exc_info=True)
        except ImportError:
            logger.warning("winreg module not available")

        return None

    def get_system_path(self, path_type: str) -> str | None:
        """Get system paths dynamically.

        Args:
            path_type: Type of system path (e.g., 'windows_system', 'program_files')

        Returns:
            System path or None if not applicable

        """
        return handler() if (handler := self.system_paths.get(path_type)) else None

    def _get_windows_system_dir(self) -> str | None:
        """Get Windows system directory."""
        return os.environ.get("SYSTEMROOT", r"C:\Windows") if self.is_windows else None

    def _get_windows_system32_dir(self) -> str | None:
        """Get Windows System32 directory."""
        if not self.is_windows:
            return None
        system_root = self._get_windows_system_dir()
        return os.path.join(system_root, "System32") if system_root else None

    def _get_windows_drivers_dir(self) -> str | None:
        """Get Windows drivers directory."""
        if not self.is_windows:
            return None
        system32 = self._get_windows_system32_dir()
        return os.path.join(system32, "drivers") if system32 else None

    def _get_program_files_dir(self) -> str | None:
        """Get Program Files directory."""
        if not self.is_windows:
            return None
        return os.environ.get("PROGRAMFILES", r"C:\Program Files")

    def _get_program_files_x86_dir(self) -> str | None:
        """Get Program Files (x86) directory."""
        if not self.is_windows:
            return None
        return os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)")

    def _get_appdata_dir(self) -> str | None:
        """Get AppData directory."""
        return os.environ.get("APPDATA") if self.is_windows else None

    def _get_localappdata_dir(self) -> str | None:
        """Get LocalAppData directory."""
        return os.environ.get("LOCALAPPDATA") if self.is_windows else None

    def _get_programdata_dir(self) -> str | None:
        """Get ProgramData directory."""
        if not self.is_windows:
            return None
        return os.environ.get("PROGRAMDATA", r"C:\ProgramData")

    def _get_user_home(self) -> str:
        """Get user home directory."""
        return os.path.expanduser("~")

    def _get_temp_dir(self) -> str:
        """Get temporary directory."""
        import tempfile

        return tempfile.gettempdir()

    def _get_startup_dir(self) -> str | None:
        """Get startup directory."""
        if self.is_windows:
            if appdata := self._get_appdata_dir():
                return os.path.join(appdata, "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
        return None

    # Validation methods
    def _validate_ghidra(self, path: str) -> bool:
        """Validate Ghidra installation."""
        ghidra_dir = os.path.dirname(path) if os.path.isfile(path) else path
        # Check for Ghidra-specific directories
        required_dirs = ["support", "Ghidra"]
        for req_dir in required_dirs:
            if not os.path.exists(os.path.join(ghidra_dir, req_dir)):
                # Try parent directory
                parent_dir = os.path.dirname(ghidra_dir)
                if not os.path.exists(os.path.join(parent_dir, req_dir)):
                    return False

        return True

    def _validate_radare2(self, path: str) -> bool:
        """Validate radare2 installation."""
        try:
            result = subprocess.run(  # nosec S603 - Legitimate subprocess usage for security research and binary analysis
                [path, "-v"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            return "radare2" in result.stdout.lower()
        except Exception as e:
            logger.error("Exception in path_discovery: %s", e, exc_info=True)
            return False

    def _validate_frida(self, path: str) -> bool:
        """Validate Frida installation."""
        try:
            result = subprocess.run(  # nosec S603 - Legitimate subprocess usage for security research and binary analysis
                [path, "--version"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            return "frida" in result.stdout.lower() or result.returncode == 0
        except Exception as e:
            logger.error("Exception in path_discovery: %s", e, exc_info=True)
            return False

    def _validate_python(self, path: str) -> bool:
        """Validate Python installation."""
        try:
            result = subprocess.run(  # nosec S603 - Legitimate subprocess usage for security research and binary analysis
                [path, "--version"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            return "python" in result.stdout.lower() or "python" in result.stderr.lower()
        except Exception as e:
            logger.error("Exception in path_discovery: %s", e, exc_info=True)
            return False

    def _validate_wireshark(self, path: str) -> bool:
        """Validate Wireshark installation."""
        # For GUI executables, just check if file exists
        return os.path.isfile(path)

    def get_cuda_path(self) -> str | None:
        """Find CUDA installation path."""
        if not self.is_windows:
            # Linux/Mac CUDA paths
            cuda_paths = [
                "/usr/local/cuda",
                "/opt/cuda",
            ]
            for path in cuda_paths:
                if os.path.exists(path):
                    return path
        else:
            # Windows CUDA paths
            cuda_base = r"C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA"
            if os.path.exists(cuda_base):
                if versions := [
                    item for item in os.listdir(cuda_base) if item.startswith("v") and Path(os.path.join(cuda_base, item)).is_dir()
                ]:
                    # Sort versions and get latest
                    versions.sort(reverse=True)
                    return os.path.join(cuda_base, versions[0])

        # Check environment variable
        cuda_path = os.environ.get("CUDA_PATH") or os.environ.get("CUDA_HOME")
        if cuda_path and os.path.exists(cuda_path):
            return cuda_path

        return None

    def ensure_tool_available(self, tool_name: str, parent_widget: object | None = None) -> str | None:
        """Ensure a tool is available, prompting user if needed.

        Args:
            tool_name: Name of the tool.
            parent_widget: Optional Qt widget for GUI prompts.

        Returns:
            Path to tool or None.

        """
        path = self.find_tool(tool_name)

        if not path:
            if parent_widget:
                try:
                    from PyQt6.QtWidgets import QFileDialog, QMessageBox

                    msg = QMessageBox()
                    msg.setWindowTitle(f"{tool_name} Not Found")
                    msg.setText(f"Could not find {tool_name}. Would you like to browse for it?")
                    msg.setStandardButtons(QMessageBox.Yes | QMessageBox.No)

                    if msg.exec() == QMessageBox.Yes:
                        file_filter = "Executable files (*.exe *.bat);;All files (*.*)" if self.is_windows else "All files (*)"
                        path, _ = QFileDialog.getOpenFileName(
                            parent_widget,
                            f"Select {tool_name} executable",
                            "",
                            file_filter,
                        )

                        if path:
                            self.cache[tool_name] = path
                            if self.config_manager:
                                self.config_manager.set(f"{tool_name}_path", path)
                            return path
                except ImportError:
                    logger.warning("PyQt6 not available for GUI prompts")
            else:
                # CLI mode
                print(f"{tool_name} not found. Please enter the path (or press Enter to skip):")
                try:
                    user_input = input().strip()
                    if not user_input:
                        return None
                    # Validate and sanitize path input
                    # Remove potentially dangerous characters
                    path = user_input.replace("\0", "").replace("\n", "").replace("\r", "")
                    # Normalize path
                    path = os.path.normpath(path)
                    # Validate path exists and is safe
                    if os.path.exists(path) and os.path.isfile(path):
                        # Additional validation: ensure it's an executable or expected file type
                        if os.access(path, os.X_OK) or path.endswith((".exe", ".bat", ".sh", ".py")):
                            self.cache[tool_name] = path
                            if self.config_manager:
                                self.config_manager.set(f"{tool_name}_path", path)
                            return path
                        logger.warning("Path %s is not an executable file", path)
                    else:
                        logger.warning("Path %s does not exist or is not a file", path)
                except (KeyboardInterrupt, EOFError) as e:
                    logger.error("Error in path_discovery: %s", e, exc_info=True)
                return None

        return path


# Global instance
_path_discovery = None


def get_path_discovery(config_manager: object | None = None) -> PathDiscovery:
    """Get global PathDiscovery instance.

    Args:
        config_manager: Optional config manager for persistence.

    Returns:
        Global PathDiscovery instance.

    """
    global _path_discovery  # pylint: disable=global-statement
    if _path_discovery is None:
        _path_discovery = PathDiscovery(config_manager)
    return _path_discovery


def find_tool(tool_name: str, required_executables: list[str] | None = None) -> str | None:
    """Find a tool."""
    return get_path_discovery().find_tool(tool_name, required_executables)


def get_system_path(path_type: str) -> str | None:
    """Get system paths."""
    return get_path_discovery().get_system_path(path_type)


def ensure_tool_available(tool_name: str, parent_widget: object | None = None) -> str | None:
    """Ensure tool availability.

    Args:
        tool_name: Name of the tool.
        parent_widget: Optional Qt widget for GUI prompts.

    Returns:
        Path to tool or None.

    """
    return get_path_discovery().ensure_tool_available(tool_name, parent_widget)

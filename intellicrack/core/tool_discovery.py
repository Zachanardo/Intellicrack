"""Advanced Tool Discovery System for Intellicrack.

Automatically discovers and validates security tools across platforms.
Handles version detection, capability checking, and intelligent fallbacks.

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
import re
import shutil
import subprocess
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any, TypedDict


logger = logging.getLogger(__name__)

try:
    from .terminal_manager import get_terminal_manager

    HAS_TERMINAL_MANAGER = True
except ImportError:
    HAS_TERMINAL_MANAGER = False
    logger.warning("Terminal manager not available for tool discovery")


class ValidationResult(TypedDict):
    """Type definition for tool validation results."""

    valid: bool
    version: str | None
    capabilities: list[str]
    issues: list[str]


class ToolValidator:
    """Validates tool installations and capabilities."""

    @staticmethod
    def validate_ghidra(tool_path: str) -> ValidationResult:
        """Validate Ghidra installation.

        Args:
            tool_path: Path to the Ghidra executable or installation directory.

        Returns:
            Dictionary containing validation results with keys 'valid', 'version',
            'capabilities', and 'issues'.

        """
        validation: ValidationResult = {
            "valid": False,
            "version": None,
            "capabilities": [],
            "issues": [],
        }

        try:
            ghidra_dir = Path(tool_path).parent

            ghidra_files = [
                "support/analyzeHeadless",
                "support/analyzeHeadless.bat",
                "Ghidra/application.properties",
            ]

            found_files: list[str] = []
            for file_path in ghidra_files:
                full_path = ghidra_dir / file_path
                if full_path.exists():
                    found_files.append(file_path)

            if not found_files:
                validation["issues"].append("Ghidra installation files not found")
                return validation

            try:
                result = subprocess.run(
                    [tool_path, "--version"],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=15,
                )

                if result.returncode == 0:
                    version_text = result.stdout or result.stderr
                    if version_match := re.search(r"(\d+\.\d+(?:\.\d+)?)", version_text):
                        validation["version"] = version_match[1]

            except Exception as e:
                logger.error("Exception in tool_discovery: %s", e)
                validation["issues"].append(f"Version check failed: {e}")

            validation["capabilities"].extend(
                [
                    "decompilation",
                    "static_analysis",
                    "script_execution",
                ],
            )

            validation["valid"] = True

        except Exception as e:
            logger.error("Exception in tool_discovery: %s", e)
            validation["issues"].append(f"Validation error: {e}")

        return validation

    @staticmethod
    def validate_radare2(tool_path: str) -> ValidationResult:
        """Validate radare2 installation.

        Args:
            tool_path: Path to the radare2 executable.

        Returns:
            Dictionary containing validation results with keys 'valid', 'version',
            'capabilities', and 'issues'.

        """
        validation: ValidationResult = {
            "valid": False,
            "version": None,
            "capabilities": [],
            "issues": [],
        }

        try:
            result = subprocess.run(
                [tool_path, "-v"],
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )

            if result.returncode == 0:
                version_text = result.stdout
                if version_match := re.search(r"radare2\s+(\d+\.\d+\.\d+)", version_text):
                    validation["version"] = version_match[1]

                if "r2pm" in version_text:
                    validation["capabilities"].append("package_manager")

                validation["capabilities"].extend(
                    [
                        "disassembly",
                        "debugging",
                        "binary_analysis",
                    ],
                )

                validation["valid"] = True
            else:
                validation["issues"].append(f"Tool execution failed: {result.stderr}")

        except subprocess.TimeoutExpired as e:
            logger.error("Subprocess timeout in tool_discovery: %s", e)
            validation["issues"].append("Tool validation timed out")
        except Exception as e:
            logger.error("Exception in tool_discovery: %s", e)
            validation["issues"].append(f"Validation error: {e}")

        return validation

    @staticmethod
    def validate_python(tool_path: str) -> ValidationResult:
        """Validate Python installation.

        Args:
            tool_path: Path to the Python executable.

        Returns:
            Dictionary containing validation results with keys 'valid', 'version',
            'capabilities', and 'issues'.

        """
        validation: ValidationResult = {
            "valid": False,
            "version": None,
            "capabilities": [],
            "issues": [],
        }

        try:
            result = subprocess.run(
                [tool_path, "--version"],
                check=False,
                capture_output=True,
                text=True,
                timeout=5,
            )

            if result.returncode == 0:
                version_text = result.stdout or result.stderr
                if version_match := re.search(r"Python\s+(\d+\.\d+\.\d+)", version_text):
                    version = version_match[1]
                    validation["version"] = version

                    major, minor = map(int, version.split(".")[:2])
                    if major >= 3 and minor >= 8:
                        validation["capabilities"].append("compatible")
                    else:
                        validation["issues"].append(f"Python {version} may not be compatible (need 3.8+)")

                validation["valid"] = True
            else:
                validation["issues"].append("Python version check failed")

        except Exception as e:
            logger.error("Exception in tool_discovery: %s", e)
            validation["issues"].append(f"Validation error: {e}")

        return validation

    @staticmethod
    def validate_frida(tool_path: str) -> ValidationResult:
        """Validate Frida installation.

        Args:
            tool_path: Path to the Frida executable.

        Returns:
            Dictionary containing validation results with keys 'valid', 'version',
            'capabilities', and 'issues'.

        """
        validation: ValidationResult = {
            "valid": False,
            "version": None,
            "capabilities": [],
            "issues": [],
        }

        try:
            result = subprocess.run(
                [tool_path, "--version"],
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )

            if result.returncode == 0:
                version_text = result.stdout
                if version_match := re.search(r"(\d+\.\d+\.\d+)", version_text):
                    validation["version"] = version_match[1]

                validation["capabilities"].extend(
                    [
                        "dynamic_instrumentation",
                        "javascript_injection",
                        "process_hooking",
                    ],
                )

                validation["valid"] = True
            else:
                validation["issues"].append("Frida execution failed")

        except Exception as e:
            logger.error("Exception in tool_discovery: %s", e)
            validation["issues"].append(f"Validation error: {e}")

        return validation

    @staticmethod
    def validate_qemu(tool_path: str) -> ValidationResult:
        """Validate QEMU installation.

        Args:
            tool_path: Path to the QEMU executable.

        Returns:
            Dictionary containing validation results with keys 'valid', 'version',
            'capabilities', and 'issues'.

        """
        validation: ValidationResult = {
            "valid": False,
            "version": None,
            "capabilities": [],
            "issues": [],
        }

        try:
            result = subprocess.run(
                [tool_path, "--version"],
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )

            if result.returncode == 0:
                version_text = result.stdout
                if version_match := re.search(r"QEMU emulator version\s+(\d+\.\d+\.\d+)", version_text):
                    validation["version"] = version_match[1]

                if "x86_64" in tool_path:
                    validation["capabilities"].append("x86_64")
                if "i386" in tool_path:
                    validation["capabilities"].append("i386")

                validation["capabilities"].extend(
                    [
                        "emulation",
                        "sandboxing",
                    ],
                )

                validation["valid"] = True
            else:
                validation["issues"].append("QEMU execution failed")

        except Exception as e:
            logger.error("Exception in tool_discovery: %s", e)
            validation["issues"].append(f"Validation error: {e}")

        return validation

    @staticmethod
    def validate_nasm(tool_path: str) -> ValidationResult:
        """Validate NASM (Netwide Assembler) installation.

        Args:
            tool_path: Path to the NASM executable.

        Returns:
            Dictionary containing validation results with keys 'valid', 'version',
            'capabilities', and 'issues'.

        """
        validation: ValidationResult = {
            "valid": False,
            "version": None,
            "capabilities": [],
            "issues": [],
        }

        try:
            result = subprocess.run(
                [tool_path, "-v"],
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )

            if result.returncode == 0:
                version_text = result.stdout
                if version_match := re.search(r"NASM version\s+(\d+\.\d+(?:\.\d+)?)", version_text):
                    validation["version"] = version_match[1]

                validation["capabilities"].extend(
                    [
                        "assembly_compilation",
                        "x86_assembly",
                        "x64_assembly",
                        "multiple_formats",
                        "macro_support",
                    ],
                )

                validation["valid"] = True
            else:
                validation["issues"].append(f"NASM execution failed: {result.stderr}")

        except subprocess.TimeoutExpired:
            validation["issues"].append("NASM validation timed out")
        except Exception as e:
            logger.error("Exception in tool_discovery: %s", e)
            validation["issues"].append(f"Validation error: {e}")

        return validation

    @staticmethod
    def validate_masm(tool_path: str) -> ValidationResult:
        """Validate MASM (Microsoft Macro Assembler) installation.

        Args:
            tool_path: Path to the MASM executable.

        Returns:
            Dictionary containing validation results with keys 'valid', 'version',
            'capabilities', and 'issues'.

        """
        validation: ValidationResult = {
            "valid": False,
            "version": None,
            "capabilities": [],
            "issues": [],
        }

        try:
            result = subprocess.run(
                [tool_path, "/?"],
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )

            version_text = result.stdout or result.stderr
            if "Microsoft (R) Macro Assembler" in version_text:
                if version_match := re.search(r"Version\s+(\d+\.\d+\.\d+(?:\.\d+)?)", version_text):
                    validation["version"] = version_match[1]

                validation["capabilities"].extend(
                    [
                        "assembly_compilation",
                        "x86_assembly",
                        "x64_assembly",
                        "microsoft_formats",
                        "macro_support",
                        "masm_syntax",
                    ],
                )

                validation["valid"] = True
            else:
                validation["issues"].append("MASM signature not found in output")

        except subprocess.TimeoutExpired:
            validation["issues"].append("MASM validation timed out")
        except Exception as e:
            logger.error("Exception in tool_discovery: %s", e)
            validation["issues"].append(f"Validation error: {e}")

        return validation

    @staticmethod
    def validate_accesschk(tool_path: str) -> ValidationResult:
        """Validate SysInternals AccessChk installation.

        Args:
            tool_path: Path to the AccessChk executable.

        Returns:
            Dictionary containing validation results with keys 'valid', 'version',
            'capabilities', and 'issues'.

        """
        validation: ValidationResult = {
            "valid": False,
            "version": None,
            "capabilities": [],
            "issues": [],
        }

        try:
            result = subprocess.run(
                [tool_path, "-accepteula", "-?"],
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )

            version_text = result.stdout or result.stderr
            if "Sysinternals" in version_text and ("AccessChk" in version_text or "accesschk" in version_text.lower()):
                if version_match := re.search(r"(?:v|Version\s+)?(\d+\.\d+)", version_text):
                    validation["version"] = version_match[1]

                validation["capabilities"].extend(
                    [
                        "privilege_escalation_analysis",
                        "permission_enumeration",
                        "access_rights_checking",
                        "file_permissions",
                        "registry_permissions",
                        "service_permissions",
                        "process_permissions",
                        "token_analysis",
                    ],
                )

                validation["valid"] = True
            else:
                validation["issues"].append("AccessChk signature not found in output")

        except subprocess.TimeoutExpired:
            validation["issues"].append("AccessChk validation timed out")
        except Exception as e:
            logger.error("Exception in tool_discovery: %s", e)
            validation["issues"].append(f"Validation error: {e}")

        return validation


class AdvancedToolDiscovery:
    """Advanced tool discovery with intelligent search and validation."""

    validators: dict[str, Callable[[str], ValidationResult]]
    discovered_tools: dict[str, dict[str, Any]]
    manual_overrides: dict[str, str]
    search_cache: dict[str, dict[str, Any]]

    def __init__(self) -> None:
        """Initialize tool discovery system."""
        self.validators = {
            "ghidra": ToolValidator.validate_ghidra,
            "radare2": ToolValidator.validate_radare2,
            "python3": ToolValidator.validate_python,
            "python": ToolValidator.validate_python,
            "frida": ToolValidator.validate_frida,
            "qemu-system-x86_64": ToolValidator.validate_qemu,
            "qemu-system-i386": ToolValidator.validate_qemu,
            "nasm": ToolValidator.validate_nasm,
            "masm": ToolValidator.validate_masm,
            "ml": ToolValidator.validate_masm,
            "ml64": ToolValidator.validate_masm,
            "accesschk": ToolValidator.validate_accesschk,
            "accesschk64": ToolValidator.validate_accesschk,
        }

        from intellicrack.core.config_manager import get_config

        self.config = get_config()

        discovered_raw = self.config.get("tools.discovered", {})
        self.discovered_tools = dict(discovered_raw) if isinstance(discovered_raw, dict) else {}

        overrides_raw = self.config.get("tools.manual_overrides", {})
        self.manual_overrides = dict(overrides_raw) if isinstance(overrides_raw, dict) else {}

        self.search_cache = {}

    def discover_all_tools(self) -> dict[str, Any]:
        """Discover all supported tools.

        Returns:
            Dictionary mapping tool names to discovery results containing availability,
            path, version, and capabilities information.

        """
        logger.info("Starting comprehensive tool discovery")

        if HAS_TERMINAL_MANAGER:
            try:
                terminal_manager = get_terminal_manager()
                terminal_manager.log_terminal_message("Starting comprehensive tool discovery")
            except Exception as e:
                logger.warning("Could not log to terminal manager: %s", e)

        tool_configs: dict[str, dict[str, Any]] = {
            "ghidra": {
                "executables": ["ghidra", "ghidraRun", "ghidraRun.bat"],
                "search_strategy": "installation_based",
                "required": False,
                "priority": "high",
            },
            "radare2": {
                "executables": ["r2", "radare2"],
                "search_strategy": "path_based",
                "required": False,
                "priority": "high",
            },
            "python3": {
                "executables": ["python3", "python"],
                "search_strategy": "path_based",
                "required": True,
                "priority": "critical",
            },
            "frida": {
                "executables": ["frida"],
                "search_strategy": "path_based",
                "required": False,
                "priority": "medium",
            },
            "qemu": {
                "executables": ["qemu-system-x86_64", "qemu-system-i386"],
                "search_strategy": "installation_based",
                "required": False,
                "priority": "low",
            },
            "nasm": {
                "executables": ["nasm", "nasm.exe"],
                "search_strategy": "installation_based",
                "required": False,
                "priority": "medium",
            },
            "masm": {
                "executables": ["ml", "ml.exe", "ml64", "ml64.exe"],
                "search_strategy": "installation_based",
                "required": False,
                "priority": "medium",
            },
            "accesschk": {
                "executables": ["accesschk", "accesschk.exe", "accesschk64.exe"],
                "search_strategy": "installation_based",
                "required": False,
                "priority": "medium",
            },
        }

        results: dict[str, Any] = {}

        for tool_name, config in tool_configs.items():
            try:
                logger.debug("Discovering %s", tool_name)
                tool_info = self.discover_tool(tool_name, config)
                results[tool_name] = tool_info

                if tool_info["available"]:
                    logger.info("OK %s found: %s", tool_name, tool_info['path'])
                    if HAS_TERMINAL_MANAGER:
                        try:
                            terminal_manager = get_terminal_manager()
                            terminal_manager.log_terminal_message(f"OK {tool_name} found: {tool_info['path']}")
                        except Exception as e:
                            logger.debug("Could not log to terminal manager: %s", e)
                else:
                    level = logging.WARNING if config["required"] else logging.INFO
                    logger.log(level, "FAIL %s not found", tool_name)
                    if HAS_TERMINAL_MANAGER:
                        try:
                            terminal_manager = get_terminal_manager()
                            terminal_manager.log_terminal_message(f"FAIL {tool_name} not found", level="warning")
                        except Exception as e:
                            logger.debug("Could not log to terminal manager: %s", e)

            except Exception as e:
                logger.error("Error discovering %s: %s", tool_name, e)
                if HAS_TERMINAL_MANAGER:
                    try:
                        terminal_manager = get_terminal_manager()
                        terminal_manager.log_terminal_message(f"Error discovering {tool_name}: {e}", level="error")
                    except Exception as e2:
                        logger.debug("Could not log to terminal manager: %s", e2)
                results[tool_name] = {
                    "available": False,
                    "error": str(e),
                    "discovery_time": time.time(),
                }

        self.discovered_tools = results
        self.config.set("tools.discovered", results)

        self.config.set("tools.last_discovery", time.time())

        if HAS_TERMINAL_MANAGER:
            try:
                terminal_manager = get_terminal_manager()
                terminal_manager.log_terminal_message(
                    f"Tool discovery completed. Found {len([t for t in results.values() if t.get('available')])} tools out of {len(results)}",
                )
            except Exception as e:
                logger.debug("Could not log to terminal manager: %s", e)

        return results

    def discover_tool(self, tool_name: str, config: dict[str, Any]) -> dict[str, Any]:
        """Discover a specific tool with comprehensive search.

        Args:
            tool_name: Name of the tool to discover.
            config: Configuration dictionary with executables and search strategy.

        Returns:
            Dictionary containing tool information with availability, path, version,
            discovery method, and other metadata.

        """
        discovery_start = time.time()

        if tool_name in self.manual_overrides:
            manual_path = self.manual_overrides[tool_name]
            if manual_path and os.path.exists(manual_path):
                logger.info("Using manual override for %s: %s", tool_name, manual_path)
                override_info = self._validate_and_populate(manual_path, tool_name)
                override_info["discovery_method"] = "manual_override"
                override_info["discovery_time"] = discovery_start
                override_info["discovery_duration"] = time.time() - discovery_start
                return override_info

        cached_tools_raw = self.config.get("tools.discovered", {})
        cached_tools: dict[str, Any] = dict(cached_tools_raw) if isinstance(cached_tools_raw, dict) else {}
        if tool_name in cached_tools:
            cached_result = cached_tools[tool_name]
            if isinstance(cached_result, dict):
                disc_time = cached_result.get("discovery_time")
                if disc_time is not None and time.time() - float(disc_time) < 3600:
                    logger.debug("Using cached result for %s", tool_name)
                    return dict(cached_result)

        tool_info: dict[str, Any] = {
            "available": False,
            "path": None,
            "version": None,
            "validation": {},
            "discovery_method": None,
            "discovery_time": discovery_start,
            "search_locations": [],
            "capabilities": [],
        }

        executables: list[str] = config.get("executables", [])
        if found_path := self._search_in_path(executables):
            tool_info |= self._validate_and_populate(found_path, tool_name)
            tool_info["discovery_method"] = "PATH"

        if not tool_info["available"] and config["search_strategy"] == "installation_based":
            if found_path := self._search_installations(tool_name, executables):
                tool_info.update(self._validate_and_populate(found_path, tool_name))
                tool_info["discovery_method"] = "installation_search"

        if not tool_info["available"]:
            if found_path := self._search_common_locations(tool_name, executables):
                tool_info.update(self._validate_and_populate(found_path, tool_name))
                tool_info["discovery_method"] = "common_locations"

        if not tool_info["available"] and sys.platform == "win32":
            if found_path := self._search_windows_registry(tool_name):
                tool_info.update(self._validate_and_populate(found_path, tool_name))
                tool_info["discovery_method"] = "registry"

        tool_info["discovery_duration"] = time.time() - discovery_start

        self.discovered_tools[tool_name] = tool_info
        self.config.set(f"tools.discovered.{tool_name}", tool_info)

        return tool_info

    def _search_in_path(self, executables: list[str]) -> str | None:
        """Search for tool in PATH.

        Args:
            executables: List of executable names to search for.

        Returns:
            Full path to the executable if found, None otherwise.

        """
        for executable in executables:
            if path := shutil.which(executable):
                return path
        return None

    def _search_installations(self, tool_name: str, executables: list[str]) -> str | None:
        """Search in typical installation directories.

        Args:
            tool_name: Name of the tool to search for.
            executables: List of executable names to search for.

        Returns:
            Full path to the executable if found, None otherwise.

        """
        search_paths = self._get_installation_paths(tool_name)

        for search_path in search_paths:
            if not os.path.exists(search_path):
                continue

            for root, dirs, _files in os.walk(search_path):
                for executable in executables:
                    potential_path = os.path.join(root, executable)
                    if os.path.exists(potential_path) and os.access(potential_path, os.X_OK):
                        return potential_path

                if len(Path(root).parts) - len(Path(search_path).parts) > 3:
                    dirs.clear()

        return None

    def _search_common_locations(self, tool_name: str, executables: list[str]) -> str | None:
        """Search in common installation locations.

        Args:
            tool_name: Name of the tool to search for.
            executables: List of executable names to search for.

        Returns:
            Full path to the executable if found, None otherwise.

        """
        logger.debug("Searching common locations for tool: %s with executables: %s", tool_name, executables)
        common_paths: list[str] = []

        if sys.platform == "win32":
            common_paths.extend(
                [
                    os.environ.get("PROGRAMFILES", ""),
                    os.environ.get("PROGRAMFILES(X86)", ""),
                    os.environ.get("LOCALAPPDATA", ""),
                    "C:\\Tools",
                    "C:\\",
                    os.path.expanduser("~\\AppData\\Local"),
                    os.path.expanduser("~\\Documents"),
                ],
            )
        else:
            common_paths.extend(
                [
                    "/usr/bin",
                    "/usr/local/bin",
                    "/opt",
                    "/usr/share",
                    os.path.expanduser("~/bin"),
                    os.path.expanduser("~/.local/bin"),
                    os.path.expanduser("~/Tools"),
                ],
            )

        for base_path in common_paths:
            if not base_path or not os.path.exists(base_path):
                continue

            for executable in executables:
                potential_path = os.path.join(base_path, executable)
                if os.path.exists(potential_path):
                    return potential_path

        return None

    def _search_windows_registry(self, tool_name: str) -> str | None:
        """Search Windows registry for tool installations.

        Args:
            tool_name: Name of the tool to search for.

        Returns:
            Installation path from Windows registry if found, None otherwise.

        """
        if sys.platform != "win32":
            return None

        try:
            import winreg

            registry_paths = [
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
            ]

            for registry_path in registry_paths:
                try:
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path) as key:
                        for i in range(winreg.QueryInfoKey(key)[0]):
                            try:
                                subkey_name = winreg.EnumKey(key, i)
                                with winreg.OpenKey(key, subkey_name) as subkey:
                                    try:
                                        display_name_tuple = winreg.QueryValueEx(subkey, "DisplayName")
                                        display_name = str(display_name_tuple[0])
                                        if tool_name.lower() in display_name.lower():
                                            install_location_tuple = winreg.QueryValueEx(subkey, "InstallLocation")
                                            install_location = str(install_location_tuple[0])
                                            if install_location and os.path.exists(install_location):
                                                return install_location
                                    except FileNotFoundError as e:
                                        logger.error("File not found in tool_discovery: %s", e)
                                        continue
                            except OSError as e:
                                logger.error("OS error in tool_discovery: %s", e)
                                continue
                except OSError as e:
                    logger.error("OS error in tool_discovery: %s", e)
                    continue

        except ImportError as e:
            logger.error("Import error in tool_discovery: %s", e)
        except Exception as e:
            logger.debug("Registry search failed: %s", e)

        return None

    def _get_installation_paths(self, tool_name: str) -> list[str]:
        """Get tool-specific installation search paths.

        Args:
            tool_name: Name of the tool to get paths for.

        Returns:
            List of paths to search for tool installations.

        """
        paths: list[str] = []

        if tool_name == "accesschk":
            if sys.platform == "win32":
                paths.extend(
                    [
                        "C:\\SysinternalsSuite",
                        "C:\\Tools\\SysinternalsSuite",
                        "C:\\Tools\\Sysinternals",
                        "C:\\Program Files\\SysinternalsSuite",
                        "C:\\Program Files (x86)\\SysinternalsSuite",
                        "C:\\Windows\\System32",
                        "C:\\Tools\\AccessChk",
                        "C:\\AccessChk",
                        os.path.expanduser("~\\Desktop"),
                        os.path.expanduser("~\\Downloads"),
                        os.path.expanduser("~\\Documents\\Tools"),
                        os.path.expanduser("~\\AppData\\Local\\Microsoft\\WinGet\\Packages"),
                    ],
                )

        elif tool_name == "ghidra":
            if sys.platform == "win32":
                paths.extend(
                    [
                        "C:\\Program Files\\Ghidra",
                        "C:\\ghidra",
                        "C:\\Tools\\ghidra",
                        os.path.expanduser("~\\ghidra"),
                    ],
                )
            else:
                paths.extend(
                    [
                        "/opt/ghidra",
                        "/usr/local/ghidra",
                        "/usr/share/ghidra",
                        os.path.expanduser("~/ghidra"),
                        "/Applications/ghidra",
                    ],
                )

        elif tool_name == "masm":
            if sys.platform == "win32":
                vs_paths: list[str] = []
                for vs_version in ["2022", "2019", "2017", "BuildTools"]:
                    vs_paths.extend(
                        [
                            f"C:\\Program Files\\Microsoft Visual Studio\\{vs_version}\\Community\\VC\\Tools\\MSVC",
                            f"C:\\Program Files\\Microsoft Visual Studio\\{vs_version}\\Professional\\VC\\Tools\\MSVC",
                            f"C:\\Program Files\\Microsoft Visual Studio\\{vs_version}\\Enterprise\\VC\\Tools\\MSVC",
                            f"C:\\Program Files (x86)\\Microsoft Visual Studio\\{vs_version}\\Community\\VC\\Tools\\MSVC",
                            f"C:\\Program Files (x86)\\Microsoft Visual Studio\\{vs_version}\\Professional\\VC\\Tools\\MSVC",
                            f"C:\\Program Files (x86)\\Microsoft Visual Studio\\{vs_version}\\Enterprise\\VC\\Tools\\MSVC",
                        ],
                    )

                sdk_paths: list[str] = []
                for version in ["10", "8.1", "8.0"]:
                    sdk_paths.extend(
                        [
                            f"C:\\Program Files (x86)\\Windows Kits\\{version}\\bin",
                            f"C:\\Program Files\\Windows Kits\\{version}\\bin",
                        ],
                    )

                paths.extend(
                    vs_paths
                    + sdk_paths
                    + [
                        "C:\\MASM",
                        "C:\\Tools\\masm",
                        "C:\\Program Files\\MASM",
                        "C:\\Program Files (x86)\\MASM",
                    ],
                )

        elif tool_name == "nasm":
            if sys.platform == "win32":
                paths.extend(
                    [
                        os.path.join(
                            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                            "tools",
                            "NASM",
                        ),
                        "C:\\Program Files\\NASM",
                        "C:\\Program Files (x86)\\NASM",
                        "C:\\NASM",
                        "C:\\Tools\\nasm",
                        os.path.expanduser(
                            "~\\AppData\\Local\\Microsoft\\WinGet\\Packages\\NASM.NASM_Microsoft.Winget.Source_8wekyb3d8bbwe",
                        ),
                        "C:\\Users\\%USERNAME%\\AppData\\Local\\Microsoft\\WinGet\\Packages\\NASM.NASM_Microsoft.Winget.Source_8wekyb3d8bbwe",
                    ],
                )
            else:
                paths.extend(
                    [
                        "/usr/bin",
                        "/usr/local/bin",
                        "/opt/nasm",
                    ],
                )

        elif tool_name == "qemu":
            if sys.platform == "win32":
                paths.extend(
                    [
                        "C:\\Program Files\\qemu",
                        "C:\\qemu",
                    ],
                )
            else:
                paths.extend(
                    [
                        "/usr/bin",
                        "/usr/local/bin",
                        "/opt/qemu",
                    ],
                )

        return paths

    def _validate_and_populate(self, tool_path: str, tool_name: str) -> dict[str, Any]:
        """Validate tool and populate information.

        Args:
            tool_path: Path to the tool executable.
            tool_name: Name of the tool being validated.

        Returns:
            Dictionary containing validation results and tool information.

        """
        result: dict[str, Any] = {
            "available": False,
            "path": tool_path,
            "validation": {},
        }

        if validator := next(
            (
                validator_func
                for validator_name, validator_func in self.validators.items()
                if validator_name in tool_name or tool_name in validator_name
            ),
            None,
        ):
            validation_result = validator(tool_path)
            result["validation"] = validation_result
            result["available"] = validation_result["valid"]
            result["version"] = validation_result.get("version")
            result["capabilities"] = validation_result.get("capabilities", [])
        elif os.path.exists(tool_path) and os.access(tool_path, os.X_OK):
            result["available"] = True

        return result

    def refresh_discovery(self) -> dict[str, Any]:
        """Refresh tool discovery by clearing cache and re-scanning.

        Returns:
            Dictionary with discovery results for all tools.

        """
        logger.info("Refreshing tool discovery")
        self.config.set("tools.discovered", {})
        self.config.set("tools.last_discovery", None)
        self.discovered_tools = {}
        return self.discover_all_tools()

    def get_tool_capabilities(self, tool_name: str) -> list[str]:
        """Get capabilities of a discovered tool.

        Args:
            tool_name: Name of the tool.

        Returns:
            List of capability strings for the tool.

        """
        if tool_name in self.discovered_tools:
            caps = self.discovered_tools[tool_name].get("capabilities", [])
            if isinstance(caps, list):
                return list(caps)
            return []
        return []

    def is_tool_compatible(self, tool_name: str, required_capabilities: list[str]) -> bool:
        """Check if tool has required capabilities.

        Args:
            tool_name: Name of the tool to check.
            required_capabilities: List of required capability strings.

        Returns:
            True if tool has all required capabilities, False otherwise.

        """
        tool_capabilities = self.get_tool_capabilities(tool_name)
        return all(cap in tool_capabilities for cap in required_capabilities)

    def set_manual_override(self, tool_name: str, tool_path: str) -> bool:
        """Set a manual override for a tool path.

        Args:
            tool_name: Name of the tool
            tool_path: Manual path to the tool executable

        Returns:
            True if override was set successfully, False otherwise

        """
        if not os.path.exists(tool_path):
            logger.error("Cannot set manual override: path %s does not exist", tool_path)
            return False

        if not os.access(tool_path, os.X_OK):
            logger.warning("Path %s may not be executable", tool_path)

        self.manual_overrides[tool_name] = tool_path
        self.config.set(f"tools.manual_overrides.{tool_name}", tool_path)

        logger.info("Set manual override for %s: %s", tool_name, tool_path)

        if tool_name in self.discovered_tools:
            del self.discovered_tools[tool_name]
            self.config.set(f"tools.discovered.{tool_name}", None)

        return True

    def clear_manual_override(self, tool_name: str) -> bool:
        """Clear a manual override for a tool.

        Args:
            tool_name: Name of the tool

        Returns:
            True if override was cleared, False if no override existed

        """
        if tool_name not in self.manual_overrides:
            return False

        del self.manual_overrides[tool_name]
        self.config.set(f"tools.manual_overrides.{tool_name}", None)

        logger.info("Cleared manual override for %s", tool_name)

        if tool_name in self.discovered_tools:
            del self.discovered_tools[tool_name]
            self.config.set(f"tools.discovered.{tool_name}", None)

        return True

    def get_manual_overrides(self) -> dict[str, str]:
        """Get all manual tool path overrides.

        Returns:
            Dictionary of tool_name -> manual_path mappings

        """
        return dict(self.manual_overrides)

    def get_tool_path(self, tool_name: str) -> str | None:
        """Get the path for a tool, checking manual overrides first.

        Args:
            tool_name: Name of the tool

        Returns:
            Path to the tool executable, or None if not found

        """
        if tool_name in self.manual_overrides:
            return self.manual_overrides[tool_name]

        if tool_name in self.discovered_tools:
            tool_info = self.discovered_tools[tool_name]
            if tool_info.get("available"):
                path_val = tool_info.get("path")
                if isinstance(path_val, str):
                    return path_val

        return None

    def health_check_tool(self, tool_name: str) -> dict[str, Any]:
        """Perform a health check on a specific tool.

        Args:
            tool_name: Name of the tool to check

        Returns:
            Dictionary with health check results

        """
        health_status: dict[str, Any] = {
            "tool_name": tool_name,
            "healthy": False,
            "available": False,
            "executable": False,
            "version_valid": False,
            "issues": [],
            "timestamp": time.time(),
        }

        issues_list: list[str] = health_status["issues"]

        tool_path = self.get_tool_path(tool_name)
        if not tool_path:
            issues_list.append("Tool path not found")
            return health_status

        if not os.path.exists(tool_path):
            issues_list.append(f"Path does not exist: {tool_path}")
            return health_status

        health_status["available"] = True

        if not os.access(tool_path, os.X_OK):
            issues_list.append("File is not executable")
        else:
            health_status["executable"] = True

        validator = next(
            (
                validator_func
                for validator_name, validator_func in self.validators.items()
                if validator_name in tool_name or tool_name in validator_name
            ),
            None,
        )
        if validator:
            validation_result = validator(tool_path)
            if validation_result["valid"]:
                health_status["version_valid"] = True
                health_status["version"] = validation_result.get("version")
                health_status["capabilities"] = validation_result.get("capabilities", [])
            else:
                val_issues = validation_result.get("issues", [])
                if isinstance(val_issues, list):
                    issues_list.extend(val_issues)

        health_status["healthy"] = (
            health_status["available"] and health_status["executable"] and (health_status["version_valid"] or not validator)
        )

        return health_status

    def health_check_all_tools(self) -> dict[str, dict[str, Any]]:
        """Perform health checks on all configured tools.

        Returns:
            Dictionary mapping tool names to health check results

        """
        results: dict[str, dict[str, Any]] = {tool_name: self.health_check_tool(tool_name) for tool_name in self.discovered_tools}
        for tool_name in self.manual_overrides:
            if tool_name not in results:
                results[tool_name] = self.health_check_tool(tool_name)

        if HAS_TERMINAL_MANAGER:
            try:
                terminal_manager = get_terminal_manager()
                healthy_count = len([tool_name for tool_name, status in results.items() if status.get("healthy", False)])
                total_count = len(results)
                terminal_manager.log_terminal_message(f"Health check completed: {healthy_count}/{total_count} tools healthy")

                for tool_name, status in results.items():
                    if not status.get("healthy", False):
                        issues = status.get("issues", [])
                        if isinstance(issues, list) and issues:
                            terminal_manager.log_terminal_message(
                                f"Unhealthy tool: {tool_name} - {', '.join(str(i) for i in issues)}",
                                level="warning",
                            )
            except Exception as e:
                logger.warning("Could not log health check to terminal manager: %s", e)

        self.config.set("tools.last_health_check", results)
        self.config.set("tools.last_health_check_time", time.time())

        return results

    def get_healthy_tools(self) -> list[str]:
        """Get list of tools that passed health checks.

        Returns:
            List of healthy tool names

        """
        health_results = self.health_check_all_tools()
        return [tool_name for tool_name, status in health_results.items() if status.get("healthy", False)]

    def discover_tool_with_fallbacks(self, tool_name: str, config: dict[str, Any]) -> dict[str, Any]:
        """Enhanced tool discovery with comprehensive fallback mechanisms.

        Args:
            tool_name: Name of the tool to discover.
            config: Configuration dictionary with executables and search strategy.

        Returns:
            Dictionary containing tool information with fallback attempts included.

        """
        logger.info("Starting enhanced discovery for %s with fallbacks", tool_name)

        tool_info = self.discover_tool(tool_name, config)

        if tool_info.get("available"):
            return tool_info

        fallback_result = self._apply_fallback_strategies(tool_name, config)
        if fallback_result.get("available"):
            return fallback_result

        alternatives = self._get_tool_alternatives(tool_name)
        for alt_tool, alt_config in alternatives.items():
            logger.info("Trying alternative tool: %s for %s", alt_tool, tool_name)
            alt_result = self.discover_tool(alt_tool, alt_config)
            if alt_result.get("available"):
                alt_result["is_alternative"] = True
                alt_result["original_tool"] = tool_name
                alt_result["alternative_for"] = tool_name
                return alt_result

        return tool_info

    def _apply_fallback_strategies(self, tool_name: str, config: dict[str, Any]) -> dict[str, Any]:
        """Apply various fallback strategies for tool discovery.

        Args:
            tool_name: Name of the tool to discover.
            config: Configuration dictionary with executables and search strategy.

        Returns:
            Dictionary with discovery results from fallback strategies.

        """
        strategies: list[Callable[[str, dict[str, Any]], dict[str, Any] | None]] = [
            self._try_portable_versions,
            self._try_package_manager_paths,
            self._try_version_fallbacks,
            self._try_bundled_tools,
            self._try_container_tools,
        ]

        for strategy in strategies:
            try:
                result = strategy(tool_name, config)
                if result and result.get("available"):
                    logger.info("Fallback strategy '%s' succeeded for %s", strategy.__name__, tool_name)
                    return result
            except Exception as e:
                logger.debug("Fallback strategy '%s' failed: %s", strategy.__name__, e)
                continue

        return {"available": False, "path": None}

    def _try_portable_versions(self, tool_name: str, config: dict[str, Any]) -> dict[str, Any] | None:
        """Try to find portable versions of tools.

        Args:
            tool_name: Name of the tool to discover.
            config: Configuration dictionary with executables and search strategy.

        Returns:
            Dictionary with discovery results if portable version found, None otherwise.

        """
        portable_paths = [
            Path.home() / "portable_tools" / tool_name,
            Path.cwd() / "tools" / tool_name,
            Path.cwd() / "portable" / tool_name,
            Path(__file__).parent.parent.parent / "tools" / tool_name,
        ]

        executables: list[str] = config.get("executables", [tool_name])
        for portable_dir in portable_paths:
            if portable_dir.exists():
                for executable in executables:
                    for ext in ["", ".exe", ".bat"]:
                        exe_path = portable_dir / f"{executable}{ext}"
                        if exe_path.exists() and os.access(exe_path, os.X_OK):
                            return self._validate_and_populate(str(exe_path), tool_name)

        return None

    def _try_package_manager_paths(self, tool_name: str, config: dict[str, Any]) -> dict[str, Any] | None:
        """Try package manager installation paths.

        Args:
            tool_name: Name of the tool to discover.
            config: Configuration dictionary with executables and search strategy.

        Returns:
            Dictionary with discovery results if package manager version found, None otherwise.

        """
        pm_paths: list[Path] = []

        if sys.platform == "win32":
            pm_paths.extend(
                [
                    Path.home() / "scoop" / "apps" / tool_name,
                    Path("C:/ProgramData/chocolatey/lib") / tool_name,
                    Path("C:/tools") / tool_name,
                    Path.home() / "AppData/Local/Programs" / tool_name,
                ],
            )

        elif sys.platform.startswith("linux"):
            pm_paths.extend(
                [
                    Path("/opt") / tool_name,
                    Path("/usr/local/bin"),
                    Path("/snap/bin"),
                    Path.home() / ".local/bin",
                ],
            )

        elif sys.platform == "darwin":
            pm_paths.extend(
                [
                    Path("/usr/local/bin"),
                    Path("/opt/homebrew/bin"),
                    Path("/Applications") / f"{tool_name}.app/Contents/MacOS",
                ],
            )

        executables: list[str] = config.get("executables", [tool_name])
        for pm_path in pm_paths:
            if pm_path.exists():
                for executable in executables:
                    for ext in ["", ".exe", ".bat"]:
                        exe_path = pm_path / f"{executable}{ext}"
                        if exe_path.exists() and os.access(exe_path, os.X_OK):
                            return self._validate_and_populate(str(exe_path), tool_name)

        return None

    def _try_version_fallbacks(self, tool_name: str, config: dict[str, Any]) -> dict[str, Any] | None:
        """Try different versions of the same tool.

        Args:
            tool_name: Name of the tool to discover.
            config: Configuration dictionary with executables and search strategy.

        Returns:
            Dictionary with discovery results if alternative version found, None otherwise.

        """
        _ = config
        version_patterns = [
            f"{tool_name}3",
            f"{tool_name}2",
            f"{tool_name}-dev",
            f"{tool_name}-stable",
            f"{tool_name}-latest",
        ]

        for version_name in version_patterns:
            if path := shutil.which(version_name):
                result = self._validate_and_populate(path, tool_name)
                if result.get("available"):
                    result["version_fallback"] = version_name
                    return result

        return None

    def _try_bundled_tools(self, tool_name: str, config: dict[str, Any]) -> dict[str, Any] | None:
        """Try tools bundled with Intellicrack.

        Args:
            tool_name: Name of the tool to discover.
            config: Configuration dictionary with executables and search strategy.

        Returns:
            Dictionary with discovery results if bundled version found, None otherwise.

        """
        bundled_dir = Path(__file__).parent.parent.parent / "bundled_tools" / tool_name

        executables: list[str] = config.get("executables", [tool_name])
        if bundled_dir.exists():
            for executable in executables:
                for ext in ["", ".exe", ".bat"]:
                    exe_path = bundled_dir / f"{executable}{ext}"
                    if exe_path.exists() and os.access(exe_path, os.X_OK):
                        result = self._validate_and_populate(str(exe_path), tool_name)
                        if result.get("available"):
                            result["bundled"] = True
                            return result

        return None

    def _try_container_tools(self, tool_name: str, config: dict[str, Any]) -> dict[str, Any] | None:
        """Try containerized versions of tools.

        Args:
            tool_name: Name of the tool to discover.
            config: Configuration dictionary with executables and search strategy.

        Returns:
            Dictionary with discovery results if containerized version found, None otherwise.

        """
        _ = tool_name
        _ = config
        return None

    def _get_tool_alternatives(self, tool_name: str) -> dict[str, dict[str, Any]]:
        """Get alternative tools for a given tool.

        Args:
            tool_name: Name of the tool to get alternatives for.

        Returns:
            Dictionary mapping alternative tool names to their configurations.

        """
        alternatives: dict[str, dict[str, dict[str, Any]]] = {
            "ghidra": {
                "cutter": {
                    "executables": ["cutter", "Cutter"],
                    "search_strategy": "path_based",
                    "description": "Cutter/Rizin GUI alternative",
                },
            },
            "radare2": {
                "rizin": {
                    "executables": ["rz", "rizin"],
                    "search_strategy": "path_based",
                    "description": "Rizin fork of Radare2",
                },
                "objdump": {
                    "executables": ["objdump"],
                    "search_strategy": "path_based",
                    "description": "GNU objdump fallback",
                },
            },
            "python3": {
                "python": {
                    "executables": ["python"],
                    "search_strategy": "path_based",
                    "description": "Python 2/3 fallback",
                },
            },
            "frida": {
                "frida-tools": {
                    "executables": ["frida-ps", "frida-trace"],
                    "search_strategy": "path_based",
                    "description": "Frida tools package",
                },
            },
        }

        return alternatives.get(tool_name, {})

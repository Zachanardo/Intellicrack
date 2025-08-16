"""Advanced Tool Discovery System for Intellicrack

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
from pathlib import Path
from typing import Any

from intellicrack.core.config_manager import get_config

logger = logging.getLogger(__name__)


class ToolValidator:
    """Validates tool installations and capabilities."""

    @staticmethod
    def validate_ghidra(tool_path: str) -> dict[str, Any]:
        """Validate Ghidra installation."""
        validation = {
            "valid": False,
            "version": None,
            "capabilities": [],
            "issues": [],
        }

        try:
            # Check if it's actually Ghidra
            ghidra_dir = Path(tool_path).parent

            # Look for Ghidra-specific files
            ghidra_files = [
                "support/analyzeHeadless",
                "support/analyzeHeadless.bat",
                "Ghidra/application.properties",
            ]

            found_files = []
            for file_path in ghidra_files:
                full_path = ghidra_dir / file_path
                if full_path.exists():
                    found_files.append(file_path)

            if not found_files:
                validation["issues"].append("Ghidra installation files not found")
                return validation

            # Try to get version
            try:
                result = subprocess.run(  # nosec S603 - Legitimate subprocess usage for security research and binary analysis  # noqa: S603
                    [tool_path, "--version"],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=15,
                )

                if result.returncode == 0:
                    version_text = result.stdout or result.stderr
                    version_match = re.search(r"(\d+\.\d+(?:\.\d+)?)", version_text)
                    if version_match:
                        validation["version"] = version_match.group(1)

            except Exception as e:
                logger.error("Exception in tool_discovery: %s", e)
                validation["issues"].append(f"Version check failed: {e}")

            # Check capabilities
            validation["capabilities"].extend(
                [
                    "decompilation",
                    "static_analysis",
                    "script_execution",
                ]
            )

            validation["valid"] = True

        except Exception as e:
            logger.error("Exception in tool_discovery: %s", e)
            validation["issues"].append(f"Validation error: {e}")

        return validation

    @staticmethod
    def validate_radare2(tool_path: str) -> dict[str, Any]:
        """Validate radare2 installation."""
        validation = {
            "valid": False,
            "version": None,
            "capabilities": [],
            "issues": [],
        }

        try:
            # Test basic functionality
            result = subprocess.run(  # nosec S603 - Legitimate subprocess usage for security research and binary analysis  # noqa: S603
                [tool_path, "-v"],
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )

            if result.returncode == 0:
                version_text = result.stdout
                version_match = re.search(r"radare2\s+(\d+\.\d+\.\d+)", version_text)
                if version_match:
                    validation["version"] = version_match.group(1)

                # Check for common plugins/capabilities
                if "r2pm" in version_text:
                    validation["capabilities"].append("package_manager")

                validation["capabilities"].extend(
                    [
                        "disassembly",
                        "debugging",
                        "binary_analysis",
                    ]
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
    def validate_python(tool_path: str) -> dict[str, Any]:
        """Validate Python installation."""
        validation = {
            "valid": False,
            "version": None,
            "capabilities": [],
            "issues": [],
        }

        try:
            result = subprocess.run(  # nosec S603 - Legitimate subprocess usage for security research and binary analysis  # noqa: S603
                [tool_path, "--version"],
                check=False,
                capture_output=True,
                text=True,
                timeout=5,
            )

            if result.returncode == 0:
                version_text = result.stdout or result.stderr
                version_match = re.search(r"Python\s+(\d+\.\d+\.\d+)", version_text)
                if version_match:
                    version = version_match.group(1)
                    validation["version"] = version

                    # Check version compatibility
                    major, minor = map(int, version.split(".")[:2])
                    if major >= 3 and minor >= 8:
                        validation["capabilities"].append("compatible")
                    else:
                        validation["issues"].append(
                            f"Python {version} may not be compatible (need 3.8+)"
                        )

                validation["valid"] = True
            else:
                validation["issues"].append("Python version check failed")

        except Exception as e:
            logger.error("Exception in tool_discovery: %s", e)
            validation["issues"].append(f"Validation error: {e}")

        return validation

    @staticmethod
    def validate_frida(tool_path: str) -> dict[str, Any]:
        """Validate Frida installation."""
        validation = {
            "valid": False,
            "version": None,
            "capabilities": [],
            "issues": [],
        }

        try:
            result = subprocess.run(  # nosec S603 - Legitimate subprocess usage for security research and binary analysis  # noqa: S603
                [tool_path, "--version"],
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )

            if result.returncode == 0:
                version_text = result.stdout
                version_match = re.search(r"(\d+\.\d+\.\d+)", version_text)
                if version_match:
                    validation["version"] = version_match.group(1)

                validation["capabilities"].extend(
                    [
                        "dynamic_instrumentation",
                        "javascript_injection",
                        "process_hooking",
                    ]
                )

                validation["valid"] = True
            else:
                validation["issues"].append("Frida execution failed")

        except Exception as e:
            logger.error("Exception in tool_discovery: %s", e)
            validation["issues"].append(f"Validation error: {e}")

        return validation

    @staticmethod
    def validate_qemu(tool_path: str) -> dict[str, Any]:
        """Validate QEMU installation."""
        validation = {
            "valid": False,
            "version": None,
            "capabilities": [],
            "issues": [],
        }

        try:
            result = subprocess.run(  # nosec S603 - Legitimate subprocess usage for security research and binary analysis  # noqa: S603
                [tool_path, "--version"],
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )

            if result.returncode == 0:
                version_text = result.stdout
                version_match = re.search(r"QEMU emulator version\s+(\d+\.\d+\.\d+)", version_text)
                if version_match:
                    validation["version"] = version_match.group(1)

                # Determine architecture support from executable name
                if "x86_64" in tool_path:
                    validation["capabilities"].append("x86_64")
                if "i386" in tool_path:
                    validation["capabilities"].append("i386")

                validation["capabilities"].extend(
                    [
                        "emulation",
                        "sandboxing",
                    ]
                )

                validation["valid"] = True
            else:
                validation["issues"].append("QEMU execution failed")

        except Exception as e:
            logger.error("Exception in tool_discovery: %s", e)
            validation["issues"].append(f"Validation error: {e}")

        return validation


class AdvancedToolDiscovery:
    """Advanced tool discovery with intelligent search and validation."""

    def __init__(self):
        """Initialize tool discovery system."""
        self.validators = {
            "ghidra": ToolValidator.validate_ghidra,
            "radare2": ToolValidator.validate_radare2,
            "python3": ToolValidator.validate_python,
            "python": ToolValidator.validate_python,
            "frida": ToolValidator.validate_frida,
            "qemu-system-x86_64": ToolValidator.validate_qemu,
            "qemu-system-i386": ToolValidator.validate_qemu,
        }

        # Load configuration
        self.config = get_config()

        # Load discovered tools from config
        self.discovered_tools = self.config.get("tools.discovered", {})

        # Load manual overrides from config
        self.manual_overrides = self.config.get("tools.manual_overrides", {})

        # Config-based caching (no longer using in-memory cache)
        self.search_cache = {}

    def discover_all_tools(self) -> dict[str, Any]:
        """Discover all supported tools."""
        logger.info("Starting comprehensive tool discovery")

        tool_configs = {
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
        }

        results = {}

        for tool_name, config in tool_configs.items():
            try:
                logger.debug(f"Discovering {tool_name}")
                tool_info = self.discover_tool(tool_name, config)
                results[tool_name] = tool_info

                if tool_info["available"]:
                    logger.info(f"✓ {tool_name} found: {tool_info['path']}")
                else:
                    level = logging.WARNING if config["required"] else logging.INFO
                    logger.log(level, f"✗ {tool_name} not found")

            except Exception as e:
                logger.error(f"Error discovering {tool_name}: {e}")
                results[tool_name] = {
                    "available": False,
                    "error": str(e),
                    "discovery_time": time.time(),
                }

        # Save discovered tools to configuration
        self.discovered_tools = results
        self.config.set("tools.discovered", results)

        # Also save last discovery timestamp
        self.config.set("tools.last_discovery", time.time())

        # Save the configuration (if auto-save is enabled)
        self.config.save()

        return results

    def discover_tool(self, tool_name: str, config: dict[str, Any]) -> dict[str, Any]:
        """Discover a specific tool with comprehensive search."""
        discovery_start = time.time()

        # Check for manual override first
        if tool_name in self.manual_overrides:
            manual_path = self.manual_overrides[tool_name]
            if manual_path and os.path.exists(manual_path):
                logger.info(f"Using manual override for {tool_name}: {manual_path}")
                tool_info = self._validate_and_populate(manual_path, tool_name)
                tool_info["discovery_method"] = "manual_override"
                tool_info["discovery_time"] = discovery_start
                tool_info["discovery_duration"] = time.time() - discovery_start
                return tool_info

        # Check config-based cache
        cached_tools = self.config.get("tools.discovered", {})
        if tool_name in cached_tools:
            cached_result = cached_tools[tool_name]
            # Check if cache is still valid (1 hour)
            if cached_result.get("discovery_time"):
                if time.time() - cached_result["discovery_time"] < 3600:
                    logger.debug(f"Using cached result for {tool_name}")
                    return cached_result

        tool_info = {
            "available": False,
            "path": None,
            "version": None,
            "validation": {},
            "discovery_method": None,
            "discovery_time": discovery_start,
            "search_locations": [],
            "capabilities": [],
        }

        # Strategy 1: PATH search
        found_path = self._search_in_path(config["executables"])
        if found_path:
            tool_info.update(self._validate_and_populate(found_path, tool_name))
            tool_info["discovery_method"] = "PATH"

        # Strategy 2: Installation-based search
        if not tool_info["available"] and config["search_strategy"] == "installation_based":
            found_path = self._search_installations(tool_name, config["executables"])
            if found_path:
                tool_info.update(self._validate_and_populate(found_path, tool_name))
                tool_info["discovery_method"] = "installation_search"

        # Strategy 3: Common locations
        if not tool_info["available"]:
            found_path = self._search_common_locations(tool_name, config["executables"])
            if found_path:
                tool_info.update(self._validate_and_populate(found_path, tool_name))
                tool_info["discovery_method"] = "common_locations"

        # Strategy 4: Registry search (Windows)
        if not tool_info["available"] and sys.platform == "win32":
            found_path = self._search_windows_registry(tool_name)
            if found_path:
                tool_info.update(self._validate_and_populate(found_path, tool_name))
                tool_info["discovery_method"] = "registry"

        tool_info["discovery_duration"] = time.time() - discovery_start

        # Save individual tool discovery to config
        self.discovered_tools[tool_name] = tool_info
        self.config.set(f"tools.discovered.{tool_name}", tool_info)

        return tool_info

    def _search_in_path(self, executables: list[str]) -> str | None:
        """Search for tool in PATH."""
        for executable in executables:
            path = shutil.which(executable)
            if path:
                return path
        return None

    def _search_installations(self, tool_name: str, executables: list[str]) -> str | None:
        """Search in typical installation directories."""
        search_paths = self._get_installation_paths(tool_name)

        for search_path in search_paths:
            if not os.path.exists(search_path):
                continue

            # Search recursively in installation directory
            for root, dirs, _files in os.walk(search_path):
                for executable in executables:
                    potential_path = os.path.join(root, executable)
                    if os.path.exists(potential_path) and os.access(potential_path, os.X_OK):
                        return potential_path

                # Limit search depth to avoid performance issues
                if len(Path(root).parts) - len(Path(search_path).parts) > 3:
                    dirs.clear()

        return None

    def _search_common_locations(self, tool_name: str, executables: list[str]) -> str | None:
        """Search in common installation locations."""
        logger.debug(
            f"Searching common locations for tool: {tool_name} with executables: {executables}"
        )
        common_paths = []

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
                ]
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
                ]
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
        """Search Windows registry for tool installations."""
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
                                        display_name = winreg.QueryValueEx(subkey, "DisplayName")[0]
                                        if tool_name.lower() in display_name.lower():
                                            install_location = winreg.QueryValueEx(
                                                subkey, "InstallLocation"
                                            )[0]
                                            if install_location and os.path.exists(
                                                install_location
                                            ):
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
            # winreg not available
        except Exception as e:
            logger.debug(f"Registry search failed: {e}")

        return None

    def _get_installation_paths(self, tool_name: str) -> list[str]:
        """Get tool-specific installation search paths."""
        paths = []

        if tool_name == "ghidra":
            if sys.platform == "win32":
                paths.extend(
                    [
                        "C:\\Program Files\\Ghidra",
                        "C:\\ghidra",
                        "C:\\Tools\\ghidra",
                        os.path.expanduser("~\\ghidra"),
                    ]
                )
            else:
                paths.extend(
                    [
                        "/opt/ghidra",
                        "/usr/local/ghidra",
                        "/usr/share/ghidra",
                        os.path.expanduser("~/ghidra"),
                        "/Applications/ghidra",
                    ]
                )

        elif tool_name == "qemu":
            if sys.platform == "win32":
                paths.extend(
                    [
                        "C:\\Program Files\\qemu",
                        "C:\\qemu",
                    ]
                )
            else:
                paths.extend(
                    [
                        "/usr/bin",
                        "/usr/local/bin",
                        "/opt/qemu",
                    ]
                )

        return paths

    def _validate_and_populate(self, tool_path: str, tool_name: str) -> dict[str, Any]:
        """Validate tool and populate information."""
        result = {
            "available": False,
            "path": tool_path,
            "validation": {},
        }

        # Find appropriate validator
        validator = None
        for validator_name, validator_func in self.validators.items():
            if validator_name in tool_name or tool_name in validator_name:
                validator = validator_func
                break

        if validator:
            validation_result = validator(tool_path)
            result["validation"] = validation_result
            result["available"] = validation_result["valid"]
            result["version"] = validation_result.get("version")
            result["capabilities"] = validation_result.get("capabilities", [])
        # Basic validation - just check if executable exists and is executable
        elif os.path.exists(tool_path) and os.access(tool_path, os.X_OK):
            result["available"] = True

        return result

    def refresh_discovery(self) -> dict[str, Any]:
        """Refresh tool discovery by clearing cache and re-scanning."""
        logger.info("Refreshing tool discovery")
        # Clear config-based cache
        self.config.set("tools.discovered", {})
        self.config.set("tools.last_discovery", None)
        self.discovered_tools = {}
        return self.discover_all_tools()

    def get_tool_capabilities(self, tool_name: str) -> list[str]:
        """Get capabilities of a discovered tool."""
        if tool_name in self.discovered_tools:
            return self.discovered_tools[tool_name].get("capabilities", [])
        return []

    def is_tool_compatible(self, tool_name: str, required_capabilities: list[str]) -> bool:
        """Check if tool has required capabilities."""
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
            logger.error(f"Cannot set manual override: path {tool_path} does not exist")
            return False

        if not os.access(tool_path, os.X_OK):
            logger.warning(f"Path {tool_path} may not be executable")

        # Save to config
        self.manual_overrides[tool_name] = tool_path
        self.config.set(f"tools.manual_overrides.{tool_name}", tool_path)
        self.config.save()

        logger.info(f"Set manual override for {tool_name}: {tool_path}")

        # Clear cached discovery for this tool to force re-validation
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
        self.config.save()

        logger.info(f"Cleared manual override for {tool_name}")

        # Clear cached discovery to force re-discovery
        if tool_name in self.discovered_tools:
            del self.discovered_tools[tool_name]
            self.config.set(f"tools.discovered.{tool_name}", None)

        return True

    def get_manual_overrides(self) -> dict[str, str]:
        """Get all manual tool path overrides.

        Returns:
            Dictionary of tool_name -> manual_path mappings
        """
        return self.manual_overrides.copy()

    def get_tool_path(self, tool_name: str) -> str | None:
        """Get the path for a tool, checking manual overrides first.

        Args:
            tool_name: Name of the tool

        Returns:
            Path to the tool executable, or None if not found
        """
        # Check manual override first
        if tool_name in self.manual_overrides:
            return self.manual_overrides[tool_name]

        # Check discovered tools
        if tool_name in self.discovered_tools:
            tool_info = self.discovered_tools[tool_name]
            if tool_info.get("available"):
                return tool_info.get("path")

        return None

    def health_check_tool(self, tool_name: str) -> dict[str, Any]:
        """Perform a health check on a specific tool.

        Args:
            tool_name: Name of the tool to check

        Returns:
            Dictionary with health check results
        """
        health_status = {
            "tool_name": tool_name,
            "healthy": False,
            "available": False,
            "executable": False,
            "version_valid": False,
            "issues": [],
            "timestamp": time.time(),
        }

        # Get tool path
        tool_path = self.get_tool_path(tool_name)
        if not tool_path:
            health_status["issues"].append("Tool path not found")
            return health_status

        # Check if path exists
        if not os.path.exists(tool_path):
            health_status["issues"].append(f"Path does not exist: {tool_path}")
            return health_status

        health_status["available"] = True

        # Check if executable
        if not os.access(tool_path, os.X_OK):
            health_status["issues"].append("File is not executable")
        else:
            health_status["executable"] = True

        # Run validator if available
        validator = None
        for validator_name, validator_func in self.validators.items():
            if validator_name in tool_name or tool_name in validator_name:
                validator = validator_func
                break

        if validator:
            validation_result = validator(tool_path)
            if validation_result["valid"]:
                health_status["version_valid"] = True
                health_status["version"] = validation_result.get("version")
                health_status["capabilities"] = validation_result.get("capabilities", [])
            else:
                health_status["issues"].extend(validation_result.get("issues", []))

        # Determine overall health
        health_status["healthy"] = (
            health_status["available"]
            and health_status["executable"]
            and (health_status["version_valid"] or not validator)
        )

        return health_status

    def health_check_all_tools(self) -> dict[str, dict[str, Any]]:
        """Perform health checks on all configured tools.

        Returns:
            Dictionary mapping tool names to health check results
        """
        results = {}

        # Check all discovered tools
        for tool_name in self.discovered_tools:
            results[tool_name] = self.health_check_tool(tool_name)

        # Check manual overrides not in discovered tools
        for tool_name in self.manual_overrides:
            if tool_name not in results:
                results[tool_name] = self.health_check_tool(tool_name)

        # Save health check results to config
        self.config.set("tools.last_health_check", results)
        self.config.set("tools.last_health_check_time", time.time())
        self.config.save()

        return results

    def get_healthy_tools(self) -> list[str]:
        """Get list of tools that passed health checks.

        Returns:
            List of healthy tool names
        """
        health_results = self.health_check_all_tools()
        return [
            tool_name
            for tool_name, status in health_results.items()
            if status.get("healthy", False)
        ]

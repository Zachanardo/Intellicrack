"""Intellicrack Plugins Package.

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

import importlib
import logging
import os
from pathlib import Path
from typing import Any, Protocol

from .plugin_config import PLUGIN_SYSTEM_EXPORTS


class AppProtocol(Protocol):
    """Protocol for app objects used in plugin functions.

    Attributes:
        binary_path: Path to the binary being analyzed.
        update_output: Callback function for updating output.
        frida_sessions: Dictionary mapping session IDs to Frida session tuples.
    """

    binary_path: str
    update_output: Any
    frida_sessions: dict[str, tuple[Any, Any]]


# Set up package logger
logger = logging.getLogger(__name__)

# Plugin directories
PLUGIN_DIR: Path = Path(__file__).parent if __file__ else Path.cwd() / "intellicrack" / "plugins"
CUSTOM_MODULES_DIR: Path = PLUGIN_DIR / "custom_modules"
FRIDA_SCRIPTS_DIR: Path = PLUGIN_DIR.parent.parent / "scripts" / "frida"
GHIDRA_SCRIPTS_DIR: Path = PLUGIN_DIR.parent.parent / "scripts" / "ghidra"

# Plugin registry
_plugins: dict[str, object] = {}


def load_plugin(plugin_name: str, plugin_type: str = "custom") -> object | None:
    """Load a plugin by name and type.

    Args:
        plugin_name: The name of the plugin to load.
        plugin_type: The type of plugin ("custom", "frida", or "ghidra").
            Defaults to "custom".

    Returns:
        The loaded module object or None if loading failed.

    """
    try:
        if plugin_type == "custom":
            module = importlib.import_module(f".custom_modules.{plugin_name}", package="intellicrack.plugins")
            _plugins[plugin_name] = module
            logger.info("Loaded plugin: %s", plugin_name)
            return module
        return None
    except (OSError, ValueError, RuntimeError) as e:
        logger.exception("Failed to load plugin %s: %s", plugin_name, e)
        return None


def list_plugins(plugin_type: str = "custom") -> list[str]:
    """List available plugins of a given type.

    Args:
        plugin_type: The type of plugins to list ("custom", "frida", or "ghidra").
            Defaults to "custom".

    Returns:
        A list of plugin names available for the specified type.

    """
    plugins: list[str] = []
    if plugin_type == "custom":
        if CUSTOM_MODULES_DIR.exists():
            plugins = [f.stem for f in CUSTOM_MODULES_DIR.glob("*.py") if f.stem != "__init__"]
    elif plugin_type == "frida":
        if FRIDA_SCRIPTS_DIR.exists():
            plugins = [f.stem for f in FRIDA_SCRIPTS_DIR.glob("*.js")]
    elif plugin_type == "ghidra":
        if GHIDRA_SCRIPTS_DIR.exists():
            plugins = [f.stem for f in GHIDRA_SCRIPTS_DIR.glob("*.java")]
            plugins.extend([f.stem for f in GHIDRA_SCRIPTS_DIR.glob("*.py")])
    return plugins


def get_frida_script(script_name: str) -> str | None:
    """Get the path to a Frida script.

    Args:
        script_name: The name of the Frida script (without .js extension).

    Returns:
        The absolute path to the script if found, None otherwise.

    """
    script_path = FRIDA_SCRIPTS_DIR / f"{script_name}.js"
    return str(script_path) if script_path.exists() else None


def get_ghidra_script(script_name: str) -> str | None:
    """Get the path to a Ghidra script.

    Args:
        script_name: The name of the Ghidra script (without extension).

    Returns:
        The absolute path to the script if found, None otherwise.
        Checks for both .java and .py extensions.

    """
    for ext in [".java", ".py"]:
        script_path = GHIDRA_SCRIPTS_DIR / f"{script_name}{ext}"
        if script_path.exists():
            return str(script_path)
    return None


def get_plugin_size(plugin_name: str, plugin_type: str = "custom") -> int:
    """Get the size of a plugin file in bytes.

    Args:
        plugin_name: The name of the plugin.
        plugin_type: The type of plugin ("custom", "frida", or "ghidra").
            Defaults to "custom".

    Returns:
        The size in bytes of the plugin file, or 0 if the file does not exist
        or an invalid plugin type is specified.

    """
    if plugin_type == "custom":
        plugin_path = CUSTOM_MODULES_DIR / f"{plugin_name}.py"
    elif plugin_type == "frida":
        plugin_path = FRIDA_SCRIPTS_DIR / f"{plugin_name}.js"
    elif plugin_type == "ghidra":
        plugin_path = GHIDRA_SCRIPTS_DIR / f"{plugin_name}.java"
        if not plugin_path.exists():
            plugin_path = GHIDRA_SCRIPTS_DIR / f"{plugin_name}.py"
    else:
        return 0

    return os.path.getsize(plugin_path) if plugin_path.exists() else 0


# Import plugin system functions
try:
    from .plugin_system import (
        create_sample_plugins,
        load_plugins,
        run_custom_plugin,
        run_frida_plugin_from_file,
        run_ghidra_plugin_from_file,
        run_plugin,
        run_plugin_in_sandbox,
        run_plugin_remotely,
    )
except ImportError as e:
    logger.warning("Failed to import plugin system functions: %s", e)

    # Provide fallback empty functions
    def load_plugins(plugin_dir: str = "intellicrack/intellicrack/plugins") -> dict[str, list[dict[str, object]]]:
        """Fallback function for loading plugins when plugin system is not available.

        Args:
            plugin_dir: The directory containing plugin files.
                Defaults to "intellicrack/intellicrack/plugins".

        Returns:
            Dictionary mapping plugin names to their metadata and modules.

        """
        logger.debug("Fallback load_plugins called with plugin_dir: %s", plugin_dir)
        # Try to load available plugins from directories
        loaded_plugins: dict[str, list[dict[str, object]]] = {}

        # Load custom Python plugins
        if CUSTOM_MODULES_DIR.exists():
            for plugin_file in CUSTOM_MODULES_DIR.glob("*.py"):
                if plugin_file.stem != "__init__":
                    try:
                        module = importlib.import_module(
                            f".custom_modules.{plugin_file.stem}",
                            package="intellicrack.plugins",
                        )
                        plugin_data: dict[str, object] = {
                            "type": "python",
                            "module": module,
                            "path": str(plugin_file),
                        }
                        if plugin_file.stem not in loaded_plugins:
                            loaded_plugins[plugin_file.stem] = []
                        loaded_plugins[plugin_file.stem].append(plugin_data)
                        logger.info("Loaded Python plugin: %s", plugin_file.stem)
                    except Exception as exc:
                        logger.exception("Failed to load plugin %s: %s", plugin_file.stem, exc)

        # Register Frida scripts
        if FRIDA_SCRIPTS_DIR.exists():
            for script_file in FRIDA_SCRIPTS_DIR.glob("*.js"):
                plugin_data = {
                    "type": "frida",
                    "path": str(script_file),
                }
                if script_file.stem not in loaded_plugins:
                    loaded_plugins[script_file.stem] = []
                loaded_plugins[script_file.stem].append(plugin_data)
                logger.info("Found Frida script: %s", script_file.stem)

        # Register Ghidra scripts
        if GHIDRA_SCRIPTS_DIR.exists():
            for ext in ["*.java", "*.py"]:
                for script_file in GHIDRA_SCRIPTS_DIR.glob(ext):
                    plugin_data = {
                        "type": "ghidra",
                        "path": str(script_file),
                        "language": "java" if ext == "*.java" else "python",
                    }
                    if script_file.stem not in loaded_plugins:
                        loaded_plugins[script_file.stem] = []
                    loaded_plugins[script_file.stem].append(plugin_data)
                    logger.info("Found Ghidra script: %s", script_file.stem)

        return loaded_plugins

    def run_plugin(app: AppProtocol, plugin_name: str) -> None:
        """Fallback function for running plugins when plugin system is not available.

        Args:
            app: Application protocol instance.
            plugin_name: Name of the plugin to run.

        Notes:
            Does nothing when the actual plugin system cannot be imported.

        """
        logger.debug("Fallback run_plugin called with app: %s, plugin_name: %s", app, plugin_name)

    def run_custom_plugin(app: AppProtocol, plugin_info: dict[str, object]) -> None:
        """Fallback function for running custom plugins when plugin system is not available.

        Args:
            app: Application protocol instance.
            plugin_info: Plugin information dictionary.

        Notes:
            Does nothing when the actual plugin system cannot be imported.

        """
        logger.debug("Fallback run_custom_plugin called with app: %s, plugin_info: %s", app, plugin_info)

    def run_frida_plugin_from_file(app: AppProtocol, plugin_path: str) -> None:
        """Fallback function for running Frida plugins when plugin system is not available.

        Args:
            app: Application protocol instance.
            plugin_path: Path to the Frida plugin file.

        Notes:
            Does nothing when the actual plugin system cannot be imported.

        """
        logger.debug("Fallback run_frida_plugin_from_file called with app: %s, plugin_path: %s", app, plugin_path)

    def run_ghidra_plugin_from_file(app: AppProtocol, plugin_path: str) -> None:
        """Fallback function for running Ghidra plugins when plugin system is not available.

        Args:
            app: Application protocol instance.
            plugin_path: Path to the Ghidra plugin file.

        Notes:
            Does nothing when the actual plugin system cannot be imported.

        """
        logger.debug("Fallback run_ghidra_plugin_from_file called with app: %s, plugin_path: %s", app, plugin_path)

    def create_sample_plugins(plugin_dir: str = "intellicrack/intellicrack/plugins") -> None:
        """Fallback function for creating sample plugins when plugin system is not available.

        Args:
            plugin_dir: Directory where sample plugins should be created.
                Defaults to "intellicrack/intellicrack/plugins".

        Notes:
            Does nothing when the actual plugin system cannot be imported.

        """
        logger.debug("Fallback create_sample_plugins called with plugin_dir: %s", plugin_dir)

    def run_plugin_in_sandbox(plugin_path: str, function_name: str, *args: object) -> list[str] | None:
        """Fallback function for running plugins in sandbox when plugin system is not available.

        Args:
            plugin_path: Path to the plugin file.
            function_name: Name of the function to execute.
            *args: Additional arguments for the plugin function.

        Returns:
            Empty list when the actual plugin system cannot be imported.

        Notes:
            Does nothing when the actual plugin system cannot be imported.

        """
        logger.debug(
            "Fallback run_plugin_in_sandbox called with plugin_path: %s, function_name: %s, args: %s",
            plugin_path,
            function_name,
            args,
        )
        return None

    def run_plugin_remotely(app: AppProtocol, plugin_info: dict[str, object]) -> list[str] | None:
        """Fallback function for running plugins remotely when plugin system is not available.

        Args:
            app: Application protocol instance.
            plugin_info: Plugin information dictionary.

        Returns:
            Empty list when the actual plugin system cannot be imported.

        Notes:
            Does nothing when the actual plugin system cannot be imported.

        """
        logger.debug("Fallback run_plugin_remotely called with app: %s, plugin_info: %s", app, plugin_info)
        return None


# Import remote executor if available
try:  # pylint: disable=unused-argument
    from .remote_executor import RemotePluginExecutor

    _REMOTE_EXECUTOR_AVAILABLE: bool = True
except ImportError as e:
    logger.warning("Remote plugin executor not available: %s", e)
    _REMOTE_EXECUTOR_AVAILABLE = False

# Define package exports
_plugin_system_exports: list[str] = []
if PLUGIN_SYSTEM_EXPORTS is not None and isinstance(PLUGIN_SYSTEM_EXPORTS, (list, tuple)):
    _plugin_system_exports = [str(item) for item in PLUGIN_SYSTEM_EXPORTS]

_base_exports: list[str] = [
    "CUSTOM_MODULES_DIR",
    "FRIDA_SCRIPTS_DIR",
    "GHIDRA_SCRIPTS_DIR",
    "get_frida_script",
    "get_ghidra_script",
    "list_plugins",
    "load_plugin",
]

if _REMOTE_EXECUTOR_AVAILABLE:
    _base_exports.append("RemotePluginExecutor")

__all__ = _base_exports

# Package metadata
__version__: str = "0.1.0"
__author__: str = "Intellicrack Development Team"

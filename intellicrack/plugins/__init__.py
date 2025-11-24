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
from typing import Any

from .plugin_config import PLUGIN_SYSTEM_EXPORTS


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
    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Failed to load plugin %s: %s", plugin_name, e)
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
    def load_plugins(*args: object, **kwargs: object) -> dict[str, object]:
        """Fallback function for loading plugins when plugin system is not available.

        Args:
            *args: Variable positional arguments (ignored).
            **kwargs: Variable keyword arguments (ignored).

        Returns:
            A dictionary mapping plugin names to their metadata and modules.

        """
        logger.debug(f"Fallback load_plugins called with args: {args}, kwargs: {kwargs}")
        # Try to load available plugins from directories
        loaded_plugins: dict[str, object] = {}

        # Load custom Python plugins
        if CUSTOM_MODULES_DIR.exists():
            for plugin_file in CUSTOM_MODULES_DIR.glob("*.py"):
                if plugin_file.stem != "__init__":
                    try:
                        module = importlib.import_module(
                            f".custom_modules.{plugin_file.stem}",
                            package="intellicrack.plugins",
                        )
                        loaded_plugins[plugin_file.stem] = {
                            "type": "python",
                            "module": module,
                            "path": str(plugin_file),
                        }
                        logger.info("Loaded Python plugin: %s", plugin_file.stem)
                    except Exception as exc:
                        logger.error("Failed to load plugin %s: %s", plugin_file.stem, exc)

        # Register Frida scripts
        if FRIDA_SCRIPTS_DIR.exists():
            for script_file in FRIDA_SCRIPTS_DIR.glob("*.js"):
                loaded_plugins[script_file.stem] = {
                    "type": "frida",
                    "path": str(script_file),
                }
                logger.info("Found Frida script: %s", script_file.stem)

        # Register Ghidra scripts
        if GHIDRA_SCRIPTS_DIR.exists():
            for ext in ["*.java", "*.py"]:
                for script_file in GHIDRA_SCRIPTS_DIR.glob(ext):
                    loaded_plugins[script_file.stem] = {
                        "type": "ghidra",
                        "path": str(script_file),
                        "language": "java" if ext == "*.java" else "python",
                    }
                    logger.info("Found Ghidra script: %s", script_file.stem)

        return loaded_plugins

    def run_plugin(*args: object, **kwargs: object) -> None:
        """Fallback function for running plugins when plugin system is not available.

        Args:
            *args: Variable positional arguments (ignored).
            **kwargs: Variable keyword arguments (ignored).

        Notes:
            Does nothing when the actual plugin system cannot be imported.

        """
        logger.debug(f"Fallback run_plugin called with args: {args}, kwargs: {kwargs}")

    def run_custom_plugin(*args: object, **kwargs: object) -> None:
        """Fallback function for running custom plugins when plugin system is not available.

        Args:
            *args: Variable positional arguments (ignored).
            **kwargs: Variable keyword arguments (ignored).

        Notes:
            Does nothing when the actual plugin system cannot be imported.

        """
        logger.debug(f"Fallback run_custom_plugin called with args: {args}, kwargs: {kwargs}")

    def run_frida_plugin_from_file(*args: object, **kwargs: object) -> None:
        """Fallback function for running Frida plugins when plugin system is not available.

        Args:
            *args: Variable positional arguments (ignored).
            **kwargs: Variable keyword arguments (ignored).

        Notes:
            Does nothing when the actual plugin system cannot be imported.

        """
        logger.debug(f"Fallback run_frida_plugin_from_file called with args: {args}, kwargs: {kwargs}")

    def run_ghidra_plugin_from_file(*args: object, **kwargs: object) -> None:
        """Fallback function for running Ghidra plugins when plugin system is not available.

        Args:
            *args: Variable positional arguments (ignored).
            **kwargs: Variable keyword arguments (ignored).

        Notes:
            Does nothing when the actual plugin system cannot be imported.

        """
        logger.debug(f"Fallback run_ghidra_plugin_from_file called with args: {args}, kwargs: {kwargs}")

    def create_sample_plugins(*args: object, **kwargs: object) -> None:
        """Fallback function for creating sample plugins when plugin system is not available.

        Args:
            *args: Variable positional arguments (ignored).
            **kwargs: Variable keyword arguments (ignored).

        Notes:
            Does nothing when the actual plugin system cannot be imported.

        """
        logger.debug(f"Fallback create_sample_plugins called with args: {args}, kwargs: {kwargs}")

    def run_plugin_in_sandbox(*args: object, **kwargs: object) -> None:
        """Fallback function for running plugins in sandbox when plugin system is not available.

        Args:
            *args: Variable positional arguments (ignored).
            **kwargs: Variable keyword arguments (ignored).

        Notes:
            Does nothing when the actual plugin system cannot be imported.

        """
        logger.debug(f"Fallback run_plugin_in_sandbox called with args: {args}, kwargs: {kwargs}")

    def run_plugin_remotely(*args: object, **kwargs: object) -> None:
        """Fallback function for running plugins remotely when plugin system is not available.

        Args:
            *args: Variable positional arguments (ignored).
            **kwargs: Variable keyword arguments (ignored).

        Notes:
            Does nothing when the actual plugin system cannot be imported.

        """
        logger.debug(f"Fallback run_plugin_remotely called with args: {args}, kwargs: {kwargs}")


# Import remote executor if available
try:  # pylint: disable=unused-argument
    from .remote_executor import RemotePluginExecutor
except ImportError as e:
    logger.warning("Remote plugin executor not available: %s", e)
    RemotePluginExecutor = None

# Define package exports
_plugin_system_exports = (
    ([str(item) for item in PLUGIN_SYSTEM_EXPORTS] if isinstance(PLUGIN_SYSTEM_EXPORTS, (list, tuple)) else [])
    if PLUGIN_SYSTEM_EXPORTS is not None
    else []
)
__all__ = [
    "CUSTOM_MODULES_DIR",
    "FRIDA_SCRIPTS_DIR",
    "GHIDRA_SCRIPTS_DIR",
    "RemotePluginExecutor",
    "get_frida_script",
    "get_ghidra_script",
    "list_plugins",
    "load_plugin",
]

# Package metadata
__version__: str = "0.1.0"
__author__: str = "Intellicrack Development Team"

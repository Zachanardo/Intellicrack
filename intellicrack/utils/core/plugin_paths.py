"""Plugin path management utilities for locating and managing plugin directories.

Plugin Path Discovery Utility
Provides centralized path management for Intellicrack components

This module centralizes all path resolution for scripts, plugins, and configuration
to ensure consistent behavior across the entire application.

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
from pathlib import Path

from ..resource_helper import get_resource_path


_logger = logging.getLogger(__name__)


def get_project_root() -> Path:
    """Get the project root directory.

    Returns:
        Path: Absolute path to the Intellicrack project root

    """
    try:
        # Use resource helper to find the package root
        intellicrack_root = Path(get_resource_path(""))
        return intellicrack_root.parent
    except Exception as e:
        _logger.exception("Exception in plugin_paths: %s", e)
        # Fallback to relative path calculation
        current_file = Path(__file__)
        # Go up from utils -> intellicrack -> project root
        return current_file.parent.parent.parent


def get_scripts_dir() -> Path:
    """Get the scripts directory.

    Returns:
        Path: Absolute path to the scripts directory

    """
    return Path(get_resource_path("scripts"))


def get_frida_scripts_dir() -> Path:
    """Get the Frida scripts directory.

    Returns:
        Path: Absolute path to the Frida scripts directory

    """
    return Path(get_resource_path("scripts/frida"))


def get_ghidra_scripts_dir() -> Path:
    """Get the Ghidra scripts directory.

    Returns:
        Path: Absolute path to the Ghidra scripts directory

    """
    return Path(get_resource_path("scripts/ghidra"))


def get_plugin_modules_dir() -> Path:
    """Get the Python plugin modules directory.

    Returns:
        Path: Absolute path to the custom plugin modules directory

    """
    return get_project_root() / "intellicrack" / "plugins" / "custom_modules"


def get_config_dir() -> Path:
    """Get the configuration directory.

    Returns:
        Path: Absolute path to the configuration directory

    Note:
        This function provides a standalone path without importing config_manager
        to avoid circular imports. Config manager will use its own path resolution.

    """
    project_root = get_project_root()
    config_dir = project_root / "config"
    config_dir.mkdir(parents=True, exist_ok=True)
    return config_dir


def get_main_config_file() -> Path:
    """Get the main configuration file path.

    Returns:
        Path: Absolute path to main config file

    Note:
        This function provides a standalone path without importing config_manager
        to avoid circular imports. Config manager will use its own path resolution.

    """
    return get_config_dir() / "intellicrack_config.json"


def get_tests_dir() -> Path:
    """Get the tests directory.

    Returns:
        Path: Absolute path to the tests directory

    """
    return get_project_root() / "tests"


# New path getters for reorganized structure with graceful fallback
def get_data_dir() -> Path:
    """Get the main data directory.

    Returns:
        Path: Absolute path to the data directory

    """
    project_root = get_project_root()
    data_dir = project_root / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    return data_dir


def get_logs_dir() -> Path:
    """Get the logs directory.

    Returns:
        Path: Absolute path to the logs directory

    """
    project_root = get_project_root()
    logs_dir = project_root / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    return logs_dir


def get_plugin_cache_dir() -> Path:
    """Get the plugin cache directory.

    Returns:
        Path: Absolute path to the plugin cache directory

    """
    project_root = get_project_root()
    cache_dir = project_root / "data" / "plugin_cache"
    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir


def get_visualizations_dir() -> Path:
    """Get the visualizations directory.

    Returns:
        Path: Absolute path to the visualizations directory

    """
    project_root = get_project_root()
    viz_dir = project_root / "data" / "visualizations"
    viz_dir.mkdir(parents=True, exist_ok=True)
    return viz_dir


def get_reports_dir() -> Path:
    """Get the reports directory.

    Returns:
        Path: Absolute path to the reports directory

    """
    project_root = get_project_root()
    reports_dir = project_root / "data" / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    return reports_dir


def get_dev_dir() -> Path:
    """Get the development directory.

    Returns:
        Path: Absolute path to the dev directory

    """
    project_root = get_project_root()
    dev_dir = project_root / "dev"
    dev_dir.mkdir(parents=True, exist_ok=True)
    return dev_dir


def get_project_docs_dir() -> Path:
    """Get the project documentation directory.

    Returns:
        Path: Absolute path to the project docs directory

    """
    project_root = get_project_root()
    docs_dir = project_root / "dev" / "project-docs"
    docs_dir.mkdir(parents=True, exist_ok=True)
    return docs_dir


def get_dev_scripts_dir() -> Path:
    """Get the development scripts directory.

    Returns:
        Path: Absolute path to the dev scripts directory

    """
    project_root = get_project_root()
    scripts_dir = project_root / "dev" / "scripts"
    scripts_dir.mkdir(parents=True, exist_ok=True)
    return scripts_dir


def get_frida_logs_dir() -> Path:
    """Get the Frida operations logs directory.

    Returns:
        Path: Absolute path to the Frida logs directory

    """
    return get_logs_dir() / "frida_operations"


def list_frida_scripts() -> list[Path]:
    """List all available Frida scripts.

    Returns:
        List[Path]: List of paths to Frida .js files

    """
    frida_dir = get_frida_scripts_dir()
    return list(frida_dir.glob("*.js")) if frida_dir.exists() else []


def list_ghidra_scripts() -> list[Path]:
    """List all available Ghidra scripts.

    Returns:
        List[Path]: List of paths to Ghidra .java and .py files

    """
    ghidra_dir = get_ghidra_scripts_dir()
    scripts = []
    if ghidra_dir.exists():
        scripts.extend(ghidra_dir.glob("**/*.java"))
        scripts.extend(ghidra_dir.glob("**/*.py"))
    return scripts


def list_plugin_modules() -> list[Path]:
    """List all available Python plugin modules.

    Returns:
        List[Path]: List of paths to Python plugin files

    """
    plugins_dir = get_plugin_modules_dir()
    if plugins_dir.exists():
        return [f for f in plugins_dir.glob("*.py") if f.stem != "__init__"]
    return []


def find_script_by_name(script_name: str, script_type: str = "auto") -> Path | None:
    """Find a script by name across all script directories.

    Args:
        script_name: Name of the script (with or without extension)
        script_type: Type of script ("frida", "ghidra", or "auto")

    Returns:
        Path: Path to the script if found, None otherwise

    """
    # Remove extension if present
    base_name = Path(script_name).stem

    if script_type in {"frida", "auto"}:
        frida_path = get_frida_scripts_dir() / f"{base_name}.js"
        if frida_path.exists():
            return frida_path

    if script_type in {"ghidra", "auto"}:
        ghidra_dir = get_ghidra_scripts_dir()
        for ext in [".java", ".py"]:
            for script_path in ghidra_dir.rglob(f"{base_name}{ext}"):
                if script_path.exists():
                    return script_path

    return None


def get_path_info() -> dict[str, str]:
    """Get information about all configured paths.

    Returns:
        Dict[str, str]: Dictionary mapping path names to their absolute paths

    """
    return {
        "project_root": str(get_project_root()),
        "scripts_dir": str(get_scripts_dir()),
        "frida_scripts": str(get_frida_scripts_dir()),
        "ghidra_scripts": str(get_ghidra_scripts_dir()),
        "plugin_modules": str(get_plugin_modules_dir()),
        "config_dir": str(get_config_dir()),
        "main_config": str(get_main_config_file()),
        "tests_dir": str(get_tests_dir()),
        # New reorganized paths
        "data_dir": str(get_data_dir()),
        "logs_dir": str(get_logs_dir()),
        "plugin_cache": str(get_plugin_cache_dir()),
        "visualizations": str(get_visualizations_dir()),
        "reports_dir": str(get_reports_dir()),
        "dev_dir": str(get_dev_dir()),
        "project_docs": str(get_project_docs_dir()),
        "dev_scripts": str(get_dev_scripts_dir()),
        "frida_logs": str(get_frida_logs_dir()),
    }


def ensure_directories_exist() -> None:
    """Ensure all required directories exist, creating them if necessary."""
    directories = [
        get_scripts_dir(),
        get_frida_scripts_dir(),
        get_ghidra_scripts_dir(),
        get_plugin_modules_dir(),
        get_config_dir(),
        get_tests_dir(),
        # New reorganized directories
        get_data_dir(),
        get_logs_dir(),
        get_plugin_cache_dir(),
        get_visualizations_dir(),
        get_reports_dir(),
        get_dev_dir(),
        get_project_docs_dir(),
        get_dev_scripts_dir(),
        get_frida_logs_dir(),
    ]

    for directory in directories:
        directory.mkdir(parents=True, exist_ok=True)


# Legacy compatibility functions for gradual migration
def get_frida_script_path(script_name: str) -> str | None:
    """Legacy function for getting Frida script paths.

    Args:
        script_name: Name of the Frida script

    Returns:
        str: Path to the script if found, None otherwise

    """
    script_path = find_script_by_name(script_name, "frida")
    return str(script_path) if script_path else None


def get_ghidra_script_path(script_name: str) -> str | None:
    """Legacy function for getting Ghidra script paths.

    Args:
        script_name: Name of the Ghidra script

    Returns:
        str: Path to the script if found, None otherwise

    """
    script_path = find_script_by_name(script_name, "ghidra")
    return str(script_path) if script_path else None


# Module initialization
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s - %(message)s")
    info = get_path_info()
    _logger.info("Intellicrack Path Configuration:")
    _logger.info("=" * 40)
    for name, path in info.items():
        exists = "OK" if Path(path).exists() else "FAIL"
        _logger.info("%s %s: %s", exists, name, path)

    _logger.info("Script Counts:")
    _logger.info("  Frida scripts: %s", len(list_frida_scripts()))
    _logger.info("  Ghidra scripts: %s", len(list_ghidra_scripts()))
    _logger.info("  Plugin modules: %s", len(list_plugin_modules()))

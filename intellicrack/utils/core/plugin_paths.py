"""
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
along with Intellicrack.  If not, see <https://www.gnu.org/licenses/>.
"""

from pathlib import Path
from typing import Dict, List, Optional


def get_project_root() -> Path:
    """
    Get the project root directory.

    Returns:
        Path: Absolute path to the Intellicrack project root
    """
    current_file = Path(__file__)
    # Go up from utils -> intellicrack -> project root
    return current_file.parent.parent.parent


def get_scripts_dir() -> Path:
    """
    Get the scripts directory.

    Returns:
        Path: Absolute path to the scripts directory
    """
    return get_project_root() / "scripts"


def get_frida_scripts_dir() -> Path:
    """
    Get the Frida scripts directory.

    Returns:
        Path: Absolute path to the Frida scripts directory
    """
    return get_scripts_dir() / "frida"


def get_ghidra_scripts_dir() -> Path:
    """
    Get the Ghidra scripts directory.

    Returns:
        Path: Absolute path to the Ghidra scripts directory
    """
    return get_scripts_dir() / "ghidra"


def get_plugin_modules_dir() -> Path:
    """
    Get the Python plugin modules directory.

    Returns:
        Path: Absolute path to the custom plugin modules directory
    """
    return get_project_root() / "intellicrack" / "plugins" / "custom_modules"


def get_config_dir() -> Path:
    """
    Get the configuration directory.

    Returns:
        Path: Absolute path to the configuration directory
    """
    return get_project_root() / "config"


def get_main_config_file() -> Path:
    """
    Get the main configuration file path.

    Returns:
        Path: Absolute path to intellicrack_config.json
    """
    return get_config_dir() / "intellicrack_config.json"


def get_tests_dir() -> Path:
    """
    Get the tests directory.

    Returns:
        Path: Absolute path to the tests directory
    """
    return get_project_root() / "tests"


def list_frida_scripts() -> List[Path]:
    """
    List all available Frida scripts.

    Returns:
        List[Path]: List of paths to Frida .js files
    """
    frida_dir = get_frida_scripts_dir()
    if frida_dir.exists():
        return list(frida_dir.glob("*.js"))
    return []


def list_ghidra_scripts() -> List[Path]:
    """
    List all available Ghidra scripts.

    Returns:
        List[Path]: List of paths to Ghidra .java and .py files
    """
    ghidra_dir = get_ghidra_scripts_dir()
    scripts = []
    if ghidra_dir.exists():
        scripts.extend(ghidra_dir.glob("**/*.java"))
        scripts.extend(ghidra_dir.glob("**/*.py"))
    return scripts


def list_plugin_modules() -> List[Path]:
    """
    List all available Python plugin modules.

    Returns:
        List[Path]: List of paths to Python plugin files
    """
    plugins_dir = get_plugin_modules_dir()
    if plugins_dir.exists():
        return [f for f in plugins_dir.glob("*.py") if f.stem != "__init__"]
    return []


def find_script_by_name(script_name: str, script_type: str = "auto") -> Optional[Path]:
    """
    Find a script by name across all script directories.

    Args:
        script_name: Name of the script (with or without extension)
        script_type: Type of script ("frida", "ghidra", or "auto")

    Returns:
        Path: Path to the script if found, None otherwise
    """
    # Remove extension if present
    base_name = Path(script_name).stem

    if script_type in ("frida", "auto"):
        frida_path = get_frida_scripts_dir() / f"{base_name}.js"
        if frida_path.exists():
            return frida_path

    if script_type in ("ghidra", "auto"):
        ghidra_dir = get_ghidra_scripts_dir()
        for ext in [".java", ".py"]:
            for script_path in ghidra_dir.rglob(f"{base_name}{ext}"):
                if script_path.exists():
                    return script_path

    return None


def get_path_info() -> Dict[str, str]:
    """
    Get information about all configured paths.

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
        "tests_dir": str(get_tests_dir())
    }


def ensure_directories_exist() -> None:
    """
    Ensure all required directories exist, creating them if necessary.
    """
    directories = [
        get_scripts_dir(),
        get_frida_scripts_dir(),
        get_ghidra_scripts_dir(),
        get_plugin_modules_dir(),
        get_config_dir(),
        get_tests_dir()
    ]

    for directory in directories:
        directory.mkdir(parents=True, exist_ok=True)


# Legacy compatibility functions for gradual migration
def get_frida_script_path(script_name: str) -> Optional[str]:
    """
    Legacy function for getting Frida script paths.

    Args:
        script_name: Name of the Frida script

    Returns:
        str: Path to the script if found, None otherwise
    """
    script_path = find_script_by_name(script_name, "frida")
    return str(script_path) if script_path else None


def get_ghidra_script_path(script_name: str) -> Optional[str]:
    """
    Legacy function for getting Ghidra script paths.

    Args:
        script_name: Name of the Ghidra script

    Returns:
        str: Path to the script if found, None otherwise
    """
    script_path = find_script_by_name(script_name, "ghidra")
    return str(script_path) if script_path else None


# Module initialization
if __name__ == "__main__":
    # Print path information when run directly
    info = get_path_info()
    print("Intellicrack Path Configuration:")
    print("=" * 40)
    for name, path in info.items():
        exists = "✓" if Path(path).exists() else "✗"
        print(f"{exists} {name}: {path}")

    print("\nScript Counts:")
    print(f"  Frida scripts: {len(list_frida_scripts())}")
    print(f"  Ghidra scripts: {len(list_ghidra_scripts())}")
    print(f"  Plugin modules: {len(list_plugin_modules())}")

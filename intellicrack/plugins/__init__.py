"""
Intellicrack Plugins Package

This package provides a plugin system for extending the Intellicrack framework's functionality.
It supports custom modules, Frida scripts for dynamic instrumentation, and Ghidra scripts for
advanced static analysis.

Subdirectories:
    - custom_modules: Python-based custom plugin modules
    - frida_scripts: JavaScript scripts for Frida instrumentation
    - ghidra_scripts: Java/Python scripts for Ghidra analysis

Key Features:
    - Dynamic plugin loading
    - Custom analysis modules
    - Frida instrumentation support
    - Ghidra integration
    - Plugin management system
    - Hot-reload capabilities

Plugin Types:
    - Analysis plugins for custom analysis techniques
    - UI plugins for interface extensions
    - Export plugins for custom output formats
    - Integration plugins for third-party tools
"""

import importlib
import logging
import os
from pathlib import Path

# Set up package logger
logger = logging.getLogger(__name__)

# Plugin directories
PLUGIN_DIR = Path(__file__).parent
CUSTOM_MODULES_DIR = PLUGIN_DIR / "custom_modules"
FRIDA_SCRIPTS_DIR = PLUGIN_DIR / "frida_scripts"
GHIDRA_SCRIPTS_DIR = PLUGIN_DIR / "ghidra_scripts"

# Plugin registry
_plugins = {}

def load_plugin(plugin_name, plugin_type="custom"):
    """Load a plugin by name and type."""
    try:
        if plugin_type == "custom":
            module = importlib.import_module(f".custom_modules.{plugin_name}", package="intellicrack.plugins")
            _plugins[plugin_name] = module
            logger.info(f"Loaded plugin: {plugin_name}")
            return module
    except Exception as e:
        logger.error(f"Failed to load plugin {plugin_name}: {e}")
        return None

def list_plugins(plugin_type="custom"):
    """List available plugins of a given type."""
    plugins = []
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

def get_frida_script(script_name):
    """Get the path to a Frida script."""
    script_path = FRIDA_SCRIPTS_DIR / f"{script_name}.js"
    if script_path.exists():
        return str(script_path)
    return None

def get_ghidra_script(script_name):
    """Get the path to a Ghidra script."""
    for ext in [".java", ".py"]:
        script_path = GHIDRA_SCRIPTS_DIR / f"{script_name}{ext}"
        if script_path.exists():
            return str(script_path)
    return None

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
    logger.warning(f"Failed to import plugin system functions: {e}")
    # Provide fallback empty functions
    def load_plugins(*args, **kwargs): return {}
    def run_plugin(*args, **kwargs): pass
    def run_custom_plugin(*args, **kwargs): pass
    def run_frida_plugin_from_file(*args, **kwargs): pass
    def run_ghidra_plugin_from_file(*args, **kwargs): pass
    def create_sample_plugins(*args, **kwargs): pass
    def run_plugin_in_sandbox(*args, **kwargs): return None
    def run_plugin_remotely(*args, **kwargs): return None

# Import remote executor if available
try:
    from .remote_executor import RemotePluginExecutor
except ImportError as e:
    logger.warning(f"Remote plugin executor not available: {e}")
    RemotePluginExecutor = None

# Define package exports
__all__ = [
    'load_plugin',
    'list_plugins',
    'get_frida_script',
    'get_ghidra_script',
    'CUSTOM_MODULES_DIR',
    'FRIDA_SCRIPTS_DIR',
    'GHIDRA_SCRIPTS_DIR',
    # Plugin system functions
    'load_plugins',
    'run_plugin',
    'run_custom_plugin',
    'run_frida_plugin_from_file',
    'run_ghidra_plugin_from_file',
    'create_sample_plugins',
    'run_plugin_in_sandbox',
    'run_plugin_remotely',
    'RemotePluginExecutor',
]

# Package metadata
__version__ = "0.1.0"
__author__ = "Intellicrack Development Team"

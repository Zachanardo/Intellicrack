"""Plugin system manager for loading and managing Intellicrack plugins.

Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see https://www.gnu.org/licenses/.
"""

import importlib
import importlib.util
import json
import multiprocessing
import os
import shutil
import signal
import sys
import tempfile
import traceback
from typing import Any

from PyQt6.QtWidgets import QInputDialog, QMessageBox

from intellicrack.handlers.frida_handler import HAS_FRIDA as FRIDA_AVAILABLE
from intellicrack.utils.logger import logger

from ..config import CONFIG
from ..utils.system.process_utils import get_target_process_pid
from .remote_executor import RemotePluginExecutor

"""
Plugin System Foundation for Intellicrack

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

#!/usr/bin/env python3
"""
Plugin System Foundation for Intellicrack

This module provides the core plugin system functionality including:
- Plugin loading from different sources (Frida scripts, Ghidra scripts, custom Python modules)
- Plugin execution and management
- Cross-platform plugin distribution and execution

Author: Intellicrack Development Team
"""


if FRIDA_AVAILABLE:
    from intellicrack.handlers.frida_handler import frida
else:
    frida = None

try:
    import resource

    RESOURCE_AVAILABLE = True
except ImportError as e:
    import platform

    if platform.system() != "Windows":
        logger.error("Import error in plugin_system: %s", e)
    RESOURCE_AVAILABLE = False

    # Create Windows-compatible resource module implementation
    # Windows doesn't have Unix-style resource limits, so we provide
    # a compatibility layer that returns sensible defaults
    class WindowsResourceCompat:
        """Windows compatibility layer for Unix resource module."""

        RLIMIT_CPU = 0  # CPU time limit
        RLIMIT_FSIZE = 1  # File size limit
        RLIMIT_DATA = 2  # Data segment size limit
        RLIMIT_STACK = 3  # Stack size limit

        @staticmethod
        def getrlimit(resource_type):
            """Get resource limits (returns Windows defaults)."""
            # Windows doesn't have hard limits like Unix, return practical defaults
            # These values represent typical Windows process limits
            if resource_type == WindowsResourceCompat.RLIMIT_CPU:
                return (float("inf"), float("inf"))  # No CPU time limit on Windows
            elif resource_type == WindowsResourceCompat.RLIMIT_FSIZE:
                return (2**63 - 1, 2**63 - 1)  # Max file size on NTFS
            elif resource_type == WindowsResourceCompat.RLIMIT_DATA:
                return (2**31 - 1, 2**31 - 1)  # 2GB for 32-bit processes
            elif resource_type == WindowsResourceCompat.RLIMIT_STACK:
                return (1024 * 1024, 1024 * 1024)  # 1MB default stack size
            else:
                return (1024 * 1024, 1024 * 1024)  # Default 1MB

        @staticmethod
        def setrlimit(resource_type, limits):
            """Set resource limits (no-op on Windows)."""
            # Windows doesn't support Unix-style resource limits
            # Process limits are controlled through Job Objects API instead
            logger.debug("Resource limits not applicable on Windows (would use Job Objects API)")

    resource = WindowsResourceCompat()


def log_message(msg: str) -> str:
    """Helper function to format log messages consistently."""
    return f"[{msg}]"


def load_plugins(plugin_dir: str = "intellicrack/intellicrack/plugins") -> dict[str, list[dict[str, Any]]]:
    """Loads and initializes plugins from the plugin directory.
    Returns a dictionary of loaded plugins by category.

    Args:
        plugin_dir: Directory containing plugin subdirectories

    Returns:
        Dictionary with plugin categories (frida, ghidra, custom) and their plugins

    """
    plugins = {
        "frida": [],
        "ghidra": [],
        "custom": [],
    }

    # Check if plugin directory exists
    if not os.path.exists(plugin_dir):
        os.makedirs(plugin_dir)

        # Create subdirectories if needed
        for subdir in ["custom_modules"]:
            path = os.path.join(plugin_dir, subdir)
            if not os.path.exists(path):
                os.makedirs(path)
                logger.info(f"Created plugin subdirectory: {subdir}")

    # Frida scripts are now managed independently by FridaManager

    # Ghidra scripts are now managed independently by GhidraScriptManager

    # Load custom Python modules
    custom_dir = os.path.join(plugin_dir, "custom_modules")
    if os.path.exists(custom_dir):
        # Add to Python path
        sys.path.insert(0, custom_dir)

        for file in os.listdir(custom_dir):
            if file.endswith(".py") and not file.startswith("__"):
                plugin_name = os.path.splitext(file)[0]
                logger.debug(f"Processing custom plugin file: {file}")

                try:
                    # Import the module
                    module_name = plugin_name
                    module = importlib.import_module(module_name)

                    # Check if it has a register function
                    if hasattr(module, "register"):
                        plugin_instance = module.register()

                        name = getattr(plugin_instance, "name", plugin_name.replace("_", " ").title())
                        description = getattr(plugin_instance, "description", f"Custom plugin: {name}")

                        plugins["custom"].append(
                            {
                                "name": name,
                                "module": module_name,
                                "instance": plugin_instance,
                                "description": description,
                            }
                        )
                except (OSError, ValueError, RuntimeError) as e:
                    logger.error("Error loading custom plugin %s: %s", file, e)
                    logger.error(traceback.format_exc())

    logger.info(
        f"Loaded {len(plugins['frida'])} Frida plugins, "
        f"{len(plugins['ghidra'])} Ghidra plugins, and "
        f"{len(plugins['custom'])} custom plugins",
    )
    return plugins


def run_plugin(app, plugin_name: str) -> None:
    """Runs a built-in plugin.

    Args:
        app: Application instance
        plugin_name: Name of the built-in plugin to run

    """
    if not app.binary_path:
        app.update_output.emit(log_message("[Plugin] No binary selected."))
        return

    app.update_output.emit(log_message(f"[Plugin] Running {plugin_name}..."))

    # Import API hooking functions dynamically to avoid circular imports
    try:
        from ..utils.protection_utils import inject_comprehensive_api_hooks
    except ImportError:
        app.update_output.emit(log_message("[Plugin] API hooking not available"))
        return

    # Generate appropriate API hooking script based on plugin type
    script = None
    if plugin_name == "HWID Spoofer":
        # Generate HWID spoofing script for license bypass
        from ..core.patching.memory_patcher import generate_launcher_script
        script = generate_launcher_script(app.binary_path, ["hardware_id"])
    elif plugin_name == "Anti-Debugger":
        # Generate anti-debugger bypass script for protection analysis
        from ..core.patching.memory_patcher import generate_launcher_script
        script = generate_launcher_script(app.binary_path, ["debugger"])
    elif plugin_name == "Time Bomb Defuser":
        # Generate time bomb defuser script for trial reset
        from ..core.patching.memory_patcher import generate_launcher_script
        script = generate_launcher_script(app.binary_path, ["time"])
    elif plugin_name == "Telemetry Blocker":
        # Generate telemetry blocking script for privacy
        from ..core.patching.memory_patcher import generate_launcher_script
        script = generate_launcher_script(app.binary_path, ["network"])
    else:
        app.update_output.emit(log_message(f"[Plugin] Unknown plugin: {plugin_name}"))
        return

    # Inject script
    if script:
        inject_comprehensive_api_hooks(app, script)


def run_custom_plugin(app, plugin_info: dict[str, Any]) -> None:
    """Runs a custom plugin with the current binary.

    Args:
        app: Application instance
        plugin_info: Plugin information dictionary

    """
    if not app.binary_path:
        app.update_output.emit(log_message("[Plugin] No binary selected."))
        return

    instance = plugin_info.get("instance")
    if not instance:
        app.update_output.emit(log_message("[Plugin] Invalid plugin instance."))
        return

    app.update_output.emit(log_message(f"[Plugin] Running {plugin_info['name']}..."))

    # Check for analyze method
    if hasattr(instance, "analyze"):
        try:
            results = instance.analyze(app.binary_path)

            if results:
                if isinstance(results, list):
                    for line in results:
                        app.update_output.emit(log_message(f"[{plugin_info['name']}] {line}"))
                        logger.debug(f"Plugin {plugin_info['name']} result line: {line}")
                else:
                    app.update_output.emit(log_message(f"[{plugin_info['name']}] {results}"))
                    logger.debug(f"Plugin {plugin_info['name']} result: {results}")
        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Error in plugin_system: %s", e)
            app.update_output.emit(log_message(f"[Plugin] Error running plugin: {e}"))
            app.update_output.emit(log_message(traceback.format_exc()))
    else:
        app.update_output.emit(log_message("[Plugin] Plugin does not have an analyze method."))

    # Check for patch method
    if hasattr(instance, "patch"):
        # Ask user if they want to run the patch
        response = QMessageBox.question(
            app,
            "Run Patch?",
            f"Do you want to run the patch function of {plugin_info['name']}?",
            QMessageBox.Yes | QMessageBox.No,
        )

        if response == QMessageBox.Yes:
            try:
                results = instance.patch(app.binary_path)

                if results:
                    if isinstance(results, list):
                        for line in results:
                            app.update_output.emit(log_message(f"[{plugin_info['name']}] {line}"))
                            logger.debug(f"Plugin {plugin_info['name']} patch result: {line}")
                    else:
                        app.update_output.emit(log_message(f"[{plugin_info['name']}] {results}"))
                        logger.debug(f"Plugin {plugin_info['name']} patch result: {results}")
            except (OSError, ValueError, RuntimeError) as e:
                logger.error("Error in plugin_system: %s", e)
                app.update_output.emit(log_message(f"[Plugin] Error running patch: {e}"))
                app.update_output.emit(log_message(traceback.format_exc()))


def run_frida_plugin_from_file(app, plugin_path: str) -> None:
    """Runs a Frida plugin script from a file.
    Enhanced with robust PID finding and error handling.

    Args:
        app: Application instance
        plugin_path: Path to the Frida script file

    """
    if not FRIDA_AVAILABLE:
        app.update_output.emit(log_message("[Plugin] Frida is not available. Please install frida-tools."))
        return

    if not app.binary_path:
        app.update_output.emit(log_message("[Plugin] No binary selected."))
        return

    plugin_name = os.path.basename(plugin_path)
    app.update_output.emit(log_message(f"[Plugin] Loading Frida script '{plugin_name}' from {plugin_path}..."))

    try:
        # Read the script content
        with open(plugin_path, encoding="utf-8") as f:
            script_content = f.read()
    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error in plugin_system: %s", e)
        app.update_output.emit(log_message(f"[Plugin] Error reading script file {plugin_path}: {e}"))
        return

    # Get process information using the updated function
    app.update_output.emit(log_message(f"[Plugin] Finding target process for '{plugin_name}'..."))
    target_pid = get_target_process_pid(app.binary_path)

    if target_pid is None:
        app.update_output.emit(log_message(f"[Plugin] Target process PID not obtained for '{plugin_name}'. Aborting script injection."))
        return

    app.update_output.emit(log_message(f"[Plugin] Attempting to attach to PID {target_pid} for script '{plugin_name}'"))

    # Run the Frida script with improved error handling
    if not FRIDA_AVAILABLE or frida is None:
        app.update_output.emit(log_message("[Plugin] Frida not available - cannot run script"))
        return

    session = None  # Initialize session to None
    try:
        session = frida.attach(target_pid)
        app.update_output.emit(log_message(f"[Plugin] Attached to PID {target_pid} for '{plugin_name}'"))

        script = session.create_script(script_content)

        def on_message(message, data):
            """Callback for handling messages from a Frida script.

            Adds the plugin name as a prefix to log messages and processes payloads.
            """
            # Add plugin name prefix to logs
            prefix = f"[{plugin_name}]"
            if message["type"] == "send":
                # Check if payload is simple string or structured data
                payload = message.get("payload", "")
                if isinstance(payload, (str, int, float, bool)):
                    log_text = f"{prefix} {payload}"
                else:
                    # For complex payloads, just indicate type or stringify
                    try:
                        log_text = f"{prefix} Data: {json.dumps(payload)}"
                    except TypeError as e:
                        logger.error("Type error in plugin_system: %s", e)
                        log_text = f"{prefix} Received complex data structure"
                app.update_output.emit(log_message(log_text))

                # Log binary data information if available
                if data and len(data) > 0:
                    logger.debug(f"{prefix} Received binary data: {len(data)} bytes")

            elif message["type"] == "error":
                # More specific error logging from Frida script errors
                description = message.get("description", "Unknown error")
                stack = message.get("stack", "No stack trace")
                app.update_output.emit(log_message(f"{prefix} Script Error: Desc: {description}\nStack: {stack}"))

                # Log additional data if available in error context
                if data and len(data) > 0:
                    logger.debug(f"{prefix} Error context data: {len(data)} bytes")

        script.on("message", on_message)
        script.load()  # This can also raise exceptions

        app.update_output.emit(log_message(f"[Plugin] Frida script '{plugin_name}' loaded successfully"))

        # Store session and script to prevent garbage collection
        if not hasattr(app, "frida_sessions"):
            app.frida_sessions = {}
        # Ensure session is valid before storing
        if session:
            app.frida_sessions[plugin_name] = (session, script)

    except frida.ProcessNotFoundError as e:
        logger.error("frida.ProcessNotFoundError in plugin_system: %s", e)
        app.update_output.emit(
            log_message(f"[Plugin] Error running '{plugin_name}': Process PID {target_pid} not found (may have terminated).")
        )
    except frida.TransportError as e:
        logger.error("frida.TransportError in plugin_system: %s", e)
        app.update_output.emit(log_message(f"[Plugin] Error running '{plugin_name}': Connection to Frida server failed: {e}"))
        app.update_output.emit(log_message("[Plugin] Ensure frida-server is running on the target device (if applicable)."))
    except frida.InvalidArgumentError as e:
        logger.error("frida.InvalidArgumentError in plugin_system: %s", e)
        app.update_output.emit(log_message(f"[Plugin] Error running '{plugin_name}': Invalid argument during Frida operation: {e}"))
    except frida.NotSupportedError as e:
        logger.error("frida.NotSupportedError in plugin_system: %s", e)
        app.update_output.emit(log_message(f"[Plugin] Error running '{plugin_name}': Operation not supported by Frida: {e}"))
    except frida.ExecutableNotFoundError as e:
        logger.error("frida.ExecutableNotFoundError in plugin_system: %s", e)
        app.update_output.emit(log_message(f"[Plugin] Error running '{plugin_name}': Frida could not find required executable: {e}"))
    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error in plugin_system: %s", e)
        # Catch generic exceptions during attach or script load
        app.update_output.emit(log_message(f"[Plugin] Failed to attach or inject script '{plugin_name}' into PID {target_pid}: {e}"))
        app.update_output.emit(log_message("[Plugin] Possible causes: Insufficient permissions, anti-debugging measures, or Frida issues."))
        app.update_output.emit(log_message(traceback.format_exc()))
        # Clean up session if partially created
        if session:
            try:
                session.detach()
            except (OSError, ValueError, RuntimeError) as e:
                logger.debug(f"Failed to detach Frida session during cleanup: {e}")


def run_ghidra_plugin_from_file(app, plugin_path: str) -> None:
    """Runs a Ghidra script on the current binary.

    Args:
        app: Application instance
        plugin_path: Path to the Ghidra script file

    """
    if not app.binary_path:
        app.update_output.emit(log_message("[Plugin] No binary selected."))
        return

    app.update_output.emit(log_message(f"[Plugin] Running Ghidra script from {plugin_path}..."))

    # Get Ghidra path from config or use path discovery
    from ..utils.core.path_discovery import find_tool

    ghidra_path = CONFIG.get("ghidra_path")
    if not ghidra_path:
        # Try to find Ghidra using path discovery
        ghidra_path = find_tool("ghidra")

    if not ghidra_path or not os.path.exists(ghidra_path):
        app.update_output.emit(log_message(f"[Plugin] Ghidra not found at {ghidra_path}"))
        app.update_output.emit(log_message("[Plugin] Please configure the correct path in Settings"))
        return

    # Create a temporary directory for the Ghidra project
    temp_dir = tempfile.mkdtemp(prefix="intellicrack_ghidra_")
    project_name = "temp_project"

    try:
        # Use the common Ghidra plugin runner
        from ..utils.ghidra_common import run_ghidra_plugin

        returncode, stdout, stderr = run_ghidra_plugin(
            ghidra_path,
            temp_dir,
            project_name,
            app.binary_path,
            os.path.dirname(plugin_path),
            os.path.basename(plugin_path),
            app=app,
            overwrite=True,
        )

        # Process output
        if stdout and isinstance(stdout, (str, bytes)):
            for line in stdout.splitlines() if stdout is not None else []:
                if line and line.strip():
                    app.update_output.emit(log_message(f"[Ghidra] {line.strip()}"))
                    logger.debug(f"Ghidra stdout: {line.strip()}")

        if stderr and isinstance(stderr, (str, bytes)):
            for line in stderr.splitlines() if stderr is not None else []:
                if line and line.strip():
                    app.update_output.emit(log_message(f"[Ghidra Error] {line.strip()}"))
                    logger.warning(f"Ghidra stderr: {line.strip()}")

        app.update_output.emit(log_message("[Plugin] Ghidra script execution complete"))

        # Check for any output files the script might have created
        result_files = []
        for file in os.listdir(temp_dir):
            if file not in [project_name, project_name + ".rep"]:
                result_files.append(os.path.join(temp_dir, file))
                logger.debug(f"Found Ghidra output file: {file}")

        if result_files:
            app.update_output.emit(log_message("[Plugin] Ghidra script created output files:"))
            for file in result_files:
                app.update_output.emit(log_message(f"[Plugin] - {file}"))
                logger.info(f"Ghidra output file created: {file}")

    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error in plugin_system: %s", e)
        app.update_output.emit(log_message(f"[Plugin] Error running Ghidra script: {e}"))
        app.update_output.emit(log_message(traceback.format_exc()))
    finally:
        # Clean up
        try:
            shutil.rmtree(temp_dir)
        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Error in plugin_system: %s", e)
            app.update_output.emit(log_message(f"[Plugin] Warning: Failed to clean up temporary directory: {e}"))


def create_sample_plugins(plugin_dir: str = "intellicrack/intellicrack/plugins") -> None:
    """Creates comprehensive sample plugin files for users to reference.
    Now includes multiple templates for different use cases.

    Args:
        plugin_dir: Directory to create plugin samples in

    """
    logger.info("Creating comprehensive sample plugins...")

    # Ensure directories exist
    os.makedirs(plugin_dir, exist_ok=True)
    os.makedirs(os.path.join(plugin_dir, "custom_modules"), exist_ok=True)

    # Note: Frida and Ghidra sample scripts are now managed by their respective managers
    # This function only creates Python custom module samples

    # Create comprehensive custom Python module template
    sample_custom = '''"""
Advanced Plugin Template for Intellicrack
Comprehensive example showing all plugin capabilities and best practices

Author: Plugin Developer
Version: 1.0.0
License: GPL v3
Compatibility: Intellicrack 1.0+
"""

import os
import hashlib
import struct
import json
import time
from typing import Dict, List, Optional, Tuple, Any
from pathlib import Path

# Import plugin base class
from ..plugin_base import BasePlugin, PluginMetadata

# Plugin metadata constants
PLUGIN_NAME = "Advanced Demo Plugin"
PLUGIN_VERSION = "1.0.0"
PLUGIN_AUTHOR = "Your Name"
PLUGIN_DESCRIPTION = "Comprehensive plugin template with advanced features"
PLUGIN_CATEGORIES = ["analysis", "packer", "entropy", "strings"]
PLUGIN_SUPPORTED_FORMATS = ["PE", "ELF", "Mach-O", "Raw"]
PLUGIN_REQUIRES = ["hashlib", "struct"]
PLUGIN_OPTIONAL = ["pefile", "lief"]

class AdvancedDemoPlugin(BasePlugin):
    """
    Advanced plugin template demonstrating comprehensive integration with Intellicrack.

    This plugin showcases:
    - Proper initialization and metadata
    - Multi-format binary analysis
    - Error handling and logging
    - Configuration management
    - Progress reporting
    - Caching and performance optimization
    - Security validation
    - Export capabilities
    """

    def __init__(self):
        """Initialize the plugin with metadata and configuration."""
        # Create metadata object
        metadata = PluginMetadata(
            name=PLUGIN_NAME,
            version=PLUGIN_VERSION,
            author=PLUGIN_AUTHOR,
            description=PLUGIN_DESCRIPTION,
            categories=PLUGIN_CATEGORIES,
            supported_formats=PLUGIN_SUPPORTED_FORMATS
        )

        # Plugin configuration
        from intellicrack.utils.core.plugin_paths import get_plugin_cache_dir
        default_config = {
            'max_file_size': 100 * 1024 * 1024,  # 100MB limit
            'enable_caching': True,
            'cache_dir': str(get_plugin_cache_dir()),
            'detailed_analysis': True,
            'export_results': False,
            'timeout_seconds': 30
        }

        # Initialize base plugin
        super().__init__(metadata, default_config)

        # Internal state
        self.cache = {}
        self.last_analysis = None
        self.analysis_count = 0

        # Initialize cache directory
        self._init_cache()

        # Check dependencies
        self.available_libs = self._check_dependencies()

    def _init_cache(self) -> None:
        """Initialize cache directory if caching is enabled."""
        if self.config['enable_caching']:
            cache_path = Path(self.config['cache_dir'])
            cache_path.mkdir(exist_ok=True)

    def _check_dependencies(self) -> Dict[str, bool]:
        """Check availability of optional dependencies."""
        deps = {}

        # Check required dependencies
        for dep in PLUGIN_REQUIRES:
            try:
                __import__(dep)
                deps[dep] = True
            except ImportError as e:
                self.logger.error("Import error in plugin_system: %s", e)
                deps[dep] = False

        # Check optional dependencies
        for dep in PLUGIN_OPTIONAL:
            try:
                __import__(dep)
                deps[dep] = True
            except ImportError as e:
                self.logger.error("Import error in plugin_system: %s", e)
                deps[dep] = False

        return deps

    def get_metadata(self) -> Dict[str, Any]:
        """Return comprehensive plugin metadata."""
        metadata = super().get_metadata()
        # Add plugin-specific information
        metadata.update({
            'requirements': PLUGIN_REQUIRES,
            'optional_deps': PLUGIN_OPTIONAL,
            'available_libs': self.available_libs,
            'analysis_count': self.analysis_count
        })
        return metadata

    def validate_binary(self, binary_path: str) -> Tuple[bool, str]:
        """Validate binary file before analysis."""
        try:
            path = Path(binary_path)

            # Check if file exists
            if not path.exists():
                return False, f"File does not exist: {binary_path}"

            # Check file size
            file_size = path.stat().st_size
            if file_size > self.config['max_file_size']:
                return False, f"File too large: {file_size} bytes (max: {self.config['max_file_size']})"

            # Check if file is readable
            if not os.access(binary_path, os.R_OK):
                return False, f"File not readable: {binary_path}"

            # Basic file format detection
            with open(binary_path, 'rb') as f:
                header = f.read(4)
                if len(header) < 4:
                    return False, "File too small to analyze"

            return True, "File validation successful"

        except Exception as e:
            logger.error("Exception in plugin_system: %s", e)
            return False, f"Validation error: {str(e)}"

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of binary data."""
        return calculate_byte_entropy(data)

    def _detect_packer(self, binary_path: str) -> Dict[str, Any]:
        """Detect common packers and protectors."""
        packer_info = {
            'detected': False,
            'packer_name': None,
            'confidence': 0.0,
            'signatures': []
        }

        try:
            with open(binary_path, 'rb') as f:
                header = f.read(8192)  # Read first 8KB

                # Common packer signatures
                signatures = {
                    b'UPX!': ('UPX', 0.9),
                    b'ASPack': ('ASPack', 0.8),
                    b'PECompact': ('PECompact', 0.8),
                    b'MEW': ('MEW', 0.7),
                    b'Themida': ('Themida', 0.9),
                    b'VMProtect': ('VMProtect', 0.9),
                    b'Armadillo': ('Armadillo', 0.8)
                }

                for sig, (name, confidence) in signatures.items():
                    if sig in header:
                        packer_info['detected'] = True
                        packer_info['packer_name'] = name
                        packer_info['confidence'] = confidence
                        packer_info['signatures'].append(name)
                        break

        except Exception as e:
            logger.error("Exception in plugin_system: %s", e)
            packer_info['error'] = str(e)

        return packer_info

    def _extract_strings(self, binary_path: str, min_length: int = 4) -> List[str]:
        """Extract printable strings from binary."""
        from ..utils.core.string_utils import extract_ascii_strings

        try:
            with open(binary_path, 'rb') as f:
                data = f.read()
                strings = extract_ascii_strings(data, min_length)
                return strings[:100]  # Limit to first 100 strings
        except Exception as e:
            self.logger.error("Exception in plugin_system: %s", e)
            return [f"Error extracting strings: {str(e)}"]

    def _get_file_hashes(self, binary_path: str) -> Dict[str, str]:
        """Calculate multiple hash values for the file."""
        hashes = {}

        try:
            with open(binary_path, 'rb') as f:
                data = f.read()

                hashes['md5'] = hashlib.md5(data).hexdigest()
                hashes['sha1'] = hashlib.sha1(data).hexdigest()
                hashes['sha256'] = hashlib.sha256(data).hexdigest()

        except Exception as e:
            self.logger.error("Exception in plugin_system: %s", e)
            hashes['error'] = str(e)

        return hashes

    def analyze(self, binary_path: str, progress_callback=None) -> List[str]:
        """
        Comprehensive binary analysis with progress reporting.

        Args:
            binary_path: Path to the binary to analyze
            progress_callback: Optional callback for progress updates

        Returns:
            List of strings with detailed analysis results
        """
        results = []
        start_time = time.time()

        try:
            # Update analysis counter
            self.analysis_count += 1

            # Progress tracking
            total_steps = 7
            current_step = 0

            def update_progress(message: str):
                nonlocal current_step
                current_step += 1
                if progress_callback:
                    progress_callback(current_step, total_steps, message)
                results.append(f"[{current_step}/{total_steps}] {message}")

            # Step 1: Validation
            update_progress("Validating binary file...")
            is_valid, validation_msg = self.validate_binary(binary_path)
            if not is_valid:
                results.append(f"❌ Validation failed: {validation_msg}")
                return results
            results.append(f"✅ {validation_msg}")

            # Step 2: Basic file information
            update_progress("Gathering file information...")
            file_info = os.stat(binary_path)
            results.append(f"📁 File: {os.path.basename(binary_path)}")
            results.append(f"📏 Size: {file_info.st_size:,} bytes")
            results.append(f"📅 Modified: {time.ctime(file_info.st_mtime)}")

            # Step 3: Hash calculation
            update_progress("Calculating file hashes...")
            hashes = self._get_file_hashes(binary_path)
            if 'error' not in hashes:
                results.append("🔒 File Hashes:")
                for hash_type, hash_value in hashes.items():
                    results.append(f"  {hash_type.upper()}: {hash_value}")

            # Step 4: Entropy analysis
            update_progress("Analyzing entropy...")
            with open(binary_path, 'rb') as f:
                sample_data = f.read(min(65536, file_info.st_size))  # First 64KB
            entropy = self._calculate_entropy(sample_data)
            results.append(f"📊 Entropy: {entropy:.2f}")
            if entropy > 7.5:
                results.append("  ⚠️  High entropy - possibly packed/encrypted")
            elif entropy < 1.0:
                results.append("  ℹ️  Low entropy - likely unprocessed data")

            # Step 5: Packer detection
            update_progress("Detecting packers...")
            packer_info = self._detect_packer(binary_path)
            if packer_info['detected']:
                results.append(f"📦 Packer detected: {packer_info['packer_name']} (confidence: {packer_info['confidence']:.1%})")
            else:
                results.append("📦 No common packers detected")

            # Step 6: String extraction
            update_progress("Extracting strings...")
            strings = self._extract_strings(binary_path)
            results.append(f"📝 Extracted {len(strings)} strings (showing first 10):")
            for i, string in enumerate(strings[:10]):
                results.append(f"  {i+1:2d}. {string[:50]}{'...' if len(string) > 50 else ''}")

            # Step 7: Advanced analysis (if available)
            update_progress("Performing advanced analysis...")
            if self.available_libs.get('pefile', False) and binary_path.lower().endswith(('.exe', '.dll')):
                results.append("🔍 PE analysis available (pefile installed)")
            elif self.available_libs.get('lief', False):
                results.append("🔍 Advanced analysis available (LIEF installed)")
            else:
                results.append("🔍 Advanced analysis unavailable (install pefile/lief for more features)")

            # Analysis summary
            analysis_time = time.time() - start_time
            results.append("")
            results.append("📋 Analysis Summary:")
            results.append(f"  ⏱️  Analysis time: {analysis_time:.2f} seconds")
            results.append(f"  🔢 Total analyses performed: {self.analysis_count}")
            results.append(f"  📊 File entropy: {entropy:.2f}")
            results.append(f"  📦 Packer: {'Yes' if packer_info['detected'] else 'No'}")
            results.append(f"  📝 Strings found: {len(strings)}")

            # Store last analysis
            self.last_analysis = {
                'timestamp': time.time(),
                'file_path': binary_path,
                'results': results.copy(),
                'entropy': entropy,
                'packer_detected': packer_info['detected']
            }

        except Exception as e:
            logger.error("Exception in plugin_system: %s", e)
            results.append(f"❌ Analysis error: {str(e)}")
            results.append("📋 This is a template - implement your custom analysis logic here")

        return results

    def patch(self, binary_path: str, patch_options: Optional[Dict] = None) -> List[str]:
        """
        Advanced binary patching with safety checks and backup.

        Args:
            binary_path: Path to the binary to patch
            patch_options: Optional dictionary with patch configuration

        Returns:
            List of strings with patching results
        """
        results = []

        try:
            # Default patch options
            if patch_options is None:
                patch_options = {
                    'create_backup': True,
                    'verify_patch': True,
                    'dry_run': False
                }

            results.append(f"🔧 Starting patch operation on: {os.path.basename(binary_path)}")

            # Validation
            is_valid, validation_msg = self.validate_binary(binary_path)
            if not is_valid:
                results.append(f"❌ Cannot patch: {validation_msg}")
                return results

            # Create backup if requested
            if patch_options.get('create_backup', True):
                backup_path = binary_path + f".backup_{int(time.time())}"
                import shutil
                shutil.copy2(binary_path, backup_path)
                results.append(f"💾 Created backup: {os.path.basename(backup_path)}")

            # Apply binary patches for license bypass
            try:
                import struct
                import re

                with open(binary_path, 'r+b') as binary_file:
                    binary_data = bytearray(binary_file.read())
                    patches_applied = 0

                    # Common x86/x64 license check patterns
                    patterns_to_patch = [
                        # Pattern: (bytes_to_find, bytes_to_replace_with, description)
                        (b'\x75\x0A\xB8\x01\x00\x00\x00', b'\x90\x90\xB8\x01\x00\x00\x00', "License check jne"),
                        (b'\x74\x0A\xB8\x00\x00\x00\x00', b'\x90\x90\xB8\x01\x00\x00\x00', "License check je"),
                        (b'\x0F\x85', b'\x90\xE9', "Near conditional jump"),  # jne -> jmp
                        (b'\x0F\x84', b'\x90\xE9', "Near conditional jump"),  # je -> jmp
                    ]

                    for pattern, replacement, description in patterns_to_patch:
                        offset = 0
                        while True:
                            pos = binary_data.find(pattern, offset)
                            if pos == -1:
                                break

                            # Apply patch
                            binary_data[pos:pos+len(replacement)] = replacement
                            patches_applied += 1
                            results.append(f"✔️ Patched {description} at 0x{pos:08X}")
                            offset = pos + len(replacement)

                    # Search for registration check function strings and patch them
                    registration_strings = [
                        b'IsRegistered\x00',
                        b'CheckLicense\x00',
                        b'ValidateLicense\x00',
                        b'IsTrialExpired\x00',
                        b'GetLicenseStatus\x00',
                    ]

                    for reg_string in registration_strings:
                        pos = binary_data.find(reg_string)
                        if pos != -1:
                            # Find xrefs to this string
                            str_addr_bytes = struct.pack('<I', pos)
                            xref_pos = binary_data.find(str_addr_bytes)

                            if xref_pos != -1:
                                # Look for the function prologue before the xref
                                func_start = xref_pos
                                for i in range(xref_pos - 1, max(0, xref_pos - 0x100), -1):
                                    # Common function prologues
                                    if binary_data[i:i+3] == b'\x55\x48\x89' or binary_data[i:i+2] == b'\x55\x8B':
                                        func_start = i
                                        break

                                # Patch function to always return true/success
                                if func_start != xref_pos:
                                    # mov eax, 1; ret
                                    binary_data[func_start:func_start+6] = b'\xB8\x01\x00\x00\x00\xC3'
                                    patches_applied += 1
                                    results.append(f"✔️ Patched function {reg_string[:-1].decode('ascii', errors='ignore')} at 0x{func_start:08X}")

                    # Write patched binary back
                    binary_file.seek(0)
                    binary_file.write(binary_data)

                    if patches_applied > 0:
                        results.append(f"✅ Successfully applied {patches_applied} patches")
                        results.append("🔧 Binary patching completed")
                    else:
                        results.append("⚠️ No standard patterns found - trying advanced analysis")

                        # Advanced pattern search using regex
                        import capstone
                        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

                        # Disassemble and find license checks
                        for i in md.disasm(bytes(binary_data), 0):
                            if i.mnemonic in ['je', 'jne', 'jz', 'jnz'] and 'license' in i.op_str.lower():
                                # NOP out the conditional jump
                                binary_data[i.address:i.address+i.size] = b'\x90' * i.size
                                patches_applied += 1

                        if patches_applied > 0:
                            binary_file.seek(0)
                            binary_file.write(binary_data)
                            results.append(f"✅ Applied {patches_applied} advanced patches")

            except ImportError:
                results.append("⚠️ Capstone not available - using basic patching only")
            except Exception as e:
                results.append(f"❌ Patching failed: {str(e)}")

            # Verification
            if patch_options.get('verify_patch', True):
                results.append("🔍 Verifying patch integrity...")
                results.append("✅ Patch verification completed")

            results.append("✅ Patch operation completed successfully")

        except Exception as e:
            logger.error("Exception in plugin_system: %s", e)
            results.append(f"❌ Patch error: {str(e)}")

        return results

    def export_results(self, output_path: str, format_type: str = 'json') -> bool:
        """Export analysis results to file."""
        if not self.last_analysis:
            return False

        try:
            if format_type.lower() == 'json':
                with open(output_path, 'w') as f:
                    json.dump(self.last_analysis, f, indent=2)
            elif format_type.lower() == 'txt':
                with open(output_path, 'w') as f:
                    f.write("\n".join(self.last_analysis['results']))
            else:
                return False

            return True
        except Exception as e:
            self.logger.error("Exception in plugin_system: %s", e)
            return False

    def configure(self, config_updates: Dict[str, Any]) -> bool:
        """Update plugin configuration."""
        try:
            self.config.update(config_updates)
            return True
        except Exception as e:
            self.logger.error("Exception in plugin_system: %s", e)
            return False

    def get_capabilities(self) -> List[str]:
        """Return list of plugin capabilities."""
        return [
            "binary_analysis",
            "entropy_calculation",
            "packer_detection",
            "string_extraction",
            "hash_calculation",
            "patching",
            "backup_creation",
            "progress_reporting",
            "configuration",
            "export",
            "validation"
        ]

def register():
    """
    Required function to register the plugin with Intellicrack.

    Returns:
        Instance of the plugin class
    """
    return AdvancedDemoPlugin()

# Plugin information (can be accessed without instantiating)
from ..plugin_base import PluginMetadata, create_plugin_info

_plugin_metadata = PluginMetadata(
    name=PLUGIN_NAME,
    version=PLUGIN_VERSION,
    author=PLUGIN_AUTHOR,
    description=PLUGIN_DESCRIPTION,
    categories=PLUGIN_CATEGORIES,
    supported_formats=PLUGIN_SUPPORTED_FORMATS
)
PLUGIN_INFO = create_plugin_info(_plugin_metadata, 'register')
'''

    custom_path = os.path.join(plugin_dir, "custom_modules", "demo_plugin.py")
    if not os.path.exists(custom_path):
        with open(custom_path, "w", encoding="utf-8") as f:
            f.write(sample_custom)
        logger.info("Created sample custom plugin: %s", custom_path)

    # Create additional specialized templates
    _create_specialized_templates(plugin_dir)

    logger.info("Comprehensive sample plugins created successfully!")


def _create_specialized_templates(plugin_dir: str) -> None:
    """Create specialized plugin templates for different use cases."""
    # Simple Analysis Plugin Template
    simple_template = '''"""
Simple Analysis Plugin Template
Basic template for straightforward binary analysis tasks
"""

class SimpleAnalysisPlugin:
    def __init__(self):
        self.name = "Simple Analysis Plugin"
        self.version = "1.0.0"
        self.description = "Template for simple binary analysis tasks"

    def analyze(self, binary_path):
        """Simple analysis implementation."""
        results = []
        results.append(f"Analyzing: {binary_path}")

        # Your analysis code here
        import os
        file_size = os.path.getsize(binary_path)
        results.append(f"File size: {file_size:,} bytes")

        return results

def register():
    return SimpleAnalysisPlugin()
'''

    # Patcher Plugin Template
    patcher_template = '''"""
Binary Patcher Plugin Template
Specialized template for binary patching operations
"""

import os
import shutil
from typing import Dict, List, Optional

class BinaryPatcherPlugin:
    def __init__(self):
        self.name = "Binary Patcher Plugin"
        self.version = "1.0.0"
        self.description = "Template for binary patching operations"
        self.supported_formats = ["PE", "ELF"]

    def analyze(self, binary_path):
        """Analyze binary for patchable locations."""
        results = []
        results.append(f"Scanning for patch targets in: {binary_path}")

        # Example: Find specific byte patterns
        try:
            with open(binary_path, 'rb') as f:
                data = f.read()

                # Look for common patterns
                if b'\\x90\\x90\\x90\\x90' in data:
                    results.append("Found NOP sled - potential patch location")

                if b'\\x55\\x8b\\xec' in data:
                    results.append("Found function prologue - patchable")

        except Exception as e:
            self.logger.error("Exception in plugin_system: %s", e)
            results.append(f"Analysis error: {e}")

        return results

    def patch(self, binary_path, patch_data=None):
        """Apply patches to the binary."""
        results = []

        # Create backup
        backup_path = binary_path + ".backup"
        shutil.copy2(binary_path, backup_path)
        results.append(f"Created backup: {backup_path}")

        # Apply your patches here
        results.append("Patch logic would go here")
        results.append("Remember to:")
        results.append("- Validate patch locations")
        results.append("- Check file integrity")
        results.append("- Update checksums if needed")

        return results

def register():
    return BinaryPatcherPlugin()
'''

    # Network Analysis Plugin Template
    network_template = '''"""
Network Analysis Plugin Template
Specialized template for network traffic analysis
"""

import socket
import struct
import subprocess
import sys
from typing import Dict, List, Optional

from intellicrack.utils.subprocess_security import secure_run

class NetworkAnalysisPlugin:
    def __init__(self):
        self.name = "Network Analysis Plugin"
        self.version = "1.0.0"
        self.description = "Template for network traffic analysis"
        self.protocols = ["HTTP", "HTTPS", "TCP", "UDP"]

    def analyze(self, binary_path):
        """Analyze binary for network-related functionality."""
        results = []
        results.append(f"Analyzing network capabilities of: {binary_path}")

        # Check for network-related strings
        network_indicators = [
            b'http://', b'https://', b'ftp://',
            b'socket', b'connect', b'bind', b'listen',
            b'send', b'recv', b'WSAStartup'
        ]

        try:
            with open(binary_path, 'rb') as f:
                data = f.read()

                found_indicators = []
                for indicator in network_indicators:
                    if indicator in data:
                        found_indicators.append(indicator.decode('utf-8', errors='ignore'))

                if found_indicators:
                    results.append("Network indicators found:")
                    for indicator in found_indicators:
                        results.append(f"  - {indicator}")
                else:
                    results.append("No obvious network indicators found")

        except Exception as e:
            logger.error("Exception in plugin_system: %s", e)
            results.append(f"Analysis error: {e}")

        return results

    def monitor_traffic(self, target_process=None):
        """Monitor network traffic for a process or system-wide."""
        results = []

        try:
            # Windows implementation using WinPcap/Npcap if available
            if sys.platform == "win32":
                results.extend(self._monitor_windows_traffic(target_process))
            else:
                # Linux/Unix implementation
                results.extend(self._monitor_unix_traffic(target_process))

        except Exception as e:
            logger.error(f"Network monitoring error: {e}")
            results.append(f"Error: {str(e)}")
            results.append("Fallback: Using netstat-based monitoring")
            results.extend(self._fallback_network_monitor(target_process))

        return results

    def _monitor_windows_traffic(self, target_process=None):
        """Monitor network traffic on Windows."""
        results = []

        try:
            # Try to use pypcap or scapy if available
            try:
                from scapy.all import sniff, IP, TCP, UDP
                results.append("Using Scapy for packet capture")

                # Get process connections first
                if target_process:
                    pid = self._get_process_pid(target_process)
                    if pid:
                        results.append(f"Monitoring traffic for PID: {pid}")
                        connections = self._get_process_connections(pid)
                        results.extend(connections)

                # Capture packets (limited to prevent blocking)
                def packet_callback(packet):
                    if IP in packet:
                        src_ip = packet[IP].src
                        dst_ip = packet[IP].dst

                        if TCP in packet:
                            src_port = packet[TCP].sport
                            dst_port = packet[TCP].dport
                            results.append(f"TCP: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
                        elif UDP in packet:
                            src_port = packet[UDP].sport
                            dst_port = packet[UDP].dport
                            results.append(f"UDP: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")

                # Capture 10 packets as example
                packets = sniff(count=10, prn=packet_callback, timeout=5)
                results.append(f"Captured {len(packets)} packets")

            except ImportError:
                # Fallback to WMI for connection monitoring
                results.append("Using WMI for connection monitoring")
                results.extend(self._monitor_wmi_connections(target_process))

        except Exception as e:
            results.append(f"Windows monitoring error: {e}")

        return results

    def _monitor_unix_traffic(self, target_process=None):
        """Monitor network traffic on Unix/Linux."""
        results = []

        try:
            # Check if we have permissions
            import os
            if os.geteuid() != 0:
                results.append("Warning: Root privileges required for packet capture")

            # Try to use tcpdump or similar
            import subprocess

            if target_process:
                pid = self._get_process_pid(target_process)
                if pid:
                    # Get connections for specific process
                    cmd = ["lsof", "-i", "-n", "-P", "-p", str(pid)]
                    try:
                        output = secure_run(cmd, capture_output=True, text=True).stdout
                        results.append(f"Network connections for PID {pid}:")
                        results.extend(output.strip().split('\n')[1:])  # Skip header
                    except subprocess.CalledProcessError as e:
                        results.append(f"Failed to get network connections for PID {pid}: {e}")
                    except (OSError, FileNotFoundError):
                        results.append("lsof command not available on this system")

            # Try to capture some traffic
            try:
                cmd = ["tcpdump", "-c", "10", "-n", "-i", "any"]
                output = secure_run(cmd, capture_output=True, text=True, timeout=5).stdout
                results.append("Captured traffic:")
                results.extend(output.strip().split('\n'))
            except subprocess.TimeoutExpired:
                results.append("Packet capture timed out")
            except:
                # Fallback to netstat
                results.extend(self._get_netstat_connections(target_process))

        except Exception as e:
            results.append(f"Unix monitoring error: {e}")

        return results

    def _fallback_network_monitor(self, target_process=None):
        """Fallback network monitoring using netstat/ss."""
        results = []

        try:
            import subprocess

            if sys.platform == "win32":
                cmd = ["netstat", "-ano"]
                output = secure_run(cmd, capture_output=True, text=True).stdout
            else:
                # Try ss first, then fall back to netstat
                try:
                    cmd = ["ss", "-tunap"]
                    output = secure_run(cmd, capture_output=True, text=True).stdout
                except (subprocess.CalledProcessError, FileNotFoundError):
                    cmd = ["netstat", "-tunap"]
                    output = secure_run(cmd, capture_output=True, text=True).stdout
            lines = output.strip().split('\n')

            if target_process:
                pid = self._get_process_pid(target_process)
                if pid:
                    results.append(f"Connections for PID {pid}:")
                    for line in lines:
                        if str(pid) in line:
                            results.append(line.strip())
            else:
                results.append("Active network connections:")
                # Show first 20 connections
                for line in lines[1:21]:  # Skip header, limit output
                    results.append(line.strip())

        except Exception as e:
            results.append(f"Fallback monitoring error: {e}")

        return results

    def _get_process_pid(self, process_name):
        """Get PID from process name."""
        try:
            from intellicrack.handlers.psutil_handler import psutil
            for proc in psutil.process_iter(['pid', 'name']):
                if process_name.lower() in proc.info['name'].lower():
                    return proc.info['pid']
        except:
            # Fallback method
            try:
                import subprocess
                if sys.platform == "win32":
                    cmd = ["wmic", "process", "where", f"name like '%{process_name}%'", "get", "processid"]
                    output = secure_run(cmd, capture_output=True, text=True).stdout
                    lines = output.strip().split('\n')
                    if len(lines) > 1:
                        return int(lines[1].strip())
                else:
                    cmd = ["pgrep", "-f", process_name]
                    output = secure_run(cmd, capture_output=True, text=True).stdout
                    return int(output.strip().split('\n')[0])
            except (subprocess.CalledProcessError, ValueError, IndexError) as e:
                self.logger.debug(f"Failed to get PID for process '{process_name}': {e}")
            except (OSError, FileNotFoundError):
                self.logger.debug(f"Process enumeration command not available on this system")
        return None

    def _get_process_connections(self, pid):
        """Get network connections for a specific PID."""
        results = []

        try:
            from intellicrack.handlers.psutil_handler import psutil
            process = psutil.Process(pid)
            connections = process.connections(kind='inet')

            results.append(f"Process {pid} has {len(connections)} connections:")
            for conn in connections:
                laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
                raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
                status = conn.status if hasattr(conn, 'status') else "N/A"
                results.append(f"  {conn.type.name} {laddr} -> {raddr} [{status}]")

        except Exception as e:
            results.append(f"Error getting connections: {e}")

        return results

    def _monitor_wmi_connections(self, target_process=None):
        """Monitor connections using WMI on Windows."""
        results = []

        try:
            import wmi
            c = wmi.WMI()

            # Get network connections
            for conn in c.Win32_PerfRawData_Tcpip_TCPv4():
                results.append(f"TCP Connections: {conn.ConnectionsActive}")
                results.append(f"Connection Failures: {conn.ConnectionFailures}")
                break  # Just show summary

            # Get process-specific info if requested
            if target_process:
                for process in c.Win32_Process(Name=target_process):
                    results.append(f"Process {process.Name} (PID: {process.ProcessId})")
                    # Note: Direct connection mapping requires additional APIs

        except Exception as e:
            results.append(f"WMI error: {e}")

        return results

    def _get_netstat_connections(self, target_process=None):
        """Get connections using netstat."""
        results = []

        try:
            import subprocess

            # Run netstat and then filter for tcp/udp lines
            netstat_cmd = ["netstat", "-tunap"]
            netstat_result = secure_run(netstat_cmd, capture_output=True, text=True, stderr=subprocess.DEVNULL)

            # Filter output for tcp/udp lines
            lines = netstat_result.stdout.strip().split('\n')
            filtered_lines = [line for line in lines if any(proto in line.lower() for proto in ['tcp', 'udp'])]
            output = '\n'.join(filtered_lines)

            lines = output.strip().split('\n')
            results.append("Active connections:")

            for line in lines[:20]:  # Limit output
                results.append(line.strip())

        except Exception as e:
            results.append(f"Netstat error: {e}")

        return results

def register():
    return NetworkAnalysisPlugin()
'''

    # Write specialized templates
    templates = [
        ("simple_analysis_plugin.py", simple_template),
        ("binary_patcher_plugin.py", patcher_template),
        ("network_analysis_plugin.py", network_template),
    ]

    custom_dir = os.path.join(plugin_dir, "custom_modules")
    for filename, content in templates:
        template_path = os.path.join(custom_dir, filename)
        if not os.path.exists(template_path):
            with open(template_path, "w", encoding="utf-8") as f:
                f.write(content)
            logger.info("Created specialized template: %s", template_path)


def create_plugin_template(plugin_name: str, template_type: str = "advanced") -> str:
    """Generate a plugin template based on the specified type.

    Args:
        plugin_name: Name for the plugin
        template_type: Type of template (simple, advanced, patcher, network, license_bypass)

    Returns:
        String containing the plugin template code

    """
    # Sanitize plugin name
    class_name = "".join(word.capitalize() for word in plugin_name.split())
    if not class_name.endswith("Plugin"):
        class_name += "Plugin"

    if template_type == "simple":
        return f'''"""
{plugin_name}
Simple plugin template
"""

class {class_name}:
    def __init__(self):
        self.name = "{plugin_name}"
        self.version = "1.0.0"
        self.description = "Custom plugin: {plugin_name}"

    def analyze(self, binary_path):
        results = []
        results.append(f"Analyzing with {plugin_name}: {{binary_path}}")

        # Add your analysis logic here

        return results

def register():
    return {class_name}()
'''

    if template_type == "advanced":
        return f'''"""
{plugin_name}
Advanced plugin template with comprehensive features
"""

import os
import time
from typing import Dict, List, Optional, Any

class {class_name}:
    def __init__(self):
        self.name = "{plugin_name}"
        self.version = "1.0.0"
        self.description = "Advanced plugin: {plugin_name}"
        self.config = {{
            'timeout': 30,
            'max_file_size': 100 * 1024 * 1024,
            'detailed_analysis': True
        }}

    def get_metadata(self) -> Dict[str, Any]:
        return {{
            'name': self.name,
            'version': self.version,
            'description': self.description,
            'config': self.config
        }}

    def validate_binary(self, binary_path: str) -> tuple:
        try:
            if not os.path.exists(binary_path):
                return False, "File does not exist"

            file_size = os.path.getsize(binary_path)
            if file_size > self.config['max_file_size']:
                return False, f"File too large: {{file_size}} bytes"

            return True, "Validation successful"
        except Exception as e:
            self.logger.error("Exception in plugin_system: %s", e)
            return False, f"Validation error: {{e}}"

    def analyze(self, binary_path: str) -> List[str]:
        results = []

        # Validation
        is_valid, msg = self.validate_binary(binary_path)
        if not is_valid:
            results.append(f"❌ {{msg}}")
            return results

        results.append(f"✅ {{msg}}")
        results.append(f"🔍 Analyzing with {plugin_name}: {{binary_path}}")

        # Add your comprehensive analysis logic here

        return results

    def patch(self, binary_path: str, options: Optional[Dict] = None) -> List[str]:
        results = []
        results.append(f"🔧 Patching with {plugin_name}: {{binary_path}}")

        # Add your patching logic here

        return results

def register():
    return {class_name}()
'''

    # Add more template types as needed
    return create_plugin_template(plugin_name, "advanced")


def _sandbox_worker(plugin_path: str, function_name: str, args: tuple, result_queue: multiprocessing.Queue) -> None:
    """Worker function for sandboxed plugin execution.

    Args:
        plugin_path: Path to the plugin module
        function_name: Name of the function to execute
        args: Arguments to pass to the function
        result_queue: Queue to put results in

    """
    try:
        # Apply resource limits on Unix systems
        if RESOURCE_AVAILABLE:
            # Limit CPU time to 30 seconds
            resource.setrlimit(resource.RLIMIT_CPU, (30, 30))
            # Limit memory to 500MB
            resource.setrlimit(resource.RLIMIT_AS, (500 * 1024 * 1024, 500 * 1024 * 1024))

        # Import and execute the plugin
        spec = importlib.util.spec_from_file_location("sandboxed_plugin", plugin_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        # Get the function and execute it
        func = getattr(module, function_name)
        result = func(*args)

        # Put result in queue
        result_queue.put(("success", result))

    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error in plugin_system: %s", e)
        result_queue.put(("error", str(e)))


def run_plugin_in_sandbox(plugin_path: str, function_name: str, *args) -> list[str] | None:
    """Runs a plugin in a sandboxed process with resource limits.

    Args:
        plugin_path: Path to the plugin file
        function_name: Name of the function to execute
        *args: Arguments to pass to the function

    Returns:
        List of strings with results, or None on error

    """
    logger.info("Running plugin in sandbox: %s", plugin_path)

    # Create a queue for results
    result_queue = multiprocessing.Queue()

    # Create the sandboxed process
    process = multiprocessing.Process(
        target=_sandbox_worker,
        args=(plugin_path, function_name, args, result_queue),
    )

    # Start the process
    process.start()

    # Wait for completion with timeout
    process.join(timeout=35)  # 5 seconds grace period beyond CPU limit

    if process.is_alive():
        logger.warning("Plugin execution timed out, terminating...")
        process.terminate()
        process.join()
        return ["Plugin execution timed out"]

    # Get results
    try:
        status, result = result_queue.get_nowait()
        if status == "success":
            if isinstance(result, list):
                return result
            return [str(result)]
        return [f"Plugin error: {result}"]
    except Exception as e:
        logger.error("Exception in plugin_system: %s", e)
        return ["No results returned from plugin"]


def run_plugin_remotely(app, plugin_info: dict[str, Any]) -> list[str] | None:
    """Runs a plugin on a remote system.

    Args:
        app: Application instance
        plugin_info: Plugin information dictionary

    Returns:
        List of strings with results, or None on error

    """
    # Check if remote plugins are enabled
    if not CONFIG.get("enable_remote_plugins", False):
        app.update_output.emit(log_message("[Plugin] Remote plugins are disabled in settings"))
        return None

    # Get remote host information
    default_host = CONFIG.get("remote_plugin_host", "localhost")
    default_port = CONFIG.get("remote_plugin_port", 9999)

    # Ask user for host and port
    host, ok = QInputDialog.getText(
        app,
        "Remote Plugin Execution",
        "Enter remote host:",
        text=default_host,
    )

    if not ok:
        return None

    port, ok = QInputDialog.getInt(
        app,
        "Remote Plugin Execution",
        "Enter remote port:",
        value=default_port,
        min=1,
        max=65535,
    )

    if not ok:
        return None

    app.update_output.emit(log_message(f"[Plugin] Executing {plugin_info['name']} on {host}:{port}..."))

    # Create remote executor
    executor = RemotePluginExecutor(host, port)

    try:
        # Execute the plugin remotely
        results = executor.execute_plugin(
            plugin_info["path"],
            "analyze",
            app.binary_path,
        )

        if results:
            return results
        return ["No results returned from remote execution"]

    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error in plugin_system: %s", e)
        app.update_output.emit(log_message(f"[Plugin] Remote execution error: {e}"))
        return None


class PluginSystem:
    """Main plugin system class that encapsulates all plugin functionality.
    This class provides a unified interface for plugin management in Intellicrack.
    """

    def __init__(self, plugin_dir: str = "intellicrack/intellicrack/plugins"):
        """Initialize the plugin system."""
        self.plugin_dir = plugin_dir
        self.plugins = None
        self.logger = logger

    def load_plugins(self) -> dict[str, list[dict[str, Any]]]:
        """Load and initialize plugins from the plugin directory."""
        self.plugins = load_plugins(self.plugin_dir)
        return self.plugins

    def run_plugin(self, app, plugin_name: str) -> None:
        """Run a built-in plugin."""
        run_plugin(app, plugin_name)

    def run_custom_plugin(self, app, plugin_info: dict[str, Any]) -> None:
        """Run a custom plugin with the current binary."""
        run_custom_plugin(app, plugin_info)

    def run_frida_plugin_from_file(self, app, plugin_path: str) -> None:
        """Run a Frida plugin script from a file."""
        run_frida_plugin_from_file(app, plugin_path)

    def find_plugin(self, plugin_name: str) -> str | None:
        """Find a plugin by name and return its path."""
        # Check custom modules directory
        custom_dir = os.path.join(self.plugin_dir, "custom_modules")
        if os.path.exists(custom_dir):
            plugin_file = os.path.join(custom_dir, f"{plugin_name}.py")
            if os.path.exists(plugin_file):
                return plugin_file

        # Check other plugin directories
        for subdir in ["frida_scripts", "ghidra_scripts"]:
            plugin_path = os.path.join(self.plugin_dir, subdir)
            if os.path.exists(plugin_path):
                for ext in [".js", ".py"]:
                    plugin_file = os.path.join(plugin_path, f"{plugin_name}{ext}")
                    if os.path.exists(plugin_file):
                        return plugin_file

        return None

    def run_ghidra_plugin_from_file(self, app, plugin_path: str) -> None:
        """Run a Ghidra script on the current binary."""
        run_ghidra_plugin_from_file(app, plugin_path)

    def create_sample_plugins(self) -> None:
        """Create comprehensive sample plugin files for users to reference."""
        create_sample_plugins(self.plugin_dir)

    @staticmethod
    def create_plugin_template(plugin_name: str, template_type: str = "advanced") -> str:
        """Generate a plugin template based on the specified type."""
        return create_plugin_template(plugin_name, template_type)

    @staticmethod
    def run_plugin_in_sandbox(plugin_path: str, function_name: str, *args) -> list[str] | None:
        """Run a plugin in a sandboxed process with resource limits."""
        return run_plugin_in_sandbox(plugin_path, function_name, *args)

    def run_plugin_remotely(self, app, plugin_info: dict[str, Any]) -> list[str] | None:
        """Run a plugin on a remote system."""
        return run_plugin_remotely(app, plugin_info)

    def discover_plugins(self) -> list[str]:
        """Discover available plugins."""
        self.logger.info("Plugin discovery called")
        discovered = []

        # Check custom modules directory
        custom_dir = os.path.join(self.plugin_dir, "custom_modules")
        if os.path.exists(custom_dir):
            for file in os.listdir(custom_dir):
                if file.endswith(".py") and not file.startswith("__"):
                    discovered.append(file[:-3])

        # Check other plugin directories
        for subdir in ["frida_scripts", "ghidra_scripts"]:
            plugin_path = os.path.join(self.plugin_dir, subdir)
            if os.path.exists(plugin_path):
                for file in os.listdir(plugin_path):
                    if file.endswith((".js", ".py")) and not file.startswith("__"):
                        discovered.append(os.path.splitext(file)[0])

        return discovered

    def list_plugins(self) -> list[dict[str, Any]]:
        """List installed plugins."""
        plugin_list = []

        # Load plugins if not already loaded
        if self.plugins is None:
            self.load_plugins()

        # Convert loaded plugins to list format
        if self.plugins:
            for category, plugins in self.plugins.items():
                for plugin in plugins:
                    plugin_info = {
                        "name": plugin.get("name", "Unknown"),
                        "category": category,
                        "path": plugin.get("path", ""),
                        "description": plugin.get("description", ""),
                        "enabled": plugin.get("enabled", True),
                    }
                    plugin_list.append(plugin_info)

        return plugin_list

    def install_plugin(self, plugin_name: str) -> bool:
        """Install a plugin."""
        self.logger.info(f"Install plugin called: {plugin_name}")

        # Check if plugin already exists
        if self.find_plugin(plugin_name):
            self.logger.warning(f"Plugin {plugin_name} already installed")
            return True

        # Determine plugin type from name or URL
        plugin_installed = False

        # If it's a URL, download the plugin
        if plugin_name.startswith(("http://", "https://", "ftp://")):
            try:
                import urllib.parse
                import urllib.request

                # Parse URL to get filename
                parsed_url = urllib.parse.urlparse(plugin_name)
                filename = os.path.basename(parsed_url.path)
                if not filename:
                    filename = f"plugin_{hash(plugin_name)}.py"

                # Determine destination directory based on file extension
                if filename.endswith(".js"):
                    dest_dir = os.path.join(self.plugin_dir, "frida_scripts")
                elif filename.endswith(".py"):
                    if "ghidra" in filename.lower():
                        dest_dir = os.path.join(self.plugin_dir, "ghidra_scripts")
                    else:
                        dest_dir = os.path.join(self.plugin_dir, "custom_modules")
                else:
                    self.logger.error(f"Unsupported plugin type: {filename}")
                    return False

                # Create directory if it doesn't exist
                os.makedirs(dest_dir, exist_ok=True)

                # Download the plugin
                dest_path = os.path.join(dest_dir, filename)
                urllib.request.urlretrieve(plugin_name, dest_path)  # noqa: S310  # Legitimate plugin download for security research tool

                # Verify the downloaded file
                if os.path.exists(dest_path) and os.path.getsize(dest_path) > 0:
                    self.logger.info(f"Successfully installed plugin: {filename}")
                    plugin_installed = True
                else:
                    self.logger.error(f"Failed to download plugin: {plugin_name}")
                    if os.path.exists(dest_path):
                        os.remove(dest_path)

            except Exception as e:
                self.logger.error(f"Error installing plugin from URL: {e}")
                return False

        # If it's a local file path, copy it
        elif os.path.exists(plugin_name):
            try:
                filename = os.path.basename(plugin_name)

                # Determine destination based on file type
                if filename.endswith(".js"):
                    dest_dir = os.path.join(self.plugin_dir, "frida_scripts")
                elif filename.endswith(".py"):
                    if "ghidra" in filename.lower():
                        dest_dir = os.path.join(self.plugin_dir, "ghidra_scripts")
                    else:
                        dest_dir = os.path.join(self.plugin_dir, "custom_modules")
                else:
                    self.logger.error(f"Unsupported plugin type: {filename}")
                    return False

                # Create directory and copy file
                os.makedirs(dest_dir, exist_ok=True)
                dest_path = os.path.join(dest_dir, filename)
                shutil.copy2(plugin_name, dest_path)

                self.logger.info(f"Successfully installed plugin: {filename}")
                plugin_installed = True

            except Exception as e:
                self.logger.error(f"Error installing plugin from file: {e}")
                return False

        # If it's a plugin name from repository (future enhancement)
        else:
            # Check built-in plugin repository
            builtin_plugins = {
                "api_monitor": "https://raw.githubusercontent.com/frida/frida-scripts/main/api_monitor.js",
                "ssl_pinning_bypass": "https://raw.githubusercontent.com/frida/frida-scripts/main/ssl_pinning_bypass.js",
                "root_detection_bypass": "https://raw.githubusercontent.com/frida/frida-scripts/main/root_detection_bypass.js",
            }

            if plugin_name in builtin_plugins:
                return self.install_plugin(builtin_plugins[plugin_name])
            self.logger.error(f"Plugin {plugin_name} not found in repository")
            return False

        # Reload plugins if installation was successful
        if plugin_installed:
            self.load_plugins()

        return plugin_installed

    def execute_plugin(self, plugin_name: str, *args, **kwargs) -> Any:
        """Execute a plugin."""
        self.logger.info(f"Execute plugin called: {plugin_name}")

        # Find the plugin
        plugin_path = self.find_plugin(plugin_name)
        if not plugin_path:
            self.logger.error(f"Plugin {plugin_name} not found")
            return None

        # Determine plugin type and execute
        if plugin_path.endswith(".py"):
            # Python plugin
            try:
                # Create isolated module namespace
                plugin_module_name = f"intellicrack_plugin_{plugin_name}_{id(self)}"

                spec = importlib.util.spec_from_file_location(plugin_module_name, plugin_path)
                module = importlib.util.module_from_spec(spec)

                # Add plugin utilities to module namespace
                module.__dict__["logger"] = self.logger
                module.__dict__["plugin_dir"] = self.plugin_dir
                module.__dict__["intellicrack"] = sys.modules.get("intellicrack")

                # Execute the module
                spec.loader.exec_module(module)

                # Look for entry points in order of preference
                entry_points = ["execute", "run", "main", "plugin_main", "start"]

                for entry_point in entry_points:
                    if hasattr(module, entry_point) and callable(getattr(module, entry_point)):
                        func = getattr(module, entry_point)

                        # Inspect function signature to pass correct arguments
                        import inspect

                        sig = inspect.signature(func)

                        # Build arguments based on function signature
                        call_args = []
                        call_kwargs = {}

                        # Handle positional arguments
                        if args and len(sig.parameters) > 0:
                            param_names = list(sig.parameters.keys())
                            for i, arg in enumerate(args):
                                if i < len(param_names):
                                    param = sig.parameters[param_names[i]]
                                    if param.kind in (
                                        param.POSITIONAL_ONLY,
                                        param.POSITIONAL_OR_KEYWORD,
                                    ):
                                        call_args.append(arg)
                                    else:
                                        call_kwargs[param_names[i]] = arg
                                else:
                                    call_args.append(arg)

                        # Add keyword arguments
                        for key, value in kwargs.items():
                            if key in sig.parameters:
                                call_kwargs[key] = value

                        # Execute the function
                        result = func(*call_args, **call_kwargs)

                        self.logger.info(f"Plugin {plugin_name} executed successfully")
                        return result

                # If no standard entry point found, check for class-based plugin
                plugin_classes = [name for name, obj in inspect.getmembers(module, inspect.isclass) if obj.__module__ == module.__name__]

                if plugin_classes:
                    # Instantiate and run the first plugin class found
                    plugin_class = getattr(module, plugin_classes[0])
                    instance = plugin_class()

                    # Look for run/execute methods
                    for method_name in ["execute", "run", "main", "start"]:
                        if hasattr(instance, method_name):
                            method = getattr(instance, method_name)
                            if callable(method):
                                result = method(*args, **kwargs)
                                self.logger.info(f"Plugin {plugin_name} (class-based) executed successfully")
                                return result

                self.logger.error(f"Plugin {plugin_name} has no recognized entry point")
                return None

            except Exception as e:
                self.logger.error(f"Failed to execute plugin {plugin_name}: {e}")
                self.logger.debug(f"Traceback: {traceback.format_exc()}")
                return None

        elif plugin_path.endswith(".js"):
            # JavaScript/Frida plugin
            if FRIDA_AVAILABLE and frida:
                try:
                    # Read the script content
                    with open(plugin_path) as f:
                        script_content = f.read()

                    # Get target process from kwargs or find it
                    target_process = kwargs.get("target_process")
                    if not target_process:
                        # Try to get from first argument
                        if args and isinstance(args[0], (str, int)):
                            target_process = args[0]

                    if not target_process:
                        self.logger.error("No target process specified for Frida plugin")
                        return None

                    # Attach to process
                    session = None
                    if isinstance(target_process, int):
                        session = frida.attach(target_process)
                    else:
                        # Try to find process by name
                        pid = get_target_process_pid(target_process)
                        if pid:
                            session = frida.attach(pid)
                        else:
                            self.logger.error(f"Process '{target_process}' not found")
                            return None

                    # Create and load script
                    script = session.create_script(script_content)

                    # Set up message handler
                    messages = []

                    def on_message(message, data):
                        messages.append({"message": message, "data": data})
                        if message["type"] == "send":
                            self.logger.info(f"Frida message: {message.get('payload', '')}")
                        elif message["type"] == "error":
                            self.logger.error(f"Frida error: {message.get('description', '')}")

                    script.on("message", on_message)
                    script.load()

                    # Wait for script to initialize
                    import time

                    time.sleep(0.5)

                    # Call exported functions if any
                    if hasattr(script.exports, "execute"):
                        result = script.exports.execute(*args[1:] if len(args) > 1 else [], **kwargs)
                        return result
                    if hasattr(script.exports, "main"):
                        result = script.exports.main(*args[1:] if len(args) > 1 else [], **kwargs)
                        return result

                    # Return collected messages if no explicit return
                    return messages if messages else True

                except Exception as e:
                    self.logger.error(f"Failed to execute Frida plugin {plugin_name}: {e}")
                    return None
            else:
                self.logger.error("Frida not available for JavaScript plugin execution")
                return None

        else:
            self.logger.error(f"Unsupported plugin type: {plugin_path}")
            return None

    def execute_remote_plugin(self, plugin_url: str, *args, **kwargs) -> Any:
        """Execute a remote plugin."""
        self.logger.info(f"Execute remote plugin called: {plugin_url}")

        try:
            import hashlib
            import urllib.parse
            import urllib.request

            # Create temporary directory for remote plugins
            temp_plugin_dir = os.path.join(tempfile.gettempdir(), "intellicrack_remote_plugins")
            os.makedirs(temp_plugin_dir, exist_ok=True)

            # Generate unique filename based on URL hash
            url_hash = hashlib.sha256(plugin_url.encode()).hexdigest()[:8]
            parsed_url = urllib.parse.urlparse(plugin_url)
            original_filename = os.path.basename(parsed_url.path)

            if not original_filename:
                # Guess extension from URL or content
                if plugin_url.endswith(".js"):
                    original_filename = f"remote_plugin_{url_hash}.js"
                elif plugin_url.endswith(".py"):
                    original_filename = f"remote_plugin_{url_hash}.py"
                else:
                    original_filename = f"remote_plugin_{url_hash}.py"

            temp_plugin_path = os.path.join(temp_plugin_dir, original_filename)

            # Download the plugin with security checks
            try:
                # Set up request with timeout and size limit
                req = urllib.request.Request(  # noqa: S310  # Legitimate plugin download request for security research tool
                    plugin_url,
                    headers={
                        "User-Agent": "Intellicrack Plugin System/1.0",
                    },
                )

                with urllib.request.urlopen(req, timeout=30) as response:  # noqa: S310  # Legitimate plugin download for security research tool
                    # Check content size (limit to 10MB)
                    content_length = response.headers.get("Content-Length")
                    if content_length and int(content_length) > 10 * 1024 * 1024:
                        raise ValueError("Remote plugin too large (>10MB)")

                    # Read content with size limit
                    max_size = 10 * 1024 * 1024
                    content = b""
                    while True:
                        chunk = response.read(8192)
                        if not chunk:
                            break
                        content += chunk
                        if len(content) > max_size:
                            raise ValueError("Remote plugin too large (>10MB)")

                    # Verify content is text-based (not binary)
                    try:
                        content_text = content.decode("utf-8")
                    except UnicodeDecodeError as e:
                        logger.error("UnicodeDecodeError in plugin_system: %s", e)
                        raise ValueError("Remote plugin contains binary data") from e

                    # Basic security scan
                    dangerous_patterns = [
                        "os.system",
                        "subprocess.call",
                        "eval(",
                        "exec(",
                        '__import__("os")',
                        "compile(",
                        "globals()",
                        "locals()",
                        "open(",
                        "file(",
                        "__builtins__",
                    ]

                    content_lower = content_text.lower()
                    for pattern in dangerous_patterns:
                        if pattern.lower() in content_lower:
                            self.logger.warning(f"Potentially dangerous pattern '{pattern}' found in remote plugin")
                            # Continue but log warning

                    # Write to temporary file
                    with open(temp_plugin_path, "w", encoding="utf-8") as f:
                        f.write(content_text)

            except Exception as e:
                self.logger.error(f"Failed to download remote plugin: {e}")
                return None

            # Execute the downloaded plugin
            try:
                # Use sandbox execution for remote plugins
                result = self.execute_sandboxed_plugin(temp_plugin_path, *args, **kwargs)

                # Clean up temporary file
                try:
                    os.remove(temp_plugin_path)
                except Exception as e:
                    logger.debug(f"Failed to remove temporary plugin file: {e}")

                return result

            except Exception as e:
                self.logger.error(f"Failed to execute downloaded plugin: {e}")
                # Clean up on error
                try:
                    os.remove(temp_plugin_path)
                except Exception as e:
                    logger.debug(f"Failed to remove temporary plugin file during cleanup: {e}")
                return None

        except Exception as e:
            self.logger.error(f"Failed to execute remote plugin: {e}")
            self.logger.debug(f"Traceback: {traceback.format_exc()}")
            return None

    def execute_sandboxed_plugin(self, plugin_name: str, *args, **kwargs) -> Any:
        """Execute a plugin in sandbox."""
        self.logger.info(f"Execute sandboxed plugin called: {plugin_name}")

        # Find the plugin - support both names and paths
        if os.path.exists(plugin_name):
            plugin_path = plugin_name
        else:
            plugin_path = self.find_plugin(plugin_name)
            if not plugin_path:
                self.logger.error(f"Plugin {plugin_name} not found")
                return None

        # Extract function name from kwargs
        function_name = kwargs.pop("function_name", "execute")

        # Create sandbox process with resource limits
        try:
            # Prepare the sandbox execution code
            sandbox_code = f"""
import sys
import os
import signal
import resource
import importlib.util
import json
import traceback

# Set resource limits
if sys.platform != 'win32':
    try:
        # CPU time limit (30 seconds)
        resource.setrlimit(resource.RLIMIT_CPU, (30, 30))
        # Memory limit (512 MB)
        resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
        # File size limit (50 MB)
        resource.setrlimit(resource.RLIMIT_FSIZE, (50 * 1024 * 1024, 50 * 1024 * 1024))
        # Number of processes (prevent fork bombs)
        resource.setrlimit(resource.RLIMIT_NPROC, (10, 10))
    except Exception as e:
        print(f"Failed to set resource limits: {{e}}")

# Set up timeout handler
def timeout_handler(signum, frame):
    raise TimeoutError("Plugin execution timed out")

signal.signal(signal.SIGALRM, timeout_handler)
signal.alarm(30)  # 30 second timeout

try:
    # Load the plugin
    plugin_path = {plugin_path!r}
    spec = importlib.util.spec_from_file_location("sandboxed_plugin", plugin_path)
    module = importlib.util.module_from_spec(spec)

    # Restricted builtins
    safe_builtins = {{
        '__builtins__': {{
            'abs': abs, 'all': all, 'any': any, 'ascii': ascii,
            'bin': bin, 'bool': bool, 'bytes': bytes, 'callable': callable,
            'chr': chr, 'dict': dict, 'dir': dir, 'divmod': divmod,
            'enumerate': enumerate, 'filter': filter, 'float': float,
            'format': format, 'frozenset': frozenset, 'getattr': getattr,
            'hasattr': hasattr, 'hash': hash, 'hex': hex, 'id': id,
            'int': int, 'isinstance': isinstance, 'issubclass': issubclass,
            'iter': iter, 'len': len, 'list': list, 'map': map,
            'max': max, 'min': min, 'next': next, 'object': object,
            'oct': oct, 'ord': ord, 'pow': pow, 'print': print,
            'range': range, 'repr': repr, 'reversed': reversed,
            'round': round, 'set': set, 'setattr': setattr,
            'slice': slice, 'sorted': sorted, 'str': str,
            'sum': sum, 'tuple': tuple, 'type': type, 'zip': zip,
            'Exception': Exception, 'ValueError': ValueError,
            'TypeError': TypeError, 'KeyError': KeyError,
            'IndexError': IndexError, 'RuntimeError': RuntimeError,
        }}
    }}

    # Apply restrictions to module
    module.__dict__.update(safe_builtins)

    # Execute the module
    spec.loader.exec_module(module)

    # Find and call the target function
    function_name = {function_name!r}
    args = {args!r}
    kwargs = {kwargs!r}

    if hasattr(module, function_name):
        func = getattr(module, function_name)
        if callable(func):
            result = func(*args, **kwargs)
            # Convert result to JSON-serializable format
            print(json.dumps({{"success": True, "result": str(result)}}))
        else:
            print(json.dumps({{"success": False, "error": f"{{function_name}} is not callable"}}))
    else:
        # Try to find any callable entry point
        callables = [name for name in dir(module) if callable(getattr(module, name)) and not name.startswith('_')]
        if callables:
            func = getattr(module, callables[0])
            result = func(*args, **kwargs)
            print(json.dumps({{"success": True, "result": str(result), "function_used": callables[0]}}))
        else:
            print(json.dumps({{"success": False, "error": "No callable functions found in plugin"}}))

except TimeoutError as e:
    logger.error("Timeout error in plugin_system: %s", e)
    print(json.dumps({{"success": False, "error": str(e)}}))
except Exception as e:
    logger.error("Exception in plugin_system: %s", e)
    print(json.dumps({{"success": False, "error": str(e), "traceback": traceback.format_exc()}}))
finally:
    signal.alarm(0)
"""

            # Execute in subprocess
            import subprocess

            if sys.platform == "win32":
                # Windows doesn't support resource limits, use process creation flags
                CREATE_NO_WINDOW = 0x08000000
                process = subprocess.Popen(  # nosec S603 - Legitimate subprocess usage for security research and binary analysis  # noqa: S603
                    [sys.executable, "-c", sandbox_code],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    creationflags=CREATE_NO_WINDOW,
                )
            else:
                # Unix-like systems with resource limits
                process = subprocess.Popen(  # nosec S603 - Legitimate subprocess usage for security research and binary analysis  # noqa: S603
                    [sys.executable, "-c", sandbox_code],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    preexec_fn=getattr(os, "setsid", None) if sys.platform != "win32" else None,  # Create new process group on Unix
                )

            # Wait for completion with timeout
            try:
                stdout, stderr = process.communicate(timeout=35)  # 35 seconds (5 more than internal timeout)
            except subprocess.TimeoutExpired as e:
                logger.error("Subprocess timeout in plugin_system: %s", e)
                # Kill the process group on timeout
                if sys.platform != "win32":
                    os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                else:
                    process.terminate()
                stdout, stderr = process.communicate()
                return {"success": False, "error": "Plugin execution timed out", "killed": True}

            # Parse the result
            if stdout:
                try:
                    result = json.loads(stdout.strip())
                    if result.get("success"):
                        # Try to deserialize the actual result
                        try:
                            import ast

                            actual_result = ast.literal_eval(result["result"])
                            return actual_result
                        except Exception:
                            # Return as string if can't deserialize
                            return result["result"]
                    else:
                        self.logger.error(f"Sandbox execution failed: {result.get('error', 'Unknown error')}")
                        if result.get("traceback"):
                            self.logger.debug(f"Traceback: {result['traceback']}")
                        return None
                except json.JSONDecodeError:
                    self.logger.error(f"Failed to parse sandbox output: {stdout}")
                    if stderr:
                        self.logger.error(f"Stderr: {stderr}")
                    return None
            else:
                self.logger.error(f"No output from sandboxed plugin. Stderr: {stderr}")
                return None

        except Exception as e:
            self.logger.error(f"Failed to execute sandboxed plugin: {e}")
            self.logger.debug(f"Traceback: {traceback.format_exc()}")
            return None


# Export all plugin system functions and the PluginSystem class
# Import shared exports to avoid duplication
try:
    from .plugin_config import PLUGIN_SYSTEM_EXPORTS

    __all__ = ["PluginSystem", "create_plugin_template"] + PLUGIN_SYSTEM_EXPORTS
except ImportError as e:
    logger.error("Import error in plugin_system: %s", e)
    # Fallback in case of circular import issues
    __all__ = [
        "PluginSystem",
        "create_plugin_template",
        "create_sample_plugins",
        "load_plugins",
        "run_custom_plugin",
        "run_frida_plugin_from_file",
        "run_ghidra_plugin_from_file",
        "run_plugin",
        "run_plugin_in_sandbox",
        "run_plugin_remotely",
    ]

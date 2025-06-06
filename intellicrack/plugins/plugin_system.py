#!/usr/bin/env python3
"""
Plugin System Foundation for Intellicrack

This module provides the core plugin system functionality including:
- Plugin loading from different sources (Frida scripts, Ghidra scripts, custom Python modules)
- Plugin execution and management
- Cross-platform plugin distribution and execution

Author: Intellicrack Development Team
"""

import importlib
import json
import multiprocessing
import os
import shutil
import subprocess
import sys
import tempfile
import traceback
from typing import Any, Dict, List, Optional

from PyQt5.QtWidgets import QInputDialog, QMessageBox

from ..utils.common_imports import FRIDA_AVAILABLE

if FRIDA_AVAILABLE:
    import frida
else:
    frida = None

try:
    import resource
    RESOURCE_AVAILABLE = True
except ImportError:
    RESOURCE_AVAILABLE = False

from ..config import CONFIG
from ..utils.logger import logger
from ..utils.process_utils import get_target_process_pid
from .remote_executor import RemotePluginExecutor


def log_message(msg: str) -> str:
    """Helper function to format log messages consistently."""
    return f"[{msg}]"


def load_plugins(plugin_dir: str = "plugins") -> Dict[str, List[Dict[str, Any]]]:
    """
    Loads and initializes plugins from the plugin directory.
    Returns a dictionary of loaded plugins by category.

    Args:
        plugin_dir: Directory containing plugin subdirectories

    Returns:
        Dictionary with plugin categories (frida, ghidra, custom) and their plugins
    """
    plugins = {
        "frida": [],
        "ghidra": [],
        "custom": []
    }

    # Check if plugin directory exists
    if not os.path.exists(plugin_dir):
        os.makedirs(plugin_dir)

        # Create subdirectories if needed
        for subdir in ["frida_scripts", "ghidra_scripts", "custom_modules"]:
            path = os.path.join(plugin_dir, subdir)
            if not os.path.exists(path):
                os.makedirs(path)

    # Load Frida scripts
    frida_dir = os.path.join(plugin_dir, "frida_scripts")
    if os.path.exists(frida_dir):
        for file in os.listdir(frida_dir):
            if file.endswith(".js"):
                plugin_path = os.path.join(frida_dir, file)
                plugin_name = os.path.splitext(
                    file)[0].replace("_", " ").title()

                # Read first 5 lines for description
                try:
                    with open(plugin_path, "r", encoding="utf-8") as f:
                        lines = [f.readline().strip() for _ in range(5)]
                        description = "".join(
                            [line for line in lines if line.startswith("//")]).replace("//", "").strip()

                        if not description:
                            description = f"Frida script: {plugin_name}"

                        plugins["frida"].append({
                            "name": plugin_name,
                            "path": plugin_path,
                            "description": description
                        })
                except Exception as e:
                    logger.error(f"Error loading Frida plugin {file}: {e}")

    # Load Ghidra scripts
    ghidra_dir = os.path.join(plugin_dir, "ghidra_scripts")
    if os.path.exists(ghidra_dir):
        for file in os.listdir(ghidra_dir):
            if file.endswith(".java"):
                plugin_path = os.path.join(ghidra_dir, file)
                plugin_name = os.path.splitext(
                    file)[0].replace("_", " ").title()

                # Read first 10 lines for description
                try:
                    with open(plugin_path, "r", encoding="utf-8") as f:
                        lines = [f.readline().strip() for _ in range(10)]
                        description = "".join(
                            [line for line in lines if line.startswith("//")]).replace("//", "").strip()

                        if not description:
                            description = f"Ghidra script: {plugin_name}"

                        plugins["ghidra"].append({
                            "name": plugin_name,
                            "path": plugin_path,
                            "description": description
                        })
                except Exception as e:
                    logger.error(f"Error loading Ghidra plugin {file}: {e}")

    # Load custom Python modules
    custom_dir = os.path.join(plugin_dir, "custom_modules")
    if os.path.exists(custom_dir):
        # Add to Python path
        sys.path.insert(0, custom_dir)

        for file in os.listdir(custom_dir):
            if file.endswith(".py") and not file.startswith("__"):
                plugin_name = os.path.splitext(file)[0]

                try:
                    # Import the module
                    module_name = plugin_name
                    module = importlib.import_module(module_name)

                    # Check if it has a register function
                    if hasattr(module, "register"):
                        plugin_instance = module.register()

                        name = getattr(plugin_instance, "name",
                                       plugin_name.replace("_", " ").title())
                        description = getattr(
                            plugin_instance, "description", f"Custom plugin: {name}")

                        plugins["custom"].append({
                            "name": name,
                            "module": module_name,
                            "instance": plugin_instance,
                            "description": description
                        })
                except Exception as e:
                    logger.error(f"Error loading custom plugin {file}: {e}")
                    logger.error(traceback.format_exc())

    logger.info(
        f"Loaded {len(plugins['frida'])} Frida plugins, "
        f"{len(plugins['ghidra'])} Ghidra plugins, and "
        f"{len(plugins['custom'])} custom plugins"
    )
    return plugins


def run_plugin(app, plugin_name: str) -> None:
    """
    Runs a built-in plugin.

    Args:
        app: Application instance
        plugin_name: Name of the built-in plugin to run
    """
    if not app.binary_path:
        app.update_output.emit(log_message("[Plugin] No binary selected."))
        return

    app.update_output.emit(log_message(f"[Plugin] Running {plugin_name}..."))

    # Import API hooking functions dynamically to avoid circular imports
    from ..core.patching.payload_generator import generate_complete_api_hooking_script
    from ..utils.protection_utils import inject_comprehensive_api_hooks

    if plugin_name == "HWID Spoofer":
        script = generate_complete_api_hooking_script(
            app, hook_types=["hardware_id"])
    elif plugin_name == "Anti-Debugger":
        script = generate_complete_api_hooking_script(
            app, hook_types=["debugger"])
    elif plugin_name == "Time Bomb Defuser":
        script = generate_complete_api_hooking_script(app, hook_types=["time"])
    elif plugin_name == "Telemetry Blocker":
        script = generate_complete_api_hooking_script(
            app, hook_types=["network"])
    else:
        app.update_output.emit(log_message(
            f"[Plugin] Unknown plugin: {plugin_name}"))
        return

    # Inject script
    inject_comprehensive_api_hooks(app, script)


def run_custom_plugin(app, plugin_info: Dict[str, Any]) -> None:
    """
    Runs a custom plugin with the current binary.

    Args:
        app: Application instance
        plugin_info: Plugin information dictionary
    """
    if not app.binary_path:
        app.update_output.emit(log_message("[Plugin] No binary selected."))
        return

    instance = plugin_info.get("instance")
    if not instance:
        app.update_output.emit(log_message(
            "[Plugin] Invalid plugin instance."))
        return

    app.update_output.emit(log_message(
        f"[Plugin] Running {plugin_info['name']}..."))

    # Check for analyze method
    if hasattr(instance, "analyze"):
        try:
            results = instance.analyze(app.binary_path)

            if results:
                if isinstance(results, list):
                    for line in results:
                        app.update_output.emit(log_message(
                            f"[{plugin_info['name']}] {line}"))
                else:
                    app.update_output.emit(log_message(
                        f"[{plugin_info['name']}] {results}"))
        except Exception as e:
            app.update_output.emit(log_message(
                f"[Plugin] Error running plugin: {e}"))
            app.update_output.emit(log_message(traceback.format_exc()))
    else:
        app.update_output.emit(log_message(
            "[Plugin] Plugin does not have an analyze method."))

    # Check for patch method
    if hasattr(instance, "patch"):
        # Ask user if they want to run the patch
        response = QMessageBox.question(
            app,
            "Run Patch?",
            f"Do you want to run the patch function of {plugin_info['name']}?",
            QMessageBox.Yes | QMessageBox.No
        )

        if response == QMessageBox.Yes:
            try:
                results = instance.patch(app.binary_path)

                if results:
                    if isinstance(results, list):
                        for line in results:
                            app.update_output.emit(log_message(
                                f"[{plugin_info['name']}] {line}"))
                    else:
                        app.update_output.emit(log_message(
                            f"[{plugin_info['name']}] {results}"))
            except Exception as e:
                app.update_output.emit(log_message(
                    f"[Plugin] Error running patch: {e}"))
                app.update_output.emit(log_message(traceback.format_exc()))


def run_frida_plugin_from_file(app, plugin_path: str) -> None:
    """
    Runs a Frida plugin script from a file.
    Enhanced with robust PID finding and error handling.

    Args:
        app: Application instance
        plugin_path: Path to the Frida script file
    """
    if not FRIDA_AVAILABLE:
        app.update_output.emit(log_message(
            "[Plugin] Frida is not available. Please install frida-tools."))
        return

    if not app.binary_path:
        app.update_output.emit(log_message("[Plugin] No binary selected."))
        return

    plugin_name = os.path.basename(plugin_path)
    app.update_output.emit(log_message(
        f"[Plugin] Loading Frida script '{plugin_name}' from {plugin_path}..."))

    try:
        # Read the script content
        with open(plugin_path, "r", encoding="utf-8") as f:
            script_content = f.read()
    except Exception as e:
        app.update_output.emit(log_message(
            f"[Plugin] Error reading script file {plugin_path}: {e}"))
        return

    # Get process information using the updated function
    app.update_output.emit(log_message(
        f"[Plugin] Finding target process for '{plugin_name}'..."))
    target_pid = get_target_process_pid(app.binary_path)

    if target_pid is None:
        app.update_output.emit(
            log_message(
                f"[Plugin] Target process PID not obtained for '{plugin_name}'. "
                "Aborting script injection."))
        return

    app.update_output.emit(log_message(
        f"[Plugin] Attempting to attach to PID {target_pid} for script '{plugin_name}'"))

    # Run the Frida script with improved error handling
    if not FRIDA_AVAILABLE or frida is None:
        app.update_output.emit(log_message("[Plugin] Frida not available - cannot run script"))
        return
        
    session = None  # Initialize session to None
    try:
        session = frida.attach(target_pid)
        app.update_output.emit(log_message(
            f"[Plugin] Attached to PID {target_pid} for '{plugin_name}'"))

        script = session.create_script(script_content)

        def on_message(message, data):
            """
            Callback for handling messages from a Frida script.

            Adds the plugin name as a prefix to log messages and processes payloads.
            """
            # Add plugin name prefix to logs
            prefix = f"[{plugin_name}]"
            if message["type"] == "send":
                # Check if payload is simple string or structured data
                payload = message.get('payload', '')
                if isinstance(payload, (str, int, float, bool)):
                    log_text = f"{prefix} {payload}"
                else:
                    # For complex payloads, just indicate type or stringify
                    try:
                        log_text = f"{prefix} Data: {json.dumps(payload)}"
                    except TypeError:
                        log_text = f"{prefix} Received complex data structure"
                app.update_output.emit(log_message(log_text))
            elif message["type"] == "error":
                # More specific error logging from Frida script errors
                description = message.get('description', 'Unknown error')
                stack = message.get('stack', 'No stack trace')
                app.update_output.emit(
                    log_message(
                        f"{prefix} Script Error: Desc: {description}\nStack: {stack}"))

        script.on("message", on_message)
        script.load()  # This can also raise exceptions

        app.update_output.emit(log_message(
            f"[Plugin] Frida script '{plugin_name}' loaded successfully"))

        # Store session and script to prevent garbage collection
        if not hasattr(app, "frida_sessions"):
            app.frida_sessions = {}
        # Ensure session is valid before storing
        if session:
            app.frida_sessions[plugin_name] = (session, script)

    except frida.ProcessNotFoundError:
        app.update_output.emit(
            log_message(
                f"[Plugin] Error running '{plugin_name}': Process PID {target_pid} "
                "not found (may have terminated)."))
    except frida.TransportError as e:
        app.update_output.emit(
            log_message(
                f"[Plugin] Error running '{plugin_name}': "
                f"Connection to Frida server failed: {e}"))
        app.update_output.emit(
            log_message(
                "[Plugin] Ensure frida-server is running on the target device (if applicable)."))
    except frida.InvalidArgumentError as e:
        app.update_output.emit(
            log_message(
                f"[Plugin] Error running '{plugin_name}': "
                f"Invalid argument during Frida operation: {e}"))
    except frida.NotSupportedError as e:
        app.update_output.emit(
            log_message(
                f"[Plugin] Error running '{plugin_name}': "
                f"Operation not supported by Frida: {e}"))
    except frida.ExecutableNotFoundError as e:
        app.update_output.emit(
            log_message(
                f"[Plugin] Error running '{plugin_name}': "
                f"Frida could not find required executable: {e}"))
    except Exception as e:
        # Catch generic exceptions during attach or script load
        app.update_output.emit(
            log_message(
                f"[Plugin] Failed to attach or inject script '{plugin_name}' "
                f"into PID {target_pid}: {e}"))
        app.update_output.emit(
            log_message(
                "[Plugin] Possible causes: Insufficient permissions, "
                "anti-debugging measures, or Frida issues."))
        app.update_output.emit(log_message(traceback.format_exc()))
        # Clean up session if partially created
        if session:
            try:
                session.detach()
            except Exception:
                pass  # Ignore errors during cleanup detach


def run_ghidra_plugin_from_file(app, plugin_path: str) -> None:
    """
    Runs a Ghidra script on the current binary.

    Args:
        app: Application instance
        plugin_path: Path to the Ghidra script file
    """
    if not app.binary_path:
        app.update_output.emit(log_message("[Plugin] No binary selected."))
        return

    app.update_output.emit(log_message(
        f"[Plugin] Running Ghidra script from {plugin_path}..."))

    # Get Ghidra path from config
    ghidra_path = CONFIG.get(
        "ghidra_path", r"C:\Program Files\Ghidra\ghidraRun.bat")

    if not os.path.exists(ghidra_path):
        app.update_output.emit(log_message(
            f"[Plugin] Ghidra not found at {ghidra_path}"))
        app.update_output.emit(log_message(
            "[Plugin] Please configure the correct path in Settings"))
        return

    # Create a temporary directory for the Ghidra project
    temp_dir = tempfile.mkdtemp(prefix="intellicrack_ghidra_")
    project_name = "temp_project"

    try:
        app.update_output.emit(log_message(
            "[Plugin] Setting up Ghidra project..."))

        # Build the command
        cmd = [
            ghidra_path,
            temp_dir,
            project_name,
            "-import", app.binary_path,
            "-scriptPath", os.path.dirname(plugin_path),
            "-postScript", os.path.basename(plugin_path),
            "-overwrite"
        ]

        app.update_output.emit(log_message(
            "[Plugin] Running Ghidra headless analyzer..."))

        # Run Ghidra
        from ..utils.process_helpers import run_ghidra_process
        returncode, stdout, stderr = run_ghidra_process(cmd)

        # Process output
        if stdout and isinstance(stdout, (str, bytes)):
            for line in (stdout.splitlines() if stdout is not None else []):
                if line and line.strip():
                    app.update_output.emit(
                        log_message(f"[Ghidra] {line.strip()}"))

        if stderr and isinstance(stderr, (str, bytes)):
            for line in (stderr.splitlines() if stderr is not None else []):
                if line and line.strip():
                    app.update_output.emit(log_message(
                        f"[Ghidra Error] {line.strip()}"))

        app.update_output.emit(log_message(
            "[Plugin] Ghidra script execution complete"))

        # Check for any output files the script might have created
        result_files = []
        for file in os.listdir(temp_dir):
            if file not in [project_name, project_name + ".rep"]:
                result_files.append(os.path.join(temp_dir, file))

        if result_files:
            app.update_output.emit(log_message(
                "[Plugin] Ghidra script created output files:"))
            for file in result_files:
                app.update_output.emit(log_message(f"[Plugin] - {file}"))

    except Exception as e:
        app.update_output.emit(log_message(
            f"[Plugin] Error running Ghidra script: {e}"))
        app.update_output.emit(log_message(traceback.format_exc()))
    finally:
        # Clean up
        try:
            shutil.rmtree(temp_dir)
        except Exception as e:
            app.update_output.emit(
                log_message(
                    f"[Plugin] Warning: Failed to clean up temporary directory: {e}"))


def create_sample_plugins(plugin_dir: str = "plugins") -> None:
    """
    Creates sample plugin files for users to reference.

    Args:
        plugin_dir: Directory to create plugin samples in
    """
    logger.info("Creating sample plugins...")

    # Ensure directories exist
    os.makedirs(plugin_dir, exist_ok=True)
    os.makedirs(os.path.join(plugin_dir, "frida_scripts"), exist_ok=True)
    os.makedirs(os.path.join(plugin_dir, "ghidra_scripts"), exist_ok=True)
    os.makedirs(os.path.join(plugin_dir, "custom_modules"), exist_ok=True)

    # Create sample Frida script
    sample_frida = '''// Registry Monitor - Monitors registry access
// This script hooks Windows registry APIs

Interceptor.attach(Module.findExportByName("advapi32.dll", "RegOpenKeyExW"), {
    onEnter: function(args) {
        var keyName = args[1].readUtf16String();
        send("[Registry] Opening key: " + keyName);
    }
});

Interceptor.attach(Module.findExportByName("advapi32.dll", "RegQueryValueExW"), {
    onEnter: function(args) {
        var valueName = args[1].readUtf16String();
        send("[Registry] Querying value: " + valueName);
    }
});

send("[Registry Monitor] Started monitoring registry access");
'''

    frida_path = os.path.join(plugin_dir, "frida_scripts", "registry_monitor.js")
    if not os.path.exists(frida_path):
        with open(frida_path, "w", encoding="utf-8") as f:
            f.write(sample_frida)
        logger.info(f"Created sample Frida script: {frida_path}")

    # Create sample Ghidra script
    sample_ghidra = '''//License Pattern Scanner
//Searches for common license validation patterns
//@category License Analysis
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;

public class LicensePatternScanner extends GhidraScript {

    @Override
    public void run() throws Exception {
        println("Scanning for license validation patterns...");

        // Common license-related strings
        String[] patterns = {
            "license", "activation", "serial", "key",
            "validate", "verify", "check", "trial",
            "expire", "register", "unlock"
        };

        Memory memory = currentProgram.getMemory();

        for (String pattern : patterns) {
            println("Searching for: " + pattern);

            // Search for strings
            byte[] searchBytes = pattern.getBytes();
            Address start = memory.getMinAddress();

            while (start != null) {
                start = memory.findBytes(start, searchBytes, null, true, monitor);
                if (start != null) {
                    println("  Found at: " + start.toString());
                    start = start.add(1);
                }
            }
        }

        println("License pattern scan complete!");
    }
}
'''

    ghidra_path = os.path.join(plugin_dir, "ghidra_scripts", "LicensePatternScanner.java")
    if not os.path.exists(ghidra_path):
        with open(ghidra_path, "w", encoding="utf-8") as f:
            f.write(sample_ghidra)
        logger.info(f"Created sample Ghidra script: {ghidra_path}")

    # Create sample custom Python module
    sample_custom = '''"""
Demo Plugin for Intellicrack
Shows how to create custom analysis plugins
"""

class DemoPlugin:
    def __init__(self):
        self.name = "Demo Plugin"
        self.description = "A sample plugin showing the plugin interface"

    def analyze(self, binary_path):
        """
        Analyze the binary and return findings.

        Args:
            binary_path: Path to the binary to analyze

        Returns:
            List of strings with analysis results
        """
        results = []
        results.append(f"Analyzing: {binary_path}")

        # Add your analysis logic here
        import os
        file_size = os.path.getsize(binary_path)
        results.append(f"File size: {file_size:,} bytes")

        # Example: Check for common packers
        with open(binary_path, "rb") as f:
            header = f.read(1024)

            if b"UPX" in header:
                results.append("Detected: UPX packer")
            elif b"ASPack" in header:
                results.append("Detected: ASPack packer")
            else:
                results.append("No common packers detected in header")

        return results

    def patch(self, binary_path):
        """
        Apply patches to the binary.

        Args:
            binary_path: Path to the binary to patch

        Returns:
            List of strings with patching results
        """
        results = []
        results.append("Patch function called")
        results.append("This is where you would implement patching logic")

        # Example: Create a backup
        import shutil
        backup_path = binary_path + ".bak"
        shutil.copy2(binary_path, backup_path)
        results.append(f"Created backup: {backup_path}")

        return results

def register():
    """
    Required function to register the plugin.
    Must return an instance of your plugin class.
    """
    return DemoPlugin()
'''

    custom_path = os.path.join(plugin_dir, "custom_modules", "demo_plugin.py")
    if not os.path.exists(custom_path):
        with open(custom_path, "w", encoding="utf-8") as f:
            f.write(sample_custom)
        logger.info(f"Created sample custom plugin: {custom_path}")

    logger.info("Sample plugins created successfully!")


def _sandbox_worker(plugin_path: str, function_name: str, args: tuple, result_queue: multiprocessing.Queue) -> None:
    """
    Worker function for sandboxed plugin execution.

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
        import importlib.util
        spec = importlib.util.spec_from_file_location("sandboxed_plugin", plugin_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        # Get the function and execute it
        func = getattr(module, function_name)
        result = func(*args)

        # Put result in queue
        result_queue.put(("success", result))

    except Exception as e:
        result_queue.put(("error", str(e)))


def run_plugin_in_sandbox(plugin_path: str, function_name: str, *args) -> Optional[List[str]]:
    """
    Runs a plugin in a sandboxed process with resource limits.

    Args:
        plugin_path: Path to the plugin file
        function_name: Name of the function to execute  
        *args: Arguments to pass to the function

    Returns:
        List of strings with results, or None on error
    """
    logger.info(f"Running plugin in sandbox: {plugin_path}")

    # Create a queue for results
    result_queue = multiprocessing.Queue()

    # Create the sandboxed process
    process = multiprocessing.Process(
        target=_sandbox_worker,
        args=(plugin_path, function_name, args, result_queue)
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
            else:
                return [str(result)]
        else:
            return [f"Plugin error: {result}"]
    except:
        return ["No results returned from plugin"]


def run_plugin_remotely(app, plugin_info: Dict[str, Any]) -> Optional[List[str]]:
    """
    Runs a plugin on a remote system.

    Args:
        app: Application instance
        plugin_info: Plugin information dictionary

    Returns:
        List of strings with results, or None on error
    """
    # Check if remote plugins are enabled
    if not CONFIG.get("enable_remote_plugins", False):
        app.update_output.emit(log_message(
            "[Plugin] Remote plugins are disabled in settings"))
        return None

    # Get remote host information
    default_host = CONFIG.get("remote_plugin_host", "localhost")
    default_port = CONFIG.get("remote_plugin_port", 9999)

    # Ask user for host and port
    host, ok = QInputDialog.getText(
        app, "Remote Plugin Execution",
        "Enter remote host:", text=default_host
    )

    if not ok:
        return None

    port, ok = QInputDialog.getInt(
        app, "Remote Plugin Execution",
        "Enter remote port:", value=default_port,
        min=1, max=65535
    )

    if not ok:
        return None

    app.update_output.emit(log_message(
        f"[Plugin] Executing {plugin_info['name']} on {host}:{port}..."))

    # Create remote executor
    executor = RemotePluginExecutor(host, port)

    try:
        # Execute the plugin remotely
        results = executor.execute_plugin(
            plugin_info['path'],
            'analyze',
            app.binary_path
        )

        if results:
            return results
        else:
            return ["No results returned from remote execution"]

    except Exception as e:
        app.update_output.emit(log_message(
            f"[Plugin] Remote execution error: {e}"))
        return None


# Export all plugin system functions
__all__ = [
    'load_plugins',
    'run_plugin',
    'run_custom_plugin',
    'run_frida_plugin_from_file',
    'run_ghidra_plugin_from_file',
    'create_sample_plugins',
    'run_plugin_in_sandbox',
    'run_plugin_remotely'
]

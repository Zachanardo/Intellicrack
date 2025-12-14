"""Core utility functions for Intellicrack.

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

import json
import logging
import sys
import traceback
from collections.abc import Callable
from typing import Any


logger = logging.getLogger(__name__)

# Tool registry for dispatch system
TOOL_REGISTRY = {}


def main(args: list[str] | None = None) -> int:
    """Run entry point for Intellicrack.

    Args:
        args: Command line arguments

    Returns:
        Exit code

    """
    if args is None:
        args = sys.argv[1:]

    # Parse command line arguments
    import argparse

    parser = argparse.ArgumentParser(
        description="Intellicrack - Advanced Binary Analysis and Security Research Tool",
    )

    parser.add_argument(
        "binary",
        nargs="?",
        help="Binary file to analyze",
    )

    parser.add_argument(
        "--gui",
        action="store_true",
        default=True,
        help="Launch GUI mode (default)",
    )

    parser.add_argument(
        "--cli",
        action="store_true",
        help="Launch CLI mode",
    )

    parser.add_argument(
        "--analyze",
        action="store_true",
        help="Run analysis on binary",
    )

    parser.add_argument(
        "--crack",
        action="store_true",
        help="Run autonomous cracking mode",
    )

    parser.add_argument(
        "--output",
        "-o",
        help="Output directory for results",
    )

    parser.add_argument(
        "--verbose",
        "-v",
        action="count",
        default=0,
        help="Increase verbosity",
    )

    parsed_args = parser.parse_args(args)

    # Configure logging
    if parsed_args.verbose >= 2:
        logging.basicConfig(level=logging.DEBUG)
    elif parsed_args.verbose >= 1:
        logging.basicConfig(level=logging.INFO)
    else:
        logging.basicConfig(level=logging.WARNING)

    try:
        if parsed_args.cli or (parsed_args.binary and not parsed_args.gui):
            # CLI mode
            return run_cli_mode(parsed_args)
        # GUI mode (default)
        return run_gui_mode(parsed_args)

    except KeyboardInterrupt:
        logger.info("Interrupted by user")
        return 1
    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Fatal error: %s", e, exc_info=True)
        return 1


def run_gui_mode(args: object) -> int:
    """Run Intellicrack in GUI mode.

    Args:
        args: Parsed command line arguments

    Returns:
        Exit code

    """
    _ = args
    try:
        from intellicrack.handlers.pyqt6_handler import QApplication

        from ...ui.main_app import launch

        # Create Qt application
        app = QApplication(sys.argv)

        # Launch main window
        launch()

        # Run event loop
        return app.exec()

    except ImportError as e:
        logger.error("GUI dependencies not available: %s", e, exc_info=True)
        logger.info("Please install PyQt6 to use GUI mode")
        return 1
    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error launching GUI: %s", e, exc_info=True)
        return 1


def run_cli_mode(args: object) -> int:
    """Run Intellicrack in CLI mode.

    Args:
        args: Parsed command line arguments

    Returns:
        Exit code

    """
    if not args.binary:
        logger.error("No binary specified for CLI mode")
        return 1

    try:
        from ..runtime.additional_runners import run_autonomous_crack, run_comprehensive_analysis

        results = {}

        # Run analysis if requested
        if args.analyze:
            logger.info("Analyzing %s...", args.binary)
            results["analysis"] = run_comprehensive_analysis(
                args.binary,
                output_dir=args.output,
            )

            if "summary" in results["analysis"]:
                logger.info("Analysis Summary:")
                for key, value in results["analysis"]["summary"].items():
                    logger.info("  %s: %s", key, value)

        # Run cracking if requested
        if args.crack:
            logger.info("Running autonomous crack on %s...", args.binary)
            results["crack"] = run_autonomous_crack(args.binary)

            if results["crack"].get("success"):
                logger.info("Cracking successful: %s", results["crack"].get("message"))
            else:
                logger.warning("Cracking failed: %s", results["crack"].get("message"))

        if args.output and results:
            output_file = f"{args.output}/intellicrack_results.json"
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=2, default=str)
            logger.info("Results saved to: %s", output_file)

        return 0

    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error in CLI mode: %s", e, exc_info=True)
        return 1


def dispatch_tool(app_instance: object, tool_name: str, parameters: dict[str, Any]) -> dict[str, Any]:
    """Dispatch an AI-requested tool to the corresponding function.

    Args:
        app_instance: Application instance (for UI updates)
        tool_name: Name of the tool to dispatch
        parameters: Parameters for the tool

    Returns:
        Dict containing tool execution results

    """
    logger.info("Dispatching tool: %s", tool_name)

    # Update UI if available
    if app_instance and hasattr(app_instance, "update_output"):
        app_instance.update_output.emit(
            f"[Tool Dispatch] Attempting to dispatch tool: {tool_name}",
        )

    # Check if tool is registered
    if tool_name not in TOOL_REGISTRY:
        error_msg = f"Unknown tool: {tool_name}"
        logger.error(error_msg)

        # Suggest similar tools
        available_tools = list(TOOL_REGISTRY.keys())
        suggestions = [t for t in available_tools if tool_name.lower() in t.lower()]

        result = {
            "status": "error",
            "error": error_msg,
            "available_tools": available_tools[:10],  # First 10 tools
            "suggestions": suggestions,
        }

        if app_instance and hasattr(app_instance, "update_output"):
            app_instance.update_output.emit(
                f"[Tool Dispatch] ERROR: {error_msg}",
            )

        return result

    try:
        # Get tool function
        tool_func = TOOL_REGISTRY[tool_name]

        # Execute tool
        result = tool_func(app_instance, parameters)

        # Update UI with result
        if app_instance and hasattr(app_instance, "update_output"):
            status = result.get("status", "unknown")
            app_instance.update_output.emit(
                f"[Tool Dispatch] Tool '{tool_name}' executed. Status: {status}",
            )

        return result

    except (OSError, ValueError, RuntimeError) as e:
        error_trace = traceback.format_exc()
        error_msg = f"Error executing tool '{tool_name}': {e!s}"

        logger.error("Error executing tool '%s': %s", tool_name, e, exc_info=True)

        # Update UI with error
        if app_instance and hasattr(app_instance, "update_output"):
            app_instance.update_output.emit(f"[Tool Dispatch] ERROR: {error_msg}")
            app_instance.update_output.emit(error_trace)

        # Return detailed error
        return {
            "status": "error",
            "error": error_msg,
            "traceback": error_trace,
            "tool": tool_name,
            "parameters": parameters,
        }


def register_tool(name: str, func: Callable, category: str = "general") -> bool:
    """Register a tool in the tool registry.

    Args:
        name: Name of the tool
        func: Function to call
        category: Tool category

    Returns:
        True if registered successfully

    """
    try:
        TOOL_REGISTRY[name] = func
        logger.info("Registered tool: %s (category: %s)", name, category)
        return True
    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error registering tool %s: %s", name, e, exc_info=True)
        return False


def register_default_tools() -> bool | None:
    """Register all default tools in the registry."""
    try:
        # Import all tool wrapper functions (moved inside function to avoid cyclic import)
        from ..tools.tool_wrappers import (
            wrapper_apply_confirmed_patch,
            wrapper_attach_target,
            wrapper_deep_license_analysis,
            wrapper_deep_runtime_monitoring,
            wrapper_detach,
            wrapper_detect_protections,
            wrapper_disassemble_address,
            wrapper_find_file,
            wrapper_generate_launcher_script,
            wrapper_get_cfg,
            wrapper_get_file_metadata,
            wrapper_get_proposed_patches,
            wrapper_launch_target,
            wrapper_list_relevant_files,
            wrapper_load_binary,
            wrapper_propose_patch,
            wrapper_read_file_chunk,
            wrapper_run_frida_script,
            wrapper_run_static_analysis,
        )

        # Register each tool
        tools = {
            "tool_find_file": wrapper_find_file,
            "tool_load_binary": wrapper_load_binary,
            "tool_list_relevant_files": wrapper_list_relevant_files,
            "tool_read_file_chunk": wrapper_read_file_chunk,
            "tool_get_file_metadata": wrapper_get_file_metadata,
            "tool_run_static_analysis": wrapper_run_static_analysis,
            "tool_deep_license_analysis": wrapper_deep_license_analysis,
            "tool_detect_protections": wrapper_detect_protections,
            "tool_disassemble_address": wrapper_disassemble_address,
            "tool_get_cfg": wrapper_get_cfg,
            "tool_launch_target": wrapper_launch_target,
            "tool_attach_target": wrapper_attach_target,
            "tool_run_frida_script": wrapper_run_frida_script,
            "tool_detach": wrapper_detach,
            "tool_propose_patch": wrapper_propose_patch,
            "tool_get_proposed_patches": wrapper_get_proposed_patches,
            "tool_apply_confirmed_patch": wrapper_apply_confirmed_patch,
            "tool_generate_launcher_script": wrapper_generate_launcher_script,
            "tool_deep_runtime_monitoring": wrapper_deep_runtime_monitoring,
        }

        for name, func in tools.items():
            register_tool(name, func, category="wrapper")

        logger.info("Registered %s default tools", len(tools))
        return True

    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error registering default tools: %s", e, exc_info=True)
        return False


def on_message(message: dict[str, Any], data: bytes | bytearray | None = None) -> None:
    """Handle messages from Frida scripts.

    This is a callback function for Frida message handling.

    Args:
        message: Message from Frida script
        data: Additional data (usually binary)

    """
    if message["type"] == "send":
        payload = message.get("payload", {})

        # Log the message
        logger.info("[Frida] %s", payload)

        if data is not None:
            logger.debug("[Frida] Binary data received: %s bytes", len(data))

        # Handle specific message types
        if isinstance(payload, dict):
            msg_type = payload.get("type")

            if msg_type == "license_check":
                logger.info("License check detected: %s", payload.get("details", {}))
            elif msg_type == "api_call":
                logger.info("API call intercepted: %s", payload.get("function", "unknown"))
            elif msg_type == "error":
                logger.error("Frida error: %s", payload.get("error", "unknown"))

    elif message["type"] == "error":
        logger.error("[Frida Error] %s", message.get("description", "Unknown error"))
        logger.error("Stack: %s", message.get("stack", "No stack trace"))


def register(plugin_info: dict[str, Any]) -> bool:
    """Register a plugin with the system.

    Args:
        plugin_info: Plugin information dictionary

    Returns:
        True if registered successfully

    """
    required_fields = ["name", "version", "entry_point"]

    # Validate plugin info
    for field in required_fields:
        if field not in plugin_info:
            logger.error("Missing required field: %s", field)
            return False

    try:
        plugin_name = plugin_info["name"]
        logger.info("Registering plugin: %s v%s", plugin_name, plugin_info["version"])

        # Store plugin info (would be in a plugin manager)
        # For now, just register tools if any
        if "tools" in plugin_info:
            for tool_name, tool_func in plugin_info["tools"].items():
                register_tool(f"plugin_{plugin_name}_{tool_name}", tool_func, category="plugin")

        logger.info("Plugin %s registered successfully", plugin_name)
        return True

    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error registering plugin: %s", e, exc_info=True)
        return False


def retrieve_few_shot_examples(task_type: str, count: int = 5) -> list[dict[str, Any]]:
    """Retrieve few-shot examples for AI model training/prompting.

    Args:
        task_type: Type of task (license_analysis, vulnerability_detection, etc.)
        count: Number of examples to retrieve

    Returns:
        List of example dictionaries

    """
    examples = {
        "license_analysis": [
            {
                "input": "Binary contains strings: 'CheckLicense', 'ValidateLicense', 'IsLicensed'",
                "analysis": "License validation functions detected. Look for conditional jumps after these calls.",
                "suggestion": "Patch conditional jumps to always take the 'licensed' branch",
            },
            {
                "input": "Found pattern: 'call CheckLicense; test eax, eax; jz invalid_license'",
                "analysis": "Classic license check pattern with zero flag test",
                "suggestion": "Change 'jz' (74) to 'jmp' (EB) to bypass check",
            },
        ],
        "vulnerability_detection": [
            {
                "input": "Function imports: strcpy, strcat, sprintf",
                "analysis": "Unsafe string functions detected - potential buffer overflow",
                "suggestion": "Look for bounds checking before these calls",
            },
            {
                "input": "No DEP/NX bit set in PE header",
                "analysis": "Stack is executable - easier exploitation",
                "suggestion": "Check for stack-based buffer overflows",
            },
        ],
        "protection_identification": [
            {
                "input": "High entropy section .text (7.8/8.0)",
                "analysis": "Likely packed or encrypted code section",
                "suggestion": "Look for unpacking routine, check entry point",
            },
            {
                "input": "Imports: IsDebuggerPresent, CheckRemoteDebuggerPresent",
                "analysis": "Anti-debugging protection detected",
                "suggestion": "Patch these API calls to always return false",
            },
        ],
    }

    # Get examples for the task type
    task_examples = examples.get(task_type, [])

    # Return requested count
    return task_examples[:count]


def deep_runtime_monitoring(target_process: str, monitoring_config: dict[str, Any] | None = None) -> dict[str, Any]:
    """Perform deep runtime monitoring of a target process.

    This function wraps the implementation in dynamic_analyzer.py

    Args:
        target_process: Process name or PID
        monitoring_config: Monitoring configuration

    Returns:
        Dict containing monitoring results

    """
    try:
        # Use the standalone deep_runtime_monitoring function from dynamic_analyzer
        from ...core.analysis.dynamic_analyzer import deep_runtime_monitoring as analyzer_drm

        # Extract timeout from config if provided
        timeout = 30000  # Default 30 seconds
        if monitoring_config:
            timeout = monitoring_config.get("timeout", timeout)

        # Call the analyzer function directly
        results = analyzer_drm(target_process, timeout)

        return {
            "status": "success",
            "target_process": target_process,
            "timeout": timeout,
            "logs": results,
            "config": monitoring_config,
        }

    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error in deep runtime monitoring: %s", e, exc_info=True)
        return {
            "status": "error",
            "error": str(e),
            "traceback": traceback.format_exc(),
        }


try:
    register_default_tools()
except (OSError, ValueError, RuntimeError) as e:
    logger.warning("Could not register default tools: %s", e, exc_info=True)


# Export all functions
__all__ = [
    "TOOL_REGISTRY",
    "deep_runtime_monitoring",
    "dispatch_tool",
    "main",
    "on_message",
    "register",
    "register_default_tools",
    "register_tool",
    "retrieve_few_shot_examples",
    "run_cli_mode",
    "run_gui_mode",
]

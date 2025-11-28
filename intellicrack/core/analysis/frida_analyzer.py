"""Frida-based Dynamic Analysis Script Runner.

This module provides a secure and user-friendly interface for running approved
Frida analysis scripts against a target binary.

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
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

import os
from threading import Thread
from typing import TYPE_CHECKING, Any

import frida

from intellicrack.handlers.pyqt6_handler import QInputDialog


if TYPE_CHECKING:
    from intellicrack.ui.main_app import IntellicrackApp

try:
    from intellicrack.core.analysis.stalker_manager import StalkerSession
except ImportError:
    StalkerSession = None

active_frida_sessions: dict[str, Any] = {}
active_stalker_sessions: dict[str, Any] = {}

ANALYSIS_SCRIPTS_WHITELIST: list[str] = [
    "registry_monitor.js",
    "telemetry_blocker.js",
    "websocket_interceptor.js",
    "memory_dumper.js",
    "obfuscation_detector.js",
    "realtime_protection_detector.js",
    "behavioral_pattern_analyzer.js",
    "anti_debugger.js",
    "certificate_pinning_bypass.js",
    "hwid_spoofer.js",
    "ntp_blocker.js",
    "time_bomb_defuser.js",
    "virtualization_bypass.js",
    "stalker_tracer.js",
]


def on_frida_message(
    main_app: "IntellicrackApp",
    binary_path: str,
    message: dict[str, Any],
    data: object,
) -> None:
    """Handle messages from Frida scripts.

    Args:
        main_app: Main application instance for emitting UI updates.
        binary_path: Path to the binary being analyzed.
        message: Message dictionary from Frida script containing type and payload.
        data: Additional data associated with the message.

    """
    try:
        if message["type"] == "send":
            payload = message.get("payload", "")
            log_message = f"[{os.path.basename(binary_path)}] {payload}"
            main_app.update_output.emit(log_message)
        elif message["type"] == "error":
            error_message = message.get("stack", "No stack trace available")
            main_app.update_output.emit(f"[Frida Error] {error_message}")
    except Exception as e:
        main_app.update_output.emit(f"[Frida Message Error] Failed to process message: {e}")


def run_frida_script_thread(
    main_app: "IntellicrackApp",
    binary_path: str,
    script_path: str,
) -> None:
    """Execute Frida script logic in a separate thread.

    Spawns a process for the target binary, attaches Frida, loads the analysis
    script, and monitors execution until the session detaches.

    Args:
        main_app: Main application instance for emitting UI updates.
        binary_path: Path to the binary to analyze.
        script_path: Path to the Frida script file to execute.

    """
    session = None
    try:
        main_app.update_output.emit(
            f"[Frida Runner] Starting script '{os.path.basename(script_path)}' on {os.path.basename(binary_path)}...",
        )

        with open(script_path, encoding="utf-8") as f:
            script_source = f.read()

        device = frida.get_local_device()
        pid = device.spawn([binary_path])
        session = device.attach(pid)

        active_frida_sessions[binary_path] = session
        main_app.update_output.emit(f"[Frida Runner] Attached to PID: {pid}. Running script.")

        script = session.create_script(script_source)
        script.on("message", lambda message, data: on_frida_message(main_app, binary_path, message, data))
        script.load()

        device.resume(pid)

        while not session.is_detached:
            frida.sleep(1)

    except Exception as e:
        main_app.update_output.emit(f"[Frida Runner] An error occurred: {e}")
    finally:
        active_frida_sessions.pop(binary_path, None)
        main_app.update_output.emit(f"[Frida Runner] Script '{os.path.basename(script_path)}' finished.")
        if hasattr(main_app, "analysis_completed"):
            main_app.analysis_completed.emit("Frida Script Runner")


def run_frida_analysis(main_app: "IntellicrackApp") -> None:
    """Present a dialog to select a whitelisted analysis script.

    Displays a selection dialog allowing the user to choose from approved Frida
    analysis scripts, then spawns a thread to run the selected script against
    the currently loaded binary.

    Args:
        main_app: Main application instance.

    """
    if not main_app.current_binary:
        main_app.update_output.emit("[Frida Runner] Error: No binary loaded.")
        return

    binary_path = main_app.current_binary
    if binary_path in active_frida_sessions:
        main_app.update_output.emit("[Frida Runner] Error: A Frida script is already running for this binary.")
        return

    try:
        current_dir = os.path.dirname(os.path.abspath(__file__))
        script_dir = os.path.join(current_dir, "..", "..", "scripts", "frida")
        script_dir = os.path.normpath(script_dir)

        available_scripts = [f for f in os.listdir(script_dir) if f.endswith(".js") and f in ANALYSIS_SCRIPTS_WHITELIST]
        if not available_scripts:
            main_app.update_output.emit("[Frida Runner] Error: No approved analysis scripts found.")
            return

    except Exception as e:
        main_app.update_output.emit(f"[Frida Runner] Error reading script directory: {e}")
        return

    script_name, ok = QInputDialog.getItem(
        main_app,
        "Select Analysis Script",
        "Choose a Frida script to run:",
        sorted(available_scripts),
        0,
        False,
    )

    if not (ok and script_name):
        main_app.update_output.emit("[Frida Runner] No script selected. Analysis cancelled.")
        return

    script_path = os.path.join(script_dir, script_name)

    thread = Thread(target=run_frida_script_thread, args=(main_app, binary_path, script_path), daemon=True)
    thread.start()
    main_app.update_output.emit("[Frida Runner] Analysis task submitted.")


def stop_frida_analysis(main_app: "IntellicrackApp") -> None:
    """Stop running Frida analysis session for the current binary.

    Detaches from the active Frida session for the currently loaded binary
    if one exists.

    Args:
        main_app: Main application instance.

    """
    if not main_app.current_binary:
        main_app.update_output.emit("[Frida Runner] Error: No binary loaded.")
        return

    binary_path = main_app.current_binary
    if binary_path in active_frida_sessions:
        session = active_frida_sessions.get(binary_path)
        if session and not session.is_detached:
            session.detach()
            main_app.update_output.emit(f"[Frida Runner] Detach signal sent for {os.path.basename(binary_path)}.")
    else:
        main_app.update_output.emit("[Frida Runner] No active analysis found for this binary.")


def start_stalker_session(
    main_app: "IntellicrackApp",
    output_dir: str | None = None,
) -> bool:
    """Start a Stalker tracing session for comprehensive dynamic analysis.

    Initializes and starts a Stalker session for the currently loaded binary,
    enabling comprehensive instruction tracing and code coverage analysis to
    identify licensing validation routines.

    Args:
        main_app: Main application instance.
        output_dir: Optional directory for trace output files. If not provided,
            uses default location.

    Returns:
        True if session started successfully, False otherwise.

    """
    if StalkerSession is None:
        main_app.update_output.emit("[Stalker] Error: Stalker module not available.")
        return False

    if not main_app.current_binary:
        main_app.update_output.emit("[Stalker] Error: No binary loaded.")
        return False

    binary_path = main_app.current_binary

    if binary_path in active_stalker_sessions:
        main_app.update_output.emit("[Stalker] Error: A Stalker session is already active for this binary.")
        return False

    try:
        session = StalkerSession(
            binary_path=binary_path,
            output_dir=output_dir,
            message_callback=main_app.update_output.emit,
        )

        if session.start():
            active_stalker_sessions[binary_path] = session
            main_app.update_output.emit("[Stalker] Session started successfully.")
            return True
        main_app.update_output.emit("[Stalker] Failed to start session.")
        return False

    except Exception as e:
        main_app.update_output.emit(f"[Stalker] Error starting session: {e}")
        return False


def stop_stalker_session(main_app: "IntellicrackApp") -> bool:
    """Stop active Stalker session and export results.

    Terminates the active Stalker tracing session, retrieves trace statistics
    including identified licensing routines and API calls, exports results to
    a file, and cleans up session resources.

    Args:
        main_app: Main application instance.

    Returns:
        True if session stopped successfully, False otherwise.

    """
    if not main_app.current_binary:
        main_app.update_output.emit("[Stalker] Error: No binary loaded.")
        return False

    binary_path = main_app.current_binary

    if binary_path not in active_stalker_sessions:
        main_app.update_output.emit("[Stalker] No active session for this binary.")
        return False

    try:
        session = active_stalker_sessions[binary_path]
        session.stop_stalking()

        stats = session.get_stats()
        main_app.update_output.emit(
            f"[Stalker] Trace Statistics:\n"
            f"  - Total Instructions: {stats.total_instructions:,}\n"
            f"  - Unique Blocks: {stats.unique_blocks:,}\n"
            f"  - Coverage Entries: {stats.coverage_entries:,}\n"
            f"  - Licensing Routines: {stats.licensing_routines}\n"
            f"  - API Calls: {stats.api_calls}\n"
            f"  - Duration: {stats.trace_duration:.2f}s",
        )

        results_file = session.export_results()
        main_app.update_output.emit(f"[Stalker] Results exported to: {results_file}")

        session.cleanup()
        del active_stalker_sessions[binary_path]

        return True

    except Exception as e:
        main_app.update_output.emit(f"[Stalker] Error stopping session: {e}")
        return False


def trace_function_stalker(
    main_app: "IntellicrackApp",
    module_name: str,
    function_name: str,
) -> bool:
    """Trace execution of a specific function using Stalker.

    Initiates instruction-level tracing for a specific function within a loaded
    module, useful for analyzing licensing validation logic and protection
    mechanisms.

    Args:
        main_app: Main application instance.
        module_name: Name of module containing the function.
        function_name: Name of function to trace.

    Returns:
        True if trace started successfully, False otherwise.

    """
    if not main_app.current_binary:
        main_app.update_output.emit("[Stalker] Error: No binary loaded.")
        return False

    binary_path = main_app.current_binary

    if binary_path not in active_stalker_sessions:
        main_app.update_output.emit("[Stalker] Error: No active session. Start a session first.")
        return False

    try:
        session = active_stalker_sessions[binary_path]
        success = session.trace_function(module_name, function_name)

        if success:
            main_app.update_output.emit(f"[Stalker] Tracing function: {module_name}!{function_name}")
        else:
            main_app.update_output.emit(f"[Stalker] Failed to trace function: {module_name}!{function_name}")

        return success

    except Exception as e:
        main_app.update_output.emit(f"[Stalker] Error tracing function: {e}")
        return False


def collect_module_coverage_stalker(
    main_app: "IntellicrackApp",
    module_name: str,
) -> bool:
    """Collect code coverage for a specific module using Stalker.

    Initiates code coverage collection for a module, identifying which code
    paths are executed and useful for analyzing protection logic and licensing
    checks during binary execution.

    Args:
        main_app: Main application instance.
        module_name: Name of module to analyze.

    Returns:
        True if coverage collection started successfully, False otherwise.

    """
    if not main_app.current_binary:
        main_app.update_output.emit("[Stalker] Error: No binary loaded.")
        return False

    binary_path = main_app.current_binary

    if binary_path not in active_stalker_sessions:
        main_app.update_output.emit("[Stalker] Error: No active session. Start a session first.")
        return False

    try:
        session = active_stalker_sessions[binary_path]
        success = session.collect_module_coverage(module_name)

        if success:
            main_app.update_output.emit(f"[Stalker] Collecting coverage for module: {module_name}")
        else:
            main_app.update_output.emit(f"[Stalker] Failed to collect coverage for: {module_name}")

        return success

    except Exception as e:
        main_app.update_output.emit(f"[Stalker] Error collecting coverage: {e}")
        return False


def get_stalker_stats(main_app: "IntellicrackApp") -> dict[str, Any] | None:
    """Get current Stalker statistics.

    Retrieves comprehensive trace statistics from the active Stalker session,
    including instruction counts, basic block information, API calls, and
    identified licensing routines.

    Args:
        main_app: Main application instance.

    Returns:
        Dictionary with trace statistics including total_instructions, unique_blocks,
        coverage_entries, licensing_routines, api_calls, and trace_duration.
        Returns None if no active session for the current binary.

    """
    if not main_app.current_binary:
        return None

    binary_path = main_app.current_binary

    if binary_path not in active_stalker_sessions:
        return None

    try:
        session = active_stalker_sessions[binary_path]
        stats = session.get_stats()

        return {
            "total_instructions": stats.total_instructions,
            "unique_blocks": stats.unique_blocks,
            "coverage_entries": stats.coverage_entries,
            "licensing_routines": stats.licensing_routines,
            "api_calls": stats.api_calls,
            "trace_duration": stats.trace_duration,
        }

    except Exception as e:
        main_app.update_output.emit(f"[Stalker] Error getting stats: {e}")
        return None


def get_licensing_routines_stalker(main_app: "IntellicrackApp") -> list[str] | None:
    """Get list of identified licensing routines from Stalker.

    Retrieves a list of licensing routines that were identified and analyzed
    during the Stalker tracing session, useful for understanding protection
    mechanisms employed by the binary.

    Args:
        main_app: Main application instance.

    Returns:
        List of licensing routine identifiers identified during tracing, or None
        if no active session for the current binary.

    """
    if not main_app.current_binary:
        return None

    binary_path = main_app.current_binary

    if binary_path not in active_stalker_sessions:
        return None

    try:
        session = active_stalker_sessions[binary_path]
        return session.get_licensing_routines()

    except Exception as e:
        main_app.update_output.emit(f"[Stalker] Error getting licensing routines: {e}")
        return None

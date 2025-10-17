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

import frida

# Import QInputDialog for a controlled, non-editable selection dialog
from intellicrack.handlers.pyqt6_handler import QInputDialog

# --- Frida Session Management ---
active_frida_sessions = {}

# --- Whitelist of Approved Analysis Scripts ---
# To maintain stability and security, only scripts from this list are selectable.
ANALYSIS_SCRIPTS_WHITELIST = [
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
]


def on_frida_message(main_app, binary_path, message, data):
    """Handle messages from Frida scripts."""
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


def run_frida_script_thread(main_app, binary_path, script_path):
    """Execute Frida script logic in a separate thread."""
    session = None
    try:
        main_app.update_output.emit(
            f"[Frida Runner] Starting script '{os.path.basename(script_path)}' on {os.path.basename(binary_path)}..."
        )

        with open(script_path, "r", encoding="utf-8") as f:
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
        if binary_path in active_frida_sessions:
            del active_frida_sessions[binary_path]
        main_app.update_output.emit(f"[Frida Runner] Script '{os.path.basename(script_path)}' finished.")
        if hasattr(main_app, "analysis_completed"):
            main_app.analysis_completed.emit("Frida Script Runner")


def run_frida_analysis(main_app):
    """Present a dialog for the user to select a whitelisted analysis script,.

    then run it against the currently loaded binary.
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
        main_app, "Select Analysis Script", "Choose a Frida script to run:", sorted(available_scripts), 0, False
    )

    if not (ok and script_name):
        main_app.update_output.emit("[Frida Runner] No script selected. Analysis cancelled.")
        return

    script_path = os.path.join(script_dir, script_name)

    thread = Thread(target=run_frida_script_thread, args=(main_app, binary_path, script_path), daemon=True)
    thread.start()
    main_app.update_output.emit("[Frida Runner] Analysis task submitted.")


def stop_frida_analysis(main_app):
    """Stop running Frida analysis session for the current binary."""
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

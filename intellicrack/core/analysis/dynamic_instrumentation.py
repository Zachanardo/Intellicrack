"""Dynamic binary instrumentation using Frida.

This module provides the core functionality for instrumenting a running
process to monitor its behavior, trace function calls, and manipulate
its execution flow in real-time.

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

import time
from threading import Thread
from typing import Any, Protocol

import frida


class SignalProtocol(Protocol):
    """Protocol for Qt signal."""

    def emit(self, arg: str) -> None:
        """Emit signal with string argument.

        Args:
            arg: String argument to emit in the signal.

        Returns:
            None
        """
        ...


class MainAppProtocol(Protocol):
    """Protocol for main application interface."""

    current_binary: str
    update_output: SignalProtocol
    analysis_completed: SignalProtocol


def on_message(
    main_app: MainAppProtocol,
    message: frida.core.ScriptPayloadMessage | frida.core.ScriptErrorMessage,
    data: bytes | None,
) -> None:
    """Handle messages from Frida scripts.

    Processes messages received from Frida instrumentation scripts and relays
    them to the main UI for display. Handles both standard output messages and
    error messages from the instrumentation engine.

    Args:
        main_app: Reference to the main application window that receives output
            updates via signals.
        message: Frida message object containing either payload data or error
            information.
        data: Optional binary data payload from Frida script (typically unused).

    Returns:
        None
    """
    msg_type: str = message.get("type", "")
    if msg_type == "send":
        payload: Any = message.get("payload", "")
        main_app.update_output.emit(f"[Frida] {payload}")
    elif msg_type == "error":
        stack: Any = message.get("stack", "")
        main_app.update_output.emit(f"[Frida Error] {stack}")


def run_instrumentation_thread(main_app: MainAppProtocol, binary_path: str, script_source: str) -> None:
    """Run instrumentation logic in a separate thread.

    Executes binary instrumentation using Frida in a separate thread to avoid
    blocking the main UI. This function handles process attachment, script
    injection, execution monitoring, and graceful cleanup of Frida sessions.

    Args:
        main_app: Reference to the main application window for emitting status
            updates via signals.
        binary_path: Absolute file path to the binary executable to instrument.
        script_source: Frida JavaScript instrumentation code to inject and
            execute in the target process.

    Returns:
        None

    Raises:
        ProcessNotFoundError: If the spawned process terminates prematurely
            before instrumentation can be completed.
        TransportError: If communication with the Frida server fails due to
            network or transport layer issues.
        Exception: For any unexpected errors during instrumentation execution.
    """
    try:
        main_app.update_output.emit("[Dynamic Instrumentation] Starting instrumentation thread...")
        device: Any = frida.get_local_device()

        main_app.update_output.emit(f"[Dynamic Instrumentation] Spawning process: {binary_path}")
        pid: Any = device.spawn([binary_path])
        session: Any = device.attach(pid)
        main_app.update_output.emit(f"[Dynamic Instrumentation] Attached to PID: {pid}")

        script: Any = session.create_script(script_source)

        script.on("message", lambda message, data: on_message(main_app, message, data))

        script.load()
        main_app.update_output.emit("[Dynamic Instrumentation] Frida script loaded. Resuming process...")
        device.resume(pid)

        time.sleep(15)

        main_app.update_output.emit("[Dynamic Instrumentation] Detaching from process.")
        session.detach()
        main_app.update_output.emit("[Dynamic Instrumentation] Analysis finished.")

    except frida.ProcessNotFoundError:
        main_app.update_output.emit("[Dynamic Instrumentation] Error: Process terminated prematurely.")
    except frida.TransportError as e:
        main_app.update_output.emit(f"[Dynamic Instrumentation] Frida transport error: {e}")
    except Exception as e:
        main_app.update_output.emit(f"[Dynamic Instrumentation] An unexpected error occurred: {e}")
    finally:
        main_app.analysis_completed.emit("Dynamic Instrumentation")


def run_dynamic_instrumentation(main_app: MainAppProtocol) -> None:
    """Launch dynamic instrumentation session using Frida.

    Initiates a Frida-based dynamic instrumentation session targeting the
    currently loaded binary. This function is designed to be called from the
    main UI thread and delegates the actual instrumentation work to a background
    thread to maintain UI responsiveness. The instrumentation hooks into system
    calls such as file operations (CreateFileW on Windows, open on Linux/macOS)
    to monitor binary behavior.

    Args:
        main_app: Reference to the main application window containing the
            currently loaded binary path and output signal for status updates.

    Returns:
        None

    Raises:
        None: This function handles all exceptions internally and communicates
            errors through the main_app signal interface.
    """
    if not main_app.current_binary:
        main_app.update_output.emit("[Dynamic Instrumentation] Error: No binary loaded.")
        return

    binary_path: str = main_app.current_binary

    script_source: str = """
    const platform = Process.platform;

    if (platform === 'windows') {
        const createFileW = Module.findExportByName('kernel32.dll', 'CreateFileW');
        Interceptor.attach(createFileW, {
            onEnter: function (args) {
                const path = args[0].readUtf16String();
                send('CreateFileW called for: ' + path);
            }
        });
    } else if (platform === 'linux' || platform === 'darwin') {
        const open = Module.findExportByName(null, 'open');
        Interceptor.attach(open, {
            onEnter: function (args) {
                const path = args[0].readUtf8String();
                send('open() called for: ' + path);
            }
        });
    }
    """

    thread: Thread = Thread(target=run_instrumentation_thread, args=(main_app, binary_path, script_source), daemon=True)
    thread.start()
    main_app.update_output.emit("[Dynamic Instrumentation] Task submitted to background thread.")

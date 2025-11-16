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

import frida


def on_message(main_app: object, message: dict[str, object], data: object) -> None:
    """Handle messages from Frida scripts.

    Processes messages received from Frida instrumentation scripts and relays
    them to the main UI for display. Handles both standard output messages and
    error messages from the instrumentation engine.

    Args:
        main_app: Reference to the main application window that receives output
            updates via signals.
        message: Dictionary containing message metadata including "type" field
            ("send" or "error") and relevant payload or stack trace data.
        data: Optional binary data payload from Frida script (typically unused).

    Returns:
        None

    """
    if message["type"] == "send":
        payload = message["payload"]
        main_app.update_output.emit(f"[Frida] {payload}")
    elif message["type"] == "error":
        main_app.update_output.emit(f"[Frida Error] {message['stack']}")


def run_instrumentation_thread(main_app: object, binary_path: str, script_source: str) -> None:
    """Run instrumentation logic in a separate thread.

    Executes binary instrumentation using Frida in a separate thread to avoid
    blocking the main UI. This function handles process attachment, script
    injection, execution monitoring, and graceful cleanup of Frida sessions.

    Args:
        main_app: Reference to the main application window for emitting status
            updates via signals.
        binary_path: Absolute file path to the binary executable to instrument.
        script_source: Frida JavaScript instrumentation code to inject and execute
            in the target process.

    Returns:
        None

    Raises:
        frida.ProcessNotFoundError: If the spawned process terminates unexpectedly
            before analysis completion.
        frida.TransportError: If Frida communication with the target process fails.
        Exception: For any other unexpected errors during instrumentation.

    """
    try:
        main_app.update_output.emit("[Dynamic Instrumentation] Starting instrumentation thread...")
        device = frida.get_local_device()

        main_app.update_output.emit(f"[Dynamic Instrumentation] Spawning process: {binary_path}")
        pid = device.spawn([binary_path])
        session = device.attach(pid)
        main_app.update_output.emit(f"[Dynamic Instrumentation] Attached to PID: {pid}")

        script = session.create_script(script_source)

        # Set up the message handler
        script.on("message", lambda message, data: on_message(main_app, message, data))

        script.load()
        main_app.update_output.emit("[Dynamic Instrumentation] Frida script loaded. Resuming process...")
        device.resume(pid)

        # Allow time for the application to run and generate events.
        # In a real scenario, this might be controlled by the user.
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
        # Notify the main thread that the analysis is complete
        if hasattr(main_app, "analysis_completed"):
            main_app.analysis_completed.emit("Dynamic Instrumentation")


def run_dynamic_instrumentation(main_app: object) -> None:
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
        None: Errors are caught internally and communicated via main_app signals.

    """
    if not main_app.current_binary:
        main_app.update_output.emit("[Dynamic Instrumentation] Error: No binary loaded.")
        return

    binary_path = main_app.current_binary

    # This example Frida script traces file access by hooking `open` on Linux/macOS
    # and `CreateFileW` on Windows. It demonstrates a real, effective use case.
    script_source = """
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

    # Run the instrumentation in a background thread to keep the UI responsive
    thread = Thread(target=run_instrumentation_thread, args=(main_app, binary_path, script_source), daemon=True)
    thread.start()
    main_app.update_output.emit("[Dynamic Instrumentation] Task submitted to background thread.")

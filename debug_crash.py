"""Aggressive crash debugging script for Intellicrack."""
from __future__ import annotations

import ctypes
import ctypes.wintypes
import faulthandler
import os
import signal
import sys
import threading
import traceback
from pathlib import Path
from types import FrameType


def setup_windows_crash_handler() -> None:
    """Set up Windows-specific crash handling."""
    kernel32 = ctypes.windll.kernel32

    SEM_FAILCRITICALERRORS = 0x0001
    SEM_NOGPFAULTERRORBOX = 0x0002
    SEM_NOOPENFILEERRORBOX = 0x8000
    kernel32.SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX)

    try:
        EXCEPTION_EXECUTE_HANDLER = 1
        kernel32.SetUnhandledExceptionFilter(None)
    except Exception:
        pass


def signal_handler(signum: int, frame: FrameType | None) -> None:
    """Handle signals."""
    print(f"\n{'='*60}", file=sys.stderr, flush=True)
    print(f"SIGNAL RECEIVED: {signum}", file=sys.stderr, flush=True)
    print(f"{'='*60}", file=sys.stderr, flush=True)
    if frame:
        traceback.print_stack(frame, file=sys.stderr)
    sys.stderr.flush()
    sys.exit(1)


def exception_hook(exc_type: type, exc_value: BaseException, exc_tb: object) -> None:
    """Global exception hook."""
    print(f"\n{'='*60}", file=sys.stderr, flush=True)
    print("UNCAUGHT EXCEPTION", file=sys.stderr, flush=True)
    print(f"{'='*60}", file=sys.stderr, flush=True)
    traceback.print_exception(exc_type, exc_value, exc_tb, file=sys.stderr)
    sys.stderr.flush()


def qt_message_handler(mode: int, context: object, message: str) -> None:
    """Qt message handler to catch Qt warnings/errors."""
    mode_names = {0: "DEBUG", 1: "WARNING", 2: "CRITICAL", 3: "FATAL", 4: "INFO"}
    mode_name = mode_names.get(mode, f"UNKNOWN({mode})")
    print(f"[Qt {mode_name}] {message}", file=sys.stderr, flush=True)

    if mode == 3:
        print("\n" + "="*60, file=sys.stderr, flush=True)
        print("QT FATAL ERROR - DUMPING STACK TRACES", file=sys.stderr, flush=True)
        print("="*60, file=sys.stderr, flush=True)
        faulthandler.dump_traceback(file=sys.stderr)
        sys.stderr.flush()


def main() -> int:
    """Main entry point with aggressive crash debugging."""
    os.environ["PYTHONFAULTHANDLER"] = "1"
    os.environ["QT_DEBUG_PLUGINS"] = "1"
    os.environ["QT_LOGGING_RULES"] = "*=true"
    os.environ["QT_FATAL_WARNINGS"] = "0"
    os.environ["QT_OPENGL"] = "software"

    faulthandler.enable(file=sys.stderr, all_threads=True)

    setup_windows_crash_handler()

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    if hasattr(signal, "SIGBREAK"):
        signal.signal(signal.SIGBREAK, signal_handler)

    sys.excepthook = exception_hook

    def threading_excepthook(args: threading.ExceptHookArgs) -> None:
        print(f"\n{'='*60}", file=sys.stderr, flush=True)
        print(f"THREAD EXCEPTION in {args.thread}", file=sys.stderr, flush=True)
        print(f"{'='*60}", file=sys.stderr, flush=True)
        traceback.print_exception(args.exc_type, args.exc_value, args.exc_traceback, file=sys.stderr)
        sys.stderr.flush()

    threading.excepthook = threading_excepthook

    print("="*60)
    print("INTELLICRACK DEBUG MODE")
    print("="*60)
    print(f"Python: {sys.version}")
    print(f"Platform: {sys.platform}")
    print(f"Executable: {sys.executable}")
    print("="*60)
    print("Crash debugging enabled:")
    print("  - faulthandler (all threads)")
    print("  - Qt message handler")
    print("  - Windows error mode")
    print("  - Signal handlers")
    print("  - Exception hooks")
    print("="*60)
    print()
    sys.stdout.flush()

    try:
        from PyQt6.QtCore import qInstallMessageHandler, QtMsgType
        qInstallMessageHandler(qt_message_handler)
        print("Qt message handler installed", flush=True)
    except ImportError:
        print("WARNING: Could not install Qt message handler", flush=True)

    print("\nStarting Intellicrack GUI...", flush=True)
    print("Click anywhere to test - crash info will appear here\n", flush=True)

    try:
        from intellicrack.ui.main_app import launch
        return launch()
    except Exception as e:
        print(f"\n{'='*60}", file=sys.stderr, flush=True)
        print("EXCEPTION DURING LAUNCH", file=sys.stderr, flush=True)
        print(f"{'='*60}", file=sys.stderr, flush=True)
        traceback.print_exc(file=sys.stderr)
        sys.stderr.flush()
        return 1


if __name__ == "__main__":
    sys.exit(main())

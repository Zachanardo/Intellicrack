"""Crash capture script for Intellicrack.

This script runs Intellicrack with aggressive crash capture settings to diagnose
Qt/C-level crashes that aren't caught by Python exception handlers.
"""

import ctypes
import faulthandler
import os
import signal
import sys
import traceback

# Enable faulthandler to dump stack traces on crashes
faulthandler.enable(all_threads=True)

# Set Windows error mode to show all errors (don't suppress them)
if sys.platform == 'win32':
    # SEM_FAILCRITICALERRORS = 0x0001
    # SEM_NOALIGNMENTFAULTEXCEPT = 0x0004
    # SEM_NOGPFAULTERRORBOX = 0x0002
    # SEM_NOOPENFILEERRORBOX = 0x8000
    # Setting to 0 means show all error dialogs
    ctypes.windll.kernel32.SetErrorMode(0)

# Custom exception hook to catch all Python exceptions
original_excepthook = sys.excepthook

def exception_hook(exc_type, exc_value, exc_tb):
    """Custom exception hook that logs before passing to original."""
    print("=" * 60, file=sys.stderr)
    print("UNCAUGHT EXCEPTION:", file=sys.stderr)
    print("=" * 60, file=sys.stderr)
    traceback.print_exception(exc_type, exc_value, exc_tb, file=sys.stderr)
    print("=" * 60, file=sys.stderr)
    original_excepthook(exc_type, exc_value, exc_tb)

sys.excepthook = exception_hook

# Handle SIGTERM and SIGINT
def signal_handler(signum, frame):
    """Handle signals."""
    print(f"\nReceived signal {signum}", file=sys.stderr)
    print("Stack trace:", file=sys.stderr)
    traceback.print_stack(frame, file=sys.stderr)
    sys.exit(128 + signum)

signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGINT, signal_handler)

# Windows-specific: handle SIGSEGV if available
if hasattr(signal, 'SIGSEGV'):
    def sigsegv_handler(signum, frame):
        """Handle segmentation fault."""
        print("\nSEGMENTATION FAULT!", file=sys.stderr)
        print("Stack trace:", file=sys.stderr)
        traceback.print_stack(frame, file=sys.stderr)
        faulthandler.dump_traceback(file=sys.stderr, all_threads=True)
        sys.exit(139)  # 128 + 11

    try:
        signal.signal(signal.SIGSEGV, sigsegv_handler)
    except (ValueError, OSError):
        pass  # Some platforms don't allow SIGSEGV handling

# Set environment variables for Qt debugging
os.environ['QT_DEBUG_PLUGINS'] = '1'
os.environ['QT_LOGGING_RULES'] = 'qt.*=true'
os.environ['QT_FATAL_WARNINGS'] = '0'  # Don't abort on Qt warnings
os.environ['PYTHONFAULTHANDLER'] = '1'

# Additional Qt debugging for crashes
os.environ['QT_ENABLE_REGEXP_JIT'] = '0'  # Disable JIT which can cause crashes
os.environ['QT_OPENGL'] = 'software'  # Force software rendering

print("=" * 60)
print("INTELLICRACK CRASH CAPTURE MODE")
print("=" * 60)
print(f"Python: {sys.version}")
print(f"Platform: {sys.platform}")
print(f"faulthandler enabled: {faulthandler.is_enabled()}")
print("=" * 60)

# Import and run Intellicrack
try:
    from intellicrack.ui.main_app import launch

    print("Starting Intellicrack GUI...")
    print("Interact with the application to trigger the crash.")
    print("=" * 60)

    result = launch()
    print(f"\nApplication exited with code: {result}")

except Exception as e:
    print("=" * 60, file=sys.stderr)
    print(f"EXCEPTION DURING LAUNCH: {type(e).__name__}: {e}", file=sys.stderr)
    print("=" * 60, file=sys.stderr)
    traceback.print_exc(file=sys.stderr)
    sys.exit(1)

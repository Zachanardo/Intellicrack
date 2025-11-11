"""Safe launcher with DLL validation and error handling.

This wrapper validates DLL dependencies before launching the main application
to prevent fatal system crashes from corrupted DLLs.
"""
import ctypes
import sys
from pathlib import Path

# Add project root to sys.path so we can import intellicrack from scripts/ directory
_SCRIPT_DIR = Path(__file__).parent
_PROJECT_ROOT = _SCRIPT_DIR.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))


def validate_mkl_dlls():
    """Pre-validate Intel MKL DLLs before importing any packages.

    Returns:
        tuple: (success: bool, error_message: str)

    """
    pixi_lib = Path(r"D:\Intellicrack\.pixi\envs\default\Library\bin")

    if not pixi_lib.exists():
        return False, f"Pixi library directory not found: {pixi_lib}"

    critical_dlls = [
        "mkl_core.2.dll",
        "mkl_intel_thread.2.dll",
        "mkl_def.2.dll",
        "mkl_sycl_blas.5.dll",
    ]

    for dll_name in critical_dlls:
        dll_path = pixi_lib / dll_name
        if not dll_path.exists():
            continue

        try:
            handle = ctypes.CDLL(str(dll_path), winmode=0)
            del handle
        except OSError as e:
            error_code = getattr(e, 'winerror', None)
            if error_code in {3221225785, 127}:
                return False, (
                    f"Entry point not found in {dll_name}: {e}\n\n"
                    f"This indicates ABI incompatibility - system Intel oneAPI DLLs may be loading instead of pixi environment DLLs.\n"
                    f"Expected DLL location: {dll_path}\n\n"
                    f"SOLUTION: Ensure system Intel oneAPI paths are not in PATH environment variable.\n"
                    f"The Rust launcher should block these automatically."
                )
            return False, f"Failed to load {dll_name}: {e}\nDLL may be corrupted or from incompatible version."

    return True, ""


def safe_import_check():
    """Safely test critical imports before launching GUI.

    Returns:
        tuple: (success: bool, error_message: str)

    """
    critical_imports = [
        ("numpy", "NumPy - required for numerical operations"),
        ("PyQt6.QtCore", "Qt6 Core - required for GUI"),
    ]

    for module_name, description in critical_imports:
        try:
            __import__(module_name)
        except ImportError as e:
            return False, f"Failed to import {description}:\n{e}"
        except Exception as e:
            return False, f"Error importing {module_name}:\n{e}\nThis may indicate DLL corruption."

    return True, ""


def main():
    """Safe entry point with comprehensive error handling."""
    print("=== Intellicrack Safe Launcher ===\n")

    print("[1/3] Validating Intel MKL DLLs...")
    success, error = validate_mkl_dlls()
    if not success:
        print(f"FAIL FAILED: {error}")
        print("\nRECOMMENDATION: Reinstall Intel MKL via pixi:")
        print("  pixi reinstall")
        input("\nPress Enter to exit safely...")
        return 1
    print("OK MKL DLLs validated successfully")

    print("\n[2/3] Testing critical imports...")
    success, error = safe_import_check()
    if not success:
        print(f"FAIL FAILED: {error}")
        print("\nRECOMMENDATION: Reinstall dependencies:")
        print("  pixi reinstall")
        input("\nPress Enter to exit safely...")
        return 1
    print("OK Critical imports successful")

    print("\n[3/3] Launching Intellicrack main application...")
    try:
        import intellicrack.main
        return intellicrack.main.main()
    except Exception as e:
        print("\nFAIL FATAL ERROR in main application:")
        print(f"  {type(e).__name__}: {e}")
        print("\nStack trace:")
        import traceback
        traceback.print_exc()
        print("\nApplication failed to start. Error details saved above.")
        input("\nPress Enter to exit safely...")
        return 1


if __name__ == "__main__":
    try:
        exit_code = main()
    except KeyboardInterrupt:
        print("\n\nInterrupted by user. Exiting safely...")
        exit_code = 130
    except Exception as e:
        print("\n\nFAIL UNEXPECTED FATAL ERROR:")
        print(f"  {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        print("\nThis error was caught to prevent system crash.")
        input("\nPress Enter to exit safely...")
        exit_code = 1

    sys.exit(exit_code)

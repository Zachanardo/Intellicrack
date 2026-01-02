"""DLL loading diagnostics tool for Intel MKL troubleshooting.

This tool verifies which DLLs are actually loaded at runtime and from what locations,
helping diagnose PATH priority issues and version conflicts.
"""
import ctypes
import os
from pathlib import Path


def get_loaded_dll_path(dll_name: str) -> str | None:
    """Get the actual path of a loaded DLL using Windows API.

    Args:
        dll_name: Name of the DLL (e.g., 'mkl_sycl_blas.5.dll')

    Returns:
        Path to loaded DLL or None if not found

    """
    try:
        kernel32 = ctypes.windll.kernel32
        h_module = kernel32.GetModuleHandleW(dll_name)

        if h_module:
            path_buffer = ctypes.create_unicode_buffer(32768)
            kernel32.GetModuleFileNameW(h_module, path_buffer, 32768)
            return path_buffer.value

        h_module = kernel32.LoadLibraryW(dll_name)
        if h_module:
            path_buffer = ctypes.create_unicode_buffer(32768)
            kernel32.GetModuleFileNameW(h_module, path_buffer, 32768)
            kernel32.FreeLibrary(h_module)
            return path_buffer.value

        return None
    except Exception as e:
        return f"Error: {e}"


def check_path_priority() -> tuple[list[str], list[str], list[str]]:
    """Analyze PATH environment variable for Intel oneAPI interference."""
    path_dirs = os.environ.get("PATH", "").split(";")

    pixi_dirs = []
    intel_dirs = []
    other_dirs = []

    for directory in path_dirs:
        dir_lower = directory.lower()
        if "pixi" in dir_lower or "intellicrack" in dir_lower:
            pixi_dirs.append(directory)
        elif "intel" in dir_lower or "oneapi" in dir_lower or "mkl" in dir_lower:
            intel_dirs.append(directory)
        else:
            other_dirs.append(directory)

    return pixi_dirs, intel_dirs, other_dirs


def diagnose_mkl_loading() -> None:
    """Comprehensive diagnostic of Intel MKL DLL loading."""
    print("=" * 80)
    print("INTEL MKL DLL LOADING DIAGNOSTICS")
    print("=" * 80)

    pixi_lib = Path(r"D:\Intellicrack\.pixi\envs\default\Library\bin")

    print("\n[1] Pixi Environment")
    print(f"    Location: {pixi_lib}")
    print(f"    Exists: {pixi_lib.exists()}")

    if pixi_lib.exists():
        mkl_dlls = list(pixi_lib.glob("mkl_*.dll")) + list(pixi_lib.glob("sycl*.dll"))
        print(f"    MKL/SYCL DLLs found: {len(mkl_dlls)}")
        for dll in sorted(mkl_dlls)[:10]:
            print(f"      - {dll.name}")
        if len(mkl_dlls) > 10:
            print(f"      ... and {len(mkl_dlls) - 10} more")

    print("\n[2] PATH Environment Variable Analysis")
    pixi_dirs, intel_dirs, _other_dirs = check_path_priority()

    print(f"    Pixi directories ({len(pixi_dirs)}):")
    for idx, directory in enumerate(pixi_dirs[:5], 1):
        print(f"      {idx}. {directory}")
    if len(pixi_dirs) > 5:
        print(f"      ... and {len(pixi_dirs) - 5} more")

    print(f"\n    Intel/oneAPI directories ({len(intel_dirs)}):")
    if intel_dirs:
        print("    WARNING  WARNING: System Intel paths detected in PATH!")
        for idx, directory in enumerate(intel_dirs[:5], 1):
            print(f"      {idx}. {directory}")
        if len(intel_dirs) > 5:
            print(f"      ... and {len(intel_dirs) - 5} more")
    else:
        print("    OK No system Intel paths found (GOOD)")

    print("\n[3] Critical DLL Loading Verification")
    critical_dlls = [
        "mkl_core.2.dll",
        "mkl_sycl_blas.5.dll",
        "mkl_intel_thread.2.dll",
        "sycl8.dll",
        "libiomp5md.dll",
        "tbb12.dll",
    ]

    for dll_name in critical_dlls:
        loaded_path = get_loaded_dll_path(dll_name)

        if loaded_path is None:
            status = "NOT LOADED"
            location = "N/A"
        elif isinstance(loaded_path, str) and loaded_path.startswith("Error"):
            status = "ERROR"
            location = loaded_path
        else:
            loaded_path_obj = Path(loaded_path)
            if pixi_lib in loaded_path_obj.parents or loaded_path_obj.parent == pixi_lib:
                status = "OK PIXI"
                location = str(loaded_path_obj)
            elif "intel" in str(loaded_path_obj).lower() or "oneapi" in str(loaded_path_obj).lower():
                status = "WARNING  SYSTEM"
                location = str(loaded_path_obj)
            else:
                status = "? OTHER"
                location = str(loaded_path_obj)

        print(f"    {dll_name:25s} : {status:12s} : {location}")

    print("\n[4] Recommendations")
    if intel_dirs:
        print("    WARNING  PROBLEM DETECTED:")
        print("    System Intel oneAPI paths are in PATH environment variable.")
        print("    This can cause DLL version conflicts and entry point errors.")
        print()
        print("    SOLUTION:")
        print("    1. Use the Rust launcher (Intellicrack.exe) which filters PATH automatically")
        print("    2. Or manually remove Intel paths from system PATH")
        print("    3. Ensure pixi environment is activated before launching")
    else:
        print("    OK PATH configuration looks correct")
        print("    Pixi environment DLLs should load properly")

    print("\n" + "=" * 80)


if __name__ == "__main__":
    try:
        diagnose_mkl_loading()
    except Exception as e:
        print(f"\nFAIL DIAGNOSTIC FAILED: {e}")
        import traceback
        traceback.print_exc()

    input("\nPress Enter to exit...")

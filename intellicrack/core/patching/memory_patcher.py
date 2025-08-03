"""Memory Patching Module for Intellicrack

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
along with Intellicrack.  If not, see <https://www.gnu.org/licenses/>.
"""

import datetime
import os
import sys
from typing import Any

from PyQt6.QtWidgets import QMessageBox

from ...utils.logger import get_logger
from ...utils.protection.protection_detection import (
    detect_checksum_verification,
    detect_obfuscation,
    detect_self_healing_code,
)

logger = get_logger(__name__)


def _get_wintypes():
    """Get wintypes module or create a mock replacement."""
    try:
        from ctypes import wintypes

        return wintypes, True
    except ImportError as e:
        logger.error("Import error in memory_patcher: %s", e)

        # Create basic wintypes replacement
        class MockWintypes:
            """Mock Windows types for cross-platform compatibility."""

            class DWORD:
                """Mock DWORD type."""

                def __init__(self):
                    """Initialize DWORD mock type with default value."""
                    self.value = 0

            class BOOL:
                """Mock BOOL type."""

                def __init__(self):
                    """Initialize BOOL mock type with default value."""
                    self.value = 0

        return MockWintypes(), False


# Windows memory protection constants
PAGE_NOACCESS = 0x01
PAGE_EXECUTE_READWRITE = 0x40
PAGE_GUARD = 0x100

# Linux ptrace constants
PTRACE_ATTACH = 16
PTRACE_DETACH = 17
PTRACE_POKEDATA = 5


def log_message(msg: str) -> str:
    """Helper function to format log messages consistently."""
    return f"[{msg}]"


def generate_launcher_script(app: Any, patching_strategy: str = "memory") -> str | None:
    """Generates a launcher script that uses Frida to patch the target program in memory.

    This function creates a Python script that launches the target application
    and applies patches in memory using Frida's dynamic instrumentation. This
    approach is useful for protected binaries that detect file modifications.

    Args:
        app: Application instance containing binary path and patches
        patching_strategy: Strategy to use - "memory" or "disk"

    Returns:
        Path to generated launcher script, or None on error

    """
    if not app.binary_path:
        app.update_output.emit(log_message("[Launcher] No binary selected."))
        return None

    if not hasattr(app, "potential_patches") or not app.potential_patches:
        app.update_output.emit(log_message("[Launcher] No patches available to create launcher."))
        return None

    # Generate launcher script path
    base_name = os.path.splitext(os.path.basename(app.binary_path))[0]
    launcher_path = os.path.join(
        os.path.dirname(app.binary_path),
        f"{base_name}_launcher.py",
    )

    app.update_output.emit(log_message(f"[Launcher] Generating launcher script: {launcher_path}"))

    # Convert patches to string for embedding - escape braces to avoid format conflicts
    import json

    patches_str = json.dumps(app.potential_patches, default=str)

    # Create launcher script content
    script_content = '''#!/usr/bin/env python3
"""
Intellicrack Memory Patcher Launcher
Generated: {timestamp}
Target: {binary_path}
Strategy: {patching_strategy}
"""

import os
import sys
import time
import subprocess
import threading

try:
    import frida
except ImportError as e:
    logger.error("Import error in memory_patcher: %s", e)
    print("Error: Frida is required. Install with: pip install frida-tools")
    sys.exit(1)

# Target binary path
TARGET_BINARY = r"{binary_path}"

# Patches to apply
PATCHES = {patches_str}

def on_message(message, data):
    """Handle messages from Frida script"""
    if message['type'] == 'send':
        print("[Frida] " + str(message['payload']))
    elif message['type'] == 'error':
        print("[Frida Error] " + str(message['stack']))

def create_frida_script():
    """Create the Frida instrumentation script"""
    script_code = """
    console.log('[+] Starting memory patcher...');

    // Get base address of main module
    var mainModule = Process.enumerateModules()[0];
    var baseAddr = mainModule.base;
    console.log('[+] Base address: ' + baseAddr);

    // Apply patches
    var patches = {patches_js};

    patches.forEach(function(patch, index) {{
        try {{
            var address = patch.address;
            var newBytes = patch.new_bytes;
            var description = patch.description || 'Patch ' + index;

            // Calculate actual address
            var patchAddr = baseAddr.add(address - {base_address});

            // Make memory writable
            Memory.protect(patchAddr, newBytes.length, 'rwx');

            // Write new bytes
            patchAddr.writeByteArray(newBytes);

            console.log('[+] Applied patch at ' + patchAddr + ': ' + description);
            send('Patch applied: ' + description);

        }} catch (e) {{
            console.log('[-] Failed to apply patch ' + index + ': ' + e);
            send('Patch failed: ' + description);
        }}
    }});

    console.log('[+] All patches applied');
    send('Memory patching complete');
    """

    return script_code

def launch_with_frida():
    """Launch target with Frida instrumentation"""
    print("[*] Launching " + TARGET_BINARY + " with memory patches...")

    try:
        # Spawn the process suspended
        pid = frida.spawn(TARGET_BINARY)
        session = frida.attach(pid)

        # Create and load script
        script = session.create_script(create_frida_script())
        script.on('message', on_message)
        script.load()

        # Resume the process
        frida.resume(pid)

        print("[+] Process launched and patched successfully")
        print("[*] Press Ctrl+C to detach and exit...")

        # Keep script running
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt as e:
            logger.error("KeyboardInterrupt in memory_patcher: %s", e)
            print("\\n[*] Detaching...")
            session.detach()

    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error in memory_patcher: %s", e)
        print("[-] Error: " + str(e))
        return 1

    return 0

def launch_normal():
    """Launch target normally without patches"""
    print("[*] Launching " + TARGET_BINARY + " normally...")
    try:
        subprocess.Popen([TARGET_BINARY], encoding='utf-8')
        print("[+] Process launched")
    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error in memory_patcher: %s", e)
        print("[-] Error: " + str(e))
        return 1
    return 0

def main():
    \"\"\"Main launcher entry point\"\"\"
    print("=" * 60)
    print("Intellicrack Memory Patcher Launcher")
    print("=" * 60)
    print("Target: " + os.path.basename(TARGET_BINARY))
    print("Patches: " + str(len(PATCHES)))
    print("=" * 60)

    if "{patching_strategy}" == "memory":
        # Check if Frida is available
        try:
            import frida
            print("[+] Frida is available")
            return launch_with_frida()
        except ImportError as e:
            logger.error("Import error in memory_patcher: %s", e)
            print("[-] Frida not available, falling back to normal launch")
            return launch_normal()
    else:
        return launch_normal()

if __name__ == "__main__":
    sys.exit(main())
'''.format(
        timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        binary_path=app.binary_path,
        patching_strategy=patching_strategy,
        patches_str=patches_str,
        patches_js=patches_str,
        base_address=0x400000,  # Default base address for PE files
    )

    # Handle patches format conversion
    patches_formatted = []
    for _patch in app.potential_patches:
        patch_dict = {
            "address": _patch.get("address", 0),
            "new_bytes": list(_patch.get("new_bytes", b""))
            if isinstance(_patch.get("new_bytes"), bytes)
            else _patch.get("new_bytes", []),
            "description": _patch.get("description", "Unknown patch"),
        }
        patches_formatted.append(patch_dict)

    # Replace patches in script
    script_content = script_content.replace(
        f"PATCHES = {app.potential_patches!s}",
        f"PATCHES = {patches_formatted!s}",
    )

    # Write launcher script
    try:
        with open(launcher_path, "w", encoding="utf-8") as f:
            f.write(script_content)

        # Make executable on Unix-like systems
        if sys.platform != "win32":
            os.chmod(launcher_path, 0o755)

        app.update_output.emit(
            log_message(f"[Launcher] Successfully created launcher script: {launcher_path}")
        )

        # Show instructions
        msg = f"Launcher script created: {launcher_path}\\n\\n"
        msg += "To use the launcher:\\n"
        msg += "1. Install Frida: pip install frida-tools\\n"
        msg += f"2. Run: python {os.path.basename(launcher_path)}\\n\\n"
        msg += "The launcher will apply patches in memory without modifying the file."

        QMessageBox.information(app, "Launcher Created", msg)

        return launcher_path

    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error in memory_patcher: %s", e)
        app.update_output.emit(log_message(f"[Launcher] Error creating launcher script: {e}"))
        return None


def setup_memory_patching(app: Any) -> None:
    """Sets up a memory patching environment for heavily protected binaries.

    This function detects various protection mechanisms and configures
    appropriate memory patching strategies. It's used when static patching
    would be detected or reversed by the target application.

    Args:
        app: Application instance with binary path and UI elements

    """
    if not app.binary_path:
        app.update_output.emit(log_message("[Memory Patch] No binary selected."))
        return

    app.update_output.emit(log_message("[Memory Patch] Analyzing protection mechanisms..."))

    # Detect various protections
    protections = []

    # Check for checksum verification
    if detect_checksum_verification(app.binary_path):
        protections.append("Checksum Verification")
        app.update_output.emit(log_message("[Memory Patch] Detected: Checksum verification"))

    # Check for self-healing code
    if detect_self_healing_code(app.binary_path):
        protections.append("Self-Healing Code")
        app.update_output.emit(log_message("[Memory Patch] Detected: Self-healing code"))

    # Check for obfuscation
    if detect_obfuscation(app.binary_path):
        protections.append("Code Obfuscation")
        app.update_output.emit(log_message("[Memory Patch] Detected: Code obfuscation"))

    if not protections:
        app.update_output.emit(
            log_message("[Memory Patch] No special protections detected. Static patching may work.")
        )

        response = QMessageBox.question(
            app,
            "Memory Patching Setup",
            "No special protections detected.\\n\\n"
            "Static patching might work for this binary.\\n"
            "Do you still want to set up memory patching?",
            QMessageBox.Yes | QMessageBox.No,
        )

        if response != QMessageBox.Yes:
            return
    else:
        app.update_output.emit(
            log_message(
                f"[Memory Patch] Found {len(protections)} protection(s): {', '.join(protections)}"
            )
        )

        msg = "The following protections were detected:\\n\\n"
        for _p in protections:
            msg += f"• {_p}\\n"
        msg += "\\nMemory patching is recommended for this binary.\\n"
        msg += "This will create a launcher that patches the program in memory.\\n\\n"
        msg += "Continue with memory patching setup?"

        response = QMessageBox.question(
            app,
            "Memory Patching Required",
            msg,
            QMessageBox.Yes | QMessageBox.No,
        )

        if response != QMessageBox.Yes:
            return

    # Check if we have patches to apply
    if not hasattr(app, "potential_patches") or not app.potential_patches:
        app.update_output.emit(
            log_message("[Memory Patch] No patches available. Run analysis first.")
        )
        QMessageBox.warning(
            app,
            "No Patches",
            "No patches are available to apply.\\n\\n"
            "Please run analysis to identify patches first.",
        )
        return

    # Generate memory patching launcher
    app.update_output.emit(log_message("[Memory Patch] Generating memory patching launcher..."))

    launcher_path = generate_launcher_script(app, patching_strategy="memory")

    if launcher_path:
        app.update_output.emit(log_message("[Memory Patch] Memory patching setup complete!"))
        app.update_output.emit(log_message(f"[Memory Patch] Launcher created: {launcher_path}"))
    else:
        app.update_output.emit(
            log_message("[Memory Patch] Failed to create memory patching launcher.")
        )


# Export functions
def bypass_memory_protection(address: int, size: int, protection: int = None) -> bool:
    """Bypass memory protection using VirtualProtect (Windows) or mprotect (Unix)

    Args:
        address: Memory address to modify protection for
        size: Size of memory region in bytes
        protection: New protection flags (optional, defaults to RWX)

    Returns:
        True if protection changed successfully, False otherwise

    """
    import platform

    system = platform.system()

    if system == "Windows":
        return _bypass_memory_protection_windows(address, size, protection)
    if system in ["Linux", "Darwin"]:
        return _bypass_memory_protection_unix(address, size, protection)
    logger.error(f"Unsupported platform for memory protection bypass: {system}")
    return False


def _bypass_memory_protection_windows(address: int, size: int, protection: int = None) -> bool:
    """Bypass memory protection on Windows using VirtualProtect

    Args:
        address: Memory address to modify protection for
        size: Size of memory region in bytes
        protection: New protection flags (optional)

    Returns:
        True if protection changed successfully, False otherwise

    """
    try:
        import ctypes

        wintypes, HAS_WINTYPES = _get_wintypes()

        # Default to RWX if not specified
        if protection is None:
            protection = PAGE_EXECUTE_READWRITE

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

        # VirtualProtect function
        VirtualProtect = kernel32.VirtualProtect
        VirtualProtect.argtypes = [
            ctypes.c_void_p,  # lpAddress
            ctypes.c_size_t,  # dwSize
            wintypes.DWORD if HAS_WINTYPES else ctypes.c_ulong,  # flNewProtect
            ctypes.POINTER(wintypes.DWORD if HAS_WINTYPES else ctypes.c_ulong),  # lpflOldProtect
        ]
        VirtualProtect.restype = wintypes.BOOL if HAS_WINTYPES else ctypes.c_int

        # Store old protection
        old_protection = wintypes.DWORD() if HAS_WINTYPES else ctypes.c_ulong()

        # Change memory protection
        success = VirtualProtect(
            ctypes.c_void_p(address),
            size,
            protection,
            ctypes.byref(old_protection),
        )

        if success:
            logger.info(f"Successfully changed memory protection at {hex(address)}")
            logger.info(
                f"Old protection: {hex(old_protection.value)}, New protection: {hex(protection)}"
            )
            return True
        error = ctypes.get_last_error()
        logger.error(f"VirtualProtect failed with error code: {error}")
        return False

    except Exception as e:
        logger.error(f"Exception during Windows memory protection bypass: {e}")
        return False


def _bypass_memory_protection_unix(address: int, size: int, protection: int = None) -> bool:
    """Bypass memory protection on Unix-like systems using mprotect

    Args:
        address: Memory address to modify protection for
        size: Size of memory region in bytes
        protection: New protection flags (optional)

    Returns:
        True if protection changed successfully, False otherwise

    """
    try:
        import ctypes
        import mmap

        # Unix memory protection constants
        PROT_NONE = 0x0
        PROT_READ = 0x1
        PROT_WRITE = 0x2
        PROT_EXEC = 0x4

        # Default to RWX if not specified
        if protection is None:
            protection = PROT_READ | PROT_WRITE | PROT_EXEC

        # Validate protection value (must not be PROT_NONE for bypass operations)
        if protection == PROT_NONE:
            raise ValueError("Cannot bypass memory protection with PROT_NONE (no access)")

        # Load libc
        libc = ctypes.CDLL(None)

        # mprotect function
        mprotect = libc.mprotect
        mprotect.argtypes = [
            ctypes.c_void_p,  # addr
            ctypes.c_size_t,  # len
            ctypes.c_int,  # prot
        ]
        mprotect.restype = ctypes.c_int

        # Align address to page boundary
        page_size = mmap.PAGESIZE
        aligned_address = address & ~(page_size - 1)

        # Adjust size to cover the entire range
        size_adjustment = address - aligned_address
        aligned_size = ((size + size_adjustment + page_size - 1) // page_size) * page_size

        # Change memory protection
        result = mprotect(
            ctypes.c_void_p(aligned_address),
            aligned_size,
            protection,
        )

        if result == 0:
            logger.info(f"Successfully changed memory protection at {hex(aligned_address)}")
            logger.info(f"Protection flags: {hex(protection)}")
            return True
        errno = ctypes.get_errno()
        logger.error(f"mprotect failed with errno: {errno}")
        return False

    except Exception as e:
        logger.error(f"Exception during Unix memory protection bypass: {e}")
        return False


def patch_memory_direct(process_id: int, address: int, data: bytes) -> bool:
    """Directly patch memory in a running process

    Args:
        process_id: Process ID to patch
        address: Memory address to patch
        data: Bytes to write

    Returns:
        True if patching successful, False otherwise

    """
    import platform

    system = platform.system()

    if system == "Windows":
        return _patch_memory_windows(process_id, address, data)
    if system in ["Linux", "Darwin"]:
        return _patch_memory_unix(process_id, address, data)
    logger.error(f"Unsupported platform for memory patching: {system}")
    return False


def _patch_memory_windows(process_id: int, address: int, data: bytes) -> bool:
    """Patch memory on Windows using WriteProcessMemory

    Args:
        process_id: Process ID to patch
        address: Memory address to patch
        data: Bytes to write

    Returns:
        True if patching successful, False otherwise

    """
    try:
        import ctypes

        wintypes, HAS_WINTYPES = _get_wintypes()

        # Constants
        PROCESS_ALL_ACCESS = 0x1F0FFF

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

        # Open process
        process_handle = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, process_id)
        if not process_handle:
            logger.error(f"Failed to open process {process_id}")
            return False

        try:
            # Change memory protection to allow writing
            old_protection = wintypes.DWORD() if HAS_WINTYPES else ctypes.c_ulong()
            success = kernel32.VirtualProtectEx(
                process_handle,
                ctypes.c_void_p(address),
                len(data),
                PAGE_EXECUTE_READWRITE,
                ctypes.byref(old_protection),
            )

            if not success:
                logger.error("Failed to change memory protection")
                return False

            # Write memory
            bytes_written = ctypes.c_size_t(0)
            success = kernel32.WriteProcessMemory(
                process_handle,
                ctypes.c_void_p(address),
                data,
                len(data),
                ctypes.byref(bytes_written),
            )

            if success and bytes_written.value == len(data):
                logger.info(f"Successfully patched {len(data)} bytes at {hex(address)}")

                # Restore original protection
                kernel32.VirtualProtectEx(
                    process_handle,
                    ctypes.c_void_p(address),
                    len(data),
                    old_protection.value,
                    ctypes.byref(old_protection),
                )

                return True
            logger.error("Failed to write process memory")
            return False

        finally:
            # Always close handle
            kernel32.CloseHandle(process_handle)

    except Exception as e:
        logger.error(f"Exception during Windows memory patching: {e}")
        return False


def _patch_memory_unix(process_id: int, address: int, data: bytes) -> bool:
    """Patch memory on Unix-like systems using ptrace or /proc/pid/mem

    Args:
        process_id: Process ID to patch
        address: Memory address to patch
        data: Bytes to write

    Returns:
        True if patching successful, False otherwise

    """
    try:
        # Try using /proc/pid/mem first (requires appropriate permissions)
        mem_path = f"/proc/{process_id}/mem"

        if os.path.exists(mem_path):
            try:
                with open(mem_path, "r+b") as mem_file:
                    mem_file.seek(address)
                    mem_file.write(data)
                    mem_file.flush()

                logger.info(
                    f"Successfully patched {len(data)} bytes at {hex(address)} via /proc/pid/mem"
                )
                return True

            except OSError as e:
                logger.warning(f"Failed to patch via /proc/pid/mem: {e}")

        # Fallback to ptrace
        import ctypes

        libc = ctypes.CDLL(None)
        ptrace = libc.ptrace
        ptrace.argtypes = [ctypes.c_long, ctypes.c_long, ctypes.c_void_p, ctypes.c_void_p]
        ptrace.restype = ctypes.c_long

        # Attach to process
        if ptrace(PTRACE_ATTACH, process_id, None, None) < 0:
            logger.error("Failed to attach to process with ptrace")
            return False

        try:
            # Write data word by word (ptrace limitation)
            word_size = ctypes.sizeof(ctypes.c_long)

            for i in range(0, len(data), word_size):
                word_data = data[i : i + word_size].ljust(word_size, b"\x00")
                word_value = int.from_bytes(word_data, "little")

                if (
                    ptrace(
                        PTRACE_POKEDATA,
                        process_id,
                        ctypes.c_void_p(address + i),
                        ctypes.c_void_p(word_value),
                    )
                    < 0
                ):
                    logger.error(f"Failed to write at offset {i}")
                    return False

            logger.info(f"Successfully patched {len(data)} bytes at {hex(address)} via ptrace")
            return True

        finally:
            # Detach from process
            ptrace(PTRACE_DETACH, process_id, None, None)

    except Exception as e:
        logger.error(f"Exception during Unix memory patching: {e}")
        return False


# Export functions
def handle_guard_pages(address: int, size: int, process_handle: int = None) -> bool:
    """Handle PAGE_GUARD protected memory regions

    Args:
        address: Memory address that may have guard pages
        size: Size of memory region
        process_handle: Process handle (None for current process)

    Returns:
        True if guard pages handled successfully, False otherwise

    """
    import platform

    system = platform.system()

    if system == "Windows":
        return _handle_guard_pages_windows(address, size, process_handle)
    if system in ["Linux", "Darwin"]:
        return _handle_guard_pages_unix(address, size, process_handle)
    logger.error(f"Unsupported platform for guard page handling: {system}")
    return False


def _handle_guard_pages_windows(address: int, size: int, process_handle: int = None) -> bool:
    """Handle PAGE_GUARD on Windows

    Args:
        address: Memory address
        size: Size of region
        process_handle: Process handle (None for current process)

    Returns:
        True if successful, False otherwise

    """
    try:
        import ctypes

        wintypes, HAS_WINTYPES = _get_wintypes()

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

        # MEMORY_BASIC_INFORMATION structure
        class MEMORY_BASIC_INFORMATION(ctypes.Structure):
            """Windows MEMORY_BASIC_INFORMATION structure for memory queries."""

            _fields_ = [
                ("BaseAddress", ctypes.c_void_p),
                ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", wintypes.DWORD if HAS_WINTYPES else ctypes.c_ulong),
                ("RegionSize", ctypes.c_size_t),
                ("State", wintypes.DWORD if HAS_WINTYPES else ctypes.c_ulong),
                ("Protect", wintypes.DWORD if HAS_WINTYPES else ctypes.c_ulong),
                ("Type", wintypes.DWORD if HAS_WINTYPES else ctypes.c_ulong),
            ]

        mbi = MEMORY_BASIC_INFORMATION()

        # Query memory information
        if process_handle:
            # Remote process
            result = kernel32.VirtualQueryEx(
                process_handle,
                ctypes.c_void_p(address),
                ctypes.byref(mbi),
                ctypes.sizeof(mbi),
            )
        else:
            # Current process
            result = kernel32.VirtualQuery(
                ctypes.c_void_p(address),
                ctypes.byref(mbi),
                ctypes.sizeof(mbi),
            )

        if not result:
            error = ctypes.get_last_error()
            logger.error(f"VirtualQuery failed with error: {error}")
            return False

        # Check if PAGE_GUARD is set
        if mbi.Protect & PAGE_GUARD:
            logger.info(f"PAGE_GUARD detected at {hex(address)}")

            # Remove PAGE_GUARD by changing protection
            old_protection = wintypes.DWORD() if HAS_WINTYPES else ctypes.c_ulong()
            new_protection = mbi.Protect & ~PAGE_GUARD  # Remove guard flag

            if process_handle:
                # Remote process
                success = kernel32.VirtualProtectEx(
                    process_handle,
                    ctypes.c_void_p(address),
                    size,
                    new_protection,
                    ctypes.byref(old_protection),
                )
            else:
                # Current process
                success = kernel32.VirtualProtect(
                    ctypes.c_void_p(address),
                    size,
                    new_protection,
                    ctypes.byref(old_protection),
                )

            if success:
                logger.info(f"Removed PAGE_GUARD from {hex(address)}")

                # Optionally trigger the guard page to clear it
                if not process_handle:  # Only for current process
                    try:
                        # Read first byte to trigger guard
                        dummy = ctypes.c_byte()
                        ctypes.memmove(ctypes.byref(dummy), address, 1)
                    except (OSError, ValueError, Exception) as e:
                        logger.error("Error in memory_patcher: %s", e)

                return True
            error = ctypes.get_last_error()
            logger.error(f"Failed to remove PAGE_GUARD: {error}")
            return False
        logger.debug(f"No PAGE_GUARD at {hex(address)}")
        return True

    except Exception as e:
        logger.error(f"Exception handling guard pages: {e}")
        return False


def _handle_guard_pages_unix(address: int, size: int, process_handle: int = None) -> bool:
    """Handle guard pages on Unix-like systems

    Args:
        address: Memory address
        size: Size of region
        process_handle: Process handle (not used on Unix)

    Returns:
        True if successful, False otherwise

    """
    try:
        import ctypes
        import mmap

        # Validate size parameter
        if size <= 0:
            logger.error(f"Invalid size parameter: {size}")
            return False

        # Calculate the full range that needs to be handled
        end_address = address + size
        logger.debug(
            f"Handling guard pages for range {hex(address)}-{hex(end_address)} (size: {size} bytes)"
        )

        # On Unix, guard pages are typically implemented differently
        # We'll check /proc/self/maps for memory regions

        if process_handle:
            maps_file = f"/proc/{process_handle}/maps"
        else:
            maps_file = "/proc/self/maps"

        # Read memory mappings
        try:
            with open(maps_file) as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 5:
                        addr_range = parts[0].split("-")
                        start_addr = int(addr_range[0], 16)
                        end_addr = int(addr_range[1], 16)

                        # Check if our target region overlaps with this memory region
                        if (
                            (start_addr <= address < end_addr)
                            or (start_addr < end_address <= end_addr)
                            or (address <= start_addr < end_address)
                        ):
                            perms = parts[1]
                            logger.info(
                                f"Memory region {hex(start_addr)}-{hex(end_addr)} overlaps target range, permissions: {perms}"
                            )

                            # Check if it's a guard page (no permissions)
                            if perms == "---p":
                                logger.info("Guard page detected in target range")

                                # Change permissions to make it accessible
                                libc = ctypes.CDLL(None)
                                mprotect = libc.mprotect

                                # Align to page boundary and calculate proper size
                                page_size = mmap.PAGESIZE
                                aligned_addr = address & ~(page_size - 1)

                                # Calculate aligned size to cover the entire requested region
                                aligned_end = (end_address + page_size - 1) & ~(page_size - 1)
                                aligned_size = aligned_end - aligned_addr

                                logger.debug(
                                    f"Aligned region: {hex(aligned_addr)}-{hex(aligned_end)} (size: {aligned_size} bytes)"
                                )

                                # Set read/write permissions
                                PROT_READ = 0x1
                                PROT_WRITE = 0x2

                                result = mprotect(
                                    ctypes.c_void_p(aligned_addr),
                                    aligned_size,
                                    PROT_READ | PROT_WRITE,
                                )

                                if result == 0:
                                    logger.info(
                                        f"Successfully removed guard page protection for {aligned_size} bytes"
                                    )
                                    return True
                                logger.error("Failed to change guard page permissions")
                                return False

        except OSError:
            logger.warning(f"Cannot read {maps_file}")

        return True

    except Exception as e:
        logger.error(f"Exception handling Unix guard pages: {e}")
        return False


def detect_and_bypass_guard_pages(process_handle: int, address: int, size: int) -> bool:
    """Detect and bypass guard pages before memory operations

    Args:
        process_handle: Handle to process
        address: Memory address to check
        size: Size of memory region

    Returns:
        True if safe to proceed, False otherwise

    """
    try:
        # First, handle any guard pages
        if not handle_guard_pages(address, size, process_handle):
            logger.warning("Failed to handle guard pages")
            return False

        # Additionally check for other protections
        import platform

        if platform.system() == "Windows":
            import ctypes

            wintypes, HAS_WINTYPES = _get_wintypes()

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

            # Check if memory is committed
            class MEMORY_BASIC_INFORMATION(ctypes.Structure):
                """Memory basic information structure for allocation checking."""

                _fields_ = [
                    ("BaseAddress", ctypes.c_void_p),
                    ("AllocationBase", ctypes.c_void_p),
                    ("AllocationProtect", wintypes.DWORD if HAS_WINTYPES else ctypes.c_ulong),
                    ("RegionSize", ctypes.c_size_t),
                    ("State", wintypes.DWORD if HAS_WINTYPES else ctypes.c_ulong),
                    ("Protect", wintypes.DWORD if HAS_WINTYPES else ctypes.c_ulong),
                    ("Type", wintypes.DWORD if HAS_WINTYPES else ctypes.c_ulong),
                ]

            mbi = MEMORY_BASIC_INFORMATION()
            result = kernel32.VirtualQueryEx(
                process_handle,
                ctypes.c_void_p(address),
                ctypes.byref(mbi),
                ctypes.sizeof(mbi),
            )

            if result:
                MEM_COMMIT = 0x1000
                if not (mbi.State & MEM_COMMIT):
                    logger.error("Memory not committed")
                    return False

                # Check for NO_ACCESS
                if mbi.Protect == PAGE_NOACCESS:
                    logger.error("Memory has PAGE_NOACCESS protection")
                    return False

        return True

    except Exception as e:
        logger.error(f"Error detecting guard pages: {e}")
        return False


# Export functions
__all__ = [
    "bypass_memory_protection",
    "detect_and_bypass_guard_pages",
    "generate_launcher_script",
    "handle_guard_pages",
    "patch_memory_direct",
    "setup_memory_patching",
]

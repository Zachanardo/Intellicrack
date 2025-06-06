"""
Memory Patching Module for Intellicrack

This module provides functions for setting up memory patching environments,
generating launcher scripts, and handling heavily protected binaries that
require runtime patching instead of static file modification.

Author: Intellicrack Team
Version: 1.0.0
"""

import datetime
import os
import sys
from typing import Any, Optional

from PyQt5.QtWidgets import QMessageBox

from ...utils.protection_detection import (
    detect_checksum_verification,
    detect_obfuscation,
    detect_self_healing_code,
)


def log_message(msg: str) -> str:
    """Helper function to format log messages consistently."""
    return f"[{msg}]"


def generate_launcher_script(app: Any, patching_strategy: str = "memory") -> Optional[str]:
    """
    Generates a launcher script that uses Frida to patch the target program in memory.

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
        app.update_output.emit(log_message(
            "[Launcher] No binary selected."))
        return None

    if not hasattr(app, 'potential_patches') or not app.potential_patches:
        app.update_output.emit(log_message(
            "[Launcher] No patches available to create launcher."))
        return None

    # Generate launcher script path
    base_name = os.path.splitext(os.path.basename(app.binary_path))[0]
    launcher_path = os.path.join(
        os.path.dirname(app.binary_path),
        f"{base_name}_launcher.py"
    )

    app.update_output.emit(log_message(
        f"[Launcher] Generating launcher script: {launcher_path}"))

    # Convert patches to string for embedding
    patches_str = str(app.potential_patches)

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
except ImportError:
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
    var patches = %s;

    patches.forEach(function(patch, index) {
        try {
            var address = patch.address;
            var newBytes = patch.new_bytes;
            var description = patch.description || 'Patch ' + index;

            // Calculate actual address
            var patchAddr = baseAddr.add(address - %s);

            // Make memory writable
            Memory.protect(patchAddr, newBytes.length, 'rwx');

            // Write new bytes
            patchAddr.writeByteArray(newBytes);

            console.log('[+] Applied patch at ' + patchAddr + ': ' + description);
            send('Patch applied: ' + description);

        } catch (e) {
            console.log('[-] Failed to apply patch ' + index + ': ' + e);
            send('Patch failed: ' + description);
        }
    });

    console.log('[+] All patches applied');
    send('Memory patching complete');
    """ % (str(PATCHES).replace("'", '"'), hex(0x400000))  # Default image base

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
        except KeyboardInterrupt:
            print("\\n[*] Detaching...")
            session.detach()

    except Exception as e:
        print("[-] Error: " + str(e))
        return 1

    return 0

def launch_normal():
    """Launch target normally without patches"""
    print("[*] Launching " + TARGET_BINARY + " normally...")
    try:
        subprocess.Popen([TARGET_BINARY])
        print("[+] Process launched")
    except Exception as e:
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
        except ImportError:
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
        patches_str=patches_str
    )

    # Handle patches format conversion
    patches_formatted = []
    for patch in app.potential_patches:
        patch_dict = {
            'address': patch.get('address', 0),
            'new_bytes': list(patch.get('new_bytes', b'')) if isinstance(patch.get('new_bytes'), bytes) else patch.get('new_bytes', []),
            'description': patch.get('description', 'Unknown patch')
        }
        patches_formatted.append(patch_dict)

    # Replace patches in script
    script_content = script_content.replace(
        f"PATCHES = {str(app.potential_patches)}",
        f"PATCHES = {str(patches_formatted)}"
    )

    # Write launcher script
    try:
        with open(launcher_path, 'w', encoding='utf-8') as f:
            f.write(script_content)

        # Make executable on Unix-like systems
        if sys.platform != 'win32':
            os.chmod(launcher_path, 0o755)

        app.update_output.emit(log_message(
            f"[Launcher] Successfully created launcher script: {launcher_path}"))

        # Show instructions
        msg = f"Launcher script created: {launcher_path}\\n\\n"
        msg += "To use the launcher:\\n"
        msg += "1. Install Frida: pip install frida-tools\\n"
        msg += f"2. Run: python {os.path.basename(launcher_path)}\\n\\n"
        msg += "The launcher will apply patches in memory without modifying the file."

        QMessageBox.information(app, "Launcher Created", msg)

        return launcher_path

    except Exception as e:
        app.update_output.emit(log_message(
            f"[Launcher] Error creating launcher script: {e}"))
        return None


def setup_memory_patching(app: Any) -> None:
    """
    Sets up a memory patching environment for heavily protected binaries.

    This function detects various protection mechanisms and configures
    appropriate memory patching strategies. It's used when static patching
    would be detected or reversed by the target application.

    Args:
        app: Application instance with binary path and UI elements
    """
    if not app.binary_path:
        app.update_output.emit(log_message(
            "[Memory Patch] No binary selected."))
        return

    app.update_output.emit(log_message(
        "[Memory Patch] Analyzing protection mechanisms..."))

    # Detect various protections
    protections = []

    # Check for checksum verification
    if detect_checksum_verification(app.binary_path):
        protections.append("Checksum Verification")
        app.update_output.emit(log_message(
            "[Memory Patch] Detected: Checksum verification"))

    # Check for self-healing code
    if detect_self_healing_code(app.binary_path):
        protections.append("Self-Healing Code")
        app.update_output.emit(log_message(
            "[Memory Patch] Detected: Self-healing code"))

    # Check for obfuscation
    if detect_obfuscation(app.binary_path):
        protections.append("Code Obfuscation")
        app.update_output.emit(log_message(
            "[Memory Patch] Detected: Code obfuscation"))

    if not protections:
        app.update_output.emit(log_message(
            "[Memory Patch] No special protections detected. Static patching may work."))

        response = QMessageBox.question(
            app,
            "Memory Patching Setup",
            "No special protections detected.\\n\\n"
            "Static patching might work for this binary.\\n"
            "Do you still want to set up memory patching?",
            QMessageBox.Yes | QMessageBox.No
        )

        if response != QMessageBox.Yes:
            return
    else:
        app.update_output.emit(log_message(
            f"[Memory Patch] Found {len(protections)} protection(s): {', '.join(protections)}"))

        msg = "The following protections were detected:\\n\\n"
        for p in protections:
            msg += f"• {p}\\n"
        msg += "\\nMemory patching is recommended for this binary.\\n"
        msg += "This will create a launcher that patches the program in memory.\\n\\n"
        msg += "Continue with memory patching setup?"

        response = QMessageBox.question(
            app,
            "Memory Patching Required",
            msg,
            QMessageBox.Yes | QMessageBox.No
        )

        if response != QMessageBox.Yes:
            return

    # Check if we have patches to apply
    if not hasattr(app, 'potential_patches') or not app.potential_patches:
        app.update_output.emit(log_message(
            "[Memory Patch] No patches available. Run analysis first."))
        QMessageBox.warning(
            app,
            "No Patches",
            "No patches are available to apply.\\n\\n"
            "Please run analysis to identify patches first."
        )
        return

    # Generate memory patching launcher
    app.update_output.emit(log_message(
        "[Memory Patch] Generating memory patching launcher..."))

    launcher_path = generate_launcher_script(app, patching_strategy="memory")

    if launcher_path:
        app.update_output.emit(log_message(
            "[Memory Patch] Memory patching setup complete!"))
        app.update_output.emit(log_message(
            f"[Memory Patch] Launcher created: {launcher_path}"))
    else:
        app.update_output.emit(log_message(
            "[Memory Patch] Failed to create memory patching launcher."))


# Export functions
__all__ = [
    'generate_launcher_script',
    'setup_memory_patching'
]

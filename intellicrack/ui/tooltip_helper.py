"""
Comprehensive tooltip definitions for Intellicrack UI.

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

from typing import Dict


def get_tooltip_definitions() -> Dict[str, str]:
    """
    Get comprehensive tooltip definitions for all UI elements.
    
    Returns:
        Dictionary mapping button text to tooltip descriptions
    """
    return {
        # Analysis Tab - Static Analysis
        "Run Full Static Analysis": (
            "Performs comprehensive static analysis without executing the binary.\n"
            "Includes: File format parsing, import/export analysis, string extraction,\n"
            "function detection, and basic vulnerability scanning.\n"
            "Safe to run on any binary - no execution risk."
        ),
        
        "Disassemble": (
            "Converts machine code into human-readable assembly instructions.\n"
            "Shows the low-level CPU instructions that make up the program.\n"
            "Useful for understanding program logic and finding vulnerabilities."
        ),
        
        "View CFG": (
            "Control Flow Graph - Visual representation of program execution paths.\n"
            "Shows how different parts of the code connect and branch.\n"
            "Helps identify loops, conditions, and potential code coverage."
        ),
        
        "Find ROP Gadgets": (
            "Return-Oriented Programming gadgets - Small instruction sequences\n"
            "ending in 'return' that can be chained for exploitation.\n"
            "Used in advanced exploit development to bypass security measures."
        ),
        
        "Binary Similarity Search": (
            "Compares this binary against a database of known binaries.\n"
            "Helps identify: Similar malware families, code reuse,\n"
            "library versions, and potential vulnerabilities from similar code."
        ),
        
        # Protection Detection
        "Scan for All Known Protections": (
            "Comprehensive scan for all security measures in the binary.\n"
            "Detects: Anti-debug, packing, obfuscation, license checks,\n"
            "DRM systems, and hardware protection mechanisms."
        ),
        
        "Detect Packing/Obfuscation": (
            "Identifies if the binary is compressed or obfuscated.\n"
            "Common packers: UPX, Themida, VMProtect, ASPack.\n"
            "Packed binaries hide their real code and need unpacking first."
        ),
        
        "Detect Commercial Protections": (
            "Scans for commercial protection systems like:\n"
            "Denuvo, SecuROM, SafeDisc, StarForce, etc.\n"
            "These are professional anti-piracy solutions."
        ),
        
        "Detect Hardware Dongles": (
            "Checks for hardware key/dongle requirements.\n"
            "Common systems: HASP, Sentinel, WibuKey.\n"
            "Hardware dongles are physical USB devices for license verification."
        ),
        
        "Detect TPM/VM/Anti-Debug": (
            "TPM: Trusted Platform Module - Hardware security chip detection\n"
            "VM: Virtual Machine detection (VMware, VirtualBox, etc.)\n"
            "Anti-Debug: Techniques to prevent debugger attachment"
        ),
        
        # Protection Bypass
        "Bypass TPM Protection": (
            "Attempts to bypass Trusted Platform Module checks.\n"
            "TPM stores encryption keys and validates system integrity.\n"
            "⚠️ Use only on software you own or have permission to test."
        ),
        
        "Bypass VM Detection": (
            "Removes or bypasses virtual machine detection.\n"
            "Many programs refuse to run in VMs for security.\n"
            "Makes the VM appear as a physical machine to the program."
        ),
        
        "Activate Dongle Emulation": (
            "Emulates hardware dongle responses without the physical device.\n"
            "Simulates the presence of USB license keys.\n"
            "⚠️ Only for testing software you have licensed."
        ),
        
        # Dynamic Analysis
        "Launch Target Binary": (
            "Executes the binary in a controlled environment.\n"
            "⚠️ WARNING: This runs the program - use in isolated environment!\n"
            "Enable monitoring options first for safety."
        ),
        
        "Attach to Running Process": (
            "Connects to an already running program for analysis.\n"
            "Allows inspection of live memory and runtime behavior.\n"
            "Requires appropriate permissions on the target process."
        ),
        
        "Start API Hooking": (
            "Intercepts Windows API calls made by the program.\n"
            "Records: File access, registry changes, network connections.\n"
            "Essential for understanding program behavior."
        ),
        
        "Start Runtime Monitoring": (
            "Monitors program execution in real-time.\n"
            "Tracks: Memory usage, CPU activity, system calls.\n"
            "Helps identify performance issues and suspicious behavior."
        ),
        
        # Advanced Analysis
        "Run Symbolic Path Exploration": (
            "Explores all possible execution paths symbolically.\n"
            "Uses mathematical constraints instead of concrete values.\n"
            "Powerful for finding hidden functionality and vulnerabilities."
        ),
        
        "Run Concolic Path Exploration": (
            "Concrete + Symbolic execution - Hybrid approach.\n"
            "Combines real execution with symbolic analysis.\n"
            "More efficient than pure symbolic execution."
        ),
        
        "Run Taint Analysis": (
            "Tracks how user input flows through the program.\n"
            "Identifies where untrusted data reaches sensitive operations.\n"
            "Critical for finding injection vulnerabilities."
        ),
        
        "Find License Bypass": (
            "Automated search for license check bypasses.\n"
            "Uses symbolic execution to find paths avoiding checks.\n"
            "⚠️ For educational/testing purposes only."
        ),
        
        # Patching Tab
        "Create Patch Plan": (
            "Analyzes the binary and creates a patching strategy.\n"
            "Identifies: Key locations, patch types needed,\n"
            "potential side effects, and success probability."
        ),
        
        "Apply Patches": (
            "Modifies the binary according to the patch plan.\n"
            "⚠️ Creates backup first - this changes the executable!\n"
            "Can patch: Jump instructions, NOP out checks, modify constants."
        ),
        
        "Generate ROP Chains": (
            "Creates Return-Oriented Programming exploit chains.\n"
            "Advanced technique for bypassing DEP/NX protection.\n"
            "Requires deep understanding of exploitation."
        ),
        
        "AI-Generated Patches": (
            "Uses machine learning to suggest optimal patches.\n"
            "Analyzes similar binaries to predict effective modifications.\n"
            "Experimental feature - verify results carefully."
        ),
        
        # Network Tab
        "Start Capture": (
            "Begins capturing network packets on selected interface.\n"
            "Records all network traffic for analysis.\n"
            "Requires administrator/root privileges."
        ),
        
        "Protocol Fingerprinting": (
            "Identifies network protocols and services automatically.\n"
            "Detects: License servers, update checks, telemetry.\n"
            "Helps understand program's network behavior."
        ),
        
        "SSL Interception": (
            "Decrypts HTTPS/SSL traffic for analysis.\n"
            "Acts as man-in-the-middle to view encrypted data.\n"
            "⚠️ Only use on your own traffic - may trigger security alerts."
        ),
        
        "Start Emulated Server": (
            "Creates fake license/activation server.\n"
            "Responds to program's network requests with success.\n"
            "Useful for offline activation and testing."
        ),
        
        # AI Assistant
        "Fine-tune AI Model": (
            "Trains the AI on your specific analysis patterns.\n"
            "Improves suggestions based on your workflow.\n"
            "Requires significant processing time and examples."
        ),
        
        # Tools
        "Key Generator": (
            "Analyzes license algorithms and generates valid keys.\n"
            "Works with: Serial numbers, activation codes, licenses.\n"
            "Success depends on algorithm complexity."
        ),
        
        "Advanced Patcher": (
            "Professional patching interface with hex editing.\n"
            "Features: Pattern search, multi-patch support,\n"
            "verification, and automated patch distribution."
        ),
        
        "API Emulator": (
            "Simulates Windows API responses without real calls.\n"
            "Useful for sandboxing and behavior analysis.\n"
            "Can fake: File existence, registry values, system info."
        ),
        
        "Binary Unpacker": (
            "Removes packing/compression from executables.\n"
            "Supports: UPX, ASPack, PECompact, and more.\n"
            "Required before analyzing packed binaries."
        ),
        
        "PE Rebuilder": (
            "Repairs corrupted or modified PE executables.\n"
            "Fixes: Import tables, section headers, checksums.\n"
            "Useful after unpacking or patching."
        ),
        
        # Memory Analysis
        "Memory Optimization Level": (
            "Controls memory usage vs performance tradeoff.\n"
            "Low: Fast but uses more RAM\n"
            "High: Slower but works with limited memory"
        ),
        
        # General Operations
        "Open Binary": (
            "Select an executable file to analyze.\n"
            "Supports: PE (.exe/.dll), ELF (Linux), Mach-O (macOS).\n"
            "File is loaded but not executed until you choose."
        ),
        
        "Save Analysis Results": (
            "Exports all analysis data to a report.\n"
            "Formats: PDF (with charts), JSON (for processing),\n"
            "HTML (for sharing), TXT (simple notes)."
        ),
        
        "One-Click Full Analysis & Patch": (
            "Automated workflow for common tasks:\n"
            "1. Analyzes the binary\n"
            "2. Detects protections\n"
            "3. Suggests and applies patches\n"
            "⚠️ Review results before using patched binary!"
        ),
        
        "Guided Workflow Wizard": (
            "Step-by-step assistant for new users.\n"
            "Guides through: Analysis → Detection → Patching.\n"
            "Explains each step and suggests best practices."
        ),
        
        # Vulnerability Scanning
        "Run Static Vulnerability Scan": (
            "Scans for known security vulnerabilities.\n"
            "Checks: Buffer overflows, format strings, integer overflows,\n"
            "use-after-free, and other common vulnerability patterns."
        ),
        
        "Run ML-Based Vulnerability Prediction": (
            "Uses machine learning to predict potential vulnerabilities.\n"
            "Trained on thousands of vulnerable binaries.\n"
            "Provides probability scores for different vulnerability types."
        )
    }


def apply_tooltips_to_buttons(parent_widget):
    """
    Apply tooltips to all buttons in a widget hierarchy.
    
    Args:
        parent_widget: The parent widget to search for buttons
    """
    try:
        from PyQt5.QtWidgets import QPushButton
    except ImportError:
        from PyQt6.QtWidgets import QPushButton
    
    tooltips = get_tooltip_definitions()
    
    # Find all QPushButton instances
    buttons = parent_widget.findChildren(QPushButton)
    
    for button in buttons:
        button_text = button.text()
        if button_text in tooltips:
            button.setToolTip(tooltips[button_text])
            
            
def create_tooltip_with_shortcut(description: str, shortcut: str = None) -> str:
    """
    Create a formatted tooltip with optional keyboard shortcut.
    
    Args:
        description: Main tooltip description
        shortcut: Optional keyboard shortcut
        
    Returns:
        Formatted tooltip string
    """
    if shortcut:
        return f"{description}\n\nShortcut: {shortcut}"
    return description
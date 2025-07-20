"""Tooltip helper utilities for enhanced UI tooltips."""
from typing import Dict

from intellicrack.logger import logger

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


def apply_tooltips_to_all_elements(parent_widget):
    """
    Apply tooltips to all UI elements in a widget hierarchy.
    Now supports: QPushButton, QLabel, QLineEdit, QComboBox, QCheckBox,
    QSpinBox, QDoubleSpinBox, QTabWidget, and other common UI elements.

    Args:
        parent_widget: The parent widget to search for UI elements
    """
    try:
        from PyQt6.QtWidgets import (
            QCheckBox,
            QComboBox,
            QDoubleSpinBox,
            QLabel,
            QLineEdit,
            QListWidget,
            QPlainTextEdit,
            QProgressBar,
            QPushButton,
            QSlider,
            QSpinBox,
            QTableWidget,
            QTabWidget,
            QTextEdit,
            QTreeWidget,
        )
    except ImportError as e:
        logger.error("Import error in tooltip_helper: %s", e)
        from PyQt6.QtWidgets import QPushButton
        QLabel = QLineEdit = QComboBox = QCheckBox = QPushButton  # Fallback
        QSpinBox = QDoubleSpinBox = QTabWidget = QSlider = QPushButton
        QProgressBar = QTextEdit = QPlainTextEdit = QPushButton
        QListWidget = QTreeWidget = QTableWidget = QPushButton

    tooltips = get_tooltip_definitions()

    # Enhanced tooltip definitions for all UI elements
    enhanced_tooltips = get_enhanced_tooltip_definitions()
    all_tooltips = {**tooltips, **enhanced_tooltips}

    # Apply tooltips to QPushButton (existing functionality)
    buttons = parent_widget.findChildren(QPushButton)
    for button in buttons:
        button_text = button.text()
        if button_text in all_tooltips:
            button.setToolTip(all_tooltips[button_text])

    # Apply tooltips to QLabel
    labels = parent_widget.findChildren(QLabel)
    for label in labels:
        label_text = label.text()
        object_name = label.objectName()

        if label_text in all_tooltips:
            label.setToolTip(all_tooltips[label_text])
        elif object_name in all_tooltips:
            label.setToolTip(all_tooltips[object_name])
        elif label_text and _get_contextual_tooltip(label_text):
            label.setToolTip(_get_contextual_tooltip(label_text))

    # Apply tooltips to QLineEdit
    line_edits = parent_widget.findChildren(QLineEdit)
    for line_edit in line_edits:
        placeholder = line_edit.placeholderText()
        object_name = line_edit.objectName()

        if placeholder in all_tooltips:
            line_edit.setToolTip(all_tooltips[placeholder])
        elif object_name in all_tooltips:
            line_edit.setToolTip(all_tooltips[object_name])
        elif placeholder and _get_contextual_tooltip(placeholder):
            line_edit.setToolTip(_get_contextual_tooltip(placeholder))

    # Apply tooltips to QComboBox
    combo_boxes = parent_widget.findChildren(QComboBox)
    for combo in combo_boxes:
        object_name = combo.objectName()
        current_text = combo.currentText()

        if object_name in all_tooltips:
            combo.setToolTip(all_tooltips[object_name])
        elif current_text in all_tooltips:
            combo.setToolTip(all_tooltips[current_text])
        elif object_name and _get_contextual_tooltip(object_name):
            combo.setToolTip(_get_contextual_tooltip(object_name))

    # Apply tooltips to QCheckBox
    checkboxes = parent_widget.findChildren(QCheckBox)
    for checkbox in checkboxes:
        checkbox_text = checkbox.text()
        object_name = checkbox.objectName()

        if checkbox_text in all_tooltips:
            checkbox.setToolTip(all_tooltips[checkbox_text])
        elif object_name in all_tooltips:
            checkbox.setToolTip(all_tooltips[object_name])
        elif checkbox_text and _get_contextual_tooltip(checkbox_text):
            checkbox.setToolTip(_get_contextual_tooltip(checkbox_text))

    # Apply tooltips to QSpinBox and QDoubleSpinBox
    spinboxes = parent_widget.findChildren(QSpinBox) + parent_widget.findChildren(QDoubleSpinBox)
    for spinbox in spinboxes:
        object_name = spinbox.objectName()

        if object_name in all_tooltips:
            spinbox.setToolTip(all_tooltips[object_name])
        elif object_name and _get_contextual_tooltip(object_name):
            spinbox.setToolTip(_get_contextual_tooltip(object_name))

    # Apply tooltips to QTabWidget tabs
    tab_widgets = parent_widget.findChildren(QTabWidget)
    for tab_widget in tab_widgets:
        for i in range(tab_widget.count()):
            tab_text = tab_widget.tabText(i)
            if tab_text in all_tooltips:
                tab_widget.setTabToolTip(i, all_tooltips[tab_text])
            elif tab_text and _get_contextual_tooltip(tab_text):
                tab_widget.setTabToolTip(i, _get_contextual_tooltip(tab_text))

    # Apply tooltips to other common widgets
    other_widgets = (parent_widget.findChildren(QSlider) +
                    parent_widget.findChildren(QProgressBar) +
                    parent_widget.findChildren(QTextEdit) +
                    parent_widget.findChildren(QPlainTextEdit) +
                    parent_widget.findChildren(QListWidget) +
                    parent_widget.findChildren(QTreeWidget) +
                    parent_widget.findChildren(QTableWidget))

    for widget in other_widgets:
        object_name = widget.objectName()
        if object_name in all_tooltips:
            widget.setToolTip(all_tooltips[object_name])
        elif object_name and _get_contextual_tooltip(object_name):
            widget.setToolTip(_get_contextual_tooltip(object_name))

def get_enhanced_tooltip_definitions() -> Dict[str, str]:
    """
    Enhanced tooltip definitions for all UI element types.

    Returns:
        Dictionary mapping UI element identifiers to tooltip descriptions
    """
    return {
        # Tab tooltips
        "Dashboard": (
            "Project overview and workspace management.\\n"
            "Manage projects, select binaries, view activity logs,\\n"
            "and access recent files for quick analysis startup."
        ),

        "Analysis": (
            "Comprehensive binary analysis tools.\\n"
            "Static analysis, protection detection, dynamic hooking,\\n"
            "and advanced execution engines for deep binary inspection."
        ),

        "Exploitation": (
            "Binary exploitation and patching tools.\\n"
            "ROP chain generation, shellcode creation, memory patching,\\n"
            "and exploit development for security testing."
        ),

        "AI Assistant": (
            "AI-powered analysis and code generation.\\n"
            "Script generation, binary analysis assistance, model training,\\n"
            "and intelligent reverse engineering support."
        ),

        "Tools": (
            "System tools, plugin management, and network analysis.\\n"
            "File operations, cryptographic tools, plugin development,\\n"
            "and network packet capture capabilities."
        ),

        "Settings": (
            "Application configuration and preferences.\\n"
            "Theme settings, tool paths, performance tuning,\\n"
            "and advanced configuration options."
        ),

        # Common UI element tooltips
        "Binary Path:": (
            "Full path to the target binary file for analysis.\\n"
            "Supports PE (.exe/.dll), ELF, and Mach-O formats."
        ),

        "Target Binary:": (
            "Select the executable file you want to analyze.\\n"
            "The binary will be loaded but not executed until you choose."
        ),

        "Output Directory:": (
            "Where analysis results and generated files will be saved.\\n"
            "Include reports, patches, extracted data, and logs."
        ),

        "API Key:": (
            "Authentication key for AI service access.\\n"
            "Required for OpenAI, Anthropic, or other AI providers."
        ),

        "Temperature:": (
            "Controls AI response creativity and randomness.\\n"
            "Lower values (0.1-0.3): More focused and deterministic\\n"
            "Higher values (0.7-1.0): More creative and varied"
        ),

        "Max Tokens:": (
            "Maximum length of AI response in tokens.\\n"
            "Higher values allow longer responses but cost more.\\n"
            "1 token ≈ 0.75 words for English text."
        ),

        "Analysis Depth:": (
            "How thorough the analysis should be.\\n"
            "Quick: Fast scan of basic properties\\n"
            "Standard: Comprehensive analysis (recommended)\\n"
            "Deep: Exhaustive analysis with all techniques"
        ),

        "Cache Size:": (
            "Amount of memory to use for caching analysis data.\\n"
            "Larger cache improves performance but uses more RAM.\\n"
            "Recommended: 512MB for most systems."
        ),

        "Worker Threads:": (
            "Number of parallel threads for analysis tasks.\\n"
            "More threads = faster analysis on multi-core CPUs.\\n"
            "Recommended: 2-4 threads for most systems."
        ),

        # Object name based tooltips
        "binary_path_edit": "Path to the target binary file for analysis",
        "analysis_depth_combo": "Select analysis thoroughness level",
        "provider_combo": "Choose AI service provider",
        "model_combo": "Select AI model for analysis",
        "temperature_slider": "Adjust AI response creativity",
        "max_tokens_spin": "Set maximum AI response length",
        "cache_size_spin": "Configure memory cache size",
        "worker_threads_spin": "Set number of worker threads",
        "log_level_combo": "Choose logging verbosity level",
        "theme_combo": "Select application theme",
        "opacity_slider": "Adjust window transparency",
        "icon_size_combo": "Choose UI icon size",

        # Placeholder text tooltips
        "Select a binary file for analysis...": (
            "Click Browse to choose an executable file.\\n"
            "Supported formats: PE, ELF, Mach-O"
        ),

        "Enter API key...": (
            "Paste your AI service API key here.\\n"
            "Keep this secret and secure!"
        ),

        "Search files...": (
            "Enter filename or pattern to search.\\n"
            "Supports wildcards like *.exe or *crack*"
        ),

        "Enter target address...": (
            "Memory address in hexadecimal format.\\n"
            "Example: 0x401000 or 401000"
        ),

        "Enter shellcode...": (
            "Raw shellcode bytes in hex format.\\n"
            "Example: \\x90\\x90\\xCC or 909090CC"
        ),

        # Analysis specific tooltips
        "Include Strings": (
            "Extract and include readable text strings from the binary.\\n"
            "Helps identify: URLs, file paths, error messages, debug info."
        ),

        "Include Imports": (
            "Analyze imported functions and libraries.\\n"
            "Shows what Windows APIs or system functions are used."
        ),

        "Include Exports": (
            "Analyze exported functions (for DLLs).\\n"
            "Shows what functions this library provides to other programs."
        ),

        "Include Disassembly": (
            "Include assembly code in the analysis.\\n"
            "⚠️ Can produce very large outputs for big binaries."
        ),

        "Enable GPU": (
            "Use GPU acceleration for analysis tasks.\\n"
            "Significantly faster but requires compatible GPU.\\n"
            "Supports CUDA, OpenCL, and DirectML."
        ),

        "Safe Mode": (
            "Enable additional safety checks and confirmations.\\n"
            "Prevents accidental dangerous operations.\\n"
            "Recommended for production environments."
        ),

        "Auto Analysis": (
            "Automatically start analysis when binary is selected.\\n"
            "Convenient but may slow down file browsing."
        ),

        "Show Tooltips": (
            "Display helpful tooltips like this one.\\n"
            "Disable to reduce visual clutter."
        ),

        "Enable Animations": (
            "Use smooth animations for UI transitions.\\n"
            "Disable to improve performance on slower systems."
        ),

        "Parallel Processing": (
            "Use multiple CPU cores for analysis tasks.\\n"
            "Faster analysis but higher resource usage."
        ),

        "Auto Cleanup": (
            "Automatically clean up temporary files and memory.\\n"
            "Keeps system clean but may slow down repeated tasks."
        ),

        "Debug Mode": (
            "Enable verbose logging and debug features.\\n"
            "Useful for troubleshooting but slower performance."
        ),

        "Experimental Features": (
            "Enable cutting-edge experimental features.\\n"
            "⚠️ May be unstable - use at your own risk."
        )
    }


def _get_contextual_tooltip(text: str) -> str:
    """
    Generate contextual tooltips for common UI patterns.

    Args:
        text: The UI element text to analyze

    Returns:
        Contextual tooltip or empty string if no match
    """
    text_lower = text.lower()

    # Binary/file related
    if any(word in text_lower for word in ['binary', 'file', 'executable', 'target']):
        return "Select or specify a binary file for analysis"

    # Path related
    if any(word in text_lower for word in ['path', 'directory', 'folder']):
        return "Specify the file or directory path"

    # Analysis related
    if any(word in text_lower for word in ['analysis', 'analyze', 'scan']):
        return "Configure or start analysis operations"

    # AI related
    if any(word in text_lower for word in ['ai', 'model', 'assistant', 'openai', 'anthropic']):
        return "AI-powered analysis and assistance settings"

    # Network related
    if any(word in text_lower for word in ['network', 'packet', 'capture', 'interface']):
        return "Network analysis and monitoring tools"

    # Security related
    if any(word in text_lower for word in ['protection', 'security', 'encrypt', 'hash']):
        return "Security analysis and cryptographic operations"

    # Performance related
    if any(word in text_lower for word in ['performance', 'memory', 'cache', 'thread']):
        return "Performance and system resource settings"

    # Theme/appearance related
    if any(word in text_lower for word in ['theme', 'color', 'font', 'appearance']):
        return "Visual appearance and theme settings"

    return ""  # No contextual match found

def apply_tooltips_to_buttons(parent_widget):
    """
    Backward compatibility wrapper for apply_tooltips_to_all_elements.

    Args:
        parent_widget: The parent widget to search for UI elements
    """
    apply_tooltips_to_all_elements(parent_widget)


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

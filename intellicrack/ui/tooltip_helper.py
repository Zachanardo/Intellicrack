"""Tooltip helper utilities for enhanced UI tooltips."""

from intellicrack.utils.logger import logger


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
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""


def get_tooltip_definitions() -> dict[str, str]:
    """Get comprehensive tooltip definitions for all UI elements.

    Returns:
        Dictionary mapping button text to tooltip descriptions

    """
    return {
        # Analysis Tab - Static Analysis
        "Run Full Static Analysis": (
            "Performs comprehensive static analysis without executing the binary.<br>"
            "Includes: File format parsing, import/export analysis, string extraction,<br>"
            "function detection, and advanced vulnerability scanning with ML prediction.<br>"
            "Safe to run on any binary - no execution risk."
        ),
        "Disassemble": (
            "Converts machine code into human-readable assembly instructions.<br>"
            "Shows the low-level CPU instructions that make up the program.<br>"
            "Useful for understanding program logic and finding vulnerabilities."
        ),
        "View CFG": (
            "Control Flow Graph - Visual representation of program execution paths.<br>"
            "Shows how different parts of the code connect and branch.<br>"
            "Helps identify loops, conditions, and potential code coverage."
        ),
        "Find ROP Gadgets": (
            "Return-Oriented Programming gadgets - Small instruction sequences<br>"
            "ending in 'return' that can be chained for exploitation.<br>"
            "Used in advanced exploit development to bypass security measures."
        ),
        "Binary Similarity Search": (
            "Compares this binary against a database of known binaries.<br>"
            "Helps identify: Similar protection methods, code reuse,<br>"
            "library versions, and potential vulnerabilities from similar code."
        ),
        # Protection Detection
        "Scan for All Known Protections": (
            "Comprehensive scan for all security measures in the binary.<br>"
            "Detects: Anti-debug, packing, obfuscation, license checks,<br>"
            "DRM systems, and hardware protection mechanisms."
        ),
        "Detect Packing/Obfuscation": (
            "Identifies if the binary is compressed or obfuscated.<br>"
            "Common packers: UPX, Themida, VMProtect, ASPack.<br>"
            "Packed binaries hide their real code and need unpacking first."
        ),
        "Detect Commercial Protections": (
            "Scans for commercial protection systems like:<br>"
            "Denuvo, SecuROM, SafeDisc, StarForce, etc.<br>"
            "These are professional anti-piracy solutions."
        ),
        "Detect Hardware Dongles": (
            "Checks for hardware key/dongle requirements.<br>"
            "Common systems: HASP, Sentinel, WibuKey.<br>"
            "Hardware dongles are physical USB devices for license verification."
        ),
        "Detect TPM/VM/Anti-Debug": (
            "TPM: Trusted Platform Module - Hardware security chip detection<br>"
            "VM: Virtual Machine detection (VMware, VirtualBox, etc.)<br>"
            "Anti-Debug: Techniques to prevent debugger attachment"
        ),
        # Protection Bypass
        "Bypass TPM Protection": (
            "Attempts to bypass Trusted Platform Module checks.<br>"
            "TPM stores encryption keys and validates system integrity.<br>"
            "WARNING️ Use only on software you own or have permission to test."
        ),
        "Bypass VM Detection": (
            "Removes or bypasses virtual machine detection.<br>"
            "Many programs refuse to run in VMs for security.<br>"
            "Makes the VM appear as a physical machine to the program."
        ),
        "Activate Dongle Emulation": (
            "Emulates hardware dongle responses without the physical device.<br>"
            "Emulates USB license key functionality.<br>"
            "WARNING️ Only for testing software you have licensed."
        ),
        # Dynamic Analysis
        "Launch Target Binary": (
            "Executes the binary in a controlled environment.<br>"
            "WARNING️ WARNING: This runs the program - use in isolated environment!<br>"
            "Enable monitoring options first for safety."
        ),
        "Attach to Running Process": (
            "Connects to an already running program for analysis.<br>"
            "Allows inspection of live memory and runtime behavior.<br>"
            "Requires appropriate permissions on the target process."
        ),
        "Start API Hooking": (
            "Intercepts Windows API calls made by the program.<br>"
            "Records: File access, registry changes, network connections.<br>"
            "Essential for understanding program behavior."
        ),
        "Start Runtime Monitoring": (
            "Monitors program execution in real-time.<br>"
            "Tracks: Memory usage, CPU activity, system calls.<br>"
            "Helps identify performance issues and suspicious behavior."
        ),
        # Advanced Analysis
        "Run Symbolic Path Exploration": (
            "Explores all possible execution paths symbolically.<br>"
            "Uses mathematical constraints instead of concrete values.<br>"
            "Powerful for finding hidden functionality and vulnerabilities."
        ),
        "Run Concolic Path Exploration": (
            "Concrete + Symbolic execution - Hybrid approach.<br>"
            "Combines real execution with symbolic analysis.<br>"
            "More efficient than pure symbolic execution."
        ),
        "Run Taint Analysis": (
            "Tracks how user input flows through the program.<br>"
            "Identifies where untrusted data reaches sensitive operations.<br>"
            "Critical for finding injection vulnerabilities."
        ),
        "Find License Bypass": (
            "Automated search for license check bypasses.<br>"
            "Uses symbolic execution to find paths avoiding checks.<br>"
            "WARNING️ For educational/testing purposes only."
        ),
        # Patching Tab
        "Create Patch Plan": (
            "Analyzes the binary and creates a patching strategy.<br>"
            "Identifies: Key locations, patch types needed,<br>"
            "potential side effects, and success probability."
        ),
        "Apply Patches": (
            "Modifies the binary according to the patch plan.<br>"
            "WARNING️ Creates backup first - this changes the executable!<br>"
            "Can patch: Jump instructions, NOP out checks, modify constants."
        ),
        "Generate ROP Chains": (
            "Creates Return-Oriented Programming exploit chains.<br>"
            "Advanced technique for bypassing DEP/NX protection.<br>"
            "Requires deep understanding of exploitation."
        ),
        "AI-Generated Patches": (
            "Uses sophisticated neural networks to suggest optimal patches.<br>"
            "Analyzes license protection patterns and binary structures.<br>"
            "Production-ready AI with license-focused pattern recognition."
        ),
        # Network Tab
        "Start Capture": (
            "Begins capturing network packets on selected interface.<br>"
            "Records all network traffic for analysis.<br>"
            "Requires administrator/root privileges."
        ),
        "Protocol Fingerprinting": (
            "Identifies network protocols and services automatically.<br>"
            "Detects: License servers, update checks, telemetry.<br>"
            "Helps understand program's network behavior."
        ),
        "SSL Interception": (
            "Decrypts HTTPS/SSL traffic for analysis.<br>"
            "Acts as man-in-the-middle to view encrypted data.<br>"
            "WARNING️ Only use on your own traffic - may trigger security alerts."
        ),
        "Start Emulated Server": (
            "Creates emulated license/activation server.<br>"
            "Responds to program's network requests with success.<br>"
            "Useful for offline activation and testing."
        ),
        # AI Assistant
        "Fine-tune AI Model": (
            "Trains sophisticated neural networks on license protection patterns.<br>"
            "Uses advanced backpropagation and Xavier initialization for optimal learning.<br>"
            "Production-ready training with real mathematical optimization algorithms."
        ),
        # Tools
        "Key Generator": (
            "Analyzes license algorithms and generates valid keys.<br>"
            "Works with: Serial numbers, activation codes, licenses.<br>"
            "Success depends on algorithm complexity."
        ),
        "Advanced Patcher": (
            "Professional patching interface with hex editing.<br>"
            "Features: Pattern search, multi-patch support,<br>"
            "verification, and automated patch distribution."
        ),
        "API Emulator": (
            "Intercepts and modifies Windows API responses.<br>"
            "Useful for sandboxing and behavior analysis.<br>"
            "Can emulate: File existence, registry values, system info."
        ),
        "Binary Unpacker": (
            "Removes packing/compression from executables.<br>"
            "Supports: UPX, ASPack, PECompact, and more.<br>"
            "Required before analyzing packed binaries."
        ),
        "PE Rebuilder": (
            "Repairs corrupted or modified PE executables.<br>"
            "Fixes: Import tables, section headers, checksums.<br>"
            "Useful after unpacking or patching."
        ),
        # Memory Analysis
        "Memory Optimization Level": (
            "Controls memory usage vs performance tradeoff.<br>Low: Fast analysis with higher RAM usage<br>High: Memory-efficient processing with intelligent caching"
        ),
        # General Operations
        "Open Binary": (
            "Select an executable file to analyze.<br>"
            "Supports: PE (.exe/.dll), ELF (Linux), Mach-O (macOS).<br>"
            "File is loaded but not executed until you choose."
        ),
        "Save Analysis Results": (
            "Exports all analysis data to a report.<br>"
            "Formats: PDF (with charts), JSON (for processing),<br>"
            "HTML (for sharing), TXT (simple notes)."
        ),
        "One-Click Full Analysis & Patch": (
            "Automated workflow for common tasks:<br>"
            "1. Analyzes the binary<br>"
            "2. Detects protections<br>"
            "3. Suggests and applies patches<br>"
            "WARNING️ Review results before using patched binary!"
        ),
        "Guided Workflow Wizard": (
            "Step-by-step assistant for new users.<br>"
            "Guides through: Analysis → Detection → Patching.<br>"
            "Explains each step and suggests best practices."
        ),
        # Vulnerability Scanning
        "Run Static Vulnerability Scan": (
            "Scans for known security vulnerabilities.<br>"
            "Checks: Buffer overflows, format strings, integer overflows,<br>"
            "use-after-free, and other common vulnerability patterns."
        ),
        "Run ML-Based Vulnerability Prediction": (
            "Uses sophisticated neural networks to predict potential vulnerabilities.<br>"
            "Trained on license protection patterns with advanced optimization.<br>"
            "Production-ready ML with precise probability scores and pattern recognition."
        ),
    }


def _apply_tooltips_to_buttons(parent_widget: object, all_tooltips: dict[str, str]) -> None:
    """Apply tooltips to QPushButton elements."""
    try:
        from intellicrack.handlers.pyqt6_handler import QPushButton
    except ImportError as e:
        logger.error("Import error in tooltip_helper: %s", e)
        QPushButton = object  # Fallback

    buttons = parent_widget.findChildren(QPushButton)
    for button in buttons:
        button_text = button.text()
        if button_text in all_tooltips:
            button.setToolTip(all_tooltips[button_text])


def _apply_tooltips_to_labels(parent_widget: object, all_tooltips: dict[str, str]) -> None:
    """Apply tooltips to QLabel elements."""
    try:
        from intellicrack.handlers.pyqt6_handler import QLabel
    except ImportError:
        from intellicrack.handlers.pyqt6_handler import QPushButton

        QLabel = QPushButton  # Fallback

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


def _apply_tooltips_to_line_edits(parent_widget: object, all_tooltips: dict[str, str]) -> None:
    """Apply tooltips to QLineEdit elements."""
    try:
        from intellicrack.handlers.pyqt6_handler import QLineEdit
    except ImportError:
        from intellicrack.handlers.pyqt6_handler import QPushButton

        QLineEdit = QPushButton  # Fallback

    line_edits = parent_widget.findChildren(QLineEdit)
    for line_edit in line_edits:
        hint_text = next(
            (
                line_edit.property("hintText") or ""
                for prop in line_edit.dynamicPropertyNames()
                if prop.data().decode() == "hintText"
            ),
            "",
        )
        object_name = line_edit.objectName()

        if hint_text in all_tooltips:
            line_edit.setToolTip(all_tooltips[hint_text])
        elif object_name in all_tooltips:
            line_edit.setToolTip(all_tooltips[object_name])
        elif hint_text and _get_contextual_tooltip(hint_text):
            line_edit.setToolTip(_get_contextual_tooltip(hint_text))


def _apply_tooltips_to_combo_boxes(parent_widget: object, all_tooltips: dict[str, str]) -> None:
    """Apply tooltips to QComboBox elements."""
    try:
        from intellicrack.handlers.pyqt6_handler import QComboBox
    except ImportError:
        from intellicrack.handlers.pyqt6_handler import QPushButton

        QComboBox = QPushButton  # Fallback

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


def _apply_tooltips_to_checkboxes(parent_widget: object, all_tooltips: dict[str, str]) -> None:
    """Apply tooltips to QCheckBox elements."""
    try:
        from intellicrack.handlers.pyqt6_handler import QCheckBox
    except ImportError:
        from intellicrack.handlers.pyqt6_handler import QPushButton

        QCheckBox = QPushButton  # Fallback

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


def _apply_tooltips_to_spinboxes(parent_widget: object, all_tooltips: dict[str, str]) -> None:
    """Apply tooltips to QSpinBox and QDoubleSpinBox elements."""
    try:
        from intellicrack.handlers.pyqt6_handler import QDoubleSpinBox, QSpinBox
    except ImportError:
        from intellicrack.handlers.pyqt6_handler import QPushButton

        QSpinBox = QDoubleSpinBox = QPushButton  # Fallback

    spinboxes = parent_widget.findChildren(QSpinBox) + parent_widget.findChildren(QDoubleSpinBox)
    for spinbox in spinboxes:
        object_name = spinbox.objectName()

        if object_name in all_tooltips:
            spinbox.setToolTip(all_tooltips[object_name])
        elif object_name and _get_contextual_tooltip(object_name):
            spinbox.setToolTip(_get_contextual_tooltip(object_name))


def _apply_tooltips_to_tab_widgets(parent_widget: object, all_tooltips: dict[str, str]) -> None:
    """Apply tooltips to QTabWidget elements."""
    try:
        from intellicrack.handlers.pyqt6_handler import QTabWidget
    except ImportError:
        from intellicrack.handlers.pyqt6_handler import QPushButton

        QTabWidget = QPushButton  # Fallback

    tab_widgets = parent_widget.findChildren(QTabWidget)
    for tab_widget in tab_widgets:
        for i in range(tab_widget.count()):
            tab_text = tab_widget.tabText(i)
            if tab_text in all_tooltips:
                tab_widget.setTabToolTip(i, all_tooltips[tab_text])
            elif tab_text and _get_contextual_tooltip(tab_text):
                tab_widget.setTabToolTip(i, _get_contextual_tooltip(tab_text))


def _apply_tooltips_to_other_widgets(parent_widget: object, all_tooltips: dict[str, str]) -> None:
    """Apply tooltips to various other widget types."""
    try:
        from intellicrack.handlers.pyqt6_handler import (
            QListWidget,
            QPlainTextEdit,
            QProgressBar,
            QSlider,
            QTableWidget,
            QTextEdit,
            QTreeWidget,
        )
    except ImportError:
        from intellicrack.handlers.pyqt6_handler import QPushButton

        QSlider = QProgressBar = QTextEdit = QPlainTextEdit = QPushButton
        QListWidget = QTreeWidget = QTableWidget = QPushButton

    other_widgets = (
        parent_widget.findChildren(QSlider)
        + parent_widget.findChildren(QProgressBar)
        + parent_widget.findChildren(QTextEdit)
        + parent_widget.findChildren(QPlainTextEdit)
        + parent_widget.findChildren(QListWidget)
        + parent_widget.findChildren(QTreeWidget)
        + parent_widget.findChildren(QTableWidget)
    )

    for widget in other_widgets:
        object_name = widget.objectName()
        if object_name in all_tooltips:
            widget.setToolTip(all_tooltips[object_name])
        elif object_name and _get_contextual_tooltip(object_name):
            widget.setToolTip(_get_contextual_tooltip(object_name))


def apply_tooltips_to_all_elements(parent_widget: object) -> None:
    """Apply tooltips to all UI elements in a widget hierarchy.

    Now supports: QPushButton, QLabel, QLineEdit, QComboBox, QCheckBox,
    QSpinBox, QDoubleSpinBox, QTabWidget, and other common UI elements.

    Args:
        parent_widget: The parent widget to search for UI elements. Must have
            findChildren() method compatible with PyQt6 widget classes.

    """
    try:
        from intellicrack.handlers.pyqt6_handler import (
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
        from intellicrack.handlers.pyqt6_handler import QPushButton

    tooltips = get_tooltip_definitions()

    # Enhanced tooltip definitions for all UI elements
    enhanced_tooltips = get_enhanced_tooltip_definitions()
    all_tooltips = {**tooltips, **enhanced_tooltips}

    # Apply tooltips to all supported widget types
    _apply_tooltips_to_buttons(parent_widget, all_tooltips)
    _apply_tooltips_to_labels(parent_widget, all_tooltips)
    _apply_tooltips_to_line_edits(parent_widget, all_tooltips)
    _apply_tooltips_to_combo_boxes(parent_widget, all_tooltips)
    _apply_tooltips_to_checkboxes(parent_widget, all_tooltips)
    _apply_tooltips_to_spinboxes(parent_widget, all_tooltips)
    _apply_tooltips_to_tab_widgets(parent_widget, all_tooltips)
    _apply_tooltips_to_other_widgets(parent_widget, all_tooltips)


def get_enhanced_tooltip_definitions() -> dict[str, str]:
    """Enhanced tooltip definitions for all UI element types.

    Returns:
        Dictionary mapping UI element identifiers to tooltip descriptions

    """
    return {
        # Tab tooltips
        "Dashboard": (
            "Project overview and workspace management.<br>"
            "Manage projects, select binaries, view activity logs,<br>"
            "and access recent files for quick analysis startup."
        ),
        "Analysis": (
            "Comprehensive binary analysis tools.<br>"
            "Static analysis, protection detection, dynamic hooking,<br>"
            "and advanced execution engines for deep binary inspection."
        ),
        "Exploitation": (
            "Binary exploitation and patching tools.<br>"
            "ROP chain generation, shellcode creation, memory patching,<br>"
            "and exploit development for security testing."
        ),
        "AI Assistant": (
            "AI-powered analysis and code generation.<br>"
            "Script generation, binary analysis assistance, model training,<br>"
            "and intelligent reverse engineering support."
        ),
        "Tools": (
            "System tools, plugin management, and network analysis.<br>"
            "File operations, cryptographic tools, plugin development,<br>"
            "and network packet capture capabilities."
        ),
        "Settings": (
            "Application configuration and preferences.<br>"
            "Theme settings, tool paths, performance tuning,<br>"
            "and advanced configuration options."
        ),
        # Common UI element tooltips
        "Binary Path:": (
            "Full path to the target binary file for analysis.<br>Supports PE (.exe/.dll), ELF, and Mach-O formats."
        ),
        "Target Binary:": (
            "Select the executable file you want to analyze.<br>The binary will be loaded but not executed until you choose."
        ),
        "Output Directory:": (
            "Where analysis results and generated files will be saved.<br>Include reports, patches, extracted data, and logs."
        ),
        "API Key:": (
            "Authentication key for AI service access.<br>Required for OpenAI, Anthropic, or other AI providers."
        ),
        "Temperature:": (
            "Controls AI response creativity and randomness.<br>"
            "Lower values (0.1-0.3): More focused and deterministic<br>"
            "Higher values (0.7-1.0): More creative and varied"
        ),
        "Max Tokens:": (
            "Maximum length of AI response in tokens.<br>"
            "Higher values allow longer responses but cost more.<br>"
            "1 token ≈ 0.75 words for English text."
        ),
        "Analysis Depth:": (
            "How thorough the analysis should be.<br>"
            "Quick: Fast scan with essential pattern recognition<br>"
            "Standard: Comprehensive analysis with ML prediction (recommended)<br>"
            "Deep: Exhaustive analysis with all AI-powered techniques"
        ),
        "Cache Size:": (
            "Amount of memory to use for caching analysis data.<br>"
            "Larger cache improves performance but uses more RAM.<br>"
            "Recommended: 512MB for most systems."
        ),
        "Worker Threads:": (
            "Number of parallel threads for analysis tasks.<br>"
            "More threads = faster analysis on multi-core CPUs.<br>"
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
        # Hint text tooltips
        "Select a binary file for analysis...": (
            "Click Browse to choose an executable file.<br>Supported formats: PE, ELF, Mach-O"
        ),
        "Enter API key...": ("Paste your AI service API key here.<br>Keep this secret and secure!"),
        "Search files...": (
            "Enter filename or pattern to search.<br>Supports wildcards like *.exe or *crack*"
        ),
        "Enter target address...": (
            "Memory address in hexadecimal format.<br>Example: 0x401000 or 401000"
        ),
        "Enter shellcode...": (
            "Raw shellcode bytes in hex format.<br>Example: \\x90\\x90\\xCC or 909090CC"
        ),
        # Analysis specific tooltips
        "Include Strings": (
            "Extract and include readable text strings from the binary.<br>Helps identify: URLs, file paths, error messages, debug info."
        ),
        "Include Imports": (
            "Analyze imported functions and libraries.<br>Shows what Windows APIs or system functions are used."
        ),
        "Include Exports": (
            "Analyze exported functions (for DLLs).<br>Shows what functions this library provides to other programs."
        ),
        "Include Disassembly": (
            "Include assembly code in the analysis.<br>WARNING️ Can produce very large outputs for big binaries."
        ),
        "Enable GPU": (
            "Use GPU acceleration for analysis tasks.<br>"
            "Significantly faster but requires compatible GPU.<br>"
            "Supports CUDA, OpenCL, and DirectML."
        ),
        "Safe Mode": (
            "Enable additional safety checks and confirmations.<br>"
            "Prevents accidental dangerous operations.<br>"
            "Recommended for production environments."
        ),
        "Auto Analysis": (
            "Automatically start analysis when binary is selected.<br>Convenient but may slow down file browsing."
        ),
        "Show Tooltips": (
            "Display helpful tooltips like this one.<br>Disable to reduce visual clutter."
        ),
        "Enable Animations": (
            "Use smooth animations for UI transitions.<br>Disable to improve performance on slower systems."
        ),
        "Parallel Processing": (
            "Use multiple CPU cores for analysis tasks.<br>Faster analysis but higher resource usage."
        ),
        "Auto Cleanup": (
            "Automatically clean up temporary files and memory.<br>Keeps system clean but may slow down repeated tasks."
        ),
        "Debug Mode": (
            "Enable verbose logging and debug features.<br>Useful for troubleshooting but slower performance."
        ),
        "Advanced Features": (
            "Enable sophisticated AI-powered analysis features.<br>Includes neural network predictions and advanced pattern recognition."
        ),
    }


def _get_contextual_tooltip(text: str) -> str:
    """Generate contextual tooltips for common UI patterns.

    Args:
        text: The UI element text to analyze

    Returns:
        Contextual tooltip or empty string if no match

    """
    text_lower = text.lower()

    # Binary/file related
    if any(word in text_lower for word in ["binary", "file", "executable", "target"]):
        return "Select or specify a binary file for analysis"

    # Path related
    if any(word in text_lower for word in ["path", "directory", "folder"]):
        return "Specify the file or directory path"

    # Analysis related
    if any(word in text_lower for word in ["analysis", "analyze", "scan"]):
        return "Configure or start analysis operations"

    # AI related
    if any(word in text_lower for word in ["ai", "model", "assistant", "openai", "anthropic"]):
        return "AI-powered analysis and assistance settings"

    # Network related
    if any(word in text_lower for word in ["network", "packet", "capture", "interface"]):
        return "Network analysis and monitoring tools"

    # Security related
    if any(word in text_lower for word in ["protection", "security", "encrypt", "hash"]):
        return "Security analysis and cryptographic operations"

    # Performance related
    if any(word in text_lower for word in ["performance", "memory", "cache", "thread"]):
        return "Performance and system resource settings"

    # Theme/appearance related
    if any(word in text_lower for word in ["theme", "color", "font", "appearance"]):
        return "Visual appearance and theme settings"

    return ""  # No contextual match found


def apply_tooltips_to_buttons(parent_widget: object) -> None:
    """Backward compatibility wrapper for apply_tooltips_to_all_elements.

    Args:
        parent_widget: The parent widget to search for UI elements. Must have
            findChildren() method compatible with PyQt6 widget classes.

    """
    apply_tooltips_to_all_elements(parent_widget)


def create_tooltip_with_shortcut(description: str, shortcut: str | None = None) -> str:
    """Create a formatted tooltip with optional keyboard shortcut.

    Args:
        description: Main tooltip description for the UI element.
        shortcut: Optional keyboard shortcut string to append to tooltip.

    Returns:
        Formatted tooltip string with optional shortcut appended.

    """
    if shortcut:
        return f"{description}<br><br>Shortcut: {shortcut}"
    return description

"""
This file is part of Intellicrack.
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

"""
Payload Generator Dialog

Advanced UI for creating custom payloads with various encoding,
obfuscation, and evasion techniques.
"""

import asyncio
import logging
from typing import Any, Dict

from PyQt6.QtCore import QThread, pyqtSignal
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QMessageBox,
    QSpinBox,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from ...core.exploitation import (
    Architecture,
    EncoderEngine,
    EvasionTechnique,
    PayloadEngine,
    PayloadTemplates,
    PayloadType,
)
from ...utils.analysis.entropy_utils import calculate_byte_entropy
from .base_dialog import BaseTemplateDialog

logger = logging.getLogger(__name__)


class PayloadGenerationThread(QThread):
    """Thread for generating payloads without blocking UI."""

    progress = pyqtSignal(str)
    finished = pyqtSignal(dict)
    error = pyqtSignal(str)

    def __init__(self, engine, config):
        """Initialize the PayloadGenerationThread with default values."""
        super().__init__()
        self.engine = engine
        self.config = config

    def run(self):
        """Execute the payload generation process in a separate thread."""
        try:
            self.progress.emit("Starting payload generation...")

            # Run async generation in thread
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

            result = loop.run_until_complete(
                self.engine.generate_payload(**self.config)
            )

            self.finished.emit(result)

        except Exception as e:
            self.logger.error("Exception in payload_generator_dialog: %s", e)
            self.error.emit(str(e))


class PayloadGeneratorDialog(BaseTemplateDialog):
    """
    Advanced payload generator dialog with comprehensive options
    for creating custom exploitation payloads.
    """

    payload_generated = pyqtSignal(dict)

    def __init__(self, parent=None):
        """Initialize the PayloadGeneratorDialog with default values."""
        super().__init__(parent)
        self.logger = logging.getLogger("IntellicrackLogger.PayloadGeneratorDialog")

        # Initialize engines
        self.payload_engine = PayloadEngine()
        self.template_engine = PayloadTemplates()
        self.encoder_engine = EncoderEngine()

        self.current_payload = None
        self.generation_thread = None

        self.setup_ui()
        self.load_templates()

    def setup_ui(self):
        """Setup the user interface."""
        from ..shared_ui_layouts import UILayoutHelpers

        # Create main tabbed dialog layout
        layout, self.tab_widget = UILayoutHelpers.create_tabbed_dialog_layout(
            self, "Advanced Payload Generator", (1000, 700), is_modal=False
        )

        # Create and add tabs
        tab_specs = [
            ("Templates", self.create_template_tab()),
            ("Custom Payload", self.create_custom_tab()),
            ("Encoding & Obfuscation", self.create_encoding_tab()),
            ("Evasion Techniques", self.create_evasion_tab()),
            ("Generated Payload", self.create_output_tab())
        ]
        UILayoutHelpers.create_tabs_from_specs(self.tab_widget, tab_specs)

        # Create dialog buttons
        button_specs = [
            ("Generate Payload", self.generate_payload, False),
            ("Save Payload", self.save_payload, False),
            ("Test Payload", self.test_payload, False),
            ("Close", self.close, True)
        ]
        buttons = UILayoutHelpers.create_dialog_buttons(button_specs, layout)

        # Store button references for enabling/disabling
        self.generate_btn, self.save_btn, self.test_btn, self.close_btn = buttons
        self.save_btn.setEnabled(False)
        self.test_btn.setEnabled(False)

        self.setLayout(layout)

    def create_template_tab(self):
        """Create template selection tab."""
        # Use base class method to create template widget
        template_categories = [
            "Shell", "Persistence", "Privilege Escalation",
            "Lateral Movement", "Steganography", "Anti-Analysis"
        ]

        # Get initial templates for first category
        initial_templates = PayloadTemplates.get_templates_by_category("Shell")

        widget = self.create_template_widget(
            title="Payload Templates",
            templates=initial_templates,
            use_combo=False,
            category_names=template_categories
        )

        # The base class already provides the template details widget
        # Add any specific customizations here if needed
        return widget

    def create_custom_tab(self):
        """Create custom payload creation tab."""
        widget = QWidget()
        layout = QVBoxLayout()

        # Payload type
        type_layout = QHBoxLayout()
        type_layout.addWidget(QLabel("Payload Type:"))

        self.payload_type_combo = QComboBox()
        self.payload_type_combo.addItems([
            "Reverse Shell", "Bind Shell", "Meterpreter",
            "Custom Shellcode", "DLL Injection", "Process Hollowing"
        ])
        type_layout.addWidget(self.payload_type_combo)

        type_layout.addWidget(QLabel("Architecture:"))
        self.custom_arch_combo = QComboBox()
        self.custom_arch_combo.addItems(["x86", "x64", "ARM", "ARM64"])
        type_layout.addWidget(self.custom_arch_combo)

        type_layout.addStretch()
        layout.addLayout(type_layout)

        # Shellcode editor
        shellcode_group = QGroupBox("Custom Shellcode / Assembly")
        shellcode_layout = QVBoxLayout()

        self.shellcode_editor = QTextEdit()
        self.shellcode_editor.setFont(QFont("Courier", 10))
        self.shellcode_editor.setPlaceholderText(
            "Enter custom shellcode (hex format) or assembly code:\n\n"
            "Example hex: \\x90\\x90\\x90\\x90\n"
            "Example assembly:\n"
            "  xor eax, eax\n"
            "  push eax\n"
            "  push 0x68732f2f\n"
            "  push 0x6e69622f"
        )
        shellcode_layout.addWidget(self.shellcode_editor)

        # Format options
        format_layout = QHBoxLayout()
        self.hex_radio = QCheckBox("Hex Format")
        self.hex_radio.setChecked(True)
        self.asm_radio = QCheckBox("Assembly")
        self.asm_radio.toggled.connect(lambda checked: self.hex_radio.setChecked(not checked))
        self.hex_radio.toggled.connect(lambda checked: self.asm_radio.setChecked(not checked))

        format_layout.addWidget(self.hex_radio)
        format_layout.addWidget(self.asm_radio)
        format_layout.addStretch()

        shellcode_layout.addLayout(format_layout)
        shellcode_group.setLayout(shellcode_layout)

        layout.addWidget(shellcode_group)

        # Options
        options_group = QGroupBox("Generation Options")
        options_layout = QVBoxLayout()

        self.null_free_check = QCheckBox("Null-free shellcode")
        self.position_independent_check = QCheckBox("Position-independent code")
        self.position_independent_check.setChecked(True)
        self.unicode_safe_check = QCheckBox("Unicode-safe encoding")

        options_layout.addWidget(self.null_free_check)
        options_layout.addWidget(self.position_independent_check)
        options_layout.addWidget(self.unicode_safe_check)

        options_group.setLayout(options_layout)
        layout.addWidget(options_group)

        widget.setLayout(layout)
        return widget

    def create_encoding_tab(self):
        """Create encoding and obfuscation tab."""
        widget = QWidget()
        layout = QVBoxLayout()

        # Encoding schemes
        encoding_group = QGroupBox("Encoding Schemes")
        encoding_layout = QVBoxLayout()

        # Available encoders
        self.encoder_list = QListWidget()
        self.encoder_list.setSelectionMode(QListWidget.MultiSelection)
        encoders = self.encoder_engine.get_encoding_schemes()
        self.encoder_list.addItems(encoders)
        encoding_layout.addWidget(QLabel("Select encoding schemes (applied in order):"))
        encoding_layout.addWidget(self.encoder_list)

        # Encoding parameters
        params_layout = QHBoxLayout()
        params_layout.addWidget(QLabel("XOR Key:"))
        self.xor_key_edit = QLineEdit()
        self.xor_key_edit.setPlaceholderText("Leave empty for random")
        params_layout.addWidget(self.xor_key_edit)

        params_layout.addWidget(QLabel("Iterations:"))
        self.iterations_spin = QSpinBox()
        self.iterations_spin.setMinimum(1)
        self.iterations_spin.setMaximum(10)
        self.iterations_spin.setValue(1)
        params_layout.addWidget(self.iterations_spin)

        params_layout.addStretch()
        encoding_layout.addLayout(params_layout)

        encoding_group.setLayout(encoding_layout)
        layout.addWidget(encoding_group)

        # Obfuscation options
        obfuscation_group = QGroupBox("Obfuscation Techniques")
        obfuscation_layout = QVBoxLayout()

        self.dead_code_check = QCheckBox("Insert dead code")
        self.code_reorder_check = QCheckBox("Reorder code blocks")
        self.register_rename_check = QCheckBox("Register renaming")
        self.garbage_insertion_check = QCheckBox("Garbage instruction insertion")
        self.metamorphic_check = QCheckBox("Metamorphic transformation")

        obfuscation_layout.addWidget(self.dead_code_check)
        obfuscation_layout.addWidget(self.code_reorder_check)
        obfuscation_layout.addWidget(self.register_rename_check)
        obfuscation_layout.addWidget(self.garbage_insertion_check)
        obfuscation_layout.addWidget(self.metamorphic_check)

        obfuscation_group.setLayout(obfuscation_layout)
        layout.addWidget(obfuscation_group)

        widget.setLayout(layout)
        return widget

    def create_evasion_tab(self):
        """Create evasion techniques tab."""
        widget = QWidget()
        layout = QVBoxLayout()

        # Anti-analysis
        anti_analysis_group = QGroupBox("Anti-Analysis Techniques")
        anti_analysis_layout = QVBoxLayout()

        self.vm_detection_check = QCheckBox("Virtual machine detection")
        self.debugger_detection_check = QCheckBox("Debugger detection")
        self.sandbox_detection_check = QCheckBox("Sandbox detection")
        self.timing_checks_check = QCheckBox("Timing-based anti-analysis")
        self.api_hooks_check = QCheckBox("API hook detection")

        anti_analysis_layout.addWidget(self.vm_detection_check)
        anti_analysis_layout.addWidget(self.debugger_detection_check)
        anti_analysis_layout.addWidget(self.sandbox_detection_check)
        anti_analysis_layout.addWidget(self.timing_checks_check)
        anti_analysis_layout.addWidget(self.api_hooks_check)

        anti_analysis_group.setLayout(anti_analysis_layout)
        layout.addWidget(anti_analysis_group)

        # Evasion techniques
        evasion_group = QGroupBox("Signature Evasion")
        evasion_layout = QVBoxLayout()

        self.polymorphic_check = QCheckBox("Polymorphic code generation")
        self.encrypted_strings_check = QCheckBox("Encrypt strings and constants")
        self.api_obfuscation_check = QCheckBox("API call obfuscation")
        self.control_flow_check = QCheckBox("Control flow obfuscation")

        evasion_layout.addWidget(self.polymorphic_check)
        evasion_layout.addWidget(self.encrypted_strings_check)
        evasion_layout.addWidget(self.api_obfuscation_check)
        evasion_layout.addWidget(self.control_flow_check)

        evasion_group.setLayout(evasion_layout)
        layout.addWidget(evasion_group)

        # Delivery options
        delivery_group = QGroupBox("Delivery Methods")
        delivery_layout = QVBoxLayout()

        self.exe_wrapper_check = QCheckBox("Wrap in executable")
        self.dll_wrapper_check = QCheckBox("Generate as DLL")
        self.doc_macro_check = QCheckBox("Office macro payload")
        self.powershell_check = QCheckBox("PowerShell payload")

        delivery_layout.addWidget(self.exe_wrapper_check)
        delivery_layout.addWidget(self.dll_wrapper_check)
        delivery_layout.addWidget(self.doc_macro_check)
        delivery_layout.addWidget(self.powershell_check)

        delivery_group.setLayout(delivery_layout)
        layout.addWidget(delivery_group)

        widget.setLayout(layout)
        return widget

    def create_output_tab(self):
        """Create output display tab."""
        widget = QWidget()
        layout = QVBoxLayout()

        # Output format selection
        format_layout = QHBoxLayout()
        format_layout.addWidget(QLabel("Output Format:"))

        self.output_format_combo = QComboBox()
        self.output_format_combo.addItems([
            "Raw Binary", "C Array", "Python String",
            "PowerShell", "Base64", "Hex String"
        ])
        self.output_format_combo.currentTextChanged.connect(self.update_output_display)
        format_layout.addWidget(self.output_format_combo)

        format_layout.addStretch()
        layout.addLayout(format_layout)

        # Output display
        self.output_display = QTextEdit()
        self.output_display.setFont(QFont("Courier", 10))
        self.output_display.setReadOnly(True)
        layout.addWidget(self.output_display)

        # Payload info
        info_group = QGroupBox("Payload Information")
        self.info_layout = QVBoxLayout()

        self.size_label = QLabel("Size: N/A")
        self.hash_label = QLabel("SHA256: N/A")
        self.entropy_label = QLabel("Entropy: N/A")
        self.null_bytes_label = QLabel("Null bytes: N/A")

        self.info_layout.addWidget(self.size_label)
        self.info_layout.addWidget(self.hash_label)
        self.info_layout.addWidget(self.entropy_label)
        self.info_layout.addWidget(self.null_bytes_label)

        info_group.setLayout(self.info_layout)
        layout.addWidget(info_group)

        widget.setLayout(layout)
        return widget

    def load_templates(self):
        """Load available templates."""
        try:
            category = self.category_combo.currentText().lower().replace(" ", "_")
            templates = self.template_engine.list_templates(category)

            self.template_list.clear()
            if category in templates:
                self.template_list.addItems(templates[category])

        except Exception as e:
            self.logger.error(f"Failed to load templates: {e}")

    def on_category_changed(self):
        """Handle category change."""
        self.load_templates()
        self.clear_template_params()

    def on_template_selected(self, template_name: str = None):
        """Handle template selection."""
        try:
            # If template_name not provided, get from list widget
            if template_name is None:
                items = self.template_list.selectedItems()
                if not items:
                    return
                template_name = items[0].text()

            # Determine category based on current selection
            category = self.category_combo.currentText().lower().replace(" ", "_") if hasattr(self, 'category_combo') else "shell"

            # Get template details
            arch = Architecture.X86  # Default for getting template info
            template = self.template_engine.get_template(category, template_name, arch)

            if template:
                self.template_name_label.setText(template.get('name', template_name))
                self.template_desc_label.setText(template.get('description', ''))

                # Clear and populate parameters
                self.clear_template_params()

                params = template.get('parameters', [])
                self.template_params = {}

                for param in params:
                    param_layout = QHBoxLayout()
                    param_layout.addWidget(QLabel(f"{param}:"))

                    param_edit = QLineEdit()
                    param_edit.setPlaceholderText(f"Enter {param}")
                    self.template_params[param] = param_edit
                    param_layout.addWidget(param_edit)

                    self.params_layout.addLayout(param_layout)

        except Exception as e:
            self.logger.error(f"Failed to load template details: {e}")

    def clear_template_params(self):
        """Clear template parameter inputs."""
        while self.params_layout.count():
            child = self.params_layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()
            elif child.layout():
                self.clear_layout(child.layout())

    def clear_layout(self, layout):
        """Recursively clear a layout."""
        while layout.count():
            child = layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()
            elif child.layout():
                self.clear_layout(child.layout())

    def generate_payload(self):
        """Generate payload based on current configuration."""
        try:
            config = self.build_payload_config()

            if not config:
                QMessageBox.warning(self, "Warning", "Please configure payload parameters")
                return

            # Disable generate button during generation
            self.generate_btn.setEnabled(False)
            self.output_display.clear()
            self.output_display.append("Generating payload...\n")

            # Start generation thread
            self.generation_thread = PayloadGenerationThread(self.payload_engine, config)
            self.generation_thread.progress.connect(self.on_generation_progress)
            self.generation_thread.finished.connect(self.on_generation_finished)
            self.generation_thread.error.connect(self.on_generation_error)
            self.generation_thread.start()

        except Exception as e:
            self.logger.error(f"Failed to generate payload: {e}")
            QMessageBox.critical(self, "Error", f"Failed to generate payload: {e}")
            self.generate_btn.setEnabled(True)

    def build_payload_config(self) -> Dict[str, Any]:
        """Build payload configuration from UI inputs."""
        config = {}

        current_tab = self.tab_widget.currentIndex()

        if current_tab == 0:  # Template tab
            items = self.template_list.selectedItems()
            if not items:
                return None

            template_name = items[0].text()
            category = self.category_combo.currentText().lower().replace(" ", "_")

            # Get parameters
            params = {}
            for param_name, param_widget in getattr(self, 'template_params', {}).items():
                value = param_widget.text()
                if value:
                    params[param_name] = value

            config = {
                'mode': 'template',
                'category': category,
                'template_name': template_name,
                'architecture': Architecture[self.arch_combo.currentText().upper()],
                'parameters': params
            }

        elif current_tab == 1:  # Custom tab
            shellcode = self.shellcode_editor.toPlainText()
            if not shellcode:
                return None

            config = {
                'mode': 'custom',
                'payload_type': PayloadType.CUSTOM,
                'architecture': Architecture[self.custom_arch_combo.currentText().upper()],
                'shellcode': shellcode,
                'is_assembly': self.asm_radio.isChecked(),
                'null_free': self.null_free_check.isChecked(),
                'position_independent': self.position_independent_check.isChecked()
            }

        # Add encoding options
        selected_encoders = []
        for i in range(self.encoder_list.count()):
            item = self.encoder_list.item(i)
            if item.isSelected():
                selected_encoders.append(item.text())

        if selected_encoders:
            config['encoding_schemes'] = selected_encoders
            config['encoding_iterations'] = self.iterations_spin.value()

            if self.xor_key_edit.text():
                config['xor_key'] = self.xor_key_edit.text()

        # Add obfuscation options
        obfuscation = []
        if self.dead_code_check.isChecked():
            obfuscation.append('dead_code')
        if self.code_reorder_check.isChecked():
            obfuscation.append('code_reorder')
        if self.register_rename_check.isChecked():
            obfuscation.append('register_rename')
        if self.garbage_insertion_check.isChecked():
            obfuscation.append('garbage_insertion')
        if self.metamorphic_check.isChecked():
            obfuscation.append('metamorphic')

        if obfuscation:
            config['obfuscation_techniques'] = obfuscation

        # Add evasion options
        evasion = []
        if self.vm_detection_check.isChecked():
            evasion.append(EvasionTechnique.VM_DETECTION)
        if self.debugger_detection_check.isChecked():
            evasion.append(EvasionTechnique.DEBUGGER_DETECTION)
        if self.sandbox_detection_check.isChecked():
            evasion.append(EvasionTechnique.SANDBOX_DETECTION)
        if self.timing_checks_check.isChecked():
            evasion.append(EvasionTechnique.TIMING_CHECKS)
        if self.api_hooks_check.isChecked():
            evasion.append(EvasionTechnique.API_HOOK_DETECTION)

        if evasion:
            config['evasion_techniques'] = evasion

        return config

    def on_generation_progress(self, message: str):
        """Handle generation progress updates."""
        self.output_display.append(message)

    def on_generation_finished(self, result: Dict[str, Any]):
        """Handle successful payload generation."""
        try:
            self.current_payload = result
            self.generate_btn.setEnabled(True)
            self.save_btn.setEnabled(True)
            self.test_btn.setEnabled(True)

            self.output_display.append("\nPayload generated successfully!")

            # Update payload info
            import hashlib
            payload_bytes = result.get('payload', b'')

            self.size_label.setText(f"Size: {len(payload_bytes)} bytes")

            sha256 = hashlib.sha256(payload_bytes).hexdigest()
            self.hash_label.setText(f"SHA256: {sha256}")

            # Calculate entropy
            entropy = calculate_byte_entropy(payload_bytes)
            self.entropy_label.setText(f"Entropy: {entropy:.2f}")

            # Count null bytes
            null_count = payload_bytes.count(b'\x00')
            self.null_bytes_label.setText(f"Null bytes: {null_count}")

            # Display payload
            self.update_output_display()

            # Switch to output tab
            self.tab_widget.setCurrentIndex(4)

            # Emit signal
            self.payload_generated.emit(result)

        except Exception as e:
            self.logger.error(f"Error displaying generated payload: {e}")

    def on_generation_error(self, error: str):
        """Handle payload generation error."""
        self.generate_btn.setEnabled(True)
        self.output_display.append(f"\nError: {error}")
        QMessageBox.critical(self, "Generation Error", f"Failed to generate payload: {error}")

    def update_output_display(self):
        """Update payload display based on selected format."""
        if not self.current_payload:
            return

        try:
            payload_bytes = self.current_payload.get('payload', b'')
            format_type = self.output_format_combo.currentText()

            self.output_display.clear()

            if format_type == "Raw Binary":
                # Display hex dump
                hex_dump = self.create_hex_dump(payload_bytes)
                self.output_display.append(hex_dump)

            elif format_type == "C Array":
                c_array = self.format_c_array(payload_bytes)
                self.output_display.append(c_array)

            elif format_type == "Python String":
                py_string = self.format_python_string(payload_bytes)
                self.output_display.append(py_string)

            elif format_type == "PowerShell":
                ps_string = self.format_powershell(payload_bytes)
                self.output_display.append(ps_string)

            elif format_type == "Base64":
                import base64
                b64 = base64.b64encode(payload_bytes).decode('utf-8')
                self.output_display.append(b64)

            elif format_type == "Hex String":
                hex_string = payload_bytes.hex()
                self.output_display.append(hex_string)

        except Exception as e:
            self.logger.error(f"Error updating output display: {e}")

    def create_hex_dump(self, data: bytes) -> str:
        """Create hex dump of data."""
        lines = []
        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            hex_part = ' '.join(f'{b:02x}' for b in chunk)
            hex_part = hex_part.ljust(48)  # 16 * 2 + 15 spaces

            ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)

            lines.append(f"{i:08x}  {hex_part}  |{ascii_part}|")

        return '\n'.join(lines)

    def format_c_array(self, data: bytes) -> str:
        """Format payload as C array."""
        lines = ["unsigned char payload[] = {"]

        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            hex_bytes = ', '.join(f'0x{b:02x}' for b in chunk)
            if i + 16 < len(data):
                hex_bytes += ','
            lines.append(f"    {hex_bytes}")

        lines.append("};")
        lines.append(f"unsigned int payload_len = {len(data)};")

        return '\n'.join(lines)

    def format_python_string(self, data: bytes) -> str:
        """Format payload as Python string."""
        lines = ['payload = (']

        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            escaped = ''.join(f'\\x{b:02x}' for b in chunk)
            lines.append(f'    "{escaped}"')

        lines.append(')')

        return '\n'.join(lines)

    def format_powershell(self, data: bytes) -> str:
        """Format payload for PowerShell."""
        lines = ['[Byte[]] $payload = @(']

        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            hex_bytes = ', '.join(f'0x{b:02x}' for b in chunk)
            if i + 16 < len(data):
                hex_bytes += ','
            lines.append(f"    {hex_bytes}")

        lines.append(')')

        return '\n'.join(lines)


    def save_payload(self):
        """Save generated payload to file."""
        if not self.current_payload:
            return

        try:
            filename, _ = QFileDialog.getSaveFileName(
                self, "Save Payload", "",
                "Binary Files (*.bin);;Executable Files (*.exe);;DLL Files (*.dll);;All Files (*.*)"
            )

            if filename:
                payload_bytes = self.current_payload.get('payload', b'')

                with open(filename, 'wb') as f:
                    f.write(payload_bytes)

                QMessageBox.information(self, "Success", f"Payload saved to {filename}")

        except Exception as e:
            self.logger.error(f"Failed to save payload: {e}")
            QMessageBox.critical(self, "Error", f"Failed to save payload: {e}")

    def test_payload(self):
        """Test generated payload in safe environment."""
        if not self.current_payload:
            return

        QMessageBox.information(
            self, "Test Payload",
            "Payload testing should be performed in an isolated environment.\n\n"
            "Consider using:\n"
            "- Virtual machine\n"
            "- Sandbox environment\n"
            "- Dedicated testing system"
        )

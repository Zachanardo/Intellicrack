"""Plugin creation wizard for developing new Intellicrack plugins.

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
along with this program.  If not, see https://www.gnu.org/licenses/.
"""

import json
from datetime import datetime
from typing import Optional

from intellicrack.handlers.pyqt6_handler import (
    QApplication,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFont,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPushButton,
    Qt,
    QTextEdit,
    QVBoxLayout,
    QWidget,
    QWizard,
    QWizardPage,
    pyqtSignal,
)
from intellicrack.utils.logger import logger


class PluginCreationWizard(QWizard):
    """Wizard for creating new plugins with professional templates."""

    #: Emitted when plugin is created (type: dict)
    plugin_created = pyqtSignal(dict)

    def __init__(self, parent: Optional[QWidget] = None, plugin_type: str = "custom") -> None:
        """Initialize the PluginCreationWizard.

        Args:
            parent: Parent widget for the wizard dialog.
            plugin_type: Type of plugin to create ('custom', 'frida', or 'ghidra').

        """
        super().__init__(parent)
        self.plugin_type = plugin_type
        self.setWindowTitle("Plugin Creation Wizard")
        self.setMinimumSize(700, 500)

        self.info_page = PluginInfoPage()
        self.template_page = TemplateSelectionPage(plugin_type)
        self.features_page = PluginFeaturesPage()
        self.code_page = CodeGenerationPage()
        self.summary_page = SummaryPage()

        self.addPage(self.info_page)
        self.addPage(self.template_page)
        self.addPage(self.features_page)
        self.addPage(self.code_page)
        self.addPage(self.summary_page)

        self.currentIdChanged.connect(self.on_page_changed)

    def on_page_changed(self, page_id: int) -> None:
        """Handle page changes.

        Args:
            page_id: The ID of the current wizard page.

        """
        _ = page_id
        current_page = self.currentPage()

        if isinstance(current_page, CodeGenerationPage):
            self.generate_plugin_code()
        elif isinstance(current_page, SummaryPage):
            self.update_summary()

    def generate_plugin_code(self) -> None:
        """Generate plugin code based on user selections."""
        info = self.info_page.get_plugin_info()
        template = self.template_page.get_selected_template()
        features = self.features_page.get_selected_features()

        code = self.generate_code_from_template(info, template, features)
        self.code_page.set_generated_code(code)

    def generate_code_from_template(
        self,
        info: dict[str, str],
        template: Optional[dict[str, Any]],
        features: list[str],
    ) -> str:
        """Generate plugin code from template.

        Args:
            info: Plugin information dictionary containing name, version, author, etc.
            template: Selected template data or None.
            features: List of selected feature identifiers.

        Returns:
            Generated plugin code as a string.

        """
        if self.plugin_type == "frida":
            return self.generate_frida_code(info, template, features)
        if self.plugin_type == "ghidra":
            return self.generate_ghidra_code(info, template, features)
        return self.generate_python_code(info, template, features)

    def generate_python_code(
        self,
        info: dict[str, str],
        template: Optional[dict[str, Any]],
        features: list[str],
    ) -> str:
        """Generate Python plugin code.

        Args:
            info: Plugin information dictionary.
            template: Selected template data (unused for Python generation).
            features: List of selected feature identifiers.

        Returns:
            Python plugin code as a formatted string.

        """
        _ = template
        code = f'''"""
{info["name"]}
{info["description"]}

Author: {info["author"]}
Version: {info["version"]}
Created: {datetime.now().strftime("%Y-%m-%d")}
"""

import os
import sys
from typing import Any

class {info["name"].replace(" ", "")}Plugin:
    """Main plugin class for {info["name"]}"""

    def __init__(self) -> None:
        self.name = "{info["name"]}"
        self.version = "{info["version"]}"
        self.description = "{info["description"]}"
        self.author = "{info["author"]}"

    def get_metadata(self) -> dict[str, Any]:
        """Return plugin metadata"""
        return {{
            'name': self.name,
            'version': self.version,
            'description': self.description,
            'author': self.author,
            'capabilities': {features}
        }}

    def run(self, binary_path: str, options: dict[str, Any] | None = None) -> dict[str, Any]:
        """Run plugin execution method"""
        results = {{
            'status': 'success',
            'binary': binary_path,
            'findings': []
        }}

        try:
            {self._generate_feature_code(features)}

        except Exception as e:
            print(f"Exception in plugin execution: {{e}}")
            results['status'] = 'error'
            results['error'] = str(e)

        return results

def get_plugin() -> Any:
    """Return plugin instance for the system"""
    return {info["name"].replace(" ", "")}Plugin()
'''
        return code

    def generate_frida_code(
        self,
        info: dict[str, str],
        template: Optional[dict[str, Any]],
        features: list[str],
    ) -> str:
        """Generate Frida script code.

        Args:
            info: Plugin information dictionary.
            template: Selected template data (unused for Frida generation).
            features: List of selected feature identifiers.

        Returns:
            Frida JavaScript code as a formatted string.

        """
        _ = template
        code = f"""/*
 * {info["name"]}
 * {info["description"]}
 *
 * Author: {info["author"]}
 * Version: {info["version"]}
 */

const PLUGIN_INFO = {{
    name: "{info["name"]}",
    version: "{info["version"]}",
    description: "{info["description"]}"
}};

if (Process.platform === 'windows') {{
    {self._generate_frida_feature_code(features)}
}}

function log(message) {{
    console.log(`[${{PLUGIN_INFO.name}}] ${{message}}`);
}}

function hexdump(buffer, options) {{
    return hexdump(buffer, options || {{
        offset: 0,
        length: 64,
        header: true,
        ansi: true
    }});
}}
"""
        return code

    def generate_ghidra_code(
        self,
        info: dict[str, str],
        template: Optional[dict[str, Any]],
        features: list[str],
    ) -> str:
        """Generate Ghidra script code.

        Args:
            info: Plugin information dictionary.
            template: Selected template data (unused for Ghidra generation).
            features: List of selected feature identifiers.

        Returns:
            Ghidra Python code as a formatted string.

        """
        _ = template
        code = f'''# {info["name"]}
# {info["description"]}
#
# @author {info["author"]}
# @version {info["version"]}
# @category Analysis

from ghidra.app.script import GhidraScript
from ghidra.program.model.address import Address
from ghidra.program.model.listing import Function

class {info["name"].replace(" ", "")}(GhidraScript):

    def run(self) -> None:
        """Run script execution"""
        print("Running {info["name"]} v{info["version"]}")

        program = getCurrentProgram()
        if not program:
            print("No program loaded")
            return

        {self._generate_ghidra_feature_code(features)}

        print("Analysis complete")

{info["name"].replace(" ", "")}().run()
'''
        return code

    def _generate_feature_code(self, features: list[str]) -> str:
        """Generate code snippets for selected features.

        Args:
            features: List of selected feature identifiers.

        Returns:
            Python code snippets for feature implementations.

        """
        code_snippets: list[str] = []

        if "binary_analysis" in features:
            code_snippets.append("""
            with open(binary_path, 'rb') as f:
                data = f.read()
                results['findings'].append({
                    'type': 'binary_structure',
                    'details': f'File size: {len(data)} bytes'
                })""")

        if "pattern_search" in features:
            code_snippets.append("""
            patterns = [b'LICENSE', b'TRIAL', b'EXPIRED']
            for pattern in patterns:
                if pattern in data:
                    results['findings'].append({
                        'type': 'pattern_match',
                        'pattern': pattern.decode('ascii'),
                        'offset': data.find(pattern)
                    })""")

        return "\n".join(code_snippets)

    def _generate_frida_feature_code(self, features: list[str]) -> str:
        """Generate Frida code for features.

        Args:
            features: List of selected feature identifiers.

        Returns:
            Frida JavaScript code snippets for feature implementations.

        """
        code_snippets: list[str] = []

        if "function_hooking" in features:
            code_snippets.append("""
    const functions = ['IsLicensed', 'CheckLicense', 'VerifyLicense'];
    functions.forEach(funcName => {
        const addr = Module.findExportByName(null, funcName);
        if (addr) {
            Interceptor.attach(addr, {
                onEnter: function(args) {
                    log(`Called ${funcName}`);
                },
                onLeave: function(retval) {
                    log(`${funcName} returned: ${retval}`);
                    retval.replace(1);
                }
            });
        }
    });""")

        return "\n".join(code_snippets)

    def _generate_ghidra_feature_code(self, features: list[str]) -> str:
        """Generate Ghidra code for features.

        Args:
            features: List of selected feature identifiers.

        Returns:
            Ghidra Python code snippets for feature implementations.

        """
        code_snippets: list[str] = []

        if "function_analysis" in features:
            code_snippets.append("""
        function_manager = program.getFunctionManager()
        for function in function_manager.getFunctions(True):
            print(f"Function: {function.getName()} at {function.getEntryPoint()}")""")

        return "\n".join(code_snippets)

    def update_summary(self) -> None:
        """Update the summary page."""
        info = self.info_page.get_plugin_info()
        template = self.template_page.get_selected_template()
        features = self.features_page.get_selected_features()
        code = self.code_page.get_code()

        self.summary_page.update_summary(info, template, features, code)

    def accept(self) -> None:
        """Handle wizard completion."""
        plugin_data = {
            "info": self.info_page.get_plugin_info(),
            "template": self.template_page.get_selected_template(),
            "features": self.features_page.get_selected_features(),
            "code": self.code_page.get_code(),
        }

        if self.save_plugin(plugin_data):
            self.plugin_created.emit(plugin_data)
            super().accept()

    def save_plugin(self, plugin_data: dict[str, Any]) -> bool:
        """Save the plugin to disk.

        Args:
            plugin_data: Dictionary containing plugin information and code.

        Returns:
            True if plugin was saved successfully, False otherwise.

        """
        info = plugin_data["info"]
        code = plugin_data["code"]

        if self.plugin_type == "frida":
            ext = ".js"
        elif self.plugin_type == "ghidra":
            ext = ".py"
        else:
            ext = ".py"

        filename = info["name"].lower().replace(" ", "_") + ext

        save_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Plugin",
            filename,
            f"Plugin Files (*{ext})",
        )

        if save_path:
            try:
                with open(save_path, "w") as f:
                    f.write(code)

                metadata_path = save_path.replace(ext, "_metadata.json")
                with open(metadata_path, "w") as f:
                    json.dump(plugin_data["info"], f, indent=2)

                QMessageBox.information(
                    self,
                    "Success",
                    f"Plugin saved successfully to:\n{save_path}",
                )
                return True

            except Exception as e:
                logger.error("Exception in plugin_creation_wizard: %s", e)
                QMessageBox.critical(
                    self,
                    "Error",
                    f"Failed to save plugin:\n{e!s}",
                )
                return False

        return False


class PluginInfoPage(QWizardPage):
    """Page for basic plugin information."""

    def __init__(self) -> None:
        """Initialize the PluginInfoPage."""
        super().__init__()
        self.setTitle("Plugin Information")
        self.setSubTitle("Enter basic information about your plugin")

        layout = QFormLayout()

        self.name_edit = QLineEdit()
        self.name_edit.setText("")
        layout.addRow("Plugin Name:", self.name_edit)

        self.version_edit = QLineEdit("1.0.0")
        layout.addRow("Version:", self.version_edit)

        self.author_edit = QLineEdit()
        self.author_edit.setText("")
        layout.addRow("Author:", self.author_edit)

        self.description_edit = QTextEdit()
        self.description_edit.setText("")
        self.description_edit.setMaximumHeight(100)
        layout.addRow("Description:", self.description_edit)

        self.category_combo = QComboBox()
        self.category_combo.addItems(
            [
                "Analysis",
                "Exploitation",
                "Patching",
                "Protection Bypass",
                "Network",
                "Utility",
            ],
        )
        layout.addRow("Category:", self.category_combo)

        self.setLayout(layout)

        self.registerField("pluginName*", self.name_edit)
        self.registerField("pluginAuthor*", self.author_edit)

    def get_plugin_info(self) -> dict[str, str]:
        """Get the plugin information.

        Returns:
            Dictionary containing plugin name, version, author, description, and category.

        """
        return {
            "name": self.name_edit.text(),
            "version": self.version_edit.text(),
            "author": self.author_edit.text(),
            "description": self.description_edit.toPlainText(),
            "category": self.category_combo.currentText(),
        }


class TemplateSelectionPage(QWizardPage):
    """Page for selecting plugin template."""

    def __init__(self, plugin_type: str) -> None:
        """Initialize the TemplateSelectionPage.

        Args:
            plugin_type: Type of plugin ('custom', 'frida', or 'ghidra').

        """
        super().__init__()
        self.plugin_type = plugin_type
        self.setTitle("Select Template")
        self.setSubTitle("Choose a template to start with")

        layout = QVBoxLayout()

        self.template_list = QListWidget()
        self.populate_templates()

        layout.addWidget(self.template_list)

        self.description_label = QLabel()
        self.description_label.setWordWrap(True)
        self.description_label.setStyleSheet("background-color: #f0f0f0; padding: 10px;")
        layout.addWidget(self.description_label)

        self.setLayout(layout)

        self.template_list.currentItemChanged.connect(self.on_template_selected)

        if self.template_list.count() > 0:
            self.template_list.setCurrentRow(0)

    def populate_templates(self) -> None:
        """Populate template list based on plugin type."""
        templates = self.get_templates_for_type(self.plugin_type)

        for template in templates:
            item = QListWidgetItem(template["name"])
            item.setData(Qt.UserRole, template)
            self.template_list.addItem(item)

    def get_templates_for_type(self, plugin_type: str) -> list[dict[str, Any]]:
        """Get available templates for plugin type.

        Args:
            plugin_type: Type of plugin ('custom', 'frida', or 'ghidra').

        Returns:
            List of template dictionaries with name, description, and features.

        """
        if plugin_type == "frida":
            return [
                {
                    "name": "Basic Function Hooking",
                    "description": "Hook and modify function calls at runtime",
                    "features": ["function_hooking", "parameter_modification"],
                },
                {
                    "name": "License Bypass Template",
                    "description": "Template for bypassing common license checks",
                    "features": [
                        "function_hooking",
                        "return_value_modification",
                        "string_replacement",
                    ],
                },
                {
                    "name": "Anti-Debug Bypass",
                    "description": "Bypass anti-debugging protections",
                    "features": ["api_hooking", "flag_modification"],
                },
            ]
        if plugin_type == "ghidra":
            return [
                {
                    "name": "Function Analysis",
                    "description": "Analyze and annotate functions in the binary",
                    "features": ["function_analysis", "cross_references"],
                },
                {
                    "name": "String Decryption",
                    "description": "Decrypt and annotate obfuscated strings",
                    "features": ["string_analysis", "decryption"],
                },
            ]
        return [
            {
                "name": "Binary Analysis",
                "description": "Basic binary analysis and information extraction",
                "features": ["binary_analysis", "header_parsing"],
            },
            {
                "name": "Pattern Scanner",
                "description": "Search for patterns and signatures in binaries",
                "features": ["pattern_search", "signature_matching"],
            },
            {
                "name": "Patch Generator",
                "description": "Generate patches for specific binary modifications",
                "features": ["patch_generation", "binary_modification"],
            },
        ]

    def on_template_selected(self, current: Optional[QListWidgetItem], previous: Optional[QListWidgetItem]) -> None:
        """Handle template selection.

        Args:
            current: Currently selected list item.
            previous: Previously selected list item.

        """
        _ = previous
        if current:
            template = current.data(Qt.UserRole)
            self.description_label.setText(template["description"])

    def get_selected_template(self) -> Optional[dict[str, Any]]:
        """Get the selected template.

        Returns:
            Selected template dictionary or None if no selection.

        """
        current = self.template_list.currentItem()
        if current:
            return current.data(Qt.UserRole)
        return None


class PluginFeaturesPage(QWizardPage):
    """Page for selecting plugin features."""

    def __init__(self) -> None:
        """Initialize the PluginFeaturesPage."""
        super().__init__()
        self.setTitle("Plugin Features")
        self.setSubTitle("Select the features you want to include")

        layout = QVBoxLayout()

        self.feature_checks: dict[str, QCheckBox] = {}

        features = [
            ("binary_analysis", "Binary structure analysis"),
            ("pattern_search", "Pattern and signature searching"),
            ("function_hooking", "Function hooking (Frida)"),
            ("memory_modification", "Memory modification"),
            ("network_analysis", "Network traffic analysis"),
            ("encryption_detection", "Encryption and obfuscation detection"),
            ("patch_generation", "Automated patch generation"),
            ("reporting", "Generate detailed reports"),
        ]

        for feature_id, feature_name in features:
            checkbox = QCheckBox(feature_name)
            self.feature_checks[feature_id] = checkbox
            layout.addWidget(checkbox)

        advanced_group = QGroupBox("Advanced Options")
        advanced_layout = QVBoxLayout()

        self.async_check = QCheckBox("Asynchronous execution")
        self.error_handling_check = QCheckBox("Enhanced error handling")
        self.logging_check = QCheckBox("Detailed logging")

        advanced_layout.addWidget(self.async_check)
        advanced_layout.addWidget(self.error_handling_check)
        advanced_layout.addWidget(self.logging_check)

        advanced_group.setLayout(advanced_layout)
        layout.addWidget(advanced_group)

        self.setLayout(layout)

    def get_selected_features(self) -> list[str]:
        """Get list of selected features.

        Returns:
            List of selected feature identifiers.

        """
        features: list[str] = []
        for feature_id, checkbox in self.feature_checks.items():
            if checkbox.isChecked():
                features.append(feature_id)
        return features


class CodeGenerationPage(QWizardPage):
    """Page showing generated code."""

    def __init__(self) -> None:
        """Initialize the CodeGenerationPage."""
        super().__init__()
        self.setTitle("Generated Code")
        self.setSubTitle("Review and edit the generated plugin code")

        layout = QVBoxLayout()

        self.code_edit = QTextEdit()
        self.code_edit.setFont(QFont("Consolas", 10))
        layout.addWidget(self.code_edit)

        button_layout = QHBoxLayout()

        self.copy_btn = QPushButton("Copy to Clipboard")
        self.copy_btn.clicked.connect(self.copy_code)

        self.validate_btn = QPushButton("Validate Code")
        self.validate_btn.clicked.connect(self.validate_code)

        button_layout.addWidget(self.copy_btn)
        button_layout.addWidget(self.validate_btn)
        button_layout.addStretch()

        layout.addLayout(button_layout)

        self.setLayout(layout)

    def set_generated_code(self, code: str) -> None:
        """Set the generated code.

        Args:
            code: The plugin code to display.

        """
        self.code_edit.setPlainText(code)

    def get_code(self) -> str:
        """Get the current code.

        Returns:
            Current code in the editor.

        """
        return self.code_edit.toPlainText()

    def copy_code(self) -> None:
        """Copy code to clipboard."""
        clipboard = QApplication.clipboard()
        clipboard.setText(self.code_edit.toPlainText())
        QMessageBox.information(self, "Copied", "Code copied to clipboard!")

    def validate_code(self) -> None:
        """Validate the plugin code."""
        code = self.code_edit.toPlainText()

        try:
            if code.strip().startswith("/*"):
                QMessageBox.information(
                    self,
                    "Validation",
                    "JavaScript syntax validation not implemented.\nPlease test in Frida.",
                )
            else:
                compile(code, "<plugin>", "exec")
                QMessageBox.information(
                    self,
                    "Validation Passed",
                    "Python syntax is valid!",
                )
        except SyntaxError as e:
            logger.error("SyntaxError in plugin_creation_wizard: %s", e)
            QMessageBox.warning(
                self,
                "Syntax Error",
                f"Line {e.lineno}: {e.msg}",
            )


class SummaryPage(QWizardPage):
    """Summary page showing all selections."""

    def __init__(self) -> None:
        """Initialize the SummaryPage."""
        super().__init__()
        self.setTitle("Summary")
        self.setSubTitle("Review your plugin configuration")

        layout = QVBoxLayout()

        self.summary_text = QTextEdit()
        self.summary_text.setReadOnly(True)
        layout.addWidget(self.summary_text)

        self.setLayout(layout)

    def update_summary(self, info: dict[str, str], template: Optional[dict[str, Any]], features: list[str], code: str) -> None:
        """Update the summary display.

        Args:
            info: Plugin information dictionary.
            template: Selected template dictionary or None.
            features: List of selected features.
            code: Generated plugin code.

        """
        summary = f"""
<h3>Plugin Summary</h3>
<p><b>Name:</b> {info["name"]}<br>
<b>Version:</b> {info["version"]}<br>
<b>Author:</b> {info["author"]}<br>
<b>Category:</b> {info["category"]}</p>

<p><b>Description:</b><br>
{info["description"]}</p>

<p><b>Template:</b> {template["name"] if template else "None"}</p>

<p><b>Features:</b><br>
{"<br>".join(" " + f for f in features) if features else "None selected"}</p>

<p><b>Code Preview:</b><br>
<pre>{code[:500]}...</pre></p>
"""
        self.summary_text.setHtml(summary)

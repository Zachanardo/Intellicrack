import json
from datetime import datetime

from PyQt5.QtCore import Qt, pyqtSignal

# Import missing class
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QWizard,
    QWizardPage,
)

from intellicrack.logger import logger

"""
Plugin Creation Wizard for Intellicrack.

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




class PluginCreationWizard(QWizard):
    """Wizard for creating new plugins with professional templates"""

    plugin_created = pyqtSignal(dict)  # Emitted when plugin is created

    def __init__(self, parent=None, plugin_type="custom"):
        super().__init__(parent)
        self.plugin_type = plugin_type
        self.setWindowTitle("Plugin Creation Wizard")
        self.setMinimumSize(700, 500)

        # Wizard pages
        self.info_page = PluginInfoPage()
        self.template_page = TemplateSelectionPage(plugin_type)
        self.features_page = PluginFeaturesPage()
        self.code_page = CodeGenerationPage()
        self.summary_page = SummaryPage()

        # Add pages
        self.addPage(self.info_page)
        self.addPage(self.template_page)
        self.addPage(self.features_page)
        self.addPage(self.code_page)
        self.addPage(self.summary_page)

        # Connect signals
        self.currentIdChanged.connect(self.on_page_changed)

    def on_page_changed(self, page_id):
        """Handle page changes"""
        _ = page_id
        current_page = self.currentPage()

        if isinstance(current_page, CodeGenerationPage):
            # Generate code based on previous selections
            self.generate_plugin_code()
        elif isinstance(current_page, SummaryPage):
            # Update summary
            self.update_summary()

    def generate_plugin_code(self):
        """Generate plugin code based on user selections"""
        info = self.info_page.get_plugin_info()
        template = self.template_page.get_selected_template()
        features = self.features_page.get_selected_features()

        # Generate code based on template and features
        code = self.generate_code_from_template(info, template, features)
        self.code_page.set_generated_code(code)

    def generate_code_from_template(self, info, template, features):
        """Generate plugin code from template"""
        if self.plugin_type == "frida":
            return self.generate_frida_code(info, template, features)
        elif self.plugin_type == "ghidra":
            return self.generate_ghidra_code(info, template, features)
        else:
            return self.generate_python_code(info, template, features)

    def generate_python_code(self, info, template, features):
        """Generate Python plugin code"""
        _ = template
        code = f'''"""
{info['name']}
{info['description']}

Author: {info['author']}
Version: {info['version']}
Created: {datetime.now().strftime('%Y-%m-%d')}
"""

import os
import sys
from typing import Dict, Any, List

class {info['name'].replace(' ', '')}Plugin:
    """Main plugin class for {info['name']}"""

    def __init__(self):
        self.name = "{info['name']}"
        self.version = "{info['version']}"
        self.description = "{info['description']}"
        self.author = "{info['author']}"

    def get_metadata(self) -> Dict[str, Any]:
        """Return plugin metadata"""
        return {{
            'name': self.name,
            'version': self.version,
            'description': self.description,
            'author': self.author,
            'capabilities': {features}
        }}

    def run(self, binary_path: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """Main plugin execution method"""
        results = {{
            'status': 'success',
            'binary': binary_path,
            'findings': []
        }}

        try:
            # Plugin logic here
            {self._generate_feature_code(features)}

        except Exception as e:
            self.logger.error("Exception in plugin_creation_wizard: %s", e)
            results['status'] = 'error'
            results['error'] = str(e)

        return results

# Plugin registration
def get_plugin():
    """Return plugin instance for the system"""
    return {info['name'].replace(' ', '')}Plugin()
'''
        return code

    def generate_frida_code(self, info, template, features):
        """Generate Frida script code"""
        _ = template
        code = f'''/*
 * {info['name']}
 * {info['description']}
 *
 * Author: {info['author']}
 * Version: {info['version']}
 */

// Plugin metadata
const PLUGIN_INFO = {{
    name: "{info['name']}",
    version: "{info['version']}",
    description: "{info['description']}"
}};

// Main instrumentation logic
if (Process.platform === 'windows') {{
    {self._generate_frida_feature_code(features)}
}}

// Helper functions
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
'''
        return code

    def generate_ghidra_code(self, info, template, features):
        """Generate Ghidra script code"""
        _ = template
        code = f'''# {info['name']}
# {info['description']}
#
# @author {info['author']}
# @version {info['version']}
# @category Analysis

from ghidra.app.script import GhidraScript
from ghidra.program.model.address import Address
from ghidra.program.model.listing import Function

class {info['name'].replace(' ', '')}(GhidraScript):

    def run(self):
        """Main script execution"""
        print("Running {info['name']} v{info['version']}")

        # Get current program
        program = getCurrentProgram()
        if not program:
            print("No program loaded")
            return

        {self._generate_ghidra_feature_code(features)}

        print("Analysis complete")

# Script entry point
{info['name'].replace(' ', '')}().run()
'''
        return code

    def _generate_feature_code(self, features):
        """Generate code snippets for selected features"""
        code_snippets = []

        if 'binary_analysis' in features:
            code_snippets.append("""
            # Analyze binary structure
            with open(binary_path, 'rb') as f:
                data = f.read()
                # Perform analysis
                results['findings'].append({
                    'type': 'binary_structure',
                    'details': f'File size: {len(data)} bytes'
                })""")

        if 'pattern_search' in features:
            code_snippets.append("""
            # Search for patterns
            patterns = [b'LICENSE', b'TRIAL', b'EXPIRED']
            for pattern in patterns:
                if pattern in data:
                    results['findings'].append({
                        'type': 'pattern_match',
                        'pattern': pattern.decode('ascii'),
                        'offset': data.find(pattern)
                    })""")

        return '\n'.join(code_snippets)

    def _generate_frida_feature_code(self, features):
        """Generate Frida code for features"""
        code_snippets = []

        if 'function_hooking' in features:
            code_snippets.append("""
    // Hook common license check functions
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
                    retval.replace(1); // Force success
                }
            });
        }
    });""")

        return '\n'.join(code_snippets)

    def _generate_ghidra_feature_code(self, features):
        """Generate Ghidra code for features"""
        code_snippets = []

        if 'function_analysis' in features:
            code_snippets.append("""
        # Analyze all functions
        function_manager = program.getFunctionManager()
        for function in function_manager.getFunctions(True):
            print(f"Function: {function.getName()} at {function.getEntryPoint()}")""")

        return '\n'.join(code_snippets)

    def update_summary(self):
        """Update the summary page"""
        info = self.info_page.get_plugin_info()
        template = self.template_page.get_selected_template()
        features = self.features_page.get_selected_features()
        code = self.code_page.get_code()

        self.summary_page.update_summary(info, template, features, code)

    def accept(self):
        """Handle wizard completion"""
        # Get all plugin data
        plugin_data = {
            'info': self.info_page.get_plugin_info(),
            'template': self.template_page.get_selected_template(),
            'features': self.features_page.get_selected_features(),
            'code': self.code_page.get_code()
        }

        # Save the plugin
        if self.save_plugin(plugin_data):
            self.plugin_created.emit(plugin_data)
            super().accept()

    def save_plugin(self, plugin_data):
        """Save the plugin to disk"""
        info = plugin_data['info']
        code = plugin_data['code']

        # Determine file extension
        if self.plugin_type == "frida":
            ext = ".js"
        elif self.plugin_type == "ghidra":
            ext = ".py"
        else:
            ext = ".py"

        # Generate filename
        filename = info['name'].lower().replace(' ', '_') + ext

        # Ask user for save location
        save_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Plugin",
            filename,
            f"Plugin Files (*{ext})"
        )

        if save_path:
            try:
                with open(save_path, 'w') as f:
                    f.write(code)

                # Save metadata
                metadata_path = save_path.replace(ext, '_metadata.json')
                with open(metadata_path, 'w') as f:
                    json.dump(plugin_data['info'], f, indent=2)

                QMessageBox.information(
                    self,
                    "Success",
                    f"Plugin saved successfully to:\n{save_path}"
                )
                return True

            except Exception as e:
                logger.error("Exception in plugin_creation_wizard: %s", e)
                QMessageBox.critical(
                    self,
                    "Error",
                    f"Failed to save plugin:\n{str(e)}"
                )
                return False

        return False


class PluginInfoPage(QWizardPage):
    """Page for basic plugin information"""

    def __init__(self):
        super().__init__()
        self.setTitle("Plugin Information")
        self.setSubTitle("Enter basic information about your plugin")

        layout = QFormLayout()

        # Plugin name
        self.name_edit = QLineEdit()
        self.name_edit.setPlaceholderText("e.g., Advanced License Bypasser")
        layout.addRow("Plugin Name:", self.name_edit)

        # Version
        self.version_edit = QLineEdit("1.0.0")
        layout.addRow("Version:", self.version_edit)

        # Author
        self.author_edit = QLineEdit()
        self.author_edit.setPlaceholderText("Your name")
        layout.addRow("Author:", self.author_edit)

        # Description
        self.description_edit = QTextEdit()
        self.description_edit.setPlaceholderText("Describe what your plugin does...")
        self.description_edit.setMaximumHeight(100)
        layout.addRow("Description:", self.description_edit)

        # Category
        self.category_combo = QComboBox()
        self.category_combo.addItems([
            "Analysis", "Exploitation", "Patching",
            "Protection Bypass", "Network", "Utility"
        ])
        layout.addRow("Category:", self.category_combo)

        self.setLayout(layout)

        # Register fields for validation
        self.registerField("pluginName*", self.name_edit)
        self.registerField("pluginAuthor*", self.author_edit)

    def get_plugin_info(self):
        """Get the plugin information"""
        return {
            'name': self.name_edit.text(),
            'version': self.version_edit.text(),
            'author': self.author_edit.text(),
            'description': self.description_edit.toPlainText(),
            'category': self.category_combo.currentText()
        }


class TemplateSelectionPage(QWizardPage):
    """Page for selecting plugin template"""

    def __init__(self, plugin_type):
        super().__init__()
        self.plugin_type = plugin_type
        self.setTitle("Select Template")
        self.setSubTitle("Choose a template to start with")

        layout = QVBoxLayout()

        # Template list
        self.template_list = QListWidget()
        self.populate_templates()

        layout.addWidget(self.template_list)

        # Template description
        self.description_label = QLabel()
        self.description_label.setWordWrap(True)
        self.description_label.setStyleSheet("background-color: #f0f0f0; padding: 10px;")
        layout.addWidget(self.description_label)

        self.setLayout(layout)

        # Connect signals
        self.template_list.currentItemChanged.connect(self.on_template_selected)

        # Select first template
        if self.template_list.count() > 0:
            self.template_list.setCurrentRow(0)

    def populate_templates(self):
        """Populate template list based on plugin type"""
        templates = self.get_templates_for_type(self.plugin_type)

        for template in templates:
            item = QListWidgetItem(template['name'])
            item.setData(Qt.UserRole, template)
            self.template_list.addItem(item)

    def get_templates_for_type(self, plugin_type):
        """Get available templates for plugin type"""
        if plugin_type == "frida":
            return [
                {
                    'name': 'Basic Function Hooking',
                    'description': 'Hook and modify function calls at runtime',
                    'features': ['function_hooking', 'parameter_modification']
                },
                {
                    'name': 'License Bypass Template',
                    'description': 'Template for bypassing common license checks',
                    'features': ['function_hooking', 'return_value_modification', 'string_replacement']
                },
                {
                    'name': 'Anti-Debug Bypass',
                    'description': 'Bypass anti-debugging protections',
                    'features': ['api_hooking', 'flag_modification']
                }
            ]
        elif plugin_type == "ghidra":
            return [
                {
                    'name': 'Function Analysis',
                    'description': 'Analyze and annotate functions in the binary',
                    'features': ['function_analysis', 'cross_references']
                },
                {
                    'name': 'String Decryption',
                    'description': 'Decrypt and annotate obfuscated strings',
                    'features': ['string_analysis', 'decryption']
                }
            ]
        else:
            return [
                {
                    'name': 'Binary Analysis',
                    'description': 'Basic binary analysis and information extraction',
                    'features': ['binary_analysis', 'header_parsing']
                },
                {
                    'name': 'Pattern Scanner',
                    'description': 'Search for patterns and signatures in binaries',
                    'features': ['pattern_search', 'signature_matching']
                },
                {
                    'name': 'Patch Generator',
                    'description': 'Generate patches for specific binary modifications',
                    'features': ['patch_generation', 'binary_modification']
                }
            ]

    def on_template_selected(self, current, previous):
        """Handle template selection"""
        _ = previous
        if current:
            template = current.data(Qt.UserRole)
            self.description_label.setText(template['description'])

    def get_selected_template(self):
        """Get the selected template"""
        current = self.template_list.currentItem()
        if current:
            return current.data(Qt.UserRole)
        return None


class PluginFeaturesPage(QWizardPage):
    """Page for selecting plugin features"""

    def __init__(self):
        super().__init__()
        self.setTitle("Plugin Features")
        self.setSubTitle("Select the features you want to include")

        layout = QVBoxLayout()

        # Feature checkboxes
        self.feature_checks = {}

        features = [
            ('binary_analysis', 'Binary structure analysis'),
            ('pattern_search', 'Pattern and signature searching'),
            ('function_hooking', 'Function hooking (Frida)'),
            ('memory_modification', 'Memory modification'),
            ('network_analysis', 'Network traffic analysis'),
            ('encryption_detection', 'Encryption/obfuscation detection'),
            ('patch_generation', 'Automated patch generation'),
            ('reporting', 'Generate detailed reports')
        ]

        for feature_id, feature_name in features:
            checkbox = QCheckBox(feature_name)
            self.feature_checks[feature_id] = checkbox
            layout.addWidget(checkbox)

        # Advanced options
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

    def get_selected_features(self):
        """Get list of selected features"""
        features = []
        for feature_id, checkbox in self.feature_checks.items():
            if checkbox.isChecked():
                features.append(feature_id)
        return features


class CodeGenerationPage(QWizardPage):
    """Page showing generated code"""

    def __init__(self):
        super().__init__()
        self.setTitle("Generated Code")
        self.setSubTitle("Review and edit the generated plugin code")

        layout = QVBoxLayout()

        # Code editor
        self.code_edit = QTextEdit()
        self.code_edit.setFont(QFont("Consolas", 10))
        layout.addWidget(self.code_edit)

        # Action buttons
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

    def set_generated_code(self, code):
        """Set the generated code"""
        self.code_edit.setPlainText(code)

    def get_code(self):
        """Get the current code"""
        return self.code_edit.toPlainText()

    def copy_code(self):
        """Copy code to clipboard"""
        clipboard = QApplication.clipboard()
        clipboard.setText(self.code_edit.toPlainText())
        QMessageBox.information(self, "Copied", "Code copied to clipboard!")

    def validate_code(self):
        """Validate the plugin code"""
        code = self.code_edit.toPlainText()

        try:
            # Basic syntax check for Python
            if code.strip().startswith('/*'):
                # JavaScript/Frida code
                QMessageBox.information(
                    self,
                    "Validation",
                    "JavaScript syntax validation not implemented.\nPlease test in Frida."
                )
            else:
                # Python code
                compile(code, '<plugin>', 'exec')
                QMessageBox.information(
                    self,
                    "Validation Passed",
                    "Python syntax is valid!"
                )
        except SyntaxError as e:
            logger.error("SyntaxError in plugin_creation_wizard: %s", e)
            QMessageBox.warning(
                self,
                "Syntax Error",
                f"Line {e.lineno}: {e.msg}"
            )


class SummaryPage(QWizardPage):
    """Summary page showing all selections"""

    def __init__(self):
        super().__init__()
        self.setTitle("Summary")
        self.setSubTitle("Review your plugin configuration")

        layout = QVBoxLayout()

        self.summary_text = QTextEdit()
        self.summary_text.setReadOnly(True)
        layout.addWidget(self.summary_text)

        self.setLayout(layout)

    def update_summary(self, info, template, features, code):
        """Update the summary display"""
        summary = f"""
<h3>Plugin Summary</h3>
<p><b>Name:</b> {info['name']}<br>
<b>Version:</b> {info['version']}<br>
<b>Author:</b> {info['author']}<br>
<b>Category:</b> {info['category']}</p>

<p><b>Description:</b><br>
{info['description']}</p>

<p><b>Template:</b> {template['name'] if template else 'None'}</p>

<p><b>Features:</b><br>
{'<br>'.join('• ' + f for f in features) if features else 'None selected'}</p>

<p><b>Code Preview:</b><br>
<pre>{code[:500]}...</pre></p>
"""
        self.summary_text.setHtml(summary)

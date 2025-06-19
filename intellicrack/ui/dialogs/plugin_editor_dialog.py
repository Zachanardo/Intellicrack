"""
Plugin Editor Dialog for Intellicrack.

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

import os
import subprocess
import sys

from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QPushButton,
    QDialogButtonBox, QMessageBox, QTabWidget,
    QTextEdit, QLabel, QGroupBox, QSplitter,
    QLineEdit, QCheckBox, QListWidget, QTextBrowser, QWidget
)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal, QProcess
from PyQt5.QtGui import QFont

from ..widgets.plugin_editor import PluginEditor


class PluginEditorDialog(QDialog):
    """Enhanced plugin editor dialog with testing capabilities"""
    
    plugin_saved = pyqtSignal(str)  # Emitted when plugin is saved
    
    def __init__(self, parent=None, plugin_path=None):
        super().__init__(parent)
        self.plugin_path = plugin_path
        self.test_process = None
        self.setWindowTitle("Plugin Editor")
        self.setMinimumSize(1000, 700)
        self.setup_ui()
        
        # Load plugin if path provided
        if plugin_path and os.path.exists(plugin_path):
            self.load_plugin(plugin_path)
    
    def setup_ui(self):
        """Set up the dialog UI"""
        layout = QVBoxLayout(self)
        
        # Create tab widget
        self.tab_widget = QTabWidget()
        
        # Editor tab
        self.editor = PluginEditor()
        self.editor.saveRequested.connect(self.on_plugin_saved)
        self.editor.validationComplete.connect(self.on_validation_complete)
        self.tab_widget.addTab(self.editor, "📝 Editor")
        
        # Testing tab
        self.test_widget = QWidget()
        self.setup_test_tab()
        self.tab_widget.addTab(self.test_widget, "🧪 Testing")
        
        # Documentation tab
        self.docs_widget = QWidget()
        self.setup_docs_tab()
        self.tab_widget.addTab(self.docs_widget, "📚 Documentation")
        
        layout.addWidget(self.tab_widget)
        
        # Bottom buttons
        button_layout = QHBoxLayout()
        
        self.run_btn = QPushButton("▶️ Run Plugin")
        self.run_btn.clicked.connect(self.run_plugin)
        button_layout.addWidget(self.run_btn)
        
        self.debug_btn = QPushButton("🐛 Debug")
        self.debug_btn.clicked.connect(self.debug_plugin)
        button_layout.addWidget(self.debug_btn)
        
        self.test_gen_btn = QPushButton("🧪 Generate Tests")
        self.test_gen_btn.clicked.connect(self.generate_tests)
        button_layout.addWidget(self.test_gen_btn)
        
        self.ci_cd_btn = QPushButton("🚀 CI/CD Pipeline")
        self.ci_cd_btn.clicked.connect(self.open_ci_cd)
        button_layout.addWidget(self.ci_cd_btn)
        
        button_layout.addStretch()
        
        # Dialog buttons
        buttons = QDialogButtonBox(
            QDialogButtonBox.Save | QDialogButtonBox.Close
        )
        buttons.button(QDialogButtonBox.Save).clicked.connect(self.save_plugin)
        buttons.rejected.connect(self.reject)
        button_layout.addWidget(buttons)
        
        layout.addLayout(button_layout)
    
    def setup_test_tab(self):
        """Set up the testing tab"""
        layout = QVBoxLayout(self.test_widget)
        
        # Test configuration
        config_group = QGroupBox("Test Configuration")
        config_layout = QVBoxLayout(config_group)
        
        # Test file selector
        file_layout = QHBoxLayout()
        file_layout.addWidget(QLabel("Test Binary:"))
        self.test_file_edit = QLineEdit()
        self.test_file_edit.setPlaceholderText("Select a binary to test with...")
        file_layout.addWidget(self.test_file_edit)
        
        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(self.browse_test_file)
        file_layout.addWidget(browse_btn)
        
        config_layout.addLayout(file_layout)
        
        # Test options
        self.verbose_check = QCheckBox("Verbose output")
        self.verbose_check.setChecked(True)
        config_layout.addWidget(self.verbose_check)
        
        layout.addWidget(config_group)
        
        # Test output
        output_group = QGroupBox("Test Output")
        output_layout = QVBoxLayout(output_group)
        
        self.test_output = QTextEdit()
        self.test_output.setReadOnly(True)
        self.test_output.setFont(QFont("Consolas", 9))
        output_layout.addWidget(self.test_output)
        
        # Test controls
        control_layout = QHBoxLayout()
        
        self.run_test_btn = QPushButton("▶️ Run Test")
        self.run_test_btn.clicked.connect(self.run_test)
        control_layout.addWidget(self.run_test_btn)
        
        self.stop_test_btn = QPushButton("⏹️ Stop")
        self.stop_test_btn.setEnabled(False)
        self.stop_test_btn.clicked.connect(self.stop_test)
        control_layout.addWidget(self.stop_test_btn)
        
        self.clear_btn = QPushButton("🗑️ Clear")
        self.clear_btn.clicked.connect(self.test_output.clear)
        control_layout.addWidget(self.clear_btn)
        
        control_layout.addStretch()
        
        output_layout.addLayout(control_layout)
        layout.addWidget(output_group)
    
    def setup_docs_tab(self):
        """Set up the documentation tab"""
        layout = QVBoxLayout(self.docs_widget)
        
        # Create splitter
        splitter = QSplitter(Qt.Horizontal)
        
        # API Reference
        api_group = QGroupBox("API Reference")
        api_layout = QVBoxLayout(api_group)
        
        self.api_list = QListWidget()
        self.api_list.addItems([
            "Plugin Base Class",
            "Binary Analysis API",
            "Patching API",
            "Network API",
            "Frida API",
            "Ghidra API"
        ])
        self.api_list.currentItemChanged.connect(self.show_api_docs)
        api_layout.addWidget(self.api_list)
        
        splitter.addWidget(api_group)
        
        # Documentation viewer
        self.docs_viewer = QTextBrowser()
        self.docs_viewer.setOpenExternalLinks(True)
        splitter.addWidget(self.docs_viewer)
        
        splitter.setSizes([200, 600])
        layout.addWidget(splitter)
        
        # Show initial docs
        if self.api_list.count() > 0:
            self.api_list.setCurrentRow(0)
    
    def show_api_docs(self, current, previous):
        """Show API documentation"""
        if not current:
            return
        
        topic = current.text()
        docs = self.get_api_documentation(topic)
        self.docs_viewer.setHtml(docs)
    
    def get_api_documentation(self, topic):
        """Get API documentation for topic"""
        docs = {
            "Plugin Base Class": """
                <h2>Plugin Base Class</h2>
                <p>All plugins should inherit from the base plugin class or implement the required interface.</p>
                
                <h3>Required Methods</h3>
                <pre>
def run(self, binary_path: str, options: dict = None) -> dict:
    '''Main plugin execution method'''
    pass

def get_metadata(self) -> dict:
    '''Return plugin metadata'''
    return {
        'name': 'Plugin Name',
        'version': '1.0',
        'description': 'Plugin description',
        'author': 'Your Name'
    }
                </pre>
                
                <h3>Example Plugin</h3>
                <pre>
class MyPlugin:
    def __init__(self):
        self.name = "My Plugin"
        
    def run(self, binary_path, options=None):
        # Plugin logic here
        return {'status': 'success', 'results': []}
                </pre>
            """,
            
            "Binary Analysis API": """
                <h2>Binary Analysis API</h2>
                <p>APIs for analyzing binary files.</p>
                
                <h3>Available Functions</h3>
                <ul>
                    <li><code>analyze_binary(path)</code> - Analyze binary structure</li>
                    <li><code>get_imports(path)</code> - Get imported functions</li>
                    <li><code>get_exports(path)</code> - Get exported functions</li>
                    <li><code>find_strings(path)</code> - Extract strings</li>
                </ul>
                
                <h3>Example Usage</h3>
                <pre>
from intellicrack.utils import analyze_binary

def run(self, binary_path, options=None):
    analysis = analyze_binary(binary_path)
    imports = analysis.get('imports', [])
    
    for imp in imports:
        if 'license' in imp.lower():
            print(f"Found license import: {imp}")
                </pre>
            """,
            
            "Frida API": """
                <h2>Frida API</h2>
                <p>APIs for runtime instrumentation with Frida.</p>
                
                <h3>Common Patterns</h3>
                
                <h4>Function Hooking</h4>
                <pre>
Interceptor.attach(Module.findExportByName(null, 'IsLicensed'), {
    onEnter: function(args) {
        console.log('IsLicensed called');
    },
    onLeave: function(retval) {
        console.log('Original return:', retval);
        retval.replace(1);  // Force true
    }
});
                </pre>
                
                <h4>Memory Searching</h4>
                <pre>
Process.enumerateModules().forEach(function(module) {
    Memory.scan(module.base, module.size, '48 8B ?? ?? ?? ?? ??', {
        onMatch: function(address, size) {
            console.log('Pattern found at:', address);
        }
    });
});
                </pre>
            """
        }
        
        return docs.get(topic, f"<h2>{topic}</h2><p>Documentation not available yet.</p>")
    
    def load_plugin(self, path):
        """Load a plugin file"""
        self.plugin_path = path
        try:
            with open(path, 'r') as f:
                content = f.read()
            self.editor.set_code(content)
            self.editor.current_file = path
            self.setWindowTitle(f"Plugin Editor - {os.path.basename(path)}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load plugin:\n{str(e)}")
    
    def save_plugin(self):
        """Save the plugin"""
        self.editor.save_file()
    
    def on_plugin_saved(self, path):
        """Handle plugin saved"""
        self.plugin_saved.emit(path)
        QMessageBox.information(self, "Saved", "Plugin saved successfully!")
    
    def on_validation_complete(self, results):
        """Handle validation results"""
        if results['valid']:
            self.run_btn.setEnabled(True)
            self.run_btn.setToolTip("Plugin is valid and ready to run")
        else:
            self.run_btn.setEnabled(False)
            self.run_btn.setToolTip("Fix validation errors before running")
    
    def browse_test_file(self):
        """Browse for test file"""
        from PyQt5.QtWidgets import QFileDialog
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Test Binary",
            "", "Executable Files (*.exe *.dll *.so);;All Files (*.*)"
        )
        if file_path:
            self.test_file_edit.setText(file_path)
    
    def run_plugin(self):
        """Run the plugin"""
        # Save first
        self.editor.save_file()
        
        if not self.editor.current_file:
            return
        
        # Switch to test tab
        self.tab_widget.setCurrentWidget(self.test_widget)
        
        # Run test
        self.run_test()
    
    def debug_plugin(self):
        """Debug the plugin"""
        if not self.editor.current_file:
            QMessageBox.warning(self, "No Plugin", "Please save the plugin first.")
            return
        
        try:
            from .debugger_dialog import DebuggerDialog
            
            debugger_dialog = DebuggerDialog(self, self.editor.current_file)
            debugger_dialog.exec_()
            
        except ImportError:
            QMessageBox.warning(
                self, "Not Available",
                "Debugger not available.\nPlease check installation."
            )
    
    def run_test(self):
        """Run plugin test"""
        if not self.editor.current_file:
            QMessageBox.warning(self, "No Plugin", "Please save the plugin first.")
            return
        
        test_file = self.test_file_edit.text()
        if not test_file:
            QMessageBox.warning(self, "No Test File", "Please select a test binary.")
            return
        
        # Clear output
        self.test_output.clear()
        self.test_output.append("Starting plugin test...\n")
        
        # Prepare command
        cmd = [sys.executable, "-u", self.editor.current_file, test_file]
        
        # Create process
        self.test_process = QProcess(self)
        self.test_process.readyReadStandardOutput.connect(self.handle_stdout)
        self.test_process.readyReadStandardError.connect(self.handle_stderr)
        self.test_process.finished.connect(self.test_finished)
        
        # Start process
        self.test_process.start(cmd[0], cmd[1:])
        
        # Update UI
        self.run_test_btn.setEnabled(False)
        self.stop_test_btn.setEnabled(True)
    
    def stop_test(self):
        """Stop running test"""
        if self.test_process:
            self.test_process.terminate()
            QTimer.singleShot(2000, self.test_process.kill)  # Force kill after 2s
    
    def handle_stdout(self):
        """Handle stdout from test process"""
        if self.test_process:
            data = self.test_process.readAllStandardOutput()
            text = data.data().decode('utf-8', errors='replace')
            self.test_output.append(text)
    
    def handle_stderr(self):
        """Handle stderr from test process"""
        if self.test_process:
            data = self.test_process.readAllStandardError()
            text = data.data().decode('utf-8', errors='replace')
            self.test_output.append(f"<span style='color: red;'>{text}</span>")
    
    def test_finished(self, exit_code, exit_status):
        """Handle test process finished"""
        self.test_output.append(f"\nTest finished with exit code: {exit_code}")
        
        # Update UI
        self.run_test_btn.setEnabled(True)
        self.stop_test_btn.setEnabled(False)
        
        # Clean up
        self.test_process = None
    
    def generate_tests(self):
        """Open test generator for current plugin"""
        if not self.editor.current_file:
            QMessageBox.warning(self, "No Plugin", "Please save the plugin first.")
            return
        
        try:
            from .test_generator_dialog import TestGeneratorDialog
            
            test_dialog = TestGeneratorDialog(self, self.editor.current_file)
            test_dialog.exec_()
            
        except ImportError:
            QMessageBox.warning(
                self, "Not Available",
                "Test generator not available.\nPlease check installation."
            )
    
    def open_ci_cd(self):
        """Open CI/CD pipeline dialog"""
        if not self.editor.current_file:
            QMessageBox.warning(self, "No Plugin", "Please save the plugin first.")
            return
        
        try:
            from .ci_cd_dialog import CICDDialog
            
            ci_cd_dialog = CICDDialog(self, self.editor.current_file)
            ci_cd_dialog.exec_()
            
        except ImportError:
            QMessageBox.warning(
                self, "Not Available",
                "CI/CD pipeline not available.\nPlease check installation."
            )
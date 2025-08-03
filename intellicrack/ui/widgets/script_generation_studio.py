"""
Script Generation Studio

Comprehensive script development environment with AIScriptGenerator integration,
live preview, multi-language support, and advanced editing capabilities.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import json
import os
import re
import time
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple

from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QThread, QRegularExpression
from PyQt6.QtGui import (
    QFont, QSyntaxHighlighter, QTextCharFormat, QColor, QPalette,
    QFontMetrics, QIcon, QPixmap, QTextCursor, QKeySequence
)
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QProgressBar,
    QGroupBox, QTabWidget, QTextEdit, QPushButton, QComboBox,
    QSpinBox, QSlider, QCheckBox, QSplitter, QTreeWidget,
    QTreeWidgetItem, QTableWidget, QTableWidgetItem, QLineEdit,
    QFileDialog, QMessageBox, QFrame, QScrollArea, QGridLayout,
    QListWidget, QListWidgetItem, QFormLayout, QPlainTextEdit,
    QHeaderView, QMenu, QAction, QShortcut
)

from ...ai.ai_script_generator import AIScriptGenerator, ScriptType, ProtectionType
from ...utils.logger import get_logger

logger = get_logger(__name__)


class SyntaxHighlighter(QSyntaxHighlighter):
    """Syntax highlighter for various script languages."""
    
    def __init__(self, language, parent=None):
        super().__init__(parent)
        self.language = language.lower()
        self.highlighting_rules = []
        
        # Define formatting styles
        self.keyword_format = QTextCharFormat()
        self.keyword_format.setColor(QColor(86, 156, 214))
        self.keyword_format.setFontWeight(QFont.Weight.Bold)
        
        self.string_format = QTextCharFormat()
        self.string_format.setColor(QColor(206, 145, 120))
        
        self.comment_format = QTextCharFormat()
        self.comment_format.setColor(QColor(106, 153, 85))
        self.comment_format.setFontItalic(True)
        
        self.number_format = QTextCharFormat()
        self.number_format.setColor(QColor(181, 206, 168))
        
        self.function_format = QTextCharFormat()
        self.function_format.setColor(QColor(220, 220, 170))
        
        self.setup_highlighting_rules()
        
    def setup_highlighting_rules(self):
        """Setup highlighting rules for the current language."""
        if self.language == "javascript":
            # JavaScript keywords
            keywords = [
                'break', 'case', 'catch', 'continue', 'debugger', 'default',
                'delete', 'do', 'else', 'finally', 'for', 'function', 'if',
                'in', 'instanceof', 'new', 'return', 'switch', 'this', 'throw',
                'try', 'typeof', 'var', 'void', 'while', 'with', 'let', 'const',
                'class', 'extends', 'import', 'export', 'from', 'async', 'await'
            ]
            
            # Frida-specific keywords
            frida_keywords = [
                'Java', 'ObjC', 'Module', 'Memory', 'Interceptor', 'Process',
                'Thread', 'NativeFunction', 'NativeCallback', 'ptr', 'NULL'
            ]
            
            keywords.extend(frida_keywords)
            
        elif self.language == "python":
            keywords = [
                'and', 'as', 'assert', 'break', 'class', 'continue', 'def',
                'del', 'elif', 'else', 'except', 'exec', 'finally', 'for',
                'from', 'global', 'if', 'import', 'in', 'is', 'lambda',
                'not', 'or', 'pass', 'print', 'raise', 'return', 'try',
                'while', 'with', 'yield', 'async', 'await'
            ]
            
            # Ghidra-specific keywords
            ghidra_keywords = [
                'currentProgram', 'currentAddress', 'currentLocation',
                'getSymbolTable', 'getFunctionManager', 'getBookmarkManager',
                'createFunction', 'createBookmark', 'monitor', 'state'
            ]
            
            keywords.extend(ghidra_keywords)
            
        elif self.language == "java":
            keywords = [
                'abstract', 'boolean', 'break', 'byte', 'case', 'catch',
                'char', 'class', 'const', 'continue', 'default', 'do',
                'double', 'else', 'extends', 'final', 'finally', 'float',
                'for', 'goto', 'if', 'implements', 'import', 'instanceof',
                'int', 'interface', 'long', 'native', 'new', 'package',
                'private', 'protected', 'public', 'return', 'short',
                'static', 'strictfp', 'super', 'switch', 'synchronized',
                'this', 'throw', 'throws', 'transient', 'try', 'void',
                'volatile', 'while'
            ]
        else:
            keywords = []
            
        # Create keyword patterns
        for keyword in keywords:
            pattern = QRegularExpression(r'\\b' + keyword + r'\\b')
            self.highlighting_rules.append((pattern, self.keyword_format))
            
        # String patterns
        string_patterns = [
            QRegularExpression(r'\".*\"'),
            QRegularExpression(r\"'.*'\"),
            QRegularExpression(r'`.*`')  # Template strings
        ]
        
        for pattern in string_patterns:
            self.highlighting_rules.append((pattern, self.string_format))
            
        # Comment patterns
        if self.language in ["javascript", "java"]:
            comment_patterns = [
                QRegularExpression(r'//[^\\n]*'),
                QRegularExpression(r'/\\*.*\\*/')
            ]
        elif self.language == "python":
            comment_patterns = [
                QRegularExpression(r'#[^\\n]*'),
                QRegularExpression(r'\"\"\".*\"\"\"'),
                QRegularExpression(r\"'''.*'''\")
            ]
        else:
            comment_patterns = []
            
        for pattern in comment_patterns:
            self.highlighting_rules.append((pattern, self.comment_format))
            
        # Number patterns
        number_pattern = QRegularExpression(r'\\b\\d+(\\.\\d+)?\\b')
        self.highlighting_rules.append((number_pattern, self.number_format))
        
        # Function patterns
        if self.language == "javascript":
            function_pattern = QRegularExpression(r'\\b\\w+(?=\\()')
        elif self.language == "python":
            function_pattern = QRegularExpression(r'\\bdef\\s+(\\w+)')
        else:
            function_pattern = QRegularExpression(r'\\b\\w+(?=\\()')
            
        self.highlighting_rules.append((function_pattern, self.function_format))
        
    def highlightBlock(self, text):
        """Apply syntax highlighting to a block of text."""
        for pattern, format_style in self.highlighting_rules:
            expression = pattern
            iterator = expression.globalMatch(text)
            
            while iterator.hasNext():
                match = iterator.next()
                self.setFormat(match.capturedStart(), match.capturedLength(), format_style)


class CodeEditor(QPlainTextEdit):
    """Enhanced code editor with line numbers and syntax highlighting."""
    
    def __init__(self, language="javascript", parent=None):
        super().__init__(parent)
        self.language = language
        
        # Setup editor
        self.setup_editor()
        self.setup_syntax_highlighting()
        
    def setup_editor(self):
        """Setup editor properties."""
        # Font
        font = QFont("Consolas", 10)
        font.setFixedPitch(True)
        self.setFont(font)
        
        # Tab settings
        tab_width = 4
        metrics = QFontMetrics(font)
        tab_stop_width = tab_width * metrics.horizontalAdvance(' ')
        self.setTabStopDistance(tab_stop_width)
        
        # Editor style
        self.setStyleSheet("""
            QPlainTextEdit {
                background-color: #1e1e1e;
                color: #d4d4d4;
                border: 1px solid #3e3e3e;
                selection-background-color: #264f78;
            }
        """)
        
        # Enable line wrapping
        self.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        
    def setup_syntax_highlighting(self):
        """Setup syntax highlighting for the current language."""
        self.highlighter = SyntaxHighlighter(self.language, self.document())
        
    def set_language(self, language):
        """Set the editor language and update syntax highlighting."""
        self.language = language
        self.setup_syntax_highlighting()


class ScriptTemplateManager:
    """Manager for script templates and snippets."""
    
    def __init__(self):
        self.templates = self.load_templates()
        
    def load_templates(self):
        """Load script templates."""
        return {
            "frida": {
                "basic_hook": {
                    "name": "Basic Function Hook",
                    "description": "Hook a function and log its calls",
                    "code": '''// Basic function hook template
Java.perform(function() {
    var targetClass = Java.use("com.example.TargetClass");
    
    targetClass.targetMethod.implementation = function(arg1, arg2) {
        console.log("[+] targetMethod called with args:", arg1, arg2);
        
        // Call original method
        var result = this.targetMethod(arg1, arg2);
        
        console.log("[+] Original result:", result);
        return result;
    };
});'''
                },
                "license_bypass": {
                    "name": "License Check Bypass",
                    "description": "Bypass license validation function",
                    "code": '''// License validation bypass
Java.perform(function() {
    var LicenseValidator = Java.use("com.example.LicenseValidator");
    
    // Hook license check function
    LicenseValidator.validateLicense.implementation = function(licenseKey) {
        console.log("[+] License validation bypassed");
        return true; // Always return valid
    };
    
    // Hook trial check
    LicenseValidator.isTrialExpired.implementation = function() {
        console.log("[+] Trial expiry check bypassed");
        return false; // Never expired
    };
});'''
                },
                "network_intercept": {
                    "name": "Network Request Intercept",
                    "description": "Intercept and modify network requests",
                    "code": '''// Network request interception
Java.perform(function() {
    var URL = Java.use("java.net.URL");
    var HttpURLConnection = Java.use("java.net.HttpURLConnection");
    
    // Hook URL constructor
    URL.$init.overload('java.lang.String').implementation = function(url) {
        console.log("[+] URL accessed:", url);
        
        // Modify license server URLs
        if (url.includes("license.example.com")) {
            console.log("[+] Redirecting license server");
            url = "http://localhost:8080/license";
        }
        
        return this.$init(url);
    };
});'''
                }
            },
            "ghidra": {
                "function_analysis": {
                    "name": "Function Analysis Script",
                    "description": "Analyze functions and create bookmarks",
                    "code": '''# Function analysis script for Ghidra
from ghidra.program.model.symbol import *
from ghidra.program.model.listing import *

def analyze_functions():
    """Analyze all functions in the program."""
    function_manager = currentProgram.getFunctionManager()
    bookmark_manager = currentProgram.getBookmarkManager()
    
    for function in function_manager.getFunctions(True):
        analyze_function(function, bookmark_manager)

def analyze_function(function, bookmark_manager):
    """Analyze a single function."""
    name = function.getName()
    address = function.getEntryPoint()
    
    # Check for suspicious patterns
    if "license" in name.lower() or "trial" in name.lower():
        bookmark_manager.setBookmark(
            address, "Analysis", "License Check",
            "Potential license validation function: " + name
        )
        # License function found and bookmarked
    
    if "check" in name.lower() and "valid" in name.lower():
        bookmark_manager.setBookmark(
            address, "Analysis", "Validation",
            "Potential validation function: " + name
        )
        # Validation function found and bookmarked

# Run analysis
analyze_functions()
# Function analysis complete'''
                },
                "string_analysis": {
                    "name": "String Analysis",
                    "description": "Find and analyze strings in the binary",
                    "code": '''# String analysis script for Ghidra
from ghidra.program.model.data import *
from ghidra.program.model.listing import *

def find_license_strings():
    """Find license-related strings."""
    listing = currentProgram.getListing()
    memory = currentProgram.getMemory()
    bookmark_manager = currentProgram.getBookmarkManager()
    
    # Keywords to search for
    keywords = ["license", "trial", "expired", "invalid", "activation", "serial"]
    
    # Search all defined strings
    string_iterator = listing.getDefinedData(True)
    
    for data in string_iterator:
        if data.hasStringValue():
            string_value = data.getValue()
            address = data.getAddress()
            
            for keyword in keywords:
                if keyword.lower() in str(string_value).lower():
                    bookmark_manager.setBookmark(
                        address, "Strings", "License String",
                        "License-related string: " + str(string_value)
                    )
                    # License string found and bookmarked
                    break

# Run string analysis
find_license_strings()
# String analysis complete'''
                }
            }
        }
        
    def get_template(self, script_type, template_name):
        """Get a specific template."""
        return self.templates.get(script_type, {}).get(template_name)
        
    def get_templates_for_type(self, script_type):
        """Get all templates for a script type."""
        return self.templates.get(script_type, {})


class ScriptGenerationStudio(QWidget):
    """
    Comprehensive script development environment with AI integration.
    
    Provides advanced script generation, editing, testing, and management
    capabilities with AIScriptGenerator backend integration.
    """
    
    script_generated = pyqtSignal(str, str, str)
    script_saved = pyqtSignal(str, str)
    script_executed = pyqtSignal(str, str)
    
    def __init__(self, shared_context=None, parent=None):
        """Initialize the script generation studio."""
        super().__init__(parent)
        self.shared_context = shared_context
        self.ai_generator = None
        self.template_manager = ScriptTemplateManager()
        
        # Studio state
        self.current_script = None
        self.script_history = []
        self.generation_in_progress = False
        
        self.setup_ui()
        self.setup_connections()
        self.initialize_generator()
        
    def setup_ui(self):
        """Setup the user interface components."""
        layout = QHBoxLayout(self)
        
        # Left panel - Controls and templates (30%)
        left_panel = self.create_control_panel()
        
        # Right panel - Editor and preview (70%)
        right_panel = self.create_editor_panel()
        
        # Main splitter
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(left_panel)
        splitter.addWidget(right_panel)
        splitter.setStretchFactor(0, 30)
        splitter.setStretchFactor(1, 70)
        
        layout.addWidget(splitter)
        
    def create_control_panel(self):
        """Create the left control panel."""
        panel = QWidget()
        layout = QVBoxLayout(panel)
        
        # Generation controls
        generation_group = self.create_generation_controls()
        layout.addWidget(generation_group)
        
        # Template library
        template_group = self.create_template_library()
        layout.addWidget(template_group)
        
        # Script history
        history_group = self.create_script_history()
        layout.addWidget(history_group)
        
        return panel
        
    def create_generation_controls(self):
        """Create AI generation controls."""
        group = QGroupBox("AI Script Generation")
        layout = QVBoxLayout(group)
        
        # Script type selection
        type_layout = QHBoxLayout()
        type_layout.addWidget(QLabel("Script Type:"))
        
        self.script_type_combo = QComboBox()
        self.script_type_combo.addItems(["Frida (JavaScript)", "Ghidra (Python)", "Unified"])
        type_layout.addWidget(self.script_type_combo)
        
        layout.addLayout(type_layout)
        
        # Target analysis
        target_layout = QVBoxLayout()
        target_layout.addWidget(QLabel("Target Analysis:"))
        
        self.target_text = QTextEdit()
        self.target_text.setMaximumHeight(80)
        self.target_text.setPlaceholderText("Describe what you want to achieve (e.g., 'bypass license check in function at 0x401000')")
        target_layout.addWidget(self.target_text)
        
        layout.addLayout(target_layout)
        
        # Protection types
        protection_layout = QVBoxLayout()
        protection_layout.addWidget(QLabel("Protection Types:"))
        
        self.protection_checkboxes = {}
        protection_types = [
            ("license_check", "License Validation"),
            ("trial_timer", "Trial Timer"),
            ("anti_debug", "Anti-Debug"),
            ("vm_detection", "VM Detection"),
            ("network_validation", "Network Validation"),
            ("integrity_check", "Integrity Check")
        ]
        
        for prot_id, name in protection_types:
            checkbox = QCheckBox(name)
            self.protection_checkboxes[prot_id] = checkbox
            protection_layout.addWidget(checkbox)
            
        layout.addLayout(protection_layout)
        
        # AI model settings
        ai_layout = QFormLayout()
        
        self.ai_model_combo = QComboBox()
        self.ai_model_combo.addItems(["GPT-4", "Claude-3", "Gemini Pro", "Local Model"])
        ai_layout.addRow("AI Model:", self.ai_model_combo)
        
        self.creativity_slider = QSlider(Qt.Orientation.Horizontal)
        self.creativity_slider.setRange(0, 100)
        self.creativity_slider.setValue(70)
        self.creativity_label = QLabel("70%")
        self.creativity_slider.valueChanged.connect(
            lambda v: self.creativity_label.setText(f"{v}%")
        )
        
        creativity_layout = QHBoxLayout()
        creativity_layout.addWidget(self.creativity_slider)
        creativity_layout.addWidget(self.creativity_label)
        ai_layout.addRow("Creativity:", creativity_layout)
        
        layout.addLayout(ai_layout)
        
        # Generation button
        self.generate_btn = QPushButton("Generate Script")
        self.generate_btn.clicked.connect(self.generate_script)
        self.generate_btn.setStyleSheet("font-weight: bold; color: blue; padding: 8px;")
        layout.addWidget(self.generate_btn)
        
        # Progress bar
        self.generation_progress = QProgressBar()
        self.generation_progress.setVisible(False)
        layout.addWidget(self.generation_progress)
        
        return group
        
    def create_template_library(self):
        """Create template library browser."""
        group = QGroupBox("Template Library")
        layout = QVBoxLayout(group)
        
        # Template tree
        self.template_tree = QTreeWidget()
        self.template_tree.setHeaderLabels(["Template", "Type"])
        self.template_tree.itemDoubleClicked.connect(self.load_template)
        
        # Populate templates
        self.populate_template_tree()
        
        layout.addWidget(self.template_tree)
        
        # Template actions
        template_actions = QHBoxLayout()
        
        load_template_btn = QPushButton("Load")
        load_template_btn.clicked.connect(self.load_selected_template)
        
        save_template_btn = QPushButton("Save as Template")
        save_template_btn.clicked.connect(self.save_as_template)
        
        template_actions.addWidget(load_template_btn)
        template_actions.addWidget(save_template_btn)
        
        layout.addLayout(template_actions)
        
        return group
        
    def create_script_history(self):
        """Create script generation history."""
        group = QGroupBox("Generation History")
        layout = QVBoxLayout(group)
        
        self.history_list = QListWidget()
        self.history_list.itemDoubleClicked.connect(self.load_from_history)
        layout.addWidget(self.history_list)
        
        # History actions
        history_actions = QHBoxLayout()
        
        clear_history_btn = QPushButton("Clear")
        clear_history_btn.clicked.connect(self.clear_history)
        
        export_history_btn = QPushButton("Export")
        export_history_btn.clicked.connect(self.export_history)
        
        history_actions.addWidget(clear_history_btn)
        history_actions.addWidget(export_history_btn)
        
        layout.addLayout(history_actions)
        
        return group
        
    def create_editor_panel(self):
        """Create the main editor panel."""
        panel = QWidget()
        layout = QVBoxLayout(panel)
        
        # Editor tabs
        self.editor_tabs = QTabWidget()
        self.editor_tabs.setTabsClosable(True)
        self.editor_tabs.tabCloseRequested.connect(self.close_editor_tab)
        
        # Create initial editor
        self.create_new_editor("Untitled", "javascript")
        
        layout.addWidget(self.editor_tabs)
        
        # Editor toolbar
        toolbar = self.create_editor_toolbar()
        layout.addWidget(toolbar)
        
        return panel
        
    def create_editor_toolbar(self):
        """Create editor toolbar with actions."""
        toolbar = QFrame()
        toolbar.setFrameStyle(QFrame.Shape.StyledPanel)
        layout = QHBoxLayout(toolbar)
        
        # File operations
        new_btn = QPushButton("New")
        new_btn.clicked.connect(self.new_script)
        
        open_btn = QPushButton("Open")
        open_btn.clicked.connect(self.open_script)
        
        save_btn = QPushButton("Save")
        save_btn.clicked.connect(self.save_script)
        save_btn.setShortcut(QKeySequence.StandardKey.Save)
        
        # Script operations
        test_btn = QPushButton("Test Script")
        test_btn.clicked.connect(self.test_script)
        test_btn.setStyleSheet("color: green;")
        
        validate_btn = QPushButton("Validate")
        validate_btn.clicked.connect(self.validate_script)
        
        format_btn = QPushButton("Format")
        format_btn.clicked.connect(self.format_script)
        
        # Language selection
        self.language_combo = QComboBox()
        self.language_combo.addItems(["JavaScript", "Python", "Java"])
        self.language_combo.currentTextChanged.connect(self.change_editor_language)
        
        layout.addWidget(new_btn)
        layout.addWidget(open_btn)
        layout.addWidget(save_btn)
        layout.addWidget(QFrame())  # Separator
        layout.addWidget(test_btn)
        layout.addWidget(validate_btn)
        layout.addWidget(format_btn)
        layout.addStretch()
        layout.addWidget(QLabel("Language:"))
        layout.addWidget(self.language_combo)
        
        return toolbar
        
    def setup_connections(self):
        """Setup signal connections."""
        # Connect to shared context
        if self.shared_context:
            if hasattr(self.shared_context, 'target_binary_selected'):
                self.shared_context.target_binary_selected.connect(self.set_target_binary)
            if hasattr(self.shared_context, 'protection_analysis_completed'):
                self.shared_context.protection_analysis_completed.connect(self.update_protection_info)
                
    def initialize_generator(self):
        """Initialize the AI script generator."""
        try:
            if self.shared_context and hasattr(self.shared_context, 'ai_generator'):
                self.ai_generator = self.shared_context.ai_generator
            else:
                self.ai_generator = AIScriptGenerator()
                
        except Exception as e:
            logger.error(f"Failed to initialize AI generator: {e}")
            
    def populate_template_tree(self):
        """Populate the template tree with available templates."""
        self.template_tree.clear()
        
        for script_type, templates in self.template_manager.templates.items():
            type_item = QTreeWidgetItem(self.template_tree)
            type_item.setText(0, script_type.title())
            type_item.setText(1, "Category")
            
            for template_name, template_data in templates.items():
                template_item = QTreeWidgetItem(type_item)
                template_item.setText(0, template_data["name"])
                template_item.setText(1, script_type)
                template_item.setData(0, Qt.ItemDataRole.UserRole, {
                    'type': script_type,
                    'name': template_name,
                    'data': template_data
                })
                
        self.template_tree.expandAll()
        
    def create_new_editor(self, title, language="javascript"):
        """Create a new editor tab."""
        editor = CodeEditor(language)
        
        # Add tab
        index = self.editor_tabs.addTab(editor, title)
        self.editor_tabs.setCurrentIndex(index)
        
        return editor
        
    def get_current_editor(self):
        """Get the currently active editor."""
        current_widget = self.editor_tabs.currentWidget()
        if isinstance(current_widget, CodeEditor):
            return current_widget
        return None
        
    def generate_script(self):
        """Generate a script using AI."""
        if self.generation_in_progress:
            return
            
        # Get generation parameters
        script_type_text = self.script_type_combo.currentText()
        if "Frida" in script_type_text:
            script_type = ScriptType.FRIDA
            language = "javascript"
        elif "Ghidra" in script_type_text:
            script_type = ScriptType.GHIDRA
            language = "python"
        else:
            script_type = ScriptType.UNIFIED
            language = "javascript"
            
        target_description = self.target_text.toPlainText().strip()
        if not target_description:
            QMessageBox.warning(self, "Warning", "Please provide a target description")
            return
            
        # Get selected protection types
        protection_types = []
        for prot_id, checkbox in self.protection_checkboxes.items():
            if checkbox.isChecked():
                # Map UI names to ProtectionType enum
                protection_map = {
                    'license_check': ProtectionType.LICENSE_CHECK,
                    'trial_timer': ProtectionType.TRIAL_TIMER,
                    'anti_debug': ProtectionType.ANTI_DEBUG,
                    'vm_detection': ProtectionType.VM_DETECTION,
                    'network_validation': ProtectionType.NETWORK_VALIDATION,
                    'integrity_check': ProtectionType.INTEGRITY_CHECK
                }
                if prot_id in protection_map:
                    protection_types.append(protection_map[prot_id])
                    
        if not protection_types:
            protection_types = [ProtectionType.UNKNOWN]
            
        # Start generation
        self.generation_in_progress = True
        self.generate_btn.setEnabled(False)
        self.generation_progress.setVisible(True)
        self.generation_progress.setRange(0, 0)  # Indeterminate
        
        try:
            if self.ai_generator:
                # Use real AI generator
                result = self.ai_generator.generate_script(
                    script_type=script_type,
                    target_description=target_description,
                    protection_types=protection_types,
                    binary_path=getattr(self.shared_context, 'current_binary', None)
                )
                
                if result.success and result.script:
                    self.on_script_generated(result.script, language)
                else:
                    self.show_generation_error(result.errors)
            else:
                # No AI generator available
                self.show_generation_error(["AI Script Generator not available. Please configure AI backend."])
                
        except Exception as e:
            logger.error(f"Script generation failed: {e}")
            self.show_generation_error([str(e)])
        finally:
            self.generation_in_progress = False
            self.generate_btn.setEnabled(True)
            self.generation_progress.setVisible(False)
            

        
    def on_script_generated(self, script, language):
        """Handle successful script generation."""
        # Create new editor tab
        timestamp = datetime.now().strftime("%H:%M:%S")
        tab_title = f"Generated {timestamp}"
        
        editor = self.create_new_editor(tab_title, language)
        editor.setPlainText(script.content)
        
        # Add to history
        self.add_to_history(script.content, script.metadata.script_type.value, timestamp)
        
        # Emit signal
        self.script_generated.emit(script.content, language, script.metadata.script_id)
        

        
    def show_generation_error(self, errors):
        """Show script generation errors."""
        error_text = "\\n".join(errors)
        QMessageBox.critical(self, "Generation Error", f"Failed to generate script:\\n\\n{error_text}")
        
    def add_to_history(self, script_content, script_type, timestamp):
        """Add generated script to history."""
        history_item = {
            'content': script_content,
            'type': script_type,
            'timestamp': timestamp,
            'description': self.target_text.toPlainText()[:50] + "..."
        }
        
        self.script_history.append(history_item)
        
        # Update history list
        item_text = f"{timestamp} - {script_type} - {history_item['description']}"
        list_item = QListWidgetItem(item_text)
        list_item.setData(Qt.ItemDataRole.UserRole, history_item)
        self.history_list.addItem(list_item)
        
    def load_template(self, item, column):
        """Load template into editor."""
        template_data = item.data(0, Qt.ItemDataRole.UserRole)
        if template_data:
            template_info = template_data['data']
            script_type = template_data['type']
            
            # Create new editor
            editor = self.create_new_editor(template_info['name'], script_type)
            editor.setPlainText(template_info['code'])
            
    def load_selected_template(self):
        """Load selected template."""
        current_item = self.template_tree.currentItem()
        if current_item:
            self.load_template(current_item, 0)
            
    def save_as_template(self):
        """Save current script as template."""
        editor = self.get_current_editor()
        if not editor:
            return
            
        # Get template info from user
        name, ok = QLineEdit().getText(self, "Template Name", "Enter template name:")
        if not ok or not name:
            return
            
        description, ok = QLineEdit().getText(self, "Template Description", "Enter description:")
        if not ok:
            description = ""
            
        # Save template
        template_data = {
            'name': name,
            'description': description,
            'code': editor.toPlainText()
        }
        
        # Add to templates (simplified - would normally save to file)
        script_type = editor.language
        if script_type not in self.template_manager.templates:
            self.template_manager.templates[script_type] = {}
            
        self.template_manager.templates[script_type][name.lower().replace(' ', '_')] = template_data
        
        # Refresh template tree
        self.populate_template_tree()
        
    def load_from_history(self, item):
        """Load script from history."""
        history_data = item.data(Qt.ItemDataRole.UserRole)
        if history_data:
            editor = self.create_new_editor(f"History - {history_data['timestamp']}", history_data['type'])
            editor.setPlainText(history_data['content'])
            
    def clear_history(self):
        """Clear generation history."""
        reply = QMessageBox.question(self, "Clear History", "Are you sure you want to clear the generation history?")
        if reply == QMessageBox.StandardButton.Yes:
            self.script_history.clear()
            self.history_list.clear()
            
    def export_history(self):
        """Export generation history."""
        if not self.script_history:
            QMessageBox.information(self, "No History", "No generation history to export")
            return
            
        filename, _ = QFileDialog.getSaveFileName(
            self, "Export History", "script_history.json",
            "JSON Files (*.json);;All Files (*)"
        )
        
        if filename:
            try:
                with open(filename, 'w') as f:
                    json.dump(self.script_history, f, indent=2, default=str)
                QMessageBox.information(self, "Success", f"History exported to {filename}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to export history: {e}")
                
    def new_script(self):
        """Create new script."""
        language = self.language_combo.currentText().lower()
        if language not in ["javascript", "python", "java"]:
            language = "javascript"
            
        self.create_new_editor("Untitled", language)
        
    def open_script(self):
        """Open script file."""
        filename, _ = QFileDialog.getOpenFileName(
            self, "Open Script", "",
            "Script Files (*.js *.py *.java);;All Files (*)"
        )
        
        if filename:
            try:
                with open(filename, 'r') as f:
                    content = f.read()
                    
                # Determine language from extension
                ext = os.path.splitext(filename)[1].lower()
                language_map = {'.js': 'javascript', '.py': 'python', '.java': 'java'}
                language = language_map.get(ext, 'javascript')
                
                editor = self.create_new_editor(os.path.basename(filename), language)
                editor.setPlainText(content)
                
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to open file: {e}")
                
    def save_script(self):
        """Save current script."""
        editor = self.get_current_editor()
        if not editor:
            return
            
        # Get filename
        current_tab = self.editor_tabs.currentIndex()
        current_title = self.editor_tabs.tabText(current_tab)
        
        if current_title == "Untitled" or "Generated" in current_title:
            # Save as new file
            language = editor.language
            ext_map = {'javascript': '.js', 'python': '.py', 'java': '.java'}
            ext = ext_map.get(language, '.js')
            
            filename, _ = QFileDialog.getSaveFileName(
                self, "Save Script", f"script{ext}",
                f"Script Files (*{ext});;All Files (*)"
            )
        else:
            filename = current_title
            
        if filename:
            try:
                with open(filename, 'w') as f:
                    f.write(editor.toPlainText())
                    
                # Update tab title
                self.editor_tabs.setTabText(current_tab, os.path.basename(filename))
                
                # Emit signal
                self.script_saved.emit(filename, editor.toPlainText())
                
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to save file: {e}")
                
    def test_script(self):
        """Test the current script."""
        editor = self.get_current_editor()
        if not editor:
            return
            
        script_content = editor.toPlainText()
        language = editor.language
        
        # Basic validation
        if not script_content.strip():
            QMessageBox.warning(self, "Warning", "Script is empty")
            return
            
        # Emit signal for testing
        self.script_executed.emit(script_content, language)
        
        # Show test message
        QMessageBox.information(self, "Test", f"Script testing initiated for {language} script")
        
    def validate_script(self):
        """Validate current script syntax."""
        editor = self.get_current_editor()
        if not editor:
            return
            
        script_content = editor.toPlainText()
        language = editor.language
        
        # Basic validation
        errors = []
        
        if language == "javascript":
            # Check for basic JavaScript syntax
            if script_content.count('{') != script_content.count('}'):
                errors.append("Mismatched braces")
            if script_content.count('(') != script_content.count(')'):
                errors.append("Mismatched parentheses")
                
        elif language == "python":
            # Check for basic Python syntax
            try:
                compile(script_content, '<string>', 'exec')
            except SyntaxError as e:
                errors.append(f"Syntax error: {e}")
                
        if errors:
            QMessageBox.warning(self, "Validation Errors", "\\n".join(errors))
        else:
            QMessageBox.information(self, "Validation", "Script syntax appears valid")
            
    def format_script(self):
        """Format current script."""
        editor = self.get_current_editor()
        if not editor:
            return
            
        # Basic formatting (simplified)
        content = editor.toPlainText()
        
        # Apply basic indentation fixes
        lines = content.split('\\n')
        formatted_lines = []
        indent_level = 0
        
        for line in lines:
            stripped = line.strip()
            if not stripped:
                formatted_lines.append('')
                continue
                
            # Decrease indent for closing braces/brackets
            if stripped.startswith(('}', ')', ']')):
                indent_level = max(0, indent_level - 1)
                
            # Add indented line
            formatted_lines.append('    ' * indent_level + stripped)
            
            # Increase indent for opening braces/brackets
            if stripped.endswith(('{', '(', '[')):
                indent_level += 1
                
        editor.setPlainText('\\n'.join(formatted_lines))
        
    def change_editor_language(self, language):
        """Change current editor language."""
        editor = self.get_current_editor()
        if editor:
            editor.set_language(language.lower())
            
    def close_editor_tab(self, index):
        """Close editor tab."""
        if self.editor_tabs.count() > 1:  # Keep at least one tab
            self.editor_tabs.removeTab(index)
            
    def set_target_binary(self, binary_path):
        """Set target binary for analysis."""
        # Update target text with binary info
        self.target_text.setPlainText(f"Analyze binary: {binary_path}")
        
    def update_protection_info(self, protection_data):
        """Update protection information from analysis."""
        # Auto-select relevant protection types
        for prot_id, checkbox in self.protection_checkboxes.items():
            # Check if protection type was detected
            checkbox.setChecked(prot_id in protection_data.get('detected_types', []))
# Plugin System Update Plan for Intellicrack

## Executive Summary

This document outlines the comprehensive plan to transform Intellicrack's plugin system into a professional single-user development environment. The implementation focuses on enhancing user experience, providing robust development tools, and creating a seamless workflow for custom plugin creation.

## Project Overview

### Goals
- Transform the plugin system from a complex, underutilized feature into a valuable productivity tool
- Create an intuitive single-user plugin development experience
- Provide comprehensive documentation and guidance within the application
- Implement professional development tools (validation, testing, debugging)
- Streamline integration with existing Frida and Ghidra managers

### Scope
- Focus exclusively on single-user, local development workflow
- No community features, sharing, or collaboration tools
- Enhanced UI/UX for plugin discovery and creation
- Professional development environment with modern tooling
- Comprehensive error handling and debugging capabilities

### Timeline
- Total Duration: 8 weeks
- Phases: 8 sequential phases, approximately 1 week each
- Testing: Continuous throughout all phases
- Documentation: Updated in parallel with development

---

## Phase 1: UI Enhancement (Week 1)

### 1.1 Add Tooltips to All Plugin UI Components

**Objective**: Improve discoverability by adding descriptive tooltips to all plugin-related UI elements.

**Implementation Details**:

**File**: `intellicrack/ui/main_app.py`
- Locate the `setup_tools_plugins_tab()` method (around line 10522)
- Add tooltips to all QPushButton, QTabWidget, and QListWidget components

**Specific Tooltips to Add**:
```python
# Custom Python Plugins tab
custom_plugins_tab.setToolTip("Create and manage personal Python analysis plugins")

# Buttons
run_custom_btn.setToolTip("Execute the selected plugin on the current binary")
edit_custom_btn.setToolTip("Open plugin source code in the built-in editor")
import_custom_btn.setToolTip("Import an existing plugin from your file system")
create_custom_btn.setToolTip("Create a new plugin from professional templates")

# Plugin list
custom_list.setToolTip("Your personal collection of custom analysis plugins\nDouble-click to view details")
```

**Testing Requirements**:
- Verify all tooltips appear on hover
- Ensure tooltip text is clear and helpful
- Test tooltip formatting and positioning

### 1.2 Add Help Buttons with Local Documentation Links

**Objective**: Provide easy access to plugin documentation directly from the UI.

**Implementation Details**:

**New Widget Creation**:
```python
def create_help_button(self, help_topic):
    """Create a help button that opens documentation"""
    help_btn = QPushButton("?")
    help_btn.setFixedSize(24, 24)
    help_btn.setToolTip(f"Get help with {help_topic}")
    help_btn.clicked.connect(lambda: self.open_plugin_documentation(help_topic))
    return help_btn
```

**File Modifications**:
1. Add help button creation method to `main_app.py`
2. Place help buttons next to each plugin category header
3. Implement `open_plugin_documentation()` method:
   ```python
   def open_plugin_documentation(self, topic):
       doc_path = os.path.join(os.path.dirname(__file__),
                              "..", "..", "docs", "development", "plugins.md")
       if os.path.exists(doc_path):
           # Open in system browser
           QDesktopServices.openUrl(QUrl.fromLocalFile(doc_path))
       else:
           # Show embedded help dialog
           self.show_embedded_help(topic)
   ```

### 1.3 Display Plugin Descriptions in Lists and Tables

**Objective**: Show rich plugin information including descriptions, versions, and capabilities.

**Implementation Details**:

**Modify Plugin Loading** (`intellicrack/plugins/plugin_system.py`):
```python
def extract_plugin_metadata(plugin_path):
    """Extract comprehensive metadata from plugin file"""
    metadata = {
        'name': 'Unknown Plugin',
        'version': '0.0.0',
        'description': 'No description available',
        'author': 'Unknown',
        'capabilities': [],
        'status': 'unknown'
    }

    try:
        # Parse plugin file for metadata
        with open(plugin_path, 'r') as f:
            content = f.read()
            # Extract from docstring or constants
            # ... parsing logic ...
    except Exception as e:
        metadata['status'] = 'error'
        metadata['error'] = str(e)

    return metadata
```

**Update UI Display** (`intellicrack/ui/main_app.py`):
- Replace QListWidget with QTableWidget for richer display
- Add columns: Name, Version, Description, Status
- Implement expandable rows for full descriptions

### 1.4 Create First-Time User Welcome Workflow

**Objective**: Guide new users through plugin system capabilities.

**New File**: `intellicrack/ui/dialogs/plugin_welcome_dialog.py`

```python
class PluginWelcomeDialog(QDialog):
    """Welcome dialog for first-time plugin users"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Welcome to Intellicrack Plugins")
        self.setModal(True)
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)

        # Welcome message
        welcome_label = QLabel(
            "<h2>Welcome to Intellicrack's Plugin System!</h2>"
            "<p>Create custom analysis tools to extend Intellicrack's capabilities.</p>"
        )
        welcome_label.setWordWrap(True)
        layout.addWidget(welcome_label)

        # Feature overview
        features_group = QGroupBox("What You Can Do")
        features_layout = QVBoxLayout(features_group)

        features = [
            "🔍 Create custom binary analysis tools",
            "🔧 Build automated patching workflows",
            "📊 Generate specialized reports",
            "🛡️ Detect specific protections or patterns",
            "🤖 Automate repetitive analysis tasks"
        ]

        for feature in features:
            features_layout.addWidget(QLabel(feature))

        layout.addWidget(features_group)

        # Quick actions
        actions_group = QGroupBox("Get Started")
        actions_layout = QVBoxLayout(actions_group)

        create_first_btn = QPushButton("Create Your First Plugin")
        create_first_btn.clicked.connect(self.create_first_plugin)

        view_examples_btn = QPushButton("View Example Plugins")
        view_examples_btn.clicked.connect(self.view_examples)

        read_docs_btn = QPushButton("Read Documentation")
        read_docs_btn.clicked.connect(self.read_documentation)

        actions_layout.addWidget(create_first_btn)
        actions_layout.addWidget(view_examples_btn)
        actions_layout.addWidget(read_docs_btn)

        layout.addWidget(actions_group)

        # Don't show again checkbox
        self.dont_show_cb = QCheckBox("Don't show this again")
        layout.addWidget(self.dont_show_cb)

        # Close button
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        layout.addWidget(close_btn)
```

**Integration in main_app.py**:
```python
def show_plugin_welcome_if_needed(self):
    """Show welcome dialog on first plugin tab access"""
    settings = QSettings("Intellicrack", "PluginSystem")
    if not settings.value("welcome_shown", False):
        dialog = PluginWelcomeDialog(self)
        if dialog.exec_() == QDialog.Accepted:
            if dialog.dont_show_cb.isChecked():
                settings.setValue("welcome_shown", True)
```

---

## Phase 2: Development Tools (Week 2)

### 2.1 Implement Real-Time Plugin Validation

**Objective**: Provide immediate feedback on plugin code validity.

**New File**: `intellicrack/plugins/plugin_validator.py`

```python
import ast
import importlib.util
from typing import List, Dict, Tuple

class PluginValidator:
    """Real-time plugin validation system"""

    REQUIRED_METHODS = ['register', 'analyze']
    OPTIONAL_METHODS = ['patch', 'get_metadata', 'get_capabilities']

    def __init__(self):
        self.errors = []
        self.warnings = []

    def validate_syntax(self, code: str) -> Tuple[bool, List[str]]:
        """Validate Python syntax"""
        try:
            ast.parse(code)
            return True, []
        except SyntaxError as e:
            return False, [f"Syntax error at line {e.lineno}: {e.msg}"]

    def validate_structure(self, code: str) -> Tuple[bool, List[str]]:
        """Validate plugin structure and required methods"""
        errors = []

        try:
            tree = ast.parse(code)

            # Find all function definitions
            functions = [node.name for node in ast.walk(tree)
                        if isinstance(node, ast.FunctionDef)]

            # Check for required methods
            for method in self.REQUIRED_METHODS:
                if method not in functions:
                    errors.append(f"Missing required method: {method}()")

            # Find all class definitions
            classes = []
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef):
                    classes.append(node)

            # Validate class methods if plugin uses class structure
            if classes:
                class_methods = []
                for cls in classes:
                    for node in cls.body:
                        if isinstance(node, ast.FunctionDef):
                            class_methods.append(node.name)

                # Check if analyze method exists in class
                if 'analyze' not in class_methods:
                    errors.append("Plugin class missing 'analyze' method")

            return len(errors) == 0, errors

        except Exception as e:
            return False, [f"Validation error: {str(e)}"]

    def validate_imports(self, code: str) -> Tuple[bool, List[str]]:
        """Check if all imports are available"""
        warnings = []

        try:
            tree = ast.parse(code)

            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        try:
                            importlib.import_module(alias.name)
                        except ImportError:
                            warnings.append(f"Module not found: {alias.name}")

                elif isinstance(node, ast.ImportFrom):
                    try:
                        importlib.import_module(node.module)
                    except ImportError:
                        warnings.append(f"Module not found: {node.module}")

            return True, warnings

        except Exception as e:
            return False, [f"Import validation error: {str(e)}"]

    def validate_full(self, code: str) -> Dict:
        """Perform complete validation"""
        result = {
            'valid': True,
            'errors': [],
            'warnings': [],
            'suggestions': []
        }

        # Syntax validation
        syntax_valid, syntax_errors = self.validate_syntax(code)
        if not syntax_valid:
            result['valid'] = False
            result['errors'].extend(syntax_errors)
            return result  # Can't continue if syntax is invalid

        # Structure validation
        structure_valid, structure_errors = self.validate_structure(code)
        if not structure_valid:
            result['valid'] = False
            result['errors'].extend(structure_errors)

        # Import validation
        imports_valid, import_warnings = self.validate_imports(code)
        result['warnings'].extend(import_warnings)

        # Add suggestions
        if 'get_metadata' not in code:
            result['suggestions'].append(
                "Consider adding get_metadata() method for better plugin information"
            )

        return result
```

**Integration with Editor**:
- Add validation on text change with debouncing
- Display errors/warnings in editor margin
- Show validation status in status bar

### 2.2 Enhanced Plugin Editor with Syntax Highlighting

**New File**: `intellicrack/ui/widgets/plugin_editor.py`

```python
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout
from PyQt5.QtCore import QTimer, pyqtSignal
from PyQt5.Qsci import QsciScintilla, QsciLexerPython

class PluginEditor(QWidget):
    """Enhanced plugin editor with syntax highlighting and validation"""

    textChanged = pyqtSignal()
    validationComplete = pyqtSignal(dict)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.validator = PluginValidator()
        self.validation_timer = QTimer()
        self.validation_timer.timeout.connect(self.perform_validation)
        self.validation_timer.setSingleShot(True)
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)

        # Create Scintilla editor
        self.editor = QsciScintilla()

        # Set Python lexer for syntax highlighting
        self.lexer = QsciLexerPython()
        self.editor.setLexer(self.lexer)

        # Configure editor
        self.editor.setIndentationsUseTabs(False)
        self.editor.setIndentationWidth(4)
        self.editor.setAutoIndent(True)
        self.editor.setBraceMatching(QsciScintilla.SloppyBraceMatch)
        self.editor.setCaretLineVisible(True)
        self.editor.setMarginLineNumbers(1, True)
        self.editor.setMarginWidth(1, "0000")
        self.editor.setFolding(QsciScintilla.BoxedTreeFoldStyle)

        # Set up autocompletion
        self.editor.setAutoCompletionSource(QsciScintilla.AcsAll)
        self.editor.setAutoCompletionThreshold(2)
        self.editor.setAutoCompletionCaseSensitivity(False)

        # Add custom API for Intellicrack
        self.setup_intellicrack_api()

        # Connect signals
        self.editor.textChanged.connect(self.on_text_changed)

        layout.addWidget(self.editor)

        # Add status bar
        self.status_bar = QLabel("Ready")
        layout.addWidget(self.status_bar)

    def setup_intellicrack_api(self):
        """Add Intellicrack API to autocompletion"""
        api_items = [
            "analyze(self, binary_path)",
            "patch(self, binary_path, options=None)",
            "get_metadata(self)",
            "get_capabilities(self)",
            "log_message(message)",
            "read_binary(path)",
            "write_binary(path, data)",
            "get_entropy(data)",
            "find_strings(data, min_length=4)",
            "detect_packer(binary_path)",
            "get_imports(binary_path)",
            "get_exports(binary_path)",
        ]

        for item in api_items:
            self.lexer.add_word(item)

    def on_text_changed(self):
        """Handle text changes with debounced validation"""
        self.textChanged.emit()
        self.validation_timer.stop()
        self.validation_timer.start(500)  # 500ms delay

    def perform_validation(self):
        """Validate the current code"""
        code = self.editor.text()
        result = self.validator.validate_full(code)

        # Clear existing markers
        self.editor.clearIndicatorRange(0, 0,
                                       self.editor.lines(), 0,
                                       self.error_indicator)

        # Add error markers
        for error in result['errors']:
            # Parse line number from error message
            if 'line' in error:
                line_num = int(error.split('line')[1].split(':')[0])
                self.mark_error_line(line_num)

        # Update status bar
        if result['valid']:
            self.status_bar.setText("✓ Valid plugin code")
            self.status_bar.setStyleSheet("color: green")
        else:
            error_count = len(result['errors'])
            self.status_bar.setText(f"✗ {error_count} error(s)")
            self.status_bar.setStyleSheet("color: red")

        self.validationComplete.emit(result)

    def mark_error_line(self, line_num):
        """Mark a line as having an error"""
        # Define error indicator style
        self.editor.indicatorDefine(QsciScintilla.SquiggleIndicator, self.error_indicator)
        self.editor.setIndicatorForegroundColor(QColor("red"), self.error_indicator)

        # Apply indicator to the line
        pos_start = self.editor.positionFromLineIndex(line_num - 1, 0)
        pos_end = self.editor.positionFromLineIndex(line_num, 0)
        self.editor.fillIndicatorRange(line_num - 1, 0, line_num, 0, self.error_indicator)
```

### 2.3 Plugin Template Wizard with Multiple Options

**New File**: `intellicrack/ui/dialogs/plugin_template_wizard.py`

```python
from PyQt5.QtWidgets import QWizard, QWizardPage, QVBoxLayout, QLabel, QLineEdit, QTextEdit, QComboBox

class PluginTemplateWizard(QWizard):
    """Multi-step wizard for creating new plugins"""

    # Template types
    TEMPLATE_SIMPLE = "simple"
    TEMPLATE_ADVANCED = "advanced"
    TEMPLATE_PATCHER = "patcher"
    TEMPLATE_ANALYZER = "analyzer"
    TEMPLATE_NETWORK = "network"

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Create New Plugin")
        self.setWizardStyle(QWizard.ModernStyle)

        # Add pages
        self.addPage(PluginInfoPage())
        self.addPage(TemplateSelectionPage())
        self.addPage(CustomizationPage())
        self.addPage(PreviewPage())

        # Store plugin data
        self.plugin_data = {}

    def generate_plugin_code(self):
        """Generate plugin code based on wizard selections"""
        template_type = self.field("templateType")
        plugin_name = self.field("pluginName")
        author = self.field("authorName")
        description = self.field("description")

        # Load appropriate template
        template = self.load_template(template_type)

        # Replace placeholders
        code = template.format(
            plugin_name=plugin_name,
            author=author,
            description=description,
            version="1.0.0",
            class_name=self.to_class_name(plugin_name)
        )

        return code

    def load_template(self, template_type):
        """Load template based on type"""
        templates = {
            self.TEMPLATE_SIMPLE: self.get_simple_template(),
            self.TEMPLATE_ADVANCED: self.get_advanced_template(),
            self.TEMPLATE_PATCHER: self.get_patcher_template(),
            self.TEMPLATE_ANALYZER: self.get_analyzer_template(),
            self.TEMPLATE_NETWORK: self.get_network_template()
        }
        return templates.get(template_type, self.get_simple_template())

    def get_simple_template(self):
        return '''"""
{plugin_name} - {description}

A simple plugin for Intellicrack that demonstrates basic functionality.

Author: {author}
Version: {version}
"""

class {class_name}:
    """Simple plugin implementation"""

    def __init__(self):
        self.name = "{plugin_name}"
        self.version = "{version}"
        self.author = "{author}"
        self.description = "{description}"

    def analyze(self, binary_path):
        """Analyze the binary and return results"""
        results = []

        # Your analysis code here
        results.append(f"Analyzing: {{binary_path}}")

        # Example: Read file size
        import os
        if os.path.exists(binary_path):
            size = os.path.getsize(binary_path)
            results.append(f"File size: {{size:,}} bytes")

        return results

def register():
    """Register this plugin with Intellicrack"""
    return {class_name}()
'''

    def get_advanced_template(self):
        return '''"""
{plugin_name} - {description}

An advanced plugin demonstrating comprehensive Intellicrack integration.

Author: {author}
Version: {version}
"""

import os
import time
import hashlib
from typing import Dict, List, Optional, Any

class {class_name}:
    """Advanced plugin with full feature demonstration"""

    def __init__(self):
        self.name = "{plugin_name}"
        self.version = "{version}"
        self.author = "{author}"
        self.description = "{description}"
        self.capabilities = ["analyze", "patch", "report"]

        # Configuration
        self.config = {{
            'verbose': True,
            'max_file_size': 100 * 1024 * 1024,  # 100MB
            'timeout': 300  # 5 minutes
        }}

        # Internal state
        self.last_analysis = None
        self.analysis_count = 0

    def get_metadata(self) -> Dict[str, Any]:
        """Return plugin metadata"""
        return {{
            'name': self.name,
            'version': self.version,
            'author': self.author,
            'description': self.description,
            'capabilities': self.capabilities,
            'config': self.config,
            'stats': {{
                'analysis_count': self.analysis_count,
                'last_analysis': self.last_analysis
            }}
        }}

    def validate_binary(self, binary_path: str) -> tuple[bool, str]:
        """Validate binary before processing"""
        if not os.path.exists(binary_path):
            return False, "File not found"

        if not os.path.isfile(binary_path):
            return False, "Not a file"

        size = os.path.getsize(binary_path)
        if size == 0:
            return False, "Empty file"

        if size > self.config['max_file_size']:
            return False, f"File too large ({{size:,}} bytes)"

        return True, "Validation passed"

    def analyze(self, binary_path: str) -> List[str]:
        """Perform comprehensive analysis"""
        results = []
        start_time = time.time()

        # Update state
        self.analysis_count += 1
        self.last_analysis = time.time()

        # Validate input
        valid, msg = self.validate_binary(binary_path)
        if not valid:
            results.append(f"Error: {{msg}}")
            return results

        results.append(f"=== {plugin_name} Analysis ===")
        results.append(f"Target: {{os.path.basename(binary_path)}}")

        try:
            # Basic file information
            file_stats = os.stat(binary_path)
            results.append(f"Size: {{file_stats.st_size:,}} bytes")
            results.append(f"Modified: {{time.ctime(file_stats.st_mtime)}}")

            # Calculate file hash
            with open(binary_path, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
            results.append(f"SHA256: {{file_hash}}")

            # Your custom analysis here
            # Example: Check for specific patterns
            with open(binary_path, 'rb') as f:
                data = f.read(1024)  # Read first 1KB

                if b'MZ' in data:
                    results.append("Type: Windows PE executable")
                elif b'\\x7fELF' in data:
                    results.append("Type: Linux ELF executable")
                else:
                    results.append("Type: Unknown binary format")

            # Add more analysis...

        except Exception as e:
            results.append(f"Analysis error: {{str(e)}}")

        # Report timing
        elapsed = time.time() - start_time
        results.append(f"Analysis completed in {{elapsed:.2f}} seconds")

        return results

    def patch(self, binary_path: str, options: Optional[Dict] = None) -> List[str]:
        """Apply patches to the binary"""
        results = []

        # Validate
        valid, msg = self.validate_binary(binary_path)
        if not valid:
            results.append(f"Cannot patch: {{msg}}")
            return results

        results.append(f"=== {plugin_name} Patcher ===")

        # Create backup
        backup_path = f"{{binary_path}}.backup_{{int(time.time())}}"
        try:
            import shutil
            shutil.copy2(binary_path, backup_path)
            results.append(f"Backup created: {{os.path.basename(backup_path)}}")
        except Exception as e:
            results.append(f"Backup failed: {{e}}")
            return results

        # Apply patches
        try:
            # Your patching logic here
            results.append("Patch analysis completed")
            results.append("No patches applied (demo mode)")

        except Exception as e:
            results.append(f"Patching error: {{str(e)}}")

        return results

    def get_capabilities(self) -> List[str]:
        """Return list of plugin capabilities"""
        return self.capabilities

    def configure(self, config: Dict[str, Any]) -> bool:
        """Update plugin configuration"""
        try:
            self.config.update(config)
            return True
        except:
            return False

def register():
    """Register this plugin with Intellicrack"""
    return {class_name}()
'''

class PluginInfoPage(QWizardPage):
    """First page - basic plugin information"""

    def __init__(self):
        super().__init__()
        self.setTitle("Plugin Information")
        self.setSubTitle("Enter basic information about your plugin")

        layout = QVBoxLayout()

        # Plugin name
        layout.addWidget(QLabel("Plugin Name:"))
        self.name_edit = QLineEdit()
        self.name_edit.setPlaceholderText("My Custom Analyzer")
        layout.addWidget(self.name_edit)
        self.registerField("pluginName*", self.name_edit)

        # Author name
        layout.addWidget(QLabel("Author Name:"))
        self.author_edit = QLineEdit()
        self.author_edit.setPlaceholderText("Your Name")
        layout.addWidget(self.author_edit)
        self.registerField("authorName*", self.author_edit)

        # Description
        layout.addWidget(QLabel("Description:"))
        self.desc_edit = QTextEdit()
        self.desc_edit.setPlaceholderText("Brief description of what your plugin does...")
        self.desc_edit.setMaximumHeight(100)
        layout.addWidget(self.desc_edit)
        self.registerField("description", self.desc_edit, "plainText")

        self.setLayout(layout)

class TemplateSelectionPage(QWizardPage):
    """Second page - template selection"""

    def __init__(self):
        super().__init__()
        self.setTitle("Choose Template")
        self.setSubTitle("Select a template that matches your plugin's purpose")

        layout = QVBoxLayout()

        self.template_combo = QComboBox()
        self.template_combo.addItems([
            ("Simple Plugin - Basic analysis functionality", PluginTemplateWizard.TEMPLATE_SIMPLE),
            ("Advanced Plugin - Full feature demonstration", PluginTemplateWizard.TEMPLATE_ADVANCED),
            ("Binary Patcher - Focus on patching operations", PluginTemplateWizard.TEMPLATE_PATCHER),
            ("Deep Analyzer - Comprehensive analysis tools", PluginTemplateWizard.TEMPLATE_ANALYZER),
            ("Network Plugin - Network and protocol analysis", PluginTemplateWizard.TEMPLATE_NETWORK)
        ])

        layout.addWidget(QLabel("Template Type:"))
        layout.addWidget(self.template_combo)

        # Template description
        self.desc_label = QLabel()
        self.desc_label.setWordWrap(True)
        self.desc_label.setStyleSheet("QLabel { background-color: #f0f0f0; padding: 10px; }")
        layout.addWidget(self.desc_label)

        self.template_combo.currentIndexChanged.connect(self.update_description)
        self.update_description(0)

        self.registerField("templateType", self.template_combo, "currentData")

        self.setLayout(layout)

    def update_description(self, index):
        """Update template description based on selection"""
        descriptions = [
            "A simple template with basic analyze() method. Perfect for beginners or quick prototypes.",
            "Comprehensive template showing all plugin features including configuration, validation, and error handling.",
            "Specialized for binary patching with backup creation and safety checks.",
            "Advanced analysis template with multiple detection algorithms and reporting.",
            "Network-focused template with packet analysis and protocol detection capabilities."
        ]
        self.desc_label.setText(descriptions[index])
```

---

## Phase 3: Testing Framework (Week 3)

### 3.1 Built-in Plugin Testing Capabilities

**New File**: `intellicrack/plugins/plugin_tester.py`

```python
import os
import sys
import time
import tempfile
import traceback
from typing import Dict, List, Any, Optional
from contextlib import contextmanager
import importlib.util

class PluginTester:
    """Comprehensive plugin testing framework"""

    def __init__(self):
        self.test_results = []
        self.performance_metrics = {}

    @contextmanager
    def capture_output(self):
        """Capture stdout/stderr during plugin execution"""
        from io import StringIO

        old_stdout = sys.stdout
        old_stderr = sys.stderr
        stdout_capture = StringIO()
        stderr_capture = StringIO()

        try:
            sys.stdout = stdout_capture
            sys.stderr = stderr_capture
            yield stdout_capture, stderr_capture
        finally:
            sys.stdout = old_stdout
            sys.stderr = old_stderr

    def create_test_binary(self, test_type="simple"):
        """Create test binary for plugin testing"""
        test_binaries = {
            "simple": b"MZ\x90\x00\x03" + b"\x00" * 60 + b"PE\x00\x00",  # Minimal PE
            "elf": b"\x7fELF" + b"\x01\x01\x01" + b"\x00" * 9,  # Minimal ELF
            "random": os.urandom(1024),  # Random data
            "text": b"Hello World! " * 100,  # Text file
            "empty": b"",  # Empty file
        }

        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(test_binaries.get(test_type, test_binaries["simple"]))
            return f.name

    def test_plugin_structure(self, plugin_path: str) -> Dict[str, Any]:
        """Test plugin structure and imports"""
        result = {
            "passed": True,
            "errors": [],
            "warnings": []
        }

        try:
            # Load plugin module
            spec = importlib.util.spec_from_file_location("test_plugin", plugin_path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            # Check for register function
            if not hasattr(module, 'register'):
                result["passed"] = False
                result["errors"].append("Missing register() function")
            else:
                # Try to instantiate plugin
                try:
                    plugin_instance = module.register()

                    # Check required attributes
                    required_attrs = ['name', 'analyze']
                    for attr in required_attrs:
                        if not hasattr(plugin_instance, attr):
                            result["passed"] = False
                            result["errors"].append(f"Missing required attribute: {attr}")

                    # Check optional but recommended attributes
                    optional_attrs = ['version', 'author', 'description']
                    for attr in optional_attrs:
                        if not hasattr(plugin_instance, attr):
                            result["warnings"].append(f"Missing optional attribute: {attr}")

                except Exception as e:
                    result["passed"] = False
                    result["errors"].append(f"Failed to instantiate plugin: {str(e)}")

        except Exception as e:
            result["passed"] = False
            result["errors"].append(f"Failed to load plugin: {str(e)}")

        return result

    def test_plugin_execution(self, plugin_path: str, test_binary: str = None) -> Dict[str, Any]:
        """Test plugin execution with various inputs"""
        result = {
            "passed": True,
            "execution_time": 0,
            "memory_usage": 0,
            "output": [],
            "errors": [],
            "test_cases": []
        }

        # Create test binary if not provided
        if not test_binary:
            test_binary = self.create_test_binary()

        try:
            # Load plugin
            spec = importlib.util.spec_from_file_location("test_plugin", plugin_path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            plugin = module.register()

            # Test different scenarios
            test_cases = [
                ("Valid binary", test_binary, True),
                ("Non-existent file", "/nonexistent/file.bin", False),
                ("Empty path", "", False),
                ("None input", None, False),
            ]

            for test_name, test_input, should_succeed in test_cases:
                case_result = self.run_test_case(plugin, test_name, test_input, should_succeed)
                result["test_cases"].append(case_result)

                if not case_result["passed"]:
                    result["passed"] = False

            # Aggregate metrics
            result["execution_time"] = sum(tc["execution_time"] for tc in result["test_cases"])

        except Exception as e:
            result["passed"] = False
            result["errors"].append(f"Test execution failed: {str(e)}")

        finally:
            # Cleanup test files
            if test_binary and os.path.exists(test_binary):
                os.unlink(test_binary)

        return result

    def run_test_case(self, plugin, test_name: str, test_input: Any, should_succeed: bool) -> Dict:
        """Run a single test case"""
        case_result = {
            "name": test_name,
            "passed": False,
            "execution_time": 0,
            "output": None,
            "error": None
        }

        start_time = time.time()

        try:
            with self.capture_output() as (stdout, stderr):
                # Run plugin analyze method
                if hasattr(plugin, 'analyze'):
                    output = plugin.analyze(test_input)
                    case_result["output"] = output

                    # Check if it succeeded as expected
                    if should_succeed:
                        case_result["passed"] = output is not None and not stderr.getvalue()
                    else:
                        # Should have failed gracefully
                        case_result["passed"] = True  # Handled error properly
                else:
                    case_result["error"] = "Plugin missing analyze() method"

        except Exception as e:
            if should_succeed:
                case_result["error"] = str(e)
                case_result["passed"] = False
            else:
                # Expected to fail, but should handle gracefully
                case_result["passed"] = True

        case_result["execution_time"] = time.time() - start_time
        return case_result

    def test_plugin_performance(self, plugin_path: str, iterations: int = 10) -> Dict[str, Any]:
        """Test plugin performance with multiple iterations"""
        result = {
            "average_time": 0,
            "min_time": float('inf'),
            "max_time": 0,
            "iterations": iterations,
            "times": []
        }

        test_binary = self.create_test_binary()

        try:
            # Load plugin
            spec = importlib.util.spec_from_file_location("test_plugin", plugin_path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            plugin = module.register()

            # Run multiple iterations
            for i in range(iterations):
                start_time = time.time()

                try:
                    plugin.analyze(test_binary)
                except:
                    pass  # Ignore errors for performance testing

                elapsed = time.time() - start_time
                result["times"].append(elapsed)
                result["min_time"] = min(result["min_time"], elapsed)
                result["max_time"] = max(result["max_time"], elapsed)

            result["average_time"] = sum(result["times"]) / len(result["times"])

        except Exception as e:
            result["error"] = str(e)

        finally:
            if os.path.exists(test_binary):
                os.unlink(test_binary)

        return result
```

**New File**: `intellicrack/ui/dialogs/plugin_test_dialog.py`

```python
class PluginTestDialog(QDialog):
    """Dialog for running plugin tests"""

    def __init__(self, plugin_path: str, parent=None):
        super().__init__(parent)
        self.plugin_path = plugin_path
        self.tester = PluginTester()
        self.setWindowTitle(f"Test Plugin: {os.path.basename(plugin_path)}")
        self.setModal(True)
        self.resize(800, 600)
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)

        # Test options
        options_group = QGroupBox("Test Options")
        options_layout = QHBoxLayout(options_group)

        self.structure_cb = QCheckBox("Structure Test")
        self.structure_cb.setChecked(True)
        self.execution_cb = QCheckBox("Execution Test")
        self.execution_cb.setChecked(True)
        self.performance_cb = QCheckBox("Performance Test")
        self.performance_cb.setChecked(True)

        options_layout.addWidget(self.structure_cb)
        options_layout.addWidget(self.execution_cb)
        options_layout.addWidget(self.performance_cb)

        layout.addWidget(options_group)

        # Run button
        self.run_btn = QPushButton("Run Tests")
        self.run_btn.clicked.connect(self.run_tests)
        layout.addWidget(self.run_btn)

        # Results area
        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        layout.addWidget(self.results_text)

        # Progress bar
        self.progress_bar = QProgressBar()
        layout.addWidget(self.progress_bar)

        # Close button
        self.close_btn = QPushButton("Close")
        self.close_btn.clicked.connect(self.accept)
        layout.addWidget(self.close_btn)

    def run_tests(self):
        """Execute selected tests"""
        self.results_text.clear()
        self.run_btn.setEnabled(False)

        total_tests = sum([
            self.structure_cb.isChecked(),
            self.execution_cb.isChecked(),
            self.performance_cb.isChecked()
        ])

        current_test = 0

        # Structure test
        if self.structure_cb.isChecked():
            self.results_text.append("=== Structure Test ===")
            result = self.tester.test_plugin_structure(self.plugin_path)
            self.display_structure_results(result)
            current_test += 1
            self.progress_bar.setValue(int(current_test / total_tests * 100))

        # Execution test
        if self.execution_cb.isChecked():
            self.results_text.append("\n=== Execution Test ===")
            result = self.tester.test_plugin_execution(self.plugin_path)
            self.display_execution_results(result)
            current_test += 1
            self.progress_bar.setValue(int(current_test / total_tests * 100))

        # Performance test
        if self.performance_cb.isChecked():
            self.results_text.append("\n=== Performance Test ===")
            result = self.tester.test_plugin_performance(self.plugin_path)
            self.display_performance_results(result)
            current_test += 1
            self.progress_bar.setValue(int(current_test / total_tests * 100))

        self.run_btn.setEnabled(True)
        self.results_text.append("\n=== All Tests Complete ===")
```

### 3.2 Plugin Performance Monitoring

**Integration in plugin_system.py**:

```python
class PluginPerformanceMonitor:
    """Monitor and track plugin performance metrics"""

    def __init__(self):
        self.metrics = {}
        self.history = {}

    def start_monitoring(self, plugin_name: str):
        """Start monitoring a plugin execution"""
        self.metrics[plugin_name] = {
            'start_time': time.time(),
            'memory_start': self.get_memory_usage()
        }

    def stop_monitoring(self, plugin_name: str):
        """Stop monitoring and calculate metrics"""
        if plugin_name not in self.metrics:
            return None

        metrics = self.metrics[plugin_name]
        end_time = time.time()
        memory_end = self.get_memory_usage()

        result = {
            'execution_time': end_time - metrics['start_time'],
            'memory_used': memory_end - metrics['memory_start'],
            'timestamp': end_time
        }

        # Store in history
        if plugin_name not in self.history:
            self.history[plugin_name] = []
        self.history[plugin_name].append(result)

        # Keep only last 100 entries
        if len(self.history[plugin_name]) > 100:
            self.history[plugin_name] = self.history[plugin_name][-100:]

        del self.metrics[plugin_name]
        return result

    def get_memory_usage(self):
        """Get current memory usage in bytes"""
        import psutil
        process = psutil.Process()
        return process.memory_info().rss

    def get_plugin_stats(self, plugin_name: str):
        """Get performance statistics for a plugin"""
        if plugin_name not in self.history:
            return None

        history = self.history[plugin_name]
        if not history:
            return None

        times = [h['execution_time'] for h in history]
        memory = [h['memory_used'] for h in history]

        return {
            'execution_count': len(history),
            'avg_time': sum(times) / len(times),
            'min_time': min(times),
            'max_time': max(times),
            'avg_memory': sum(memory) / len(memory),
            'last_run': history[-1]['timestamp']
        }
```

---

## Phase 4: Documentation System (Week 4)

### 4.1 Embedded API Reference Viewer

**New File**: `intellicrack/ui/widgets/api_reference_viewer.py`

```python
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QTreeWidget, QTreeWidgetItem, QTextBrowser, QSplitter
from PyQt5.QtCore import Qt

class APIReferenceViewer(QWidget):
    """Interactive API documentation viewer"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.api_docs = self.load_api_documentation()
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)

        # Create splitter for tree and content
        splitter = QSplitter(Qt.Horizontal)

        # API tree
        self.api_tree = QTreeWidget()
        self.api_tree.setHeaderLabel("Intellicrack API")
        self.populate_api_tree()
        self.api_tree.itemClicked.connect(self.on_item_clicked)

        # Documentation display
        self.doc_browser = QTextBrowser()
        self.doc_browser.setOpenExternalLinks(True)

        splitter.addWidget(self.api_tree)
        splitter.addWidget(self.doc_browser)
        splitter.setSizes([300, 500])

        layout.addWidget(splitter)

    def load_api_documentation(self):
        """Load API documentation from embedded resource"""
        return {
            "Core Functions": {
                "analyze_binary": {
                    "signature": "analyze_binary(binary_path: str) -> Dict",
                    "description": "Perform comprehensive binary analysis",
                    "parameters": {
                        "binary_path": "Path to the binary file to analyze"
                    },
                    "returns": "Dictionary containing analysis results",
                    "example": '''result = analyze_binary("/path/to/binary.exe")
print(f"File type: {result['file_type']}")
print(f"Architecture: {result['arch']}")'''
                },
                "get_imports": {
                    "signature": "get_imports(binary_path: str) -> List[str]",
                    "description": "Extract import table from binary",
                    "parameters": {
                        "binary_path": "Path to the binary file"
                    },
                    "returns": "List of imported functions",
                    "example": '''imports = get_imports("/path/to/binary.exe")
for imp in imports:
    print(f"Import: {imp}")'''
                },
                "get_exports": {
                    "signature": "get_exports(binary_path: str) -> List[str]",
                    "description": "Extract export table from binary",
                    "parameters": {
                        "binary_path": "Path to the binary file"
                    },
                    "returns": "List of exported functions",
                    "example": '''exports = get_exports("/path/to/library.dll")
for exp in exports:
    print(f"Export: {exp}")'''
                }
            },
            "Binary Operations": {
                "read_binary": {
                    "signature": "read_binary(path: str) -> bytes",
                    "description": "Read binary file contents",
                    "parameters": {
                        "path": "Path to the binary file"
                    },
                    "returns": "Binary data as bytes",
                    "example": '''data = read_binary("/path/to/file.bin")
print(f"File size: {len(data)} bytes")'''
                },
                "write_binary": {
                    "signature": "write_binary(path: str, data: bytes) -> bool",
                    "description": "Write binary data to file",
                    "parameters": {
                        "path": "Path where to write the file",
                        "data": "Binary data to write"
                    },
                    "returns": "True if successful, False otherwise",
                    "example": '''data = b"\\x4D\\x5A\\x90\\x00"  # PE header
success = write_binary("/path/to/output.bin", data)'''
                },
                "patch_binary": {
                    "signature": "patch_binary(path: str, offset: int, data: bytes) -> bool",
                    "description": "Patch binary at specific offset",
                    "parameters": {
                        "path": "Path to the binary file",
                        "offset": "Offset where to apply patch",
                        "data": "Patch data"
                    },
                    "returns": "True if successful, False otherwise",
                    "example": '''# NOP out a function call
patch_binary("/path/to/binary.exe", 0x1000, b"\\x90\\x90\\x90\\x90\\x90")'''
                }
            },
            "Analysis Utilities": {
                "get_entropy": {
                    "signature": "get_entropy(data: bytes) -> float",
                    "description": "Calculate Shannon entropy of data",
                    "parameters": {
                        "data": "Binary data to analyze"
                    },
                    "returns": "Entropy value (0.0 - 8.0)",
                    "example": '''data = read_binary("/path/to/file.bin")
entropy = get_entropy(data)
if entropy > 7.5:
    print("High entropy - possibly packed/encrypted")'''
                },
                "find_strings": {
                    "signature": "find_strings(data: bytes, min_length: int = 4) -> List[str]",
                    "description": "Extract printable strings from binary data",
                    "parameters": {
                        "data": "Binary data to search",
                        "min_length": "Minimum string length (default: 4)"
                    },
                    "returns": "List of found strings",
                    "example": '''data = read_binary("/path/to/binary.exe")
strings = find_strings(data, min_length=6)
for s in strings[:10]:  # First 10 strings
    print(s)'''
                },
                "detect_packer": {
                    "signature": "detect_packer(binary_path: str) -> Optional[str]",
                    "description": "Detect if binary is packed and identify packer",
                    "parameters": {
                        "binary_path": "Path to the binary file"
                    },
                    "returns": "Packer name or None if not packed",
                    "example": '''packer = detect_packer("/path/to/binary.exe")
if packer:
    print(f"Detected packer: {packer}")
else:
    print("Binary is not packed")'''
                }
            },
            "Plugin Helpers": {
                "log_message": {
                    "signature": "log_message(message: str, level: str = 'info')",
                    "description": "Log a message to Intellicrack's output",
                    "parameters": {
                        "message": "Message to log",
                        "level": "Log level: 'info', 'warning', 'error'"
                    },
                    "returns": "None",
                    "example": '''log_message("Analysis started")
log_message("Warning: Large file detected", "warning")
log_message("Error: Invalid format", "error")'''
                },
                "update_progress": {
                    "signature": "update_progress(value: int, total: int = 100)",
                    "description": "Update progress bar in UI",
                    "parameters": {
                        "value": "Current progress value",
                        "total": "Total value (default: 100)"
                    },
                    "returns": "None",
                    "example": '''for i in range(100):
    # Do some work
    update_progress(i + 1, 100)'''
                }
            }
        }

    def populate_api_tree(self):
        """Populate the API tree with categories and functions"""
        for category, functions in self.api_docs.items():
            category_item = QTreeWidgetItem(self.api_tree, [category])
            category_item.setExpanded(True)

            for func_name, func_info in functions.items():
                func_item = QTreeWidgetItem(category_item, [func_name])
                func_item.setData(0, Qt.UserRole, (category, func_name))

    def on_item_clicked(self, item, column):
        """Display documentation for selected API item"""
        data = item.data(0, Qt.UserRole)
        if not data:
            return

        category, func_name = data
        func_info = self.api_docs[category][func_name]

        # Generate HTML documentation
        html = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; }}
                h1 {{ color: #2c3e50; }}
                h2 {{ color: #34495e; }}
                .signature {{
                    background-color: #ecf0f1;
                    padding: 10px;
                    border-radius: 5px;
                    font-family: monospace;
                }}
                .parameter {{
                    margin-left: 20px;
                    margin-bottom: 5px;
                }}
                .example {{
                    background-color: #2c3e50;
                    color: #ecf0f1;
                    padding: 10px;
                    border-radius: 5px;
                    font-family: monospace;
                    white-space: pre-wrap;
                }}
            </style>
        </head>
        <body>
            <h1>{func_name}</h1>
            <div class="signature">{func_info['signature']}</div>

            <h2>Description</h2>
            <p>{func_info['description']}</p>

            <h2>Parameters</h2>
        """

        for param, desc in func_info.get('parameters', {}).items():
            html += f'<div class="parameter"><b>{param}</b>: {desc}</div>'

        html += f"""
            <h2>Returns</h2>
            <p>{func_info.get('returns', 'None')}</p>

            <h2>Example</h2>
            <div class="example">{func_info.get('example', 'No example available')}</div>
        </body>
        </html>
        """

        self.doc_browser.setHtml(html)
```

### 4.2 Interactive Tutorial System

**New File**: `intellicrack/ui/dialogs/plugin_tutorial.py`

```python
class PluginTutorial(QDialog):
    """Interactive plugin development tutorial"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Plugin Development Tutorial")
        self.setModal(True)
        self.resize(900, 700)
        self.current_step = 0
        self.tutorial_steps = self.create_tutorial_steps()
        self.setup_ui()

    def create_tutorial_steps(self):
        """Define tutorial steps"""
        return [
            {
                "title": "Welcome to Plugin Development",
                "content": """
                <h2>Welcome to Intellicrack Plugin Development!</h2>
                <p>This interactive tutorial will guide you through creating your first plugin.</p>
                <p>You'll learn:</p>
                <ul>
                    <li>Basic plugin structure</li>
                    <li>How to analyze binaries</li>
                    <li>Working with the Intellicrack API</li>
                    <li>Testing and debugging plugins</li>
                </ul>
                <p>Let's get started!</p>
                """,
                "code": "",
                "task": "Click 'Next' to continue"
            },
            {
                "title": "Plugin Structure",
                "content": """
                <h2>Basic Plugin Structure</h2>
                <p>Every Intellicrack plugin needs:</p>
                <ul>
                    <li>A plugin class with required methods</li>
                    <li>A register() function to instantiate the plugin</li>
                    <li>Basic metadata (name, version, etc.)</li>
                </ul>
                <p>Here's the minimal structure:</p>
                """,
                "code": '''class MyFirstPlugin:
    def __init__(self):
        self.name = "My First Plugin"
        self.version = "1.0.0"

    def analyze(self, binary_path):
        return ["Analysis results here"]

def register():
    return MyFirstPlugin()''',
                "task": "Study the code structure, then click 'Next'"
            },
            {
                "title": "Adding Analysis Logic",
                "content": """
                <h2>Implementing Binary Analysis</h2>
                <p>Let's add real analysis functionality to our plugin.</p>
                <p>We'll check the file size and type:</p>
                """,
                "code": '''import os

class MyFirstPlugin:
    def __init__(self):
        self.name = "My First Plugin"
        self.version = "1.0.0"

    def analyze(self, binary_path):
        results = []

        # Check if file exists
        if not os.path.exists(binary_path):
            results.append("Error: File not found")
            return results

        # Get file size
        size = os.path.getsize(binary_path)
        results.append(f"File size: {size:,} bytes")

        # Check file type
        with open(binary_path, 'rb') as f:
            header = f.read(2)
            if header == b'MZ':
                results.append("File type: Windows PE executable")
            elif header == b'\\x7fE':
                results.append("File type: Linux ELF executable")
            else:
                results.append("File type: Unknown")

        return results

def register():
    return MyFirstPlugin()''',
                "task": "Modify the code to add your own analysis feature"
            },
            {
                "title": "Using Intellicrack API",
                "content": """
                <h2>Leveraging Intellicrack's API</h2>
                <p>Intellicrack provides powerful analysis functions you can use:</p>
                <ul>
                    <li>get_entropy() - Calculate file entropy</li>
                    <li>find_strings() - Extract strings</li>
                    <li>get_imports() - List imported functions</li>
                </ul>
                """,
                "code": '''from intellicrack.utils import get_entropy, find_strings

class AdvancedPlugin:
    def __init__(self):
        self.name = "Advanced Analysis Plugin"
        self.version = "1.0.0"

    def analyze(self, binary_path):
        results = []

        with open(binary_path, 'rb') as f:
            data = f.read()

        # Calculate entropy
        entropy = get_entropy(data)
        results.append(f"Entropy: {entropy:.2f}")

        if entropy > 7.5:
            results.append("⚠️ High entropy - possibly packed!")

        # Find strings
        strings = find_strings(data, min_length=6)
        results.append(f"Found {len(strings)} strings")

        # Show first 5 strings
        for s in strings[:5]:
            results.append(f"  String: {s}")

        return results

def register():
    return AdvancedPlugin()''',
                "task": "Try using different API functions in your plugin"
            },
            {
                "title": "Testing Your Plugin",
                "content": """
                <h2>Testing and Debugging</h2>
                <p>Always test your plugin thoroughly:</p>
                <ul>
                    <li>Test with different file types</li>
                    <li>Handle errors gracefully</li>
                    <li>Check edge cases (empty files, large files)</li>
                </ul>
                <p>Use the built-in testing tools to validate your plugin.</p>
                """,
                "code": '''# Good practice: Add error handling
class RobustPlugin:
    def __init__(self):
        self.name = "Robust Plugin"
        self.version = "1.0.0"

    def analyze(self, binary_path):
        results = []

        try:
            # Validate input
            if not binary_path:
                results.append("Error: No file path provided")
                return results

            if not os.path.exists(binary_path):
                results.append(f"Error: File not found: {binary_path}")
                return results

            # Check file size
            size = os.path.getsize(binary_path)
            if size == 0:
                results.append("Warning: File is empty")
                return results

            if size > 100 * 1024 * 1024:  # 100MB
                results.append("Warning: Large file, analysis may be slow")

            # Perform analysis
            # ... your analysis code here ...

        except Exception as e:
            results.append(f"Error during analysis: {str(e)}")

        return results

def register():
    return RobustPlugin()''',
                "task": "Add error handling to your plugin"
            },
            {
                "title": "Congratulations!",
                "content": """
                <h2>Tutorial Complete!</h2>
                <p>Congratulations! You've learned the basics of plugin development.</p>
                <p>Next steps:</p>
                <ul>
                    <li>Create your own custom plugin</li>
                    <li>Explore the API documentation</li>
                    <li>Study the example plugins</li>
                    <li>Test with real binaries</li>
                </ul>
                <p>Happy plugin development!</p>
                """,
                "code": "",
                "task": "Click 'Finish' to close the tutorial"
            }
        ]

    def setup_ui(self):
        layout = QVBoxLayout(self)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setMaximum(len(self.tutorial_steps) - 1)
        layout.addWidget(self.progress_bar)

        # Content area
        content_widget = QWidget()
        content_layout = QVBoxLayout(content_widget)

        # Title
        self.title_label = QLabel()
        self.title_label.setStyleSheet("font-size: 18px; font-weight: bold;")
        content_layout.addWidget(self.title_label)

        # Content browser
        self.content_browser = QTextBrowser()
        content_layout.addWidget(self.content_browser)

        # Code editor
        self.code_editor = PluginEditor()  # Reuse the enhanced editor
        self.code_editor.setMaximumHeight(300)
        content_layout.addWidget(self.code_editor)

        # Task label
        self.task_label = QLabel()
        self.task_label.setStyleSheet("background-color: #f0f0f0; padding: 10px;")
        content_layout.addWidget(self.task_label)

        layout.addWidget(content_widget)

        # Navigation buttons
        nav_layout = QHBoxLayout()

        self.prev_btn = QPushButton("Previous")
        self.prev_btn.clicked.connect(self.prev_step)
        nav_layout.addWidget(self.prev_btn)

        nav_layout.addStretch()

        self.next_btn = QPushButton("Next")
        self.next_btn.clicked.connect(self.next_step)
        nav_layout.addWidget(self.next_btn)

        layout.addLayout(nav_layout)

        # Load first step
        self.load_step(0)

    def load_step(self, step_index):
        """Load tutorial step"""
        if 0 <= step_index < len(self.tutorial_steps):
            step = self.tutorial_steps[step_index]

            self.title_label.setText(step["title"])
            self.content_browser.setHtml(step["content"])
            self.code_editor.editor.setText(step["code"])
            self.task_label.setText(f"Task: {step['task']}")

            self.progress_bar.setValue(step_index)

            # Update navigation buttons
            self.prev_btn.setEnabled(step_index > 0)

            if step_index == len(self.tutorial_steps) - 1:
                self.next_btn.setText("Finish")
            else:
                self.next_btn.setText("Next")

    def prev_step(self):
        """Go to previous step"""
        if self.current_step > 0:
            self.current_step -= 1
            self.load_step(self.current_step)

    def next_step(self):
        """Go to next step or finish"""
        if self.current_step < len(self.tutorial_steps) - 1:
            self.current_step += 1
            self.load_step(self.current_step)
        else:
            self.accept()  # Close dialog
```

---

## Phase 5: Error Handling (Week 5)

### 5.1 Comprehensive Error Reporting and Recovery

**Modifications to plugin_system.py**:

```python
class PluginErrorHandler:
    """Advanced error handling for plugin system"""

    def __init__(self):
        self.error_log = []
        self.recovery_strategies = {
            "ImportError": self.handle_import_error,
            "SyntaxError": self.handle_syntax_error,
            "AttributeError": self.handle_attribute_error,
            "Exception": self.handle_generic_error
        }

    def handle_plugin_error(self, plugin_name: str, error: Exception, context: str = "") -> Dict:
        """Handle plugin errors with recovery suggestions"""
        error_type = type(error).__name__

        # Log error
        error_entry = {
            "plugin": plugin_name,
            "error_type": error_type,
            "message": str(error),
            "context": context,
            "timestamp": time.time(),
            "traceback": traceback.format_exc()
        }
        self.error_log.append(error_entry)

        # Get recovery strategy
        handler = self.recovery_strategies.get(error_type, self.handle_generic_error)
        recovery = handler(error, plugin_name)

        return {
            "error": error_entry,
            "recovery": recovery,
            "can_recover": recovery.get("can_recover", False)
        }

    def handle_import_error(self, error: ImportError, plugin_name: str) -> Dict:
        """Handle import errors with specific suggestions"""
        missing_module = str(error).split("'")[1] if "'" in str(error) else "unknown"

        suggestions = []

        # Check common modules
        if missing_module in ["numpy", "scipy", "pandas"]:
            suggestions.append(f"Install {missing_module}: pip install {missing_module}")

        if missing_module.startswith("intellicrack"):
            suggestions.append("Ensure Intellicrack is properly installed")
            suggestions.append("Check if running from correct directory")

        return {
            "can_recover": False,
            "suggestions": suggestions,
            "fix_action": f"Install missing module: {missing_module}"
        }

    def handle_syntax_error(self, error: SyntaxError, plugin_name: str) -> Dict:
        """Handle syntax errors with line information"""
        return {
            "can_recover": False,
            "suggestions": [
                f"Syntax error at line {error.lineno}: {error.msg}",
                "Check for missing colons, parentheses, or indentation",
                "Use the plugin editor for syntax highlighting"
            ],
            "fix_action": "Fix syntax error in plugin code"
        }

    def handle_attribute_error(self, error: AttributeError, plugin_name: str) -> Dict:
        """Handle attribute errors"""
        suggestions = []

        if "analyze" in str(error):
            suggestions.append("Plugin must have an 'analyze' method")
            suggestions.append("Check method spelling and indentation")

        if "register" in str(error):
            suggestions.append("Plugin file must have a 'register' function")

        return {
            "can_recover": False,
            "suggestions": suggestions,
            "fix_action": "Add missing method or attribute"
        }

    def handle_generic_error(self, error: Exception, plugin_name: str) -> Dict:
        """Handle generic errors"""
        return {
            "can_recover": False,
            "suggestions": [
                "Check plugin code for errors",
                "Ensure all required methods are implemented",
                "Test plugin with simpler input first"
            ],
            "fix_action": "Debug plugin code"
        }

    def create_error_report(self, plugin_name: str) -> str:
        """Create detailed error report for a plugin"""
        plugin_errors = [e for e in self.error_log if e["plugin"] == plugin_name]

        if not plugin_errors:
            return "No errors recorded for this plugin"

        report = f"Error Report for {plugin_name}\n"
        report += "=" * 50 + "\n\n"

        for i, error in enumerate(plugin_errors, 1):
            report += f"Error #{i}\n"
            report += f"Time: {time.ctime(error['timestamp'])}\n"
            report += f"Type: {error['error_type']}\n"
            report += f"Message: {error['message']}\n"
            report += f"Context: {error['context']}\n"
            report += f"Traceback:\n{error['traceback']}\n"
            report += "-" * 30 + "\n\n"

        return report
```

### 5.2 Plugin Debugging and Logging Tools

**New File**: `intellicrack/plugins/plugin_debugger.py`

```python
import sys
import io
import logging
from contextlib import contextmanager
from typing import Any, Dict, List

class PluginDebugger:
    """Advanced debugging tools for plugin development"""

    def __init__(self):
        self.breakpoints = {}
        self.watch_variables = {}
        self.execution_log = []
        self.output_buffer = io.StringIO()

    def set_breakpoint(self, plugin_name: str, line_number: int, condition: str = None):
        """Set a breakpoint in plugin code"""
        if plugin_name not in self.breakpoints:
            self.breakpoints[plugin_name] = []

        self.breakpoints[plugin_name].append({
            "line": line_number,
            "condition": condition,
            "hit_count": 0
        })

    def watch_variable(self, plugin_name: str, variable_name: str):
        """Watch a variable during plugin execution"""
        if plugin_name not in self.watch_variables:
            self.watch_variables[plugin_name] = []

        self.watch_variables[plugin_name].append(variable_name)

    @contextmanager
    def debug_context(self, plugin_name: str):
        """Context manager for debugging plugin execution"""
        # Set up logging
        logger = logging.getLogger(plugin_name)
        handler = logging.StreamHandler(self.output_buffer)
        handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)

        # Capture stdout/stderr
        old_stdout = sys.stdout
        old_stderr = sys.stderr
        sys.stdout = self.output_buffer
        sys.stderr = self.output_buffer

        try:
            yield logger
        finally:
            # Restore stdout/stderr
            sys.stdout = old_stdout
            sys.stderr = old_stderr

            # Remove handler
            logger.removeHandler(handler)

            # Get output
            output = self.output_buffer.getvalue()
            self.execution_log.append({
                "plugin": plugin_name,
                "output": output,
                "timestamp": time.time()
            })

    def trace_execution(self, plugin_name: str, func):
        """Trace plugin function execution"""
        def traced_func(*args, **kwargs):
            self.log_call(plugin_name, func.__name__, args, kwargs)

            try:
                result = func(*args, **kwargs)
                self.log_return(plugin_name, func.__name__, result)
                return result
            except Exception as e:
                self.log_exception(plugin_name, func.__name__, e)
                raise

        return traced_func

    def log_call(self, plugin_name: str, func_name: str, args: tuple, kwargs: dict):
        """Log function call"""
        self.execution_log.append({
            "type": "call",
            "plugin": plugin_name,
            "function": func_name,
            "args": str(args),
            "kwargs": str(kwargs),
            "timestamp": time.time()
        })

    def log_return(self, plugin_name: str, func_name: str, result: Any):
        """Log function return"""
        self.execution_log.append({
            "type": "return",
            "plugin": plugin_name,
            "function": func_name,
            "result": str(result),
            "timestamp": time.time()
        })

    def log_exception(self, plugin_name: str, func_name: str, exception: Exception):
        """Log exception"""
        self.execution_log.append({
            "type": "exception",
            "plugin": plugin_name,
            "function": func_name,
            "exception": str(exception),
            "traceback": traceback.format_exc(),
            "timestamp": time.time()
        })

    def get_execution_trace(self, plugin_name: str = None) -> List[Dict]:
        """Get execution trace for debugging"""
        if plugin_name:
            return [log for log in self.execution_log if log.get("plugin") == plugin_name]
        return self.execution_log

    def create_debug_report(self, plugin_name: str) -> str:
        """Create comprehensive debug report"""
        report = f"Debug Report for {plugin_name}\n"
        report += "=" * 50 + "\n\n"

        # Execution trace
        trace = self.get_execution_trace(plugin_name)
        if trace:
            report += "Execution Trace:\n"
            for entry in trace:
                timestamp = time.strftime("%H:%M:%S", time.localtime(entry["timestamp"]))
                if entry["type"] == "call":
                    report += f"[{timestamp}] CALL {entry['function']}({entry['args']})\n"
                elif entry["type"] == "return":
                    report += f"[{timestamp}] RETURN {entry['function']} -> {entry['result']}\n"
                elif entry["type"] == "exception":
                    report += f"[{timestamp}] EXCEPTION in {entry['function']}: {entry['exception']}\n"

        # Output
        output = self.output_buffer.getvalue()
        if output:
            report += "\nPlugin Output:\n"
            report += output

        return report
```

**New File**: `intellicrack/ui/widgets/plugin_console.py`

```python
class PluginConsole(QWidget):
    """Plugin execution console with debugging features"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.debugger = PluginDebugger()
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)

        # Toolbar
        toolbar = QToolBar()

        clear_action = toolbar.addAction("Clear")
        clear_action.triggered.connect(self.clear_console)

        save_action = toolbar.addAction("Save Log")
        save_action.triggered.connect(self.save_log)

        toolbar.addSeparator()

        self.filter_combo = QComboBox()
        self.filter_combo.addItems(["All", "Info", "Warning", "Error", "Debug"])
        self.filter_combo.currentTextChanged.connect(self.apply_filter)
        toolbar.addWidget(QLabel("Filter:"))
        toolbar.addWidget(self.filter_combo)

        layout.addWidget(toolbar)

        # Console output
        self.console_output = QTextEdit()
        self.console_output.setReadOnly(True)
        self.console_output.setFont(QFont("Consolas", 9))
        layout.addWidget(self.console_output)

        # Input area for debugging commands
        input_layout = QHBoxLayout()
        self.command_input = QLineEdit()
        self.command_input.setPlaceholderText("Enter debug command...")
        self.command_input.returnPressed.connect(self.execute_command)

        self.execute_btn = QPushButton("Execute")
        self.execute_btn.clicked.connect(self.execute_command)

        input_layout.addWidget(self.command_input)
        input_layout.addWidget(self.execute_btn)

        layout.addLayout(input_layout)

    def log_message(self, message: str, level: str = "info"):
        """Log a message to the console"""
        timestamp = time.strftime("%H:%M:%S")

        # Color coding based on level
        colors = {
            "info": "black",
            "warning": "orange",
            "error": "red",
            "debug": "blue",
            "success": "green"
        }

        color = colors.get(level.lower(), "black")

        # Format message
        formatted = f'<span style="color: gray">[{timestamp}]</span> '
        formatted += f'<span style="color: {color}">[{level.upper()}]</span> '
        formatted += f'<span>{message}</span>'

        # Append to console
        cursor = self.console_output.textCursor()
        cursor.movePosition(cursor.End)
        cursor.insertHtml(formatted + "<br>")
        self.console_output.setTextCursor(cursor)

        # Auto-scroll
        self.console_output.verticalScrollBar().setValue(
            self.console_output.verticalScrollBar().maximum()
        )

    def clear_console(self):
        """Clear console output"""
        self.console_output.clear()
        self.log_message("Console cleared", "info")

    def save_log(self):
        """Save console log to file"""
        filename, _ = QFileDialog.getSaveFileName(
            self, "Save Log", "", "Text Files (*.txt);;All Files (*)"
        )

        if filename:
            with open(filename, 'w') as f:
                f.write(self.console_output.toPlainText())
            self.log_message(f"Log saved to {filename}", "success")

    def apply_filter(self, filter_level: str):
        """Apply log level filter"""
        # Implementation depends on how logs are stored
        self.log_message(f"Filter applied: {filter_level}", "info")

    def execute_command(self):
        """Execute debug command"""
        command = self.command_input.text().strip()
        if not command:
            return

        self.log_message(f"> {command}", "debug")

        # Process debug commands
        if command.startswith("break "):
            # Set breakpoint
            parts = command.split()
            if len(parts) >= 2:
                self.log_message(f"Breakpoint set at line {parts[1]}", "success")

        elif command.startswith("watch "):
            # Watch variable
            var_name = command[6:]
            self.log_message(f"Watching variable: {var_name}", "success")

        elif command == "trace":
            # Show execution trace
            trace = self.debugger.get_execution_trace()
            for entry in trace[-10:]:  # Last 10 entries
                self.log_message(str(entry), "debug")

        elif command == "help":
            # Show help
            help_text = """
Debug Commands:
  break <line>  - Set breakpoint at line
  watch <var>   - Watch variable
  trace         - Show execution trace
  clear         - Clear console
  help          - Show this help
            """
            self.log_message(help_text, "info")

        else:
            self.log_message(f"Unknown command: {command}", "error")

        self.command_input.clear()
```

---

## Phase 6: Advanced Features (Week 6)

### 6.1 Plugin Backup and Version Management

**New File**: `intellicrack/plugins/plugin_backup.py`

```python
import os
import shutil
import json
import hashlib
from datetime import datetime
from typing import Dict, List, Optional

class PluginBackupManager:
    """Manage plugin backups and version history"""

    def __init__(self, backup_dir: str = None):
        if backup_dir:
            self.backup_dir = backup_dir
        else:
            # Default backup directory
            self.backup_dir = os.path.join(
                os.path.expanduser("~"),
                ".intellicrack",
                "plugin_backups"
            )

        os.makedirs(self.backup_dir, exist_ok=True)
        self.version_index_file = os.path.join(self.backup_dir, "version_index.json")
        self.version_index = self.load_version_index()

    def load_version_index(self) -> Dict:
        """Load version index from file"""
        if os.path.exists(self.version_index_file):
            with open(self.version_index_file, 'r') as f:
                return json.load(f)
        return {}

    def save_version_index(self):
        """Save version index to file"""
        with open(self.version_index_file, 'w') as f:
            json.dump(self.version_index, f, indent=2)

    def create_backup(self, plugin_path: str, description: str = "") -> Optional[str]:
        """Create a backup of a plugin"""
        if not os.path.exists(plugin_path):
            return None

        plugin_name = os.path.basename(plugin_path)

        # Calculate file hash
        with open(plugin_path, 'rb') as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()[:8]

        # Create backup filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_name = f"{plugin_name}.{timestamp}.{file_hash}.bak"
        backup_path = os.path.join(self.backup_dir, backup_name)

        # Copy file
        shutil.copy2(plugin_path, backup_path)

        # Update version index
        if plugin_name not in self.version_index:
            self.version_index[plugin_name] = []

        self.version_index[plugin_name].append({
            "backup_path": backup_path,
            "original_path": plugin_path,
            "timestamp": timestamp,
            "hash": file_hash,
            "description": description,
            "size": os.path.getsize(plugin_path)
        })

        self.save_version_index()
        return backup_path

    def get_plugin_history(self, plugin_name: str) -> List[Dict]:
        """Get version history for a plugin"""
        return self.version_index.get(plugin_name, [])

    def restore_backup(self, backup_info: Dict) -> bool:
        """Restore a plugin from backup"""
        backup_path = backup_info["backup_path"]
        original_path = backup_info["original_path"]

        if not os.path.exists(backup_path):
            return False

        # Create backup of current version before restoring
        if os.path.exists(original_path):
            self.create_backup(original_path, "Before restore")

        # Restore from backup
        shutil.copy2(backup_path, original_path)
        return True

    def compare_versions(self, plugin_name: str, version1_idx: int, version2_idx: int) -> Dict:
        """Compare two versions of a plugin"""
        history = self.get_plugin_history(plugin_name)

        if version1_idx >= len(history) or version2_idx >= len(history):
            return {"error": "Invalid version index"}

        v1 = history[version1_idx]
        v2 = history[version2_idx]

        # Read both versions
        with open(v1["backup_path"], 'r') as f:
            content1 = f.readlines()

        with open(v2["backup_path"], 'r') as f:
            content2 = f.readlines()

        # Simple diff
        import difflib
        diff = list(difflib.unified_diff(
            content1, content2,
            fromfile=f"{plugin_name} v{version1_idx}",
            tofile=f"{plugin_name} v{version2_idx}",
            lineterm=''
        ))

        return {
            "version1": v1,
            "version2": v2,
            "diff": diff,
            "additions": sum(1 for line in diff if line.startswith('+')),
            "deletions": sum(1 for line in diff if line.startswith('-'))
        }

    def cleanup_old_backups(self, plugin_name: str, keep_count: int = 10):
        """Remove old backups, keeping only the most recent ones"""
        history = self.get_plugin_history(plugin_name)

        if len(history) <= keep_count:
            return

        # Sort by timestamp (newest first)
        history.sort(key=lambda x: x["timestamp"], reverse=True)

        # Remove old backups
        for backup in history[keep_count:]:
            if os.path.exists(backup["backup_path"]):
                os.remove(backup["backup_path"])

        # Update index
        self.version_index[plugin_name] = history[:keep_count]
        self.save_version_index()
```

### 6.2 Plugin Dependency Management

**New File**: `intellicrack/plugins/plugin_dependencies.py`

```python
import ast
import pkg_resources
import subprocess
import sys
from typing import Dict, List, Set, Tuple

class PluginDependencyManager:
    """Manage plugin dependencies"""

    def __init__(self):
        self.installed_packages = self.get_installed_packages()
        self.intellicrack_modules = self.get_intellicrack_modules()

    def get_installed_packages(self) -> Set[str]:
        """Get list of installed Python packages"""
        return {pkg.key for pkg in pkg_resources.working_set}

    def get_intellicrack_modules(self) -> Set[str]:
        """Get list of available Intellicrack modules"""
        modules = set()

        # Core modules
        modules.update([
            "intellicrack.utils",
            "intellicrack.core",
            "intellicrack.core.analysis",
            "intellicrack.core.patching",
            "intellicrack.plugins"
        ])

        return modules

    def analyze_plugin_dependencies(self, plugin_path: str) -> Dict:
        """Analyze plugin dependencies"""
        result = {
            "external_packages": [],
            "intellicrack_modules": [],
            "missing_packages": [],
            "available_packages": [],
            "suggestions": []
        }

        try:
            with open(plugin_path, 'r') as f:
                tree = ast.parse(f.read())

            imports = self.extract_imports(tree)

            for module in imports:
                # Check if it's an Intellicrack module
                if module.startswith("intellicrack"):
                    result["intellicrack_modules"].append(module)
                    if module not in self.intellicrack_modules:
                        result["suggestions"].append(
                            f"Module '{module}' not found in Intellicrack"
                        )

                # Check if it's a standard library module
                elif module in sys.stdlib_module_names:
                    continue  # Standard library, always available

                # External package
                else:
                    package_name = module.split('.')[0]
                    result["external_packages"].append(package_name)

                    if package_name in self.installed_packages:
                        result["available_packages"].append(package_name)
                    else:
                        result["missing_packages"].append(package_name)
                        result["suggestions"].append(
                            f"Install missing package: pip install {package_name}"
                        )

        except Exception as e:
            result["error"] = str(e)

        return result

    def extract_imports(self, tree: ast.AST) -> List[str]:
        """Extract all imports from AST"""
        imports = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.append(alias.name)

            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imports.append(node.module)

        return imports

    def install_dependencies(self, packages: List[str]) -> Tuple[bool, str]:
        """Install missing dependencies"""
        if not packages:
            return True, "No packages to install"

        try:
            # Use subprocess to install packages
            cmd = [sys.executable, "-m", "pip", "install"] + packages
            result = subprocess.run(cmd, capture_output=True, text=True)

            if result.returncode == 0:
                # Update installed packages list
                self.installed_packages = self.get_installed_packages()
                return True, f"Successfully installed: {', '.join(packages)}"
            else:
                return False, f"Installation failed: {result.stderr}"

        except Exception as e:
            return False, f"Error installing packages: {str(e)}"

    def check_compatibility(self, plugin_path: str) -> Dict:
        """Check plugin compatibility with current environment"""
        result = {
            "compatible": True,
            "issues": [],
            "python_version": sys.version,
            "platform": sys.platform
        }

        try:
            with open(plugin_path, 'r') as f:
                content = f.read()

            # Check for platform-specific code
            if "win32" in content and sys.platform != "win32":
                result["issues"].append("Plugin contains Windows-specific code")
                result["compatible"] = False

            if "linux" in content and not sys.platform.startswith("linux"):
                result["issues"].append("Plugin contains Linux-specific code")
                result["compatible"] = False

            # Check Python version requirements
            if "python_requires" in content:
                # Extract version requirement
                # This is simplified - real implementation would parse properly
                result["issues"].append("Plugin has specific Python version requirements")

        except Exception as e:
            result["error"] = str(e)
            result["compatible"] = False

        return result
```

---

## Phase 7: Integration (Week 7)

### 7.1 Streamline with Independent Frida/Ghidra Managers

**Modifications to plugin_system.py**:

```python
# Remove legacy Frida/Ghidra loading code
# Update load_plugins function to focus on custom modules only

def load_plugins(plugin_dir: str = None) -> Dict[str, List[Dict[str, Any]]]:
    """
    Load plugins from the plugin directory.
    Now focuses exclusively on custom Python modules.

    Frida and Ghidra scripts are managed by their respective managers:
    - FridaManager (intellicrack/core/frida_manager.py)
    - GhidraScriptManager (intellicrack/utils/ghidra_script_manager.py)
    """
    if not plugin_dir:
        plugin_dir = os.path.join(os.path.dirname(__file__))

    plugins = {
        "custom": []  # Only custom Python plugins
    }

    # Ensure plugin directory exists
    if not os.path.exists(plugin_dir):
        os.makedirs(plugin_dir)
        os.makedirs(os.path.join(plugin_dir, "custom_modules"), exist_ok=True)

    # Load custom Python modules
    custom_dir = os.path.join(plugin_dir, "custom_modules")
    if os.path.exists(custom_dir):
        # Add to Python path
        sys.path.insert(0, custom_dir)

        for _file in os.listdir(custom_dir):
            if _file.endswith(".py") and not _file.startswith("__"):
                plugin_name = os.path.splitext(_file)[0]

                try:
                    # Import the module
                    module_name = plugin_name
                    module = importlib.import_module(module_name)

                    # Check if it has a register function
                    if hasattr(module, "register"):
                        plugin_instance = module.register()

                        # Extract metadata
                        metadata = extract_plugin_metadata(plugin_instance)

                        plugins["custom"].append({
                            "name": metadata.get("name", plugin_name),
                            "module": module_name,
                            "instance": plugin_instance,
                            "description": metadata.get("description", ""),
                            "version": metadata.get("version", "0.0.0"),
                            "author": metadata.get("author", "Unknown"),
                            "capabilities": metadata.get("capabilities", []),
                            "path": os.path.join(custom_dir, _file)
                        })
                except Exception as e:
                    logger.error("Error loading custom plugin %s: %s", _file, e)

    logger.info(f"Loaded {len(plugins['custom'])} custom plugins")
    return plugins

def extract_plugin_metadata(plugin_instance) -> Dict[str, Any]:
    """Extract comprehensive metadata from plugin instance"""
    metadata = {}

    # Try to get metadata from various sources
    if hasattr(plugin_instance, 'get_metadata'):
        metadata.update(plugin_instance.get_metadata())

    # Direct attributes
    for attr in ['name', 'version', 'author', 'description', 'capabilities']:
        if hasattr(plugin_instance, attr):
            metadata[attr] = getattr(plugin_instance, attr)

    return metadata
```

### 7.2 Plugin Execution Optimization

**Performance optimizations for plugin_system.py**:

```python
class PluginCache:
    """Cache for plugin metadata and instances"""

    def __init__(self):
        self.metadata_cache = {}
        self.instance_cache = {}
        self.last_modified = {}

    def get_plugin_metadata(self, plugin_path: str) -> Optional[Dict]:
        """Get cached plugin metadata"""
        # Check if file has been modified
        current_mtime = os.path.getmtime(plugin_path)

        if plugin_path in self.metadata_cache:
            if self.last_modified.get(plugin_path) == current_mtime:
                return self.metadata_cache[plugin_path]

        # Cache miss or file modified
        return None

    def cache_plugin_metadata(self, plugin_path: str, metadata: Dict):
        """Cache plugin metadata"""
        self.metadata_cache[plugin_path] = metadata
        self.last_modified[plugin_path] = os.path.getmtime(plugin_path)

    def clear_cache(self, plugin_path: str = None):
        """Clear cache for specific plugin or all"""
        if plugin_path:
            self.metadata_cache.pop(plugin_path, None)
            self.instance_cache.pop(plugin_path, None)
            self.last_modified.pop(plugin_path, None)
        else:
            self.metadata_cache.clear()
            self.instance_cache.clear()
            self.last_modified.clear()

# Global cache instance
plugin_cache = PluginCache()

class OptimizedPluginLoader:
    """Optimized plugin loading with lazy evaluation"""

    def __init__(self):
        self.loading_queue = []
        self.loaded_plugins = {}

    def queue_plugin_load(self, plugin_path: str):
        """Queue plugin for lazy loading"""
        if plugin_path not in self.loading_queue:
            self.loading_queue.append(plugin_path)

    def load_queued_plugins(self) -> Dict[str, Any]:
        """Load all queued plugins efficiently"""
        results = {}

        for plugin_path in self.loading_queue:
            # Check cache first
            metadata = plugin_cache.get_plugin_metadata(plugin_path)

            if metadata:
                results[plugin_path] = metadata
            else:
                # Load plugin
                try:
                    metadata = self.load_plugin_metadata(plugin_path)
                    plugin_cache.cache_plugin_metadata(plugin_path, metadata)
                    results[plugin_path] = metadata
                except Exception as e:
                    logger.error(f"Failed to load plugin {plugin_path}: {e}")
                    results[plugin_path] = {"error": str(e)}

        self.loading_queue.clear()
        return results

    def load_plugin_metadata(self, plugin_path: str) -> Dict:
        """Load plugin metadata without full instantiation"""
        metadata = {
            "path": plugin_path,
            "name": os.path.basename(plugin_path),
            "size": os.path.getsize(plugin_path)
        }

        try:
            # Parse file for metadata without executing
            with open(plugin_path, 'r') as f:
                content = f.read()

            # Extract from docstring
            tree = ast.parse(content)
            docstring = ast.get_docstring(tree)
            if docstring:
                metadata["description"] = docstring.split('\n')[0]

            # Extract from constants
            for node in ast.walk(tree):
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            if target.id == "PLUGIN_NAME":
                                metadata["name"] = ast.literal_eval(node.value)
                            elif target.id == "PLUGIN_VERSION":
                                metadata["version"] = ast.literal_eval(node.value)
                            elif target.id == "PLUGIN_AUTHOR":
                                metadata["author"] = ast.literal_eval(node.value)

        except Exception as e:
            metadata["parse_error"] = str(e)

        return metadata
```

---

## Phase 8: Polish (Week 8)

### 8.1 UI Refinements and User Experience Improvements

**UI Polish Tasks**:

1. **Consistent Styling**
   - Create unified style sheet for all plugin UI components
   - Consistent icon usage across plugin features
   - Improved spacing and alignment

2. **Keyboard Shortcuts**
   - Ctrl+N: Create new plugin
   - Ctrl+E: Edit selected plugin
   - Ctrl+T: Test plugin
   - F5: Run plugin
   - Ctrl+S: Save plugin changes

3. **Visual Feedback**
   - Loading indicators during plugin operations
   - Success/error animations
   - Progress indicators for long operations

4. **Accessibility**
   - Proper tab order for keyboard navigation
   - Screen reader friendly labels
   - High contrast mode support

### 8.2 Comprehensive Testing and Bug Fixes

**Test Suite Creation**:

```python
# tests/test_plugin_system_integration.py

import unittest
import tempfile
import os
from intellicrack.plugins import plugin_system
from intellicrack.plugins.plugin_validator import PluginValidator
from intellicrack.plugins.plugin_tester import PluginTester

class TestPluginSystemIntegration(unittest.TestCase):
    """Comprehensive integration tests for plugin system"""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.validator = PluginValidator()
        self.tester = PluginTester()

    def tearDown(self):
        # Cleanup
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_plugin_creation_workflow(self):
        """Test complete plugin creation workflow"""
        # Create plugin from template
        plugin_code = plugin_system.generate_plugin_template("simple")
        self.assertIn("def analyze", plugin_code)
        self.assertIn("def register", plugin_code)

        # Validate plugin
        result = self.validator.validate_full(plugin_code)
        self.assertTrue(result['valid'])

        # Save plugin
        plugin_path = os.path.join(self.test_dir, "test_plugin.py")
        with open(plugin_path, 'w') as f:
            f.write(plugin_code)

        # Test plugin execution
        test_result = self.tester.test_plugin_execution(plugin_path)
        self.assertTrue(test_result['passed'])

    def test_plugin_error_handling(self):
        """Test error handling and recovery"""
        # Create plugin with syntax error
        bad_plugin = "def analyze(self, path)\n    return []"  # Missing colon

        # Validate should catch error
        result = self.validator.validate_syntax(bad_plugin)
        self.assertFalse(result[0])
        self.assertIn("Syntax error", result[1][0])

    def test_plugin_performance(self):
        """Test plugin performance monitoring"""
        # Create simple plugin
        plugin_code = '''
class TestPlugin:
    def __init__(self):
        self.name = "Test Plugin"

    def analyze(self, path):
        import time
        time.sleep(0.1)  # Simulate work
        return ["Test result"]

def register():
    return TestPlugin()
'''

        plugin_path = os.path.join(self.test_dir, "perf_test.py")
        with open(plugin_path, 'w') as f:
            f.write(plugin_code)

        # Test performance
        perf_result = self.tester.test_plugin_performance(plugin_path, iterations=5)

        self.assertGreater(perf_result['average_time'], 0.09)
        self.assertLess(perf_result['average_time'], 0.15)

    def test_plugin_backup_restore(self):
        """Test backup and restore functionality"""
        from intellicrack.plugins.plugin_backup import PluginBackupManager

        backup_mgr = PluginBackupManager(self.test_dir)

        # Create plugin
        plugin_path = os.path.join(self.test_dir, "backup_test.py")
        with open(plugin_path, 'w') as f:
            f.write("# Version 1")

        # Create backup
        backup_path = backup_mgr.create_backup(plugin_path, "Initial version")
        self.assertTrue(os.path.exists(backup_path))

        # Modify plugin
        with open(plugin_path, 'w') as f:
            f.write("# Version 2")

        # Get history
        history = backup_mgr.get_plugin_history("backup_test.py")
        self.assertEqual(len(history), 1)

        # Restore
        success = backup_mgr.restore_backup(history[0])
        self.assertTrue(success)

        # Verify restored content
        with open(plugin_path, 'r') as f:
            content = f.read()
        self.assertEqual(content, "# Version 1")
```

### 8.3 Documentation Updates and Final Validation

**Update Documentation Files**:

1. **Update `/docs/development/plugins.md`**:
   - Add new features documentation
   - Update API reference
   - Add troubleshooting section
   - Include best practices guide

2. **Create Plugin Development Guide**:
   - Step-by-step tutorials
   - Common patterns and examples
   - Performance optimization tips
   - Security considerations

3. **Update README.md**:
   - Add plugin system overview
   - Quick start guide for plugin development
   - Link to detailed documentation

---

## Implementation Checklist

### Pre-Implementation
- [ ] Review and approve implementation plan
- [ ] Set up development branch
- [ ] Prepare test environment
- [ ] Backup current plugin system

### Phase 1: UI Enhancement
- [ ] Add tooltips to all components
- [ ] Implement help buttons
- [ ] Enhance plugin list display
- [ ] Create welcome workflow
- [ ] Test UI improvements

### Phase 2: Development Tools
- [ ] Implement plugin validator
- [ ] Create enhanced editor
- [ ] Build template wizard
- [ ] Test development tools

### Phase 3: Testing Framework
- [ ] Build plugin tester
- [ ] Add performance monitoring
- [ ] Create test dialog
- [ ] Validate testing tools

### Phase 4: Documentation
- [ ] Create API viewer
- [ ] Build tutorial system
- [ ] Test documentation tools

### Phase 5: Error Handling
- [ ] Implement error handler
- [ ] Create debugger
- [ ] Build console widget
- [ ] Test error handling

### Phase 6: Advanced Features
- [ ] Add backup system
- [ ] Implement dependency management
- [ ] Test advanced features

### Phase 7: Integration
- [ ] Streamline architecture
- [ ] Optimize performance
- [ ] Test integration

### Phase 8: Polish
- [ ] Apply UI refinements
- [ ] Run comprehensive tests
- [ ] Update documentation
- [ ] Final validation

### Post-Implementation
- [ ] Code review
- [ ] Performance testing
- [ ] User acceptance testing
- [ ] Merge to main branch
- [ ] Deploy and monitor

## Success Criteria

1. **User Experience**
   - New users can create first plugin in < 5 minutes
   - Clear understanding of plugin capabilities
   - Intuitive workflow without documentation

2. **Development Experience**
   - Real-time validation catches errors before execution
   - Comprehensive API documentation accessible
   - Professional debugging tools available

3. **System Quality**
   - All tests pass with > 95% coverage
   - Performance metrics meet targets
   - No critical bugs in production

4. **Documentation**
   - Complete API reference available
   - Step-by-step tutorials created
   - Troubleshooting guide comprehensive

## Risk Mitigation

1. **Backward Compatibility**
   - Maintain support for existing plugins
   - Provide migration tools if needed
   - Test with current plugin collection

2. **Performance Impact**
   - Profile all new features
   - Implement caching where appropriate
   - Lazy load heavy components

3. **Complexity Creep**
   - Focus on single-user experience
   - Avoid over-engineering
   - Regular design reviews

## Conclusion

This comprehensive plan transforms Intellicrack's plugin system from an underutilized feature into a powerful, user-friendly extensibility platform. The implementation focuses on practical improvements that directly benefit single users developing custom analysis tools.

Total estimated effort: 8 weeks
Expected outcome: Professional plugin development environment that justifies its existence through genuine user value.

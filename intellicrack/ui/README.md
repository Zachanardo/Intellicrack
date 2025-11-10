# Intellicrack User Interface

The UI module provides a modern, professional graphical interface built with
PyQt6 for cross-platform compatibility.

## Architecture Overview

The UI follows a modular design with clear separation between:

- **Main Application** - Core window and application management
- **Widgets** - Reusable UI components
- **Dialogs** - Modal windows for specific tasks
- **Utilities** - Common UI helpers and styling

## Module Structure

### Core Application (`main_*.py`)

- **main_app.py** - Main application class and startup logic
- **main_window.py** - Primary application window with three-panel layout
- **menu_utils.py** - Menu bar and context menu management
- **shared_ui_layouts.py** - Common layout templates
- **style_utils.py** - Consistent styling and theming
- **tooltip_helper.py** - Enhanced tooltip functionality

### Widget Components (`widgets/`)

Reusable UI components for different analysis functions:

- **batch_analysis_widget.py** - Batch processing interface
- **console_widget.py** - Integrated console/terminal
- **hex_viewer.py** - Binary hex editor component
- **hex_viewer_widget.py** - Enhanced hex viewer with features
- **icp_analysis_widget.py** - ICP engine analysis interface
- **intellicrack_protection_widget.py** - Protection analysis display
- **intellicrack_advanced_protection_widget.py** - Advanced protection details
- **plugin_editor.py** - Plugin development interface
- **string_extraction_widget.py** - String analysis and extraction
- **unified_protection_widget.py** - Unified protection overview
- **widget_factory.py** - Widget creation and management

### Dialog Windows (`dialogs/`)

Specialized modal dialogs for specific tasks:

#### Analysis & Configuration

- **frida_manager_dialog.py** - Frida script management
- **llm_config_dialog.py** - LLM backend configuration
- **model_manager_dialog.py** - AI model management
- **preferences_dialog.py** - Application settings
- **script_generator_dialog.py** - Script generation interface

#### Development & Testing

- **ci_cd_dialog.py** - CI/CD pipeline integration
- **model_finetuning_dialog.py** - AI model fine-tuning
- **plugin_creation_wizard.py** - Plugin development wizard
- **plugin_manager_dialog.py** - Plugin management interface
- **test_generator_dialog.py** - Test case generation
- **qemu_test_dialog.py** - QEMU testing interface
- **qemu_test_results_dialog.py** - QEMU test results

#### Advanced Tools

- **c2_management_dialog.py** - C2 infrastructure management
- **guided_workflow_wizard.py** - Step-by-step analysis workflows
- **keygen_dialog.py** - Key generation utilities
- **model_loading_dialog.py** - Model loading progress
- **payload_generator_dialog.py** - Payload generation interface
- **similarity_search_dialog.py** - Binary similarity search
- **smart_program_selector_dialog.py** - Intelligent program selection
- **system_utilities_dialog.py** - System utility access
- **visual_patch_editor.py** - Visual binary patching
- **vulnerability_research_dialog.py** - Vulnerability research tools

#### Common Components

- **common_imports.py** - Shared imports and dependencies
- **event_handler_utils.py** - Event handling utilities

### Specialized Components

- **adobe_injector_src/** - Adobe-specific injection interfaces
- **Windows_Patch/** - Windows-specific patching utilities
- **models/** - UI data models and structures

### Integration Modules

- **emulator_ui_enhancements.py** - Emulator interface improvements
- **exploitation_handlers.py** - Exploitation workflow handlers

## Key Features

### Three-Panel Layout

The main interface uses a professional three-panel design:

1. **Left Panel** - File browser and project navigation
2. **Center Panel** - Primary analysis view (hex editor, disassembly, etc.)
3. **Right Panel** - Analysis results, properties, and tools

### Modern UI Elements

- **Dark/Light Theme Support** - Automatic theme detection
- **Responsive Layout** - Adapts to different screen sizes
- **Professional Styling** - Consistent look and feel
- **Context Menus** - Right-click functionality throughout
- **Keyboard Shortcuts** - Efficient workflow navigation

### Advanced Widgets

- **Enhanced Hex Viewer** - Multi-format display with syntax highlighting
- **Integrated Console** - Embedded terminal for command execution
- **Real-time Logging** - Live log display with filtering
- **Progress Indicators** - Visual feedback for long operations
- **Interactive Charts** - Analysis result visualization

## Usage Examples

### Basic Window Creation

```python
from intellicrack.ui.main_app import IntellicracApp
from PyQt6.QtWidgets import QApplication
import sys

# Create application
app = QApplication(sys.argv)
main_window = IntellicracApp()
main_window.show()

# Start event loop
sys.exit(app.exec_())
```

### Custom Widget Integration

```python
from intellicrack.ui.widgets.widget_factory import WidgetFactory
from PyQt6.QtWidgets import QWidget

class CustomAnalysisWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()

    def setup_ui(self):
        # Use widget factory for consistent styling
        layout = WidgetFactory.create_vertical_layout()
        self.setLayout(layout)
```

### Dialog Implementation

```python
from intellicrack.ui.dialogs.common_imports import *

class CustomDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Custom Dialog")
        self.setup_ui()
        self.load_settings()

    def setup_ui(self):
        layout = QVBoxLayout()
        # Add UI elements
        self.setLayout(layout)

    def accept(self):
        self.save_settings()
        super().accept()
```

## Styling and Theming

### Style Management

The UI uses a centralized styling system:

```python
from intellicrack.ui.style_utils import apply_style, get_theme_color

# Apply consistent styling
apply_style(widget, "primary-button")

# Get theme-appropriate colors
bg_color = get_theme_color("background")
accent_color = get_theme_color("accent")
```

### Theme Support

- **Automatic Detection** - Follows system theme preferences
- **Manual Override** - User can select preferred theme
- **Consistent Colors** - Theme-aware color palette
- **Icon Adaptation** - Icons adapt to theme

## Event Handling

### Centralized Event Management

```python
from intellicrack.ui.dialogs.event_handler_utils import EventHandler

class MyWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.event_handler = EventHandler(self)
        self.setup_events()

    def setup_events(self):
        self.event_handler.connect_button(
            self.analyze_button,
            self.start_analysis
        )
```

### Custom Events

```python
from PyQt6.QtCore import pyqtSignal

class AnalysisWidget(QWidget):
    analysis_completed = pyqtSignal(dict)

    def finish_analysis(self, results):
        self.analysis_completed.emit(results)
```

## Plugin UI Integration

### Plugin Widget Creation

```python
from intellicrack.ui.widgets.plugin_editor import PluginEditor

class PluginWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.plugin_editor = PluginEditor(self)

    def load_plugin(self, plugin_path):
        self.plugin_editor.load_plugin_file(plugin_path)
```

### UI Plugin Registration

```python
from intellicrack.plugins import PluginBase

class UIPlugin(PluginBase):
    def create_widget(self, parent):
        """Create plugin-specific widget"""
        return MyPluginWidget(parent)

    def get_menu_actions(self):
        """Return menu actions for this plugin"""
        return [
            ("My Plugin Action", self.run_action),
            ("Plugin Settings", self.show_settings)
        ]
```

## Configuration and Settings

### Settings Management

```python
from intellicrack.ui.dialogs.preferences_dialog import PreferencesDialog

# Show preferences
prefs = PreferencesDialog(self)
if prefs.exec_() == QDialog.Accepted:
    # Settings were saved
    self.apply_new_settings()
```

### Persistent UI State

```python
from PyQt6.QtCore import QSettings

class MainWindow(QMainWindow):
    def save_state(self):
        settings = QSettings()
        settings.setValue("geometry", self.saveGeometry())
        settings.setValue("windowState", self.saveState())

    def restore_state(self):
        settings = QSettings()
        self.restoreGeometry(settings.value("geometry", b""))
        self.restoreState(settings.value("windowState", b""))
```

## Performance Optimization

### Lazy Loading

- **Widget Creation** - Create widgets only when needed
- **Data Loading** - Load data progressively
- **Image Resources** - Load images on demand

### Memory Management

- **Widget Cleanup** - Proper widget destruction
- **Event Disconnection** - Clean up signal connections
- **Resource Release** - Release graphics resources

### Threading

```python
from PyQt6.QtCore import QThread, pyqtSignal

class AnalysisThread(QThread):
    progress_updated = pyqtSignal(int)
    analysis_completed = pyqtSignal(dict)

    def run(self):
        # Long-running analysis
        for i in range(100):
            # Do work
            self.progress_updated.emit(i)

        self.analysis_completed.emit(results)
```

## Accessibility

### Keyboard Navigation

- **Tab Order** - Logical tab sequence
- **Shortcuts** - Comprehensive keyboard shortcuts
- **Focus Indicators** - Clear focus visualization

### Screen Reader Support

- **Labels** - Descriptive labels for all controls
- **Alt Text** - Alternative text for images
- **ARIA** - Appropriate ARIA attributes

## Testing UI Components

### Unit Testing

```python
import unittest
from PyQt6.QtTest import QTest
from PyQt6.QtCore import Qt

class TestAnalysisWidget(unittest.TestCase):
    def setUp(self):
        self.widget = AnalysisWidget()

    def test_button_click(self):
        # Simulate button click
        QTest.mouseClick(self.widget.analyze_button, Qt.LeftButton)
        self.assertTrue(self.widget.analysis_started)
```

### Integration Testing

```python
def test_full_analysis_workflow(self):
    # Test complete analysis workflow
    self.load_binary("test_file.exe")
    self.start_analysis()
    self.wait_for_completion()
    self.verify_results()
```

## Deployment Considerations

### Cross-Platform Compatibility

- **Qt Version** - Use compatible Qt version across platforms
- **Font Handling** - Platform-appropriate fonts
- **File Paths** - Cross-platform path handling
- **Permissions** - Handle different permission models

### Packaging

- **PyInstaller** - Bundle application with dependencies
- **Resource Files** - Include UI resources (icons, styles)
- **Plugin Discovery** - Ensure plugins are found in packaged app

## Troubleshooting

### Common Issues

1. **Widget Not Displaying**
    - Check parent-child relationships
    - Verify layout management
    - Ensure show() is called

2. **Styling Issues**
    - Check CSS syntax
    - Verify resource paths
    - Test theme compatibility

3. **Event Handling Problems**
    - Verify signal-slot connections
    - Check event propagation
    - Debug with print statements

### Debug Tools

```python
# Enable Qt debug output
import os
os.environ['QT_LOGGING_RULES'] = '*=true'

# Widget hierarchy inspection
def print_widget_tree(widget, indent=0):
    print("  " * indent + str(widget))
    for child in widget.children():
        if hasattr(child, 'children'):
            print_widget_tree(child, indent + 1)
```

## Development Guidelines

### Code Style

- Follow PyQt6 naming conventions
- Use meaningful widget names
- Group related functionality
- Document complex UI logic

### Performance

- Minimize widget creation in constructors
- Use layouts efficiently
- Avoid unnecessary repaints
- Cache expensive operations

### Maintainability

- Keep UI logic separate from business logic
- Use signals and slots for communication
- Create reusable components
- Document UI behavior

## Contributing

When contributing to the UI:

1. Follow existing design patterns
2. Ensure cross-platform compatibility
3. Add appropriate tests
4. Update documentation
5. Consider accessibility requirements

For more information, see the [Contributing Guide](../../CONTRIBUTING.md).

# Plugin Development Guide

## Overview

This guide covers creating custom plugins for Intellicrack. Learn to extend functionality, integrate new tools, and build custom analysis modules.

## Table of Contents

1. [Plugin Architecture](#plugin-architecture)
2. [Getting Started](#getting-started)
3. [Plugin Types](#plugin-types)
4. [Development Workflow](#development-workflow)
5. [API Reference](#api-reference)
6. [UI Integration](#ui-integration)
7. [Testing and Debugging](#testing-and-debugging)
8. [Distribution](#distribution)

## Plugin Architecture

### Plugin Structure

```
my_plugin/
├── __init__.py          # Plugin metadata and entry point
├── plugin.json          # Configuration and manifest
├── core/                # Core functionality
│   ├── __init__.py
│   └── analyzer.py
├── ui/                  # UI components (optional)
│   ├── __init__.py
│   └── widget.py
├── resources/           # Assets and data files
│   ├── icons/
│   └── data/
├── tests/              # Unit tests
│   └── test_plugin.py
└── README.md           # Documentation
```

### Plugin Manifest

**plugin.json**:
```json
{
  "name": "MyCustomPlugin",
  "version": "1.0.0",
  "author": "Your Name",
  "description": "Custom analysis plugin",
  "category": "analysis",
  "dependencies": {
    "intellicrack": ">=2.0.0",
    "python": ">=3.8",
    "packages": ["numpy", "capstone"]
  },
  "entry_point": "my_plugin.MyPlugin",
  "ui_components": ["my_plugin.ui.MyWidget"],
  "settings": {
    "timeout": 300,
    "max_memory": 1024
  }
}
```

## Getting Started

### Basic Plugin Template

```python
# my_plugin/__init__.py
from intellicrack.plugins.plugin_system import BasePlugin

class MyPlugin(BasePlugin):
    """Custom analysis plugin for Intellicrack"""
    
    def __init__(self):
        super().__init__()
        self.name = "MyCustomPlugin"
        self.version = "1.0.0"
        self.description = "Performs custom analysis"
        
    def initialize(self):
        """Called when plugin is loaded"""
        self.logger.info(f"{self.name} initialized")
        return True
    
    def analyze(self, target_file, options=None):
        """Main analysis method"""
        results = {
            "status": "success",
            "findings": []
        }
        
        try:
            # Your analysis logic here
            with open(target_file, 'rb') as f:
                data = f.read()
            
            # Process data
            findings = self.process_data(data)
            results["findings"] = findings
            
        except Exception as e:
            self.logger.error(f"Analysis failed: {e}")
            results["status"] = "error"
            results["error"] = str(e)
        
        return results
    
    def process_data(self, data):
        """Process binary data"""
        # Implementation here
        return []
```

### Plugin Registration

```python
# Register plugin with Intellicrack
def register_plugin():
    from intellicrack.plugins.plugin_system import PluginManager
    
    manager = PluginManager()
    manager.register_plugin(MyPlugin)
    
    return MyPlugin

# Export plugin class
__all__ = ['MyPlugin', 'register_plugin']
```

## Plugin Types

### Analysis Plugin

```python
from intellicrack.plugins.plugin_system import AnalysisPlugin

class CustomAnalyzer(AnalysisPlugin):
    """Custom binary analysis plugin"""
    
    def __init__(self):
        super().__init__()
        self.supported_formats = ["PE", "ELF", "MACH-O"]
        
    def can_analyze(self, file_path):
        """Check if plugin can analyze this file"""
        import pefile
        try:
            pe = pefile.PE(file_path)
            return True
        except:
            return False
    
    def analyze_binary(self, file_path, options):
        """Perform binary analysis"""
        import pefile
        
        pe = pefile.PE(file_path)
        results = {
            "imports": self.analyze_imports(pe),
            "exports": self.analyze_exports(pe),
            "sections": self.analyze_sections(pe),
            "anomalies": self.detect_anomalies(pe)
        }
        
        return results
```

### Tool Integration Plugin

```python
from intellicrack.plugins.plugin_system import ToolPlugin

class ExternalToolPlugin(ToolPlugin):
    """Integrates external analysis tool"""
    
    def __init__(self):
        super().__init__()
        self.tool_name = "CustomTool"
        self.tool_path = self.find_tool()
        
    def find_tool(self):
        """Locate external tool"""
        import shutil
        return shutil.which("customtool") or "/opt/customtool/bin/tool"
    
    def run_tool(self, target, args=None):
        """Execute external tool"""
        import subprocess
        
        cmd = [self.tool_path, target]
        if args:
            cmd.extend(args)
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True
        )
        
        return self.parse_output(result.stdout)
```

### UI Extension Plugin

```python
from intellicrack.plugins.plugin_system import UIPlugin
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QTextEdit

class CustomUIPlugin(UIPlugin):
    """Adds custom UI components"""
    
    def __init__(self):
        super().__init__()
        self.widget = None
        
    def create_widget(self, parent=None):
        """Create custom widget"""
        self.widget = CustomAnalysisWidget(parent)
        return self.widget
    
    def get_menu_items(self):
        """Add menu items"""
        return [
            {
                "path": "Tools/Custom Analysis",
                "action": self.show_custom_dialog,
                "shortcut": "Ctrl+Shift+C"
            }
        ]

class CustomAnalysisWidget(QWidget):
    """Custom analysis widget"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        
    def setup_ui(self):
        layout = QVBoxLayout()
        self.output = QTextEdit()
        layout.addWidget(self.output)
        self.setLayout(layout)
```

## Development Workflow

### Plugin Development Environment

```python
# setup_dev_env.py
import os
import sys

def setup_plugin_dev():
    """Set up development environment"""
    
    # Add plugin path to Python path
    plugin_path = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, plugin_path)
    
    # Set development mode
    os.environ['INTELLICRACK_DEV_MODE'] = '1'
    
    # Enable debug logging
    import logging
    logging.basicConfig(level=logging.DEBUG)

if __name__ == "__main__":
    setup_plugin_dev()
```

### Hot Reloading

```python
from intellicrack.plugins.plugin_system import PluginManager

# Enable hot reloading during development
manager = PluginManager()
manager.enable_hot_reload()

# Watch for changes
manager.watch_plugin("my_plugin", auto_reload=True)
```

### Debugging

```python
class DebugPlugin(BasePlugin):
    """Plugin with debugging capabilities"""
    
    def __init__(self):
        super().__init__()
        self.debug_mode = True
        
    def analyze(self, target, options):
        if self.debug_mode:
            import pdb
            pdb.set_trace()
        
        # Set breakpoints
        self.debug_checkpoint("Starting analysis")
        
        results = self.perform_analysis(target)
        
        self.debug_checkpoint("Analysis complete", results)
        
        return results
    
    def debug_checkpoint(self, message, data=None):
        """Debug checkpoint"""
        if self.debug_mode:
            self.logger.debug(f"CHECKPOINT: {message}")
            if data:
                self.logger.debug(f"Data: {data}")
```

## API Reference

### Core APIs

```python
from intellicrack.plugins.plugin_system import (
    BasePlugin,
    AnalysisPlugin,
    ToolPlugin,
    UIPlugin
)

# Access Intellicrack APIs
from intellicrack.core import (
    BinaryAnalyzer,
    MemoryAnalyzer,
    NetworkAnalyzer
)

# UI APIs
from intellicrack.ui.widgets import (
    ConsoleWidget,
    HexViewerWidget,
    GraphWidget
)
```

### Plugin Context

```python
class ContextAwarePlugin(BasePlugin):
    """Plugin with full context access"""
    
    def analyze(self, target, options):
        # Access application context
        app_context = self.get_app_context()
        
        # Get current project
        project = app_context.current_project
        
        # Access other analysis results
        previous_results = project.get_analysis_results()
        
        # Use shared resources
        cache = app_context.cache_manager
        cached_data = cache.get(f"analysis_{target}")
        
        # Access configuration
        config = app_context.config_manager
        timeout = config.get("plugins.my_plugin.timeout", 300)
        
        return results
```

### Event System

```python
class EventDrivenPlugin(BasePlugin):
    """Plugin using event system"""
    
    def initialize(self):
        # Subscribe to events
        self.subscribe("file.loaded", self.on_file_loaded)
        self.subscribe("analysis.complete", self.on_analysis_complete)
        
        # Emit custom events
        self.emit("plugin.initialized", {"name": self.name})
        
        return True
    
    def on_file_loaded(self, event_data):
        """Handle file loaded event"""
        file_path = event_data['path']
        self.logger.info(f"File loaded: {file_path}")
        
        # Trigger automatic analysis
        if self.should_analyze(file_path):
            self.analyze(file_path)
    
    def on_analysis_complete(self, event_data):
        """Handle analysis completion"""
        results = event_data['results']
        self.post_process(results)
```

## UI Integration

### Adding Tab to Main Window

```python
from intellicrack.ui.tabs.base_tab import BaseTab

class CustomTab(BaseTab):
    """Custom analysis tab"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.name = "Custom Analysis"
        self.icon = "icons/custom.png"
        
    def setup_ui(self):
        """Set up tab UI"""
        layout = QVBoxLayout()
        
        # Add components
        self.toolbar = self.create_toolbar()
        self.main_widget = self.create_main_widget()
        
        layout.addWidget(self.toolbar)
        layout.addWidget(self.main_widget)
        
        self.setLayout(layout)
    
    def register_tab(self):
        """Register with main window"""
        from intellicrack.ui.main_window import MainWindow
        
        window = MainWindow.instance()
        window.add_tab(self, position=5)
```

### Custom Dialogs

```python
from PyQt6.QtWidgets import QDialog
from intellicrack.ui.dialogs.base_dialog import BaseDialog

class CustomAnalysisDialog(BaseDialog):
    """Custom analysis configuration dialog"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Custom Analysis Options")
        self.setup_ui()
        
    def setup_ui(self):
        layout = QVBoxLayout()
        
        # Add options
        self.options_widget = self.create_options()
        layout.addWidget(self.options_widget)
        
        # Add buttons
        buttons = self.create_button_box()
        layout.addWidget(buttons)
        
        self.setLayout(layout)
    
    def get_options(self):
        """Get selected options"""
        return {
            "deep_scan": self.deep_scan_check.isChecked(),
            "timeout": self.timeout_spin.value()
        }
```

## Testing and Debugging

### Unit Tests

```python
# tests/test_plugin.py
import unittest
from my_plugin import MyPlugin

class TestMyPlugin(unittest.TestCase):
    """Test custom plugin"""
    
    def setUp(self):
        self.plugin = MyPlugin()
        self.plugin.initialize()
        
    def test_initialization(self):
        """Test plugin initialization"""
        self.assertTrue(self.plugin.initialized)
        self.assertEqual(self.plugin.name, "MyCustomPlugin")
        
    def test_analysis(self):
        """Test analysis functionality"""
        # Create test file
        test_file = "test_binary.exe"
        
        # Run analysis
        results = self.plugin.analyze(test_file)
        
        # Verify results
        self.assertEqual(results['status'], 'success')
        self.assertIn('findings', results)
        
    def test_error_handling(self):
        """Test error handling"""
        # Invalid file
        results = self.plugin.analyze("nonexistent.exe")
        
        self.assertEqual(results['status'], 'error')
        self.assertIn('error', results)
```

### Integration Tests

```python
from intellicrack.tests.plugin_test_base import PluginTestBase

class TestPluginIntegration(PluginTestBase):
    """Integration tests"""
    
    def test_with_intellicrack(self):
        """Test plugin with Intellicrack"""
        # Load plugin
        self.load_plugin("my_plugin")
        
        # Create project
        project = self.create_test_project()
        
        # Add file
        file_id = project.add_file("samples/test.exe")
        
        # Run plugin analysis
        results = self.run_plugin_analysis(
            "MyCustomPlugin",
            file_id
        )
        
        self.assertIsNotNone(results)
```

## Distribution

### Packaging

```python
# setup.py
from setuptools import setup, find_packages

setup(
    name="intellicrack-my-plugin",
    version="1.0.0",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "intellicrack>=2.0.0",
        "capstone>=4.0"
    ],
    entry_points={
        "intellicrack.plugins": [
            "my_plugin = my_plugin:register_plugin"
        ]
    },
    package_data={
        "my_plugin": ["resources/*", "plugin.json"]
    }
)
```

### Plugin Repository

```bash
# Create plugin package
python setup.py sdist bdist_wheel

# Upload to PyPI (optional)
twine upload dist/*

# Or distribute via GitHub
git tag v1.0.0
git push origin v1.0.0
```

### Installation

```bash
# Install from file
intellicrack plugin install my_plugin-1.0.0.tar.gz

# Install from repository
intellicrack plugin install intellicrack-my-plugin

# Install from GitHub
intellicrack plugin install https://github.com/user/my-plugin
```

## Best Practices

1. **Error Handling**
   - Always handle exceptions gracefully
   - Provide meaningful error messages
   - Don't crash the main application

2. **Performance**
   - Use async operations for long tasks
   - Implement progress callbacks
   - Cache expensive computations

3. **Security**
   - Validate all inputs
   - Run in sandboxed environment
   - Don't expose sensitive data

4. **Documentation**
   - Document all public APIs
   - Provide usage examples
   - Include configuration options

## Advanced Topics

### Async Plugin Operations

```python
import asyncio
from intellicrack.plugins.plugin_system import AsyncPlugin

class AsyncAnalysisPlugin(AsyncPlugin):
    """Asynchronous analysis plugin"""
    
    async def analyze_async(self, target, options):
        """Async analysis method"""
        # Perform async operations
        async with aiohttp.ClientSession() as session:
            async with session.get(f"https://api.example.com/analyze?file={target}") as resp:
                data = await resp.json()
        
        # Process results
        results = await self.process_async(data)
        
        return results
    
    async def process_async(self, data):
        """Process data asynchronously"""
        tasks = []
        for item in data:
            task = asyncio.create_task(self.analyze_item(item))
            tasks.append(task)
        
        results = await asyncio.gather(*tasks)
        return results
```

### Plugin Communication

```python
class CommunicatingPlugin(BasePlugin):
    """Plugin that communicates with others"""
    
    def analyze(self, target, options):
        # Get another plugin
        other_plugin = self.get_plugin("OtherPlugin")
        
        if other_plugin:
            # Call other plugin's method
            other_results = other_plugin.analyze(target)
            
            # Combine results
            combined = self.combine_results(
                self.results,
                other_results
            )
            
            return combined
        
        return self.results
```

### Custom Commands

```python
class CommandPlugin(BasePlugin):
    """Plugin with custom commands"""
    
    def get_commands(self):
        """Register custom commands"""
        return [
            {
                "name": "custom-analyze",
                "description": "Run custom analysis",
                "handler": self.cmd_analyze,
                "args": [
                    {"name": "file", "required": True},
                    {"name": "--deep", "action": "store_true"}
                ]
            }
        ]
    
    def cmd_analyze(self, args):
        """Handle custom command"""
        results = self.analyze(
            args.file,
            {"deep": args.deep}
        )
        
        return results
```
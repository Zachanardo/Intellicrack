# Plugin System Architecture

## Overview

The Intellicrack plugin system provides a flexible and secure way to extend the framework's functionality without modifying core code. This document describes the plugin architecture, API, and development guidelines.

## Architecture

### Plugin Types

1. **Analysis Plugins**: Extend binary analysis capabilities
2. **UI Plugins**: Add new user interface components
3. **Export Plugins**: Custom report formats and data export
4. **Protocol Plugins**: Network protocol handlers
5. **Tool Plugins**: Integration with external tools

### Plugin Structure

```python
intellicrack/intellicrack/plugins/
├── __init__.py
├── plugin_system.py      # Core plugin manager
├── custom_modules/       # User plugins directory
│   ├── __init__.py
│   └── demo_plugin.py
└── remote_executor.py    # Remote plugin execution
```

### Plugin Lifecycle

1. **Discovery**: Scan plugin directories
2. **Validation**: Verify plugin structure and metadata
3. **Loading**: Import and initialize plugins
4. **Registration**: Register callbacks and hooks
5. **Execution**: Run plugin code in sandbox
6. **Cleanup**: Proper resource cleanup

## Plugin API

### Basic Plugin Structure

```python
from intellicrack.plugins import PluginBase

class MyPlugin(PluginBase):
    """Example plugin implementation."""

    metadata = {
        'name': 'My Custom Plugin',
        'version': '1.0.0',
        'author': 'Your Name',
        'description': 'Plugin description',
        'category': 'analysis',
        'dependencies': ['numpy', 'requests']
    }

    def __init__(self):
        super().__init__()
        self.config = self.load_config()

    def analyze(self, binary_data):
        """Main analysis method."""
        results = {}
        # Plugin logic here
        return results

    def get_ui_components(self):
        """Return UI components if applicable."""
        return None
```

### Hook System

Plugins can register for various hooks:

```python
@hook('pre_analysis')
def before_analysis(self, context):
    """Called before binary analysis starts."""
    pass

@hook('post_analysis')
def after_analysis(self, context, results):
    """Called after analysis completes."""
    pass

@hook('vulnerability_found')
def on_vulnerability(self, vuln_data):
    """Called when vulnerability is detected."""
    pass
```

### Available APIs

#### Binary Analysis API
```python
# Access binary data
binary = self.api.get_binary()
sections = self.api.get_sections()
imports = self.api.get_imports()
exports = self.api.get_exports()

# Disassembly
asm = self.api.disassemble(address, size)
cfg = self.api.get_cfg()

# Pattern matching
matches = self.api.find_pattern(pattern)
```

#### UI API
```python
# Add menu items
self.api.ui.add_menu_item('Tools/My Plugin', self.show_dialog)

# Create dialogs
dialog = self.api.ui.create_dialog('My Plugin Dialog')
dialog.add_widget(widget)

# Status updates
self.api.ui.set_status('Processing...')
self.api.ui.show_progress(50)
```

#### Data API
```python
# Store plugin data
self.api.data.store('my_key', data)
data = self.api.data.retrieve('my_key')

# Access shared data
shared = self.api.data.get_shared('analysis_results')
```

## Security Model

### Sandboxing

Plugins run in restricted environments:
- Limited file system access
- Network restrictions
- Resource limits (CPU, memory)
- No direct process spawning

### Permissions

Plugin manifest declares required permissions:
```json
{
    "permissions": {
        "filesystem": ["read"],
        "network": ["http", "https"],
        "system": ["env_vars"]
    }
}
```

### Code Signing

Optional plugin signing for trusted sources:
```bash
# Sign plugin
intellicrack-sign-plugin my_plugin.zip private_key.pem

# Verify signature
intellicrack-verify-plugin my_plugin.zip
```

## Plugin Development

### Project Structure

```
my_plugin/
├── __init__.py
├── plugin.py         # Main plugin code
├── manifest.json     # Plugin metadata
├── requirements.txt  # Dependencies
├── tests/           # Plugin tests
└── docs/            # Documentation
```

### Manifest File

```json
{
    "name": "My Plugin",
    "version": "1.0.0",
    "api_version": "1.0",
    "author": "Your Name",
    "description": "Plugin description",
    "category": "analysis",
    "entry_point": "plugin.MyPlugin",
    "permissions": {
        "filesystem": ["read"],
        "network": ["http"]
    },
    "dependencies": {
        "python": ">=3.8",
        "packages": ["requests>=2.25.0"]
    }
}
```

### Testing Plugins

```python
import pytest
from intellicrack.plugins.testing import PluginTestCase

class TestMyPlugin(PluginTestCase):
    def test_analysis(self):
        # Load test binary
        binary = self.load_test_binary('test.exe')

        # Run plugin
        results = self.plugin.analyze(binary)

        # Verify results
        assert 'vulnerabilities' in results
        assert len(results['vulnerabilities']) > 0
```

### Debugging

Enable plugin debugging:
```python
# In plugin code
self.logger.debug('Debug message')

# Run with debug mode
intellicrack --plugin-debug my_plugin
```

## Best Practices

### Performance
1. Use async/await for I/O operations
2. Implement progress callbacks for long operations
3. Cache expensive computations
4. Release resources properly

### Error Handling
```python
def analyze(self, binary_data):
    try:
        # Analysis code
        return results
    except AnalysisError as e:
        self.logger.error(f"Analysis failed: {e}")
        return {'error': str(e)}
    except Exception as e:
        self.logger.exception("Unexpected error")
        raise PluginError(f"Plugin error: {e}")
```

### Configuration
```python
# Default configuration
DEFAULT_CONFIG = {
    'timeout': 30,
    'max_memory': '1GB',
    'cache_results': True
}

def load_config(self):
    config = DEFAULT_CONFIG.copy()
    user_config = self.api.config.get_plugin_config(self.name)
    config.update(user_config)
    return config
```

## Plugin Distribution

### Package Format
Plugins distributed as ZIP files:
```
my_plugin-1.0.0.zip
├── manifest.json
├── plugin.py
├── requirements.txt
└── assets/
```

### Installation
```bash
# Install from file
intellicrack-plugin install my_plugin-1.0.0.zip

# Install from repository
intellicrack-plugin install my-plugin

# List installed
intellicrack-plugin list
```

### Publishing
```bash
# Package plugin
intellicrack-plugin package .

# Publish to repository
intellicrack-plugin publish my_plugin-1.0.0.zip
```

## Advanced Topics

### Inter-Plugin Communication
```python
# Send message to another plugin
self.api.plugins.send_message('other_plugin', 'analyze', data)

# Subscribe to events
@subscribe('analysis_complete')
def on_analysis_complete(self, event_data):
    pass
```

### Custom Analysis Engines
```python
from intellicrack.core.analysis import AnalysisEngine

class MyAnalysisEngine(AnalysisEngine):
    """Custom analysis engine."""

    def analyze(self, binary):
        # Custom analysis logic
        pass
```

### UI Extensions
```python
from PyQt5.QtWidgets import QWidget

class MyPluginWidget(QWidget):
    """Custom UI widget."""

    def __init__(self, plugin_api):
        super().__init__()
        self.api = plugin_api
        self.setup_ui()
```

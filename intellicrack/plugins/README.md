# Intellicrack Plugins

The plugins system provides an extensible architecture for adding custom analysis tools, scripts, and modules to Intellicrack.

## Plugin Architecture

Intellicrack supports multiple types of plugins:
- **Python Modules** - Custom analysis modules
- **Frida Scripts** - Dynamic instrumentation scripts
- **Ghidra Scripts** - Static analysis scripts
- **Radare2 Modules** - Custom radare2 extensions

## Directory Structure

```
plugins/
├── README.md                    # This file
├── __init__.py                  # Plugin system initialization
├── plugin_base.py               # Base plugin class
├── plugin_system.py             # Plugin management system
├── remote_executor.py           # Remote plugin execution
├── custom_modules/              # Custom Python modules
│   ├── README.md               # Custom modules documentation
│   ├── demo_plugin.py          # Example plugin
│   ├── binary_patcher_plugin.py
│   ├── malware_analysis_plugin.py
│   ├── network_analysis_plugin.py
│   └── simple_analysis_plugin.py
├── frida_scripts/              # Dynamic instrumentation scripts
│   ├── adobe_bypass.js         # Adobe license bypass
│   ├── android_bypass_suite.js # Android security bypasses
│   ├── anti_debugger.js        # Anti-debugging bypasses
│   ├── behavioral_pattern_analyzer.js
│   ├── bypass_success_tracker.js
│   ├── central_orchestrator.js
│   ├── certificate_pinner_bypass.js
│   ├── cloud_licensing_bypass.js
│   ├── code_integrity_bypass.js
│   ├── dotnet_bypass_suite.js
│   ├── drm_bypass.js
│   ├── dynamic_script_generator.js
│   ├── enhanced_hardware_spoofer.js
│   ├── hook_effectiveness_monitor.js
│   ├── http3_quic_interceptor.js
│   ├── hwid_spoofer.js
│   ├── kernel_bridge.js
│   ├── kernel_mode_bypass.js
│   ├── memory_integrity_bypass.js
│   ├── ml_license_detector.js
│   ├── modular_hook_library.js
│   ├── ntp_blocker.js
│   ├── obfuscation_detector.js
│   ├── realtime_protection_detector.js
│   ├── registry_monitor.js
│   ├── registry_monitor_enhanced.js
│   ├── telemetry_blocker.js
│   ├── time_bomb_defuser.js
│   ├── time_bomb_defuser_advanced.js
│   ├── tpm_emulator.js
│   ├── virtualization_bypass.js
│   └── websocket_interceptor.js
├── ghidra_scripts/             # Static analysis scripts
│   ├── README.md               # Ghidra scripts documentation
│   ├── __init__.py
│   ├── community/              # Community contributed scripts
│   │   └── README.md
│   └── user/                   # User scripts
│       └── AntiAnalysisDetector.py
└── radare2_modules/            # Radare2 extensions
    └── custom_analysis.r2
```

## Plugin Types

### 1. Custom Python Modules

Located in `custom_modules/`, these are full Python plugins that extend Intellicrack's capabilities.

#### Base Plugin Structure

```python
from intellicrack.plugins import PluginBase

class MyCustomPlugin(PluginBase):
    def __init__(self):
        super().__init__()
        self.name = "My Custom Plugin"
        self.version = "1.0.0"
        self.description = "Description of what the plugin does"
        self.author = "Your Name"
    
    def run(self, binary_path, **kwargs):
        """Main plugin execution method"""
        # Your analysis logic here
        return {
            'success': True,
            'results': {},
            'errors': []
        }
    
    def validate_input(self, binary_path):
        """Validate input before processing"""
        return os.path.exists(binary_path)
    
    def get_config_schema(self):
        """Return configuration schema for the plugin"""
        return {
            'timeout': {'type': 'int', 'default': 300},
            'deep_scan': {'type': 'bool', 'default': False}
        }
```

#### Available Example Plugins

- **demo_plugin.py** - Basic plugin template and example
- **binary_patcher_plugin.py** - Binary patching utilities
- **malware_analysis_plugin.py** - Malware analysis specific tools
- **network_analysis_plugin.py** - Network behavior analysis
- **simple_analysis_plugin.py** - Simple analysis tasks

### 2. Frida Scripts

JavaScript/TypeScript scripts for dynamic instrumentation and runtime analysis.

#### Key Script Categories

- **Bypass Scripts** - License, protection, and security bypasses
- **Monitoring Scripts** - Runtime behavior monitoring
- **Detection Scripts** - Protection and analysis detection
- **Utility Scripts** - Helper and orchestration scripts

#### Example Usage

```javascript
// Basic Frida script structure
Java.perform(function() {
    // Hook a specific method
    var targetClass = Java.use("com.example.TargetClass");
    targetClass.targetMethod.implementation = function(param) {
        console.log("[+] Method called with: " + param);
        return this.targetMethod(param);
    };
});
```

### 3. Ghidra Scripts

Java and Python scripts for static analysis using Ghidra's powerful API.

See [ghidra_scripts/README.md](ghidra_scripts/README.md) for detailed documentation.

### 4. Radare2 Modules

Custom radare2 extensions and analysis scripts.

## Plugin Management

### Loading Plugins

Plugins are automatically discovered and loaded by the plugin system:

```python
from intellicrack.plugins import PluginSystem

# Initialize plugin system
plugin_system = PluginSystem()

# Load all available plugins
plugin_system.load_plugins()

# Get available plugins
plugins = plugin_system.get_available_plugins()

# Run a specific plugin
result = plugin_system.run_plugin("plugin_name", binary_path="/path/to/binary")
```

### Plugin Configuration

Each plugin can have its own configuration schema:

```json
{
    "plugins": {
        "my_custom_plugin": {
            "enabled": true,
            "timeout": 300,
            "deep_scan": false,
            "custom_option": "value"
        }
    }
}
```

### Remote Execution

Plugins can be executed remotely using the remote executor:

```python
from intellicrack.plugins.remote_executor import RemoteExecutor

executor = RemoteExecutor()
result = executor.execute_plugin_remote(
    plugin_name="malware_analysis",
    target_host="analysis.server.com",
    binary_path="/path/to/suspicious.exe"
)
```

## Creating Custom Plugins

### 1. Python Module Plugin

1. Create a new file in `custom_modules/`
2. Inherit from `PluginBase`
3. Implement required methods:
   - `run()` - Main execution logic
   - `validate_input()` - Input validation
   - `get_config_schema()` - Configuration schema

### 2. Frida Script Plugin

1. Create a new `.js` file in `frida_scripts/`
2. Use standard Frida API
3. Include metadata comments:

```javascript
/**
 * Script Name: My Custom Script
 * Description: What this script does
 * Author: Your Name
 * Version: 1.0.0
 * Target: Android/iOS/Windows/Linux
 */
```

### 3. Ghidra Script Plugin

See the Ghidra scripts documentation for detailed instructions.

## Plugin Development Guidelines

### Code Quality
- Follow Python PEP 8 for Python plugins
- Use meaningful variable and function names
- Include comprehensive error handling
- Add logging for debugging

### Documentation
- Include docstrings for all methods
- Provide usage examples
- Document configuration options
- List dependencies

### Testing
- Write unit tests for your plugins
- Test with various binary types
- Verify error handling

### Security
- Validate all inputs
- Sanitize file paths
- Handle untrusted data safely
- Follow secure coding practices

## Plugin APIs

### Analysis API
Access to core analysis functions:

```python
from intellicrack.core.analysis import CoreAnalyzer

class MyPlugin(PluginBase):
    def run(self, binary_path, **kwargs):
        analyzer = CoreAnalyzer()
        results = analyzer.analyze_binary(binary_path)
        return results
```

### UI Integration
For GUI plugins:

```python
from intellicrack.ui.widgets import WidgetFactory

class UIPlugin(PluginBase):
    def create_widget(self, parent):
        """Create a custom widget for the UI"""
        return WidgetFactory.create_plugin_widget(parent, self)
```

### Configuration API
Access to application configuration:

```python
from intellicrack.utils.config import get_config

class ConfigurablePlugin(PluginBase):
    def run(self, binary_path, **kwargs):
        config = get_config()
        timeout = config.get('plugins', {}).get(self.name, {}).get('timeout', 300)
        # Use configuration
```

## Troubleshooting

### Common Issues

1. **Plugin Not Loading**
   - Check plugin inheritance from PluginBase
   - Verify __init__.py exists in directory
   - Check for syntax errors

2. **Import Errors**
   - Ensure all dependencies are installed
   - Check Python path
   - Verify module structure

3. **Runtime Errors**
   - Check input validation
   - Verify file permissions
   - Review error logs

### Debug Mode

Enable debug mode for detailed plugin loading information:

```python
import logging
logging.basicConfig(level=logging.DEBUG)

from intellicrack.plugins import PluginSystem
plugin_system = PluginSystem(debug=True)
```

## Contributing Plugins

To contribute plugins to Intellicrack:

1. Follow the development guidelines
2. Include comprehensive tests
3. Document thoroughly
4. Submit a pull request

For more information, see the [Contributing Guide](../../CONTRIBUTING.md).

## Plugin Security

### Sandboxing
Plugins run in controlled environments to prevent:
- Unauthorized file system access
- Network abuse
- System compromise

### Validation
All plugins undergo validation:
- Code review for malicious content
- Automated security scanning
- Input sanitization verification

### Trust Levels
Plugins have different trust levels:
- **System** - Built-in trusted plugins
- **Verified** - Community verified plugins
- **User** - User-created plugins (sandboxed)

## Performance Considerations

### Resource Usage
- Monitor memory usage in long-running plugins
- Implement timeouts for operations
- Use efficient algorithms for large binaries

### Parallel Execution
- Design plugins to be thread-safe
- Use async/await for I/O operations
- Consider distributed execution for heavy workloads

## License and Legal

- Plugins must comply with applicable laws
- Respect software licenses and copyrights
- Use only for authorized security research
- Follow responsible disclosure practices

All plugins are subject to the same GPL v3 license as Intellicrack unless otherwise specified.
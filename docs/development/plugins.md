# Plugin Development Guide

Create custom plugins to extend Intellicrack's functionality with new analysis techniques, patching methods, and integrations.

## Overview

Intellicrack's plugin system allows you to:
- Add custom analysis algorithms
- Integrate external tools
- Create new UI components
- Implement specialized patchers
- Extend network capabilities

## Getting Started

### Plugin Structure

```
plugins/
├── custom_modules/
│   └── my_plugin.py
├── frida_scripts/
│   └── my_hook.js
└── ghidra_scripts/
    └── MyAnalysis.java
```

### Basic Plugin Template

```python
# plugins/custom_modules/my_plugin.py
from intellicrack.plugins import PluginBase
from typing import Dict, Any

class MyPlugin(PluginBase):
    """Example plugin for custom analysis"""
    
    def __init__(self):
        super().__init__()
        self.name = "My Custom Plugin"
        self.version = "1.0.0"
        self.author = "Your Name"
        self.description = "Custom analysis plugin"
        self.enabled = True
    
    def initialize(self) -> bool:
        """Called when plugin is loaded"""
        self.logger.info(f"Initializing {self.name}")
        return True
    
    def run(self, binary_data: bytes, **kwargs) -> Dict[str, Any]:
        """Main plugin execution"""
        results = {
            "status": "success",
            "findings": []
        }
        
        # Your analysis logic here
        if b"MZ" in binary_data[:2]:
            results["findings"].append({
                "type": "file_format",
                "value": "PE executable detected"
            })
        
        return results
    
    def cleanup(self):
        """Called when plugin is unloaded"""
        self.logger.info(f"Cleaning up {self.name}")
```

## Plugin Types

### Analysis Plugins

Extend binary analysis capabilities:

```python
class VulnerabilityScanner(PluginBase):
    def __init__(self):
        super().__init__()
        self.name = "Custom Vulnerability Scanner"
        self.category = "analysis"
    
    def analyze_function(self, func_data: bytes, func_addr: int) -> list:
        vulnerabilities = []
        
        # Check for unsafe functions
        unsafe_calls = [b"strcpy", b"gets", b"sprintf"]
        for call in unsafe_calls:
            if call in func_data:
                vulnerabilities.append({
                    "type": "unsafe_function",
                    "function": call.decode(),
                    "address": func_addr,
                    "severity": "high"
                })
        
        return vulnerabilities
```

### Patching Plugins

Create automated patchers:

```python
class AutoPatcher(PluginBase):
    def __init__(self):
        super().__init__()
        self.name = "License Check Remover"
        self.category = "patching"
    
    def find_patterns(self, binary_data: bytes) -> list:
        patterns = []
        
        # Common license check patterns
        license_patterns = [
            (b"\x83\xF8\x01\x75", b"\x83\xF8\x01\xEB"),  # cmp eax,1; jnz -> jmp
            (b"\x85\xC0\x74", b"\x85\xC0\xEB"),          # test eax,eax; jz -> jmp
        ]
        
        for pattern, replacement in license_patterns:
            offset = 0
            while True:
                pos = binary_data.find(pattern, offset)
                if pos == -1:
                    break
                patterns.append({
                    "offset": pos,
                    "original": pattern,
                    "patch": replacement,
                    "description": "Potential license check"
                })
                offset = pos + 1
        
        return patterns
```

### UI Plugins

Add custom UI components:

```python
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QPushButton

class CustomUIPlugin(PluginBase):
    def __init__(self):
        super().__init__()
        self.name = "Custom Analysis Panel"
        self.category = "ui"
    
    def create_widget(self, parent=None) -> QWidget:
        widget = QWidget(parent)
        layout = QVBoxLayout()
        
        analyze_btn = QPushButton("Run Custom Analysis")
        analyze_btn.clicked.connect(self.on_analyze)
        layout.addWidget(analyze_btn)
        
        widget.setLayout(layout)
        return widget
    
    def on_analyze(self):
        # Trigger custom analysis
        self.emit_signal("analysis_requested", {"type": "custom"})
```

### Network Plugins

Extend network analysis:

```python
class ProtocolAnalyzer(PluginBase):
    def __init__(self):
        super().__init__()
        self.name = "Custom Protocol Analyzer"
        self.category = "network"
        self.protocols = {}
    
    def analyze_packet(self, packet_data: bytes) -> dict:
        # Custom protocol detection
        if packet_data.startswith(b"CUSTOM"):
            return {
                "protocol": "custom_protocol",
                "version": packet_data[6:7],
                "payload": packet_data[8:]
            }
        return {}
```

## Plugin API

### Available Methods

```python
class PluginBase:
    # Core methods
    def initialize(self) -> bool
    def run(self, binary_data: bytes, **kwargs) -> dict
    def cleanup(self)
    
    # Analysis helpers
    def get_binary_info(self, path: str) -> dict
    def disassemble(self, data: bytes, arch: str) -> list
    def find_strings(self, data: bytes, min_length: int) -> list
    
    # UI integration
    def create_widget(self, parent) -> QWidget
    def show_dialog(self, title: str, message: str)
    def get_user_input(self, prompt: str) -> str
    
    # Data access
    def read_config(self, key: str) -> Any
    def write_config(self, key: str, value: Any)
    def get_temp_dir(self) -> str
    
    # Signals
    def emit_signal(self, signal: str, data: dict)
    def connect_signal(self, signal: str, handler: callable)
```

### Plugin Events

Subscribe to application events:

```python
def initialize(self):
    # Connect to events
    self.connect_signal("file_loaded", self.on_file_loaded)
    self.connect_signal("analysis_complete", self.on_analysis_done)
    self.connect_signal("patch_applied", self.on_patch_applied)
    
def on_file_loaded(self, data):
    self.logger.info(f"File loaded: {data['path']}")
    # React to file loading
```

## Advanced Features

### Frida Integration

Create dynamic instrumentation scripts:

```javascript
// plugins/frida_scripts/trace_calls.js
{
    name: "Function Call Tracer",
    description: "Traces specific function calls",
    
    onAttach: function(pid) {
        console.log("Attached to process: " + pid);
    },
    
    run: function() {
        // Hook Windows API
        Interceptor.attach(Module.findExportByName("kernel32.dll", "CreateFileW"), {
            onEnter: function(args) {
                send({
                    type: "api_call",
                    function: "CreateFileW",
                    filename: args[0].readUtf16String()
                });
            }
        });
    }
}
```

### Ghidra Scripts

Integrate with Ghidra for advanced analysis:

```java
// plugins/ghidra_scripts/CustomAnalysis.java
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;

public class CustomAnalysis extends GhidraScript {
    @Override
    public void run() throws Exception {
        // Analyze all functions
        for (Function func : currentProgram.getFunctionManager().getFunctions(true)) {
            if (func.getName().contains("license")) {
                println("Found license function: " + func.getName());
                // Mark for further analysis
                func.setComment("Potential license check");
            }
        }
    }
}
```

### Machine Learning Integration

```python
class MLPredictor(PluginBase):
    def __init__(self):
        super().__init__()
        self.name = "ML Vulnerability Predictor"
        self.model = None
    
    def initialize(self):
        # Load pre-trained model
        import joblib
        model_path = self.get_resource_path("model.pkl")
        self.model = joblib.load(model_path)
        return True
    
    def predict_vulnerability(self, func_features: dict) -> float:
        # Extract features
        features = [
            func_features.get("cyclomatic_complexity", 0),
            func_features.get("num_branches", 0),
            func_features.get("stack_size", 0),
            len(func_features.get("called_functions", []))
        ]
        
        # Predict vulnerability probability
        prob = self.model.predict_proba([features])[0][1]
        return prob
```

## Plugin Management

### Installation

1. **Manual Installation**:
   - Place plugin file in `plugins/custom_modules/`
   - Restart Intellicrack or use Plugin Manager

2. **Via Plugin Manager**:
   - Open Plugins tab
   - Click "Install Plugin"
   - Select .py or .zip file

3. **From Repository**:
   ```python
   # In Intellicrack console
   plugin_manager.install_from_url(
       "https://github.com/user/intellicrack-plugins/my-plugin.zip"
   )
   ```

### Configuration

Plugins can have custom settings:

```python
class ConfigurablePlugin(PluginBase):
    def __init__(self):
        super().__init__()
        self.config_schema = {
            "sensitivity": {
                "type": "slider",
                "min": 0,
                "max": 100,
                "default": 50,
                "description": "Detection sensitivity"
            },
            "deep_scan": {
                "type": "checkbox",
                "default": False,
                "description": "Enable deep scanning"
            }
        }
    
    def run(self, binary_data: bytes, **kwargs):
        sensitivity = self.get_config("sensitivity")
        deep_scan = self.get_config("deep_scan")
        # Use configuration values
```

## Best Practices

### Error Handling

```python
def run(self, binary_data: bytes, **kwargs):
    try:
        # Plugin logic
        results = self.analyze(binary_data)
        return {"status": "success", "results": results}
    except Exception as e:
        self.logger.error(f"Plugin error: {str(e)}")
        return {"status": "error", "message": str(e)}
```

### Performance

- Use generators for large data sets
- Implement progress callbacks
- Cache expensive computations
- Release resources in cleanup()

### Security

- Validate all inputs
- Use sandboxing for untrusted code
- Limit resource usage
- Log security-relevant actions

## Plugin Examples

### Complete License Bypasser

```python
class ComprehensiveLicenseBypasser(PluginBase):
    def __init__(self):
        super().__init__()
        self.name = "Comprehensive License Bypasser"
        self.version = "2.0.0"
        self.patterns = self.load_patterns()
    
    def load_patterns(self):
        return {
            "trial_check": [
                (b"\x3D\x1E\x00\x00\x00\x77", b"\x3D\x1E\x00\x00\x00\xEB"),
            ],
            "key_validation": [
                (b"\x85\xC0\x74", b"\x85\xC0\xEB"),
                (b"\x85\xC0\x75", b"\x85\xC0\x90\x90"),
            ],
            "online_check": [
                (b"connect", "patch_network_check"),
            ]
        }
    
    def run(self, binary_data: bytes, **kwargs):
        patches = []
        
        for category, patterns in self.patterns.items():
            for pattern in patterns:
                if isinstance(pattern[1], bytes):
                    # Direct patch
                    patches.extend(self.find_and_patch(
                        binary_data, pattern[0], pattern[1], category
                    ))
                else:
                    # Complex patch
                    method = getattr(self, pattern[1])
                    patches.extend(method(binary_data, pattern[0]))
        
        return {
            "status": "success",
            "patches": patches,
            "categories": list(set(p["category"] for p in patches))
        }
```

### Binary Differ

```python
class BinaryDiffer(PluginBase):
    def __init__(self):
        super().__init__()
        self.name = "Binary Difference Analyzer"
    
    def compare_binaries(self, bin1: bytes, bin2: bytes):
        import difflib
        
        # Basic diff
        matcher = difflib.SequenceMatcher(None, bin1, bin2)
        changes = []
        
        for tag, i1, i2, j1, j2 in matcher.get_opcodes():
            if tag != 'equal':
                changes.append({
                    "type": tag,
                    "offset1": i1,
                    "offset2": j1,
                    "size1": i2 - i1,
                    "size2": j2 - j1,
                    "data1": bin1[i1:i2].hex(),
                    "data2": bin2[j1:j2].hex()
                })
        
        return {
            "similarity": matcher.ratio(),
            "changes": changes,
            "total_changes": len(changes)
        }
```

## Debugging Plugins

### Enable Debug Mode

```python
# In plugin
self.debug = True
self.logger.setLevel(logging.DEBUG)

# In Intellicrack
Settings → Developer → Enable Plugin Debug Mode
```

### Testing Framework

```python
# tests/test_my_plugin.py
import unittest
from plugins.custom_modules.my_plugin import MyPlugin

class TestMyPlugin(unittest.TestCase):
    def setUp(self):
        self.plugin = MyPlugin()
        self.plugin.initialize()
    
    def test_basic_analysis(self):
        test_data = b"MZ\x90\x00\x03"
        result = self.plugin.run(test_data)
        self.assertEqual(result["status"], "success")
    
    def tearDown(self):
        self.plugin.cleanup()
```

## Publishing Plugins

### Package Structure

```
my-plugin/
├── plugin.json          # Metadata
├── __init__.py         # Plugin entry point
├── requirements.txt    # Dependencies
├── README.md          # Documentation
└── tests/             # Unit tests
```

### Metadata Format

```json
{
    "name": "My Awesome Plugin",
    "version": "1.0.0",
    "author": "Your Name",
    "description": "Advanced analysis plugin",
    "category": "analysis",
    "min_intellicrack_version": "2.0.0",
    "dependencies": ["numpy", "capstone"],
    "entry_point": "MyPlugin"
}
```


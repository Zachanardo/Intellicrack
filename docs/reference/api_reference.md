# API Reference

Comprehensive API documentation for Intellicrack's core modules and functions.

## Core Analysis API

### intellicrack.core.analysis

#### CoreAnalyzer

Main analysis engine for binary files.

```python
from intellicrack.core.analysis import CoreAnalyzer

analyzer = CoreAnalyzer()
```

**Methods:**

##### analyze_binary(file_path: str, options: dict = None) -> dict
Performs comprehensive analysis on a binary file.

```python
result = analyzer.analyze_binary("target.exe", {
    "deep_scan": True,
    "extract_strings": True,
    "detect_protections": True
})
```

**Parameters:**
- `file_path` (str): Path to binary file
- `options` (dict): Analysis options
  - `deep_scan` (bool): Enable thorough analysis
  - `extract_strings` (bool): Extract string literals
  - `detect_protections` (bool): Detect anti-analysis techniques

**Returns:**
- `dict`: Analysis results containing:
  - `file_info`: Basic file information
  - `headers`: PE/ELF/Mach-O headers
  - `sections`: Section information
  - `imports`: Imported functions
  - `exports`: Exported functions
  - `strings`: Extracted strings
  - `protections`: Detected protections

#### VulnerabilityEngine

Automated vulnerability detection system.

```python
from intellicrack.core.analysis import VulnerabilityEngine

vuln_engine = VulnerabilityEngine()
```

##### scan_binary(binary_path: str) -> List[Vulnerability]
Scans binary for common vulnerabilities.

```python
vulnerabilities = vuln_engine.scan_binary("app.exe")
for vuln in vulnerabilities:
    print(f"{vuln.type}: {vuln.description} at {vuln.address}")
```

##### check_buffer_overflow(func_data: bytes) -> List[dict]
Checks for potential buffer overflow vulnerabilities.

##### check_format_string(func_data: bytes) -> List[dict]
Detects format string vulnerabilities.

#### SymbolicExecutor

Symbolic execution engine for path exploration.

```python
from intellicrack.core.analysis import SymbolicExecutor

executor = SymbolicExecutor()
paths = executor.explore_function(func_addr, max_depth=10)
```

## Patching API

### intellicrack.core.patching

#### PayloadGenerator

Creates patches and payloads for binary modification.

```python
from intellicrack.core.patching import PayloadGenerator

patcher = PayloadGenerator()
```

##### patch_bytes(file_path: str, offset: int, new_bytes: bytes) -> bool
Patches bytes at specified offset.

```python
# Change JZ to JMP
success = patcher.patch_bytes("app.exe", 0x1234, b'\xEB')
```

##### generate_nop_sled(size: int) -> bytes
Generates NOP sled of specified size.

```python
nops = patcher.generate_nop_sled(10)  # Returns b'\x90' * 10
```

##### create_jump(from_addr: int, to_addr: int) -> bytes
Creates jump instruction between addresses.

#### MemoryPatcher

Runtime memory patching capabilities.

```python
from intellicrack.core.patching import MemoryPatcher

mem_patcher = MemoryPatcher()
```

##### attach_process(process_name: str) -> bool
Attaches to running process.

##### patch_memory(address: int, data: bytes) -> bool
Patches process memory at runtime.

##### detach() -> None
Detaches from process.

## Network Analysis API

### intellicrack.core.network

#### NetworkTrafficAnalyzer

Analyzes network traffic and protocols.

```python
from intellicrack.core.network import NetworkTrafficAnalyzer

analyzer = NetworkTrafficAnalyzer()
```

##### start_capture(interface: str = None) -> None
Starts packet capture on specified interface.

##### analyze_packet(packet_data: bytes) -> dict
Analyzes individual network packet.

##### stop_capture() -> List[dict]
Stops capture and returns analyzed packets.

#### LicenseServerEmulator

Emulates license servers for testing.

```python
from intellicrack.core.network import LicenseServerEmulator

emulator = LicenseServerEmulator()
```

##### start_server(port: int = 8080) -> None
Starts emulated license server.

##### add_license(key: str, features: dict) -> None
Adds license key to server.

##### stop_server() -> None
Stops license server.

## Protection Bypass API

### intellicrack.core.protection_bypass

#### AntiDebugBypass

Bypasses anti-debugging protections.

```python
from intellicrack.core.protection_bypass import AntiDebugBypass

bypasser = AntiDebugBypass()
```

##### remove_isdebuggerpresent(binary_data: bytes) -> bytes
Removes IsDebuggerPresent checks.

##### patch_timing_checks(binary_data: bytes) -> bytes
Neutralizes timing-based anti-debug.

#### VMBypass

Bypasses virtual machine detection.

```python
from intellicrack.core.protection_bypass import VMBypass

vm_bypasser = VMBypass()
```

##### hide_vm_artifacts() -> None
Hides VM-specific artifacts from detection.

##### patch_cpuid_checks(binary_data: bytes) -> bytes
Patches CPUID-based VM detection.

## Utility Functions

### intellicrack.utils.binary_utils

#### read_binary(file_path: str) -> bytes
Safely reads binary file.

```python
from intellicrack.utils.binary_utils import read_binary

data = read_binary("target.exe")
```

#### write_binary(file_path: str, data: bytes) -> None
Writes binary data to file.

```python
from intellicrack.utils.binary_utils import write_binary

write_binary("patched.exe", modified_data)
```

#### calculate_checksum(data: bytes) -> int
Calculates CRC32 checksum.

#### find_pattern(data: bytes, pattern: bytes, mask: bytes = None) -> List[int]
Finds byte pattern in data.

```python
# Find all CALL instructions
offsets = find_pattern(data, b'\xE8', None)
```

### intellicrack.utils.protection_detection

#### ProtectionDetector

Detects various protection mechanisms.

```python
from intellicrack.utils.protection_detection import ProtectionDetector

detector = ProtectionDetector()
protections = detector.detect_all_protections("app.exe")
```

##### detect_packer(file_path: str) -> dict
Detects executable packers.

##### detect_anti_debug(file_path: str) -> dict
Identifies anti-debugging techniques.

##### detect_obfuscation(file_path: str) -> dict
Detects code obfuscation.

## Plugin Development API

### intellicrack.plugins

#### PluginBase

Base class for plugin development.

```python
from intellicrack.plugins import PluginBase

class MyPlugin(PluginBase):
    def __init__(self):
        super().__init__()
        self.name = "My Plugin"
    
    def run(self, binary_data: bytes, **kwargs) -> dict:
        # Plugin logic
        return {"status": "success"}
```

**Required Methods:**
- `initialize() -> bool`: Plugin initialization
- `run(binary_data: bytes, **kwargs) -> dict`: Main execution
- `cleanup() -> None`: Cleanup resources

**Available Properties:**
- `logger`: Plugin-specific logger
- `config`: Plugin configuration
- `temp_dir`: Temporary directory path

#### PluginManager

Manages plugin loading and execution.

```python
from intellicrack.plugins import PluginManager

manager = PluginManager()
```

##### load_plugin(plugin_path: str) -> bool
Loads plugin from file.

##### list_plugins() -> List[dict]
Lists all loaded plugins.

##### execute_plugin(plugin_name: str, data: bytes) -> dict
Executes specific plugin.

## AI/ML API

### intellicrack.ai

#### MLPredictor

Machine learning prediction engine.

```python
from intellicrack.ai import MLPredictor

predictor = MLPredictor()
```

##### predict_vulnerability(features: dict) -> float
Predicts vulnerability probability.

```python
probability = predictor.predict_vulnerability({
    "cyclomatic_complexity": 15,
    "num_branches": 20,
    "has_unsafe_functions": True
})
```

##### train_model(training_data: List[dict]) -> None
Trains ML model with new data.

#### ModelManager

Manages AI/ML models.

```python
from intellicrack.ai import ModelManager

model_mgr = ModelManager()
```

##### load_model(model_path: str) -> bool
Loads pre-trained model.

##### save_model(model_path: str) -> bool
Saves current model.

##### list_available_models() -> List[str]
Lists available models.

## UI Components API

### intellicrack.ui

#### MainWindow

Main application window.

```python
from intellicrack.ui import MainWindow
from PyQt5.QtWidgets import QApplication

app = QApplication([])
window = MainWindow()
window.show()
app.exec_()
```

#### HexEditor

Hex editor widget.

```python
from intellicrack.ui.widgets import HexEditor

hex_editor = HexEditor()
hex_editor.load_data(binary_data)
hex_editor.highlight_range(0x100, 0x200, "red")
```

##### load_data(data: bytes) -> None
Loads binary data into editor.

##### get_selection() -> Tuple[int, int]
Gets current selection range.

##### patch_bytes(offset: int, new_bytes: bytes) -> None
Patches bytes in editor.

## Error Handling

### Common Exceptions

```python
from intellicrack.exceptions import (
    InvalidBinaryError,
    AnalysisError,
    PatchingError,
    PluginError
)

try:
    analyzer.analyze_binary("invalid.exe")
except InvalidBinaryError as e:
    print(f"Invalid binary: {e}")
except AnalysisError as e:
    print(f"Analysis failed: {e}")
```

### Error Codes

| Code | Description |
|------|-------------|
| 1001 | Invalid binary format |
| 1002 | File not found |
| 1003 | Insufficient permissions |
| 2001 | Analysis timeout |
| 2002 | Memory allocation failed |
| 3001 | Patching failed |
| 3002 | Invalid patch offset |

## Configuration

### Config Structure

```python
{
    "analysis": {
        "timeout": 300,
        "max_memory": "1GB",
        "parallel_threads": 8
    },
    "patching": {
        "backup_files": true,
        "verify_patches": true
    },
    "network": {
        "capture_interface": "auto",
        "proxy_port": 8080
    },
    "ai": {
        "model_path": "models/",
        "auto_train": false
    }
}
```

### Accessing Configuration

```python
from intellicrack.config import Config

config = Config()
timeout = config.get("analysis.timeout", default=300)
config.set("analysis.timeout", 600)
config.save()
```

## Logging

### Logger Usage

```python
from intellicrack.utils.logger import get_logger

logger = get_logger(__name__)

logger.debug("Debug information")
logger.info("General information")
logger.warning("Warning message")
logger.error("Error occurred")
logger.critical("Critical error")
```

### Log Levels

- `DEBUG`: Detailed debugging information
- `INFO`: General informational messages
- `WARNING`: Warning messages
- `ERROR`: Error messages
- `CRITICAL`: Critical errors

## Performance Considerations

### Memory Management

```python
# Use context managers for large operations
from intellicrack.utils import MemoryManager

with MemoryManager(max_memory="2GB") as mm:
    # Memory-intensive operations
    large_data = analyze_large_binary("huge.exe")
```

### Parallel Processing

```python
from intellicrack.utils import parallel_map

# Process multiple files in parallel
results = parallel_map(analyze_binary, file_list, max_workers=4)
```

## Best Practices

1. **Always validate input**:
```python
if not os.path.exists(file_path):
    raise FileNotFoundError(f"File not found: {file_path}")
```

2. **Use context managers**:
```python
with BinaryLoader(file_path) as loader:
    data = loader.read()
```

3. **Handle errors gracefully**:
```python
try:
    result = analyze_binary(path)
except AnalysisError:
    logger.error("Analysis failed, using fallback")
    result = basic_analysis(path)
```

4. **Clean up resources**:
```python
analyzer = CoreAnalyzer()
try:
    analyzer.analyze(data)
finally:
    analyzer.cleanup()
```
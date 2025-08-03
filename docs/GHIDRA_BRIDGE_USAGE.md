# Ghidra Bridge Integration - Usage Guide

## Overview

The Ghidra Bridge integration provides programmatic control over Ghidra for advanced binary analysis within Intellicrack. This replaces the previous fragile script-based approach with real-time, bidirectional communication between Python and Ghidra.

## Key Components

### 1. GhidraBridgeManager
**File**: `intellicrack/core/analysis/ghidra_bridge_manager.py`

The core component that manages the bridge connection and provides all Ghidra operations:

```python
from intellicrack.core.analysis.ghidra_bridge_manager import GhidraBridgeManager

# Initialize with automatic Ghidra discovery
manager = GhidraBridgeManager()

# Or specify custom Ghidra path and port
manager = GhidraBridgeManager(
    ghidra_path="/custom/ghidra/path",
    server_port=13100
)

# Use as context manager (recommended)
with manager as bridge:
    if manager.load_program("/path/to/binary.exe"):
        result = manager.decompile_function("main")
        print(result)
```

### 2. GhidraDecompiler (Updated)
**File**: `intellicrack/core/analysis/ghidra_decompiler.py`

The main decompilation interface, now using bridge-based communication:

```python
from intellicrack.core.analysis.ghidra_decompiler import GhidraDecompiler

# Create decompiler instance
decompiler = GhidraDecompiler("/path/to/binary.exe")

# Decompile specific function
result = decompiler.decompile_function("main")

# Analyze protection schemes
protection_analysis = decompiler.analyze_protection_scheme()

# Extract imports and exports
imports = decompiler.extract_imports()
exports = decompiler.extract_exports()
```

### 3. Ghidra Common Utilities
**File**: `intellicrack/utils/ghidra_common.py`

Utility functions for common Ghidra operations:

```python
from intellicrack.utils.ghidra_common import analyze_binary_with_bridge

# Quick binary analysis
result = analyze_binary_with_bridge("/path/to/binary.exe")
print(f"Architecture: {result.get('architecture')}")
print(f"Format: {result.get('format')}")
```

## Key Features

### Session Management
- **Automatic lifecycle management** with context managers
- **Connection pooling** for performance optimization
- **Graceful cleanup** on exceptions or exit
- **Configurable timeouts** for server startup

### Real-time Operations
- **Function decompilation** with full C-like output
- **Symbol extraction** (functions, variables, strings)
- **Import/Export analysis** with detailed metadata
- **License pattern detection** for protection analysis
- **Vulnerability identification** with severity scoring

### Error Handling
- **Robust exception handling** for all bridge operations
- **Automatic retry logic** for transient failures
- **Detailed error logging** with audit trail
- **Graceful degradation** when Ghidra is unavailable

### Performance Optimizations
- **Efficient binary loading** with smart caching
- **Bulk operations** for batch processing
- **Memory management** for large binaries
- **Connection reuse** across multiple operations

## Installation Requirements

### Package Dependencies
```bash
# Core bridge package
pip install ghidra_bridge

# Settings management (already installed)
pip install pydantic-settings
```

### Ghidra Installation
- **Ghidra 10.0+** installed and configured
- **Java 17+** required for Ghidra bridge server
- **Network access** on bridge port (default: 13100)

## Configuration

### Automatic Discovery
The system automatically discovers Ghidra installations:

```python
from intellicrack.utils.core.path_discovery import discover_ghidra_path

ghidra_path = discover_ghidra_path()
if ghidra_path:
    print(f"Found Ghidra at: {ghidra_path}")
```

### Manual Configuration
Override automatic discovery with custom paths:

```python
manager = GhidraBridgeManager(
    ghidra_path="/opt/ghidra",  # Custom Ghidra installation
    server_port=15000           # Custom bridge port
)
```

## Usage Examples

### Basic Binary Analysis
```python
from intellicrack.core.analysis.ghidra_bridge_manager import GhidraBridgeManager

def analyze_binary(binary_path):
    with GhidraBridgeManager() as manager:
        if not manager.load_program(binary_path):
            return {"error": "Failed to load binary"}
        
        # Get basic information
        info = manager.get_basic_info()
        
        # Extract all functions
        functions = manager.extract_functions()
        
        # Analyze license patterns
        license_analysis = manager.analyze_license_patterns()
        
        return {
            "info": info,
            "functions": functions,
            "license_analysis": license_analysis
        }

result = analyze_binary("/path/to/protected.exe")
```

### Function Decompilation
```python
def decompile_target_function(binary_path, function_name):
    decompiler = GhidraDecompiler(binary_path)
    
    # Decompile specific function
    result = decompiler.decompile_function(function_name)
    
    if result and 'decompiled_code' in result:
        print("Decompiled C code:")
        print(result['decompiled_code'])
        
        print("\nAssembly instructions:")
        for instruction in result.get('assembly', []):
            print(f"  {instruction}")
    
    return result
```

### Protection Analysis
```python
def analyze_protection_scheme(binary_path):
    decompiler = GhidraDecompiler(binary_path)
    analysis = decompiler.analyze_protection_scheme()
    
    print(f"Protection Type: {analysis.get('protection_type', 'Unknown')}")
    print(f"Confidence: {analysis.get('confidence', 0)}%")
    
    patterns = analysis.get('detected_patterns', [])
    if patterns:
        print("Detected Patterns:")
        for pattern in patterns:
            print(f"  - {pattern}")
    
    return analysis
```

## Error Handling Best Practices

### Context Manager Usage
Always use context managers for automatic cleanup:

```python
# ✓ GOOD: Automatic cleanup
with GhidraBridgeManager() as manager:
    result = manager.load_program(binary_path)

# ✗ BAD: Manual cleanup required
manager = GhidraBridgeManager()
try:
    result = manager.load_program(binary_path)
finally:
    manager.cleanup()
```

### Exception Handling
Handle specific bridge exceptions:

```python
from intellicrack.core.analysis.ghidra_bridge_manager import GhidraBridgeManager

try:
    with GhidraBridgeManager() as manager:
        if not manager.load_program(binary_path):
            print("Failed to load binary - check file format")
            return
        
        result = manager.decompile_function("main")
        
except TimeoutError:
    print("Bridge server startup timed out")
except ConnectionError:
    print("Failed to connect to Ghidra")
except Exception as e:
    print(f"Unexpected error: {e}")
```

## Troubleshooting

### Common Issues

**Bridge Server Won't Start**
- Check Ghidra installation path
- Verify Java 17+ is installed
- Ensure port 13100 is available
- Check firewall settings

**Binary Loading Fails**
- Verify binary format is supported
- Check file permissions
- Ensure sufficient memory for large binaries

**Decompilation Errors**
- Function name/address might be invalid
- Binary might be heavily obfuscated
- Ghidra analysis might be incomplete

### Debug Logging
Enable detailed logging for troubleshooting:

```python
import logging
logging.getLogger('intellicrack.ghidra_bridge').setLevel(logging.DEBUG)

# Bridge operations will now show detailed logs
with GhidraBridgeManager() as manager:
    manager.load_program(binary_path)
```

## Performance Considerations

### Large Binary Handling
- Use streaming for binaries > 100MB
- Implement analysis timeouts
- Consider memory limits

### Batch Processing
- Reuse bridge connections
- Process related binaries in sequence
- Implement connection pooling

### Resource Management
- Monitor memory usage
- Close unused projects
- Clean up temporary files

## Migration from Script-Based Approach

### Old Approach (Deprecated)
```python
# Old fragile script-based method
result = run_ghidra_script(binary_path, script_content)
```

### New Bridge Approach
```python
# New robust bridge-based method
with GhidraBridgeManager() as manager:
    manager.load_program(binary_path)
    result = manager.decompile_function("target_function")
```

### Backwards Compatibility
The old API is still supported but deprecated:
```python
# Still works but uses bridge internally
decompiler = GhidraDecompiler(binary_path)
result = decompiler.decompile_function("main")
```

## Security Considerations

### Network Security
- Bridge server runs on localhost only
- Use firewall rules for port restrictions
- Monitor bridge connections

### Data Security
- Binary data stays local
- No cloud communication
- Audit logs for all operations

### Process Security
- Bridge server runs with limited privileges
- Automatic cleanup of temporary files
- Secure handling of analysis results

This integration provides robust, production-ready programmatic control over Ghidra while maintaining all existing functionality and adding significant new capabilities.
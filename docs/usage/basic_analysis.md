# Basic Analysis Guide

This guide covers the fundamentals of using Intellicrack for binary analysis, from loading files to interpreting results.

## Getting Started

### Loading a Binary

1. **Via GUI**: Click "Open File" or drag-and-drop a binary onto the main window
2. **Via CLI**: `python -m intellicrack analyze <filename>`
3. **Supported Formats**:
   - PE (.exe, .dll, .sys)
   - ELF (Linux executables)
   - Mach-O (macOS executables)
   - Raw binary files

### Quick Analysis

Click the "Quick Analyze" button for an automated analysis that includes:
- File format detection
- Basic header parsing
- Protection detection
- String extraction
- Import/export analysis

## Analysis Types

### Static Analysis

#### File Information
- **Headers**: PE/ELF/Mach-O header details
- **Sections**: Code, data, resource sections
- **Entropy**: Detect packing/encryption
- **Checksums**: Verify file integrity

#### Protection Detection
```python
# Example: Detecting protections programmatically
from intellicrack.utils.protection_detection import ProtectionDetector

detector = ProtectionDetector()
protections = detector.detect_all_protections("target.exe")
print(f"Anti-debug: {protections['anti_debug']}")
print(f"Packer: {protections['packer']}")
```

Common protections detected:
- **Packers**: UPX, ASPack, Themida, VMProtect
- **Anti-Debug**: IsDebuggerPresent, CheckRemoteDebuggerPresent
- **Anti-VM**: CPUID checks, timing attacks
- **Obfuscation**: Code virtualization, control flow flattening

### Dynamic Analysis

#### Runtime Monitoring
1. **Process Injection**: Monitor API calls and behavior
2. **Network Activity**: Track connections and data transfer
3. **File System**: Log file operations
4. **Registry**: Monitor Windows registry access

#### Memory Analysis
- Dump process memory
- Search for patterns
- Extract decrypted/unpacked code
- Analyze heap and stack

## Vulnerability Detection

### Automated Scanning

The vulnerability engine checks for:
- **Buffer Overflows**: Stack and heap-based
- **Format Strings**: Printf vulnerabilities
- **Integer Overflows**: Arithmetic errors
- **Use After Free**: Memory corruption bugs
- **Path Traversal**: Directory traversal flaws

### Manual Analysis

1. **Control Flow Graph**: Visualize program flow
2. **Cross References**: Find function usage
3. **Pattern Matching**: Search for vulnerable patterns
4. **Symbolic Execution**: Explore execution paths

## Using the Interface

### Analysis Tab Layout

```
┌─────────────────┬──────────────────┐
│ File Browser    │ Analysis Results │
├─────────────────┼──────────────────┤
│ Hex View        │ Disassembly      │
├─────────────────┴──────────────────┤
│ Console Output                      │
└─────────────────────────────────────┘
```

### Key Features

1. **Hex Editor**:
   - Pattern highlighting
   - Search and replace
   - Bookmarks
   - Structure templates

2. **Disassembler**:
   - x86/x64/ARM support
   - Syntax highlighting
   - Cross-references
   - Comments and labels

3. **Strings View**:
   - Unicode/ASCII detection
   - Filtering options
   - Context navigation
   - Export capabilities

## Configuration

### Analysis Settings

Edit `config.json` to customize:

```json
{
  "analysis": {
    "max_string_length": 1000,
    "min_string_length": 4,
    "deep_scan": true,
    "timeout": 300,
    "parallel_threads": 8
  },
  "vulnerability_detection": {
    "check_buffer_overflow": true,
    "check_format_string": true,
    "check_integer_overflow": true,
    "confidence_threshold": 0.7
  }
}
```

### Performance Tuning

- **CPU Analysis**: Set `parallel_threads` to CPU core count
- **GPU Acceleration**: Enable in Settings → Performance
- **Memory Limit**: Adjust `max_memory_usage` for large files
- **Caching**: Enable incremental analysis for repeated scans

## Windows Executable Analysis

### Example Workflow

1. **Load the executable**:
   ```python
   from intellicrack.core.analysis import CoreAnalyzer

   analyzer = CoreAnalyzer()
   result = analyzer.analyze_pe("application.exe")
   ```

2. **Check for protections**:
   - Anti-debugging techniques
   - License checks
   - Trial limitations

3. **Identify key functions**:
   - License validation
   - Feature restrictions
   - Time checks

4. **Extract strings**:
   - Error messages
   - Registry keys
   - Network endpoints

### Common Patterns

#### License Checks
Look for:
- Registry key comparisons
- Hardware ID validation
- Network license servers
- Time-based trials

#### Anti-Tampering
Identify:
- Checksum verification
- Self-modifying code
- Debugger detection
- Integrity checks

## Tips and Best Practices

### Efficient Analysis

1. **Start Simple**: Use quick analysis before deep scanning
2. **Filter Noise**: Hide system libraries and focus on application code
3. **Use Bookmarks**: Mark interesting locations for later review
4. **Take Notes**: Document findings in the built-in notepad

### Common Pitfalls

- **Packed Code**: Unpack before analyzing for better results
- **Obfuscation**: Use dynamic analysis when static fails
- **False Positives**: Verify vulnerabilities before reporting
- **Resource Usage**: Monitor memory for large binaries

## Advanced Techniques

### Scripting

Create custom analysis scripts:

```python
# Custom vulnerability scanner
from intellicrack.plugins import PluginBase

class CustomScanner(PluginBase):
    def run(self, binary_data):
        # Your analysis logic here
        vulnerabilities = []
        # ... scanning code ...
        return vulnerabilities
```

### Integration

- **Ghidra**: Share project files
- **radare2**: Command-line integration
- **Custom Tools**: Plugin API for extensions

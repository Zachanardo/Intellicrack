# Pure Python .lnk File Parser Implementation

## Overview

This implementation provides a comprehensive, cross-platform solution for parsing Windows .lnk (shortcut) files using pure Python, eliminating dependencies on Windows-specific APIs or external tools.

## Key Features

### ✅ Cross-Platform Compatibility
- **Pure Python implementation** - No Windows API dependencies
- **Works on Linux, macOS, and Windows** - Universal shortcut parsing
- **Fallback mechanism** - Uses Windows COM when available for enhanced compatibility

### ✅ Complete .lnk Format Support
- **Full binary format parsing** - Handles all .lnk file structures
- **Unicode and ANSI strings** - Supports both text encodings
- **Timestamp parsing** - Converts Windows FILETIME to datetime objects
- **File attributes decoding** - Readable file attribute descriptions
- **Show command interpretation** - Window display state descriptions

### ✅ Robust Integration
- **FileResolver integration** - Seamless integration with existing file resolution
- **Error handling** - Graceful handling of corrupted or malformed files
- **Environment variable expansion** - Resolves %VARIABLE% references
- **Relative path resolution** - Handles relative target paths correctly

## Implementation Details

### Core Components

#### 1. LnkParser Class (`intellicrack/utils/system/lnk_parser.py`)
```python
from intellicrack.utils.system.lnk_parser import LnkParser, parse_lnk_file

# Direct parsing
parser = LnkParser()
lnk_info = parser.parse_lnk_file("shortcut.lnk")

# Convenience function
lnk_data = parse_lnk_file("shortcut.lnk")
```

#### 2. FileResolver Integration (`intellicrack/utils/system/file_resolution.py`)
```python
from intellicrack.utils.system.file_resolution import FileResolver

resolver = FileResolver()
resolved_path, metadata = resolver.resolve_file_path("shortcut.lnk")
```

### File Format Support

The parser handles the complete Windows .lnk file format:

1. **Header (76 bytes)**
   - File signature validation
   - CLSID verification
   - Link flags and file attributes
   - Timestamps (creation, access, write)
   - File size, icon index, show command
   - Hotkey configuration

2. **LinkTargetIDList** (optional)
   - Shell item identifier list
   - PIDL structure parsing

3. **LinkInfo** (optional)
   - Volume information
   - Local and network paths
   - Unicode path support

4. **String Data** (optional)
   - Name string
   - Relative path
   - Working directory
   - Command line arguments
   - Icon location

5. **Extra Data** (optional)
   - Additional metadata blocks
   - Extended properties

### Technical Implementation

#### Binary Format Parsing
```python
def _parse_header(self, data: bytes, offset: int, lnk_info: LnkInfo) -> int:
    """Parse the .lnk file header with comprehensive validation."""
    # Signature verification
    signature = data[offset:offset + 4]
    if signature != self.LNK_SIGNATURE:
        raise LnkParseError(f"Invalid .lnk signature: {signature.hex()}")
    
    # Parse all header fields with proper struct unpacking
    lnk_info.link_flags = struct.unpack('<I', data[offset:offset + 4])[0]
    # ... additional parsing
```

#### String Handling
```python
def _read_string_data(self, data: bytes, offset: int, is_unicode: bool) -> Tuple[str, int]:
    """Handle both Unicode (UTF-16LE) and ANSI (CP1252) strings."""
    if is_unicode:
        return data[offset:offset + string_bytes].decode('utf-16le')
    else:
        return data[offset:offset + string_length].decode('cp1252', errors='replace')
```

#### Timestamp Conversion
```python
def _filetime_to_datetime(self, filetime: int) -> Optional[datetime]:
    """Convert Windows FILETIME (100ns intervals since 1601) to datetime."""
    EPOCH_AS_FILETIME = 116444736000000000
    timestamp = (filetime - EPOCH_AS_FILETIME) / 10000000.0
    return datetime.fromtimestamp(timestamp, tz=timezone.utc)
```

## Usage Examples

### Basic .lnk Parsing
```python
from intellicrack.utils.system.lnk_parser import parse_lnk_file

# Parse a shortcut file
lnk_data = parse_lnk_file(r"C:\Users\Public\Desktop\MyApp.lnk")

print(f"Target: {lnk_data['target_path']}")
print(f"Working Directory: {lnk_data['working_directory']}")
print(f"Arguments: {lnk_data['command_line_arguments']}")
print(f"Creation Time: {lnk_data['creation_time']}")
```

### FileResolver Integration
```python
from intellicrack.utils.system.file_resolution import FileResolver

resolver = FileResolver()
resolved_path, metadata = resolver.resolve_file_path("shortcut.lnk")

if metadata['is_shortcut']:
    print(f"Shortcut resolves to: {resolved_path}")
    print(f"Parser used: {metadata['parser_type']}")
    print(f"Working directory: {metadata.get('working_directory')}")
```

### Advanced Parsing with Error Handling
```python
from intellicrack.utils.system.lnk_parser import LnkParser, LnkParseError

parser = LnkParser()

try:
    lnk_info = parser.parse_lnk_file("complex_shortcut.lnk")
    
    # Access detailed information
    print(f"Target: {lnk_info.target_path}")
    print(f"File attributes: {parser.get_file_attributes_description(lnk_info.file_attributes)}")
    print(f"Show command: {parser.get_show_command_description(lnk_info.show_command)}")
    print(f"Is Unicode: {lnk_info.is_unicode}")
    
    if lnk_info.parse_errors:
        print(f"Warnings: {lnk_info.parse_errors}")
        
except LnkParseError as e:
    print(f"Failed to parse .lnk file: {e}")
```

## Fallback Mechanism

The implementation provides intelligent fallback:

1. **Primary**: Pure Python parser (cross-platform)
2. **Fallback**: Windows COM interface (Windows-only, when available)

```python
def _resolve_windows_shortcut(self, lnk_path: Path) -> Tuple[Optional[str], Dict[str, any]]:
    """Primary: Pure Python parser with COM fallback."""
    try:
        # Try pure Python parser first
        parser = LnkParser()
        lnk_info = parser.parse_lnk_file(lnk_path)
        # ... process result
    except LnkParseError:
        # Fallback to Windows COM if available
        if IS_WINDOWS and HAS_WIN32:
            return self._resolve_windows_shortcut_com(lnk_path)
```

## Testing

### Unit Tests
- **Format validation** - Tests for signature and structure validation
- **String parsing** - Unicode and ANSI string handling
- **Timestamp conversion** - Windows FILETIME to datetime conversion
- **Error handling** - Invalid files and edge cases

### Integration Tests
- **FileResolver integration** - End-to-end shortcut resolution
- **Real file testing** - Tests with actual Windows shortcuts
- **Cross-platform compatibility** - Tests without Windows dependencies

### Running Tests
```bash
# Unit tests
python -m pytest tests/unit/utils/test_lnk_parser.py -v

# Integration tests
python -m pytest tests/integration/test_file_resolution_lnk.py -v

# All .lnk related tests
python -m pytest -k "lnk" -v
```

## Performance Characteristics

- **Memory efficient** - Streaming parser, low memory footprint
- **Fast parsing** - Direct binary parsing without external tools
- **Minimal dependencies** - Only uses Python standard library
- **Caching support** - Can be extended with caching mechanisms

## Error Handling

The implementation provides comprehensive error handling:

### LnkParseError
- **File not found** - Missing .lnk file
- **Invalid format** - Corrupted or non-.lnk files
- **Parsing failures** - Malformed file structures

### Graceful Degradation
- **Partial parsing** - Extracts available information from damaged files
- **Fallback mechanisms** - COM interface when pure Python fails
- **Error metadata** - Detailed error information in results

## Security Considerations

- **Input validation** - All binary data is validated before processing
- **Buffer overflow protection** - Bounds checking on all data access
- **Path traversal prevention** - Target paths are validated
- **Memory safety** - No unsafe memory operations

## Future Enhancements

### Potential Improvements
1. **Extended format support** - Additional .lnk variants and features
2. **Performance optimization** - Caching and streaming improvements
3. **Metadata extraction** - More detailed file properties
4. **Format validation** - Enhanced corruption detection

### Integration Opportunities
1. **Analyzers** - Integration with binary analysis tools
2. **Forensics** - Timeline analysis and metadata extraction
3. **Security** - Malicious shortcut detection
4. **Automation** - Batch processing capabilities

## File Structure

```
intellicrack/utils/system/
├── lnk_parser.py              # Pure Python .lnk parser
├── file_resolution.py         # Updated with .lnk integration
tests/unit/utils/
├── test_lnk_parser.py         # Unit tests
tests/integration/
├── test_file_resolution_lnk.py # Integration tests
```

## Dependencies

- **Python 3.7+** - Core language features
- **Standard library only** - No external dependencies
- **Optional**: `win32com` (Windows COM fallback)

## Compatibility

- ✅ **Windows** - Full support with optional COM fallback
- ✅ **Linux** - Pure Python implementation
- ✅ **macOS** - Pure Python implementation
- ✅ **Python 3.7+** - All supported Python versions

This implementation successfully provides pure Python .lnk file parsing capabilities, eliminating Windows-specific dependencies while maintaining full compatibility and providing robust error handling and integration with the existing Intellicrack file resolution system.
# Hex Editor Feature Guide

## Overview

Intellicrack's advanced hex editor provides professional-grade binary editing capabilities with AI-powered analysis integration. This guide covers all hex editor features, from basic editing to advanced pattern analysis and AI-assisted modifications.

## Table of Contents

1. [Getting Started](#getting-started)
2. [Basic Features](#basic-features)
3. [Advanced Search](#advanced-search)
4. [Data Inspector](#data-inspector)
5. [AI Integration](#ai-integration)
6. [Large File Handling](#large-file-handling)
7. [Highlighting and Bookmarks](#highlighting-and-bookmarks)
8. [Keyboard Shortcuts](#keyboard-shortcuts)

## Getting Started

### Opening the Hex Editor

```python
from intellicrack.hexview.hex_widget import HexWidget
from PyQt6.QtWidgets import QApplication

app = QApplication([])
hex_editor = HexWidget()
hex_editor.load_file("target.exe")
hex_editor.show()
```

### UI Components

The hex editor interface consists of:
- **Address Column**: Shows file offsets
- **Hex View**: Displays binary data in hexadecimal
- **ASCII View**: Shows ASCII representation
- **Data Inspector**: Interprets data at cursor position
- **Search Panel**: Advanced search capabilities
- **AI Assistant**: Context-aware suggestions

## Basic Features

### Navigation

```python
# Go to specific offset
hex_editor.goto_offset(0x1000)

# Jump to address
hex_editor.goto_address(0x00401000)

# Navigate by pages
hex_editor.page_down()
hex_editor.page_up()
```

### Editing Operations

```python
# Modify single byte
hex_editor.write_byte(0x1000, 0x90)  # Write NOP

# Modify multiple bytes
hex_editor.write_bytes(0x1000, b"\x90\x90\x90\x90")

# Insert bytes
hex_editor.insert_bytes(0x1000, b"\x00\x00")

# Delete bytes
hex_editor.delete_bytes(0x1000, count=4)
```

### Copy/Paste Operations

```python
# Copy selection
hex_editor.copy_selection()  # Copies as hex string

# Copy as different formats
hex_editor.copy_as_c_array()     # unsigned char data[] = {...}
hex_editor.copy_as_python()       # data = b"..."
hex_editor.copy_as_assembly()     # db 0x90, 0x90, ...

# Paste operations
hex_editor.paste_hex("90 90 90 90")
hex_editor.paste_binary(b"\x90\x90\x90\x90")
```

## Advanced Search

### Pattern Search

```python
from intellicrack.hexview.advanced_search import AdvancedSearch

searcher = AdvancedSearch(hex_editor)

# Hex pattern search
results = searcher.search_hex("48 8B ?? ?? 8B")

# String search
results = searcher.search_string("LICENSE_KEY", encoding="utf-16")

# Regex search
results = searcher.search_regex(rb"KEY[A-Z0-9]{16}")

# Binary pattern with wildcards
results = searcher.search_pattern("48 8B ? ? ? 90")
```

### Multi-Pattern Search

```python
# Search for multiple patterns
patterns = [
    {"type": "hex", "pattern": "48 8B EC"},
    {"type": "string", "pattern": "Trial"},
    {"type": "regex", "pattern": rb"Serial:\s*\w+"}
]

results = searcher.search_multiple(patterns)
```

### Search and Replace

```python
# Replace all occurrences
searcher.replace_all(
    search_hex="75 10",  # JNE
    replace_hex="90 90"  # NOP NOP
)

# Interactive replace
searcher.replace_interactive(
    pattern="Trial Version",
    replacement="Full Version",
    callback=confirm_replacement
)
```

## Data Inspector

### Interpreting Data

The Data Inspector automatically interprets data at cursor position:

```python
# Get interpretations
inspector = hex_editor.data_inspector
interpretations = inspector.get_interpretations(offset=0x1000)

print(interpretations['uint32'])    # 4-byte integer
print(interpretations['float'])     # 4-byte float
print(interpretations['string'])    # ASCII string
print(interpretations['timestamp']) # Unix timestamp
```

### Custom Data Types

```python
from intellicrack.hexview.data_inspector import DataType

# Define custom structure
class LicenseStruct(DataType):
    def __init__(self):
        self.fields = [
            ("magic", "uint32"),
            ("version", "uint16"),
            ("serial", "char[32]"),
            ("expiry", "uint32")
        ]

# Register custom type
inspector.register_type("License", LicenseStruct)
```

## AI Integration

### AI-Powered Analysis

```python
from intellicrack.hexview.ai_bridge import AIBridge

ai = AIBridge(hex_editor)

# Analyze selection
analysis = ai.analyze_selection()
print(analysis['structure'])  # Detected data structure
print(analysis['purpose'])    # Likely purpose
print(analysis['suggestions']) # Modification suggestions
```

### Pattern Recognition

```python
# Find similar patterns
similar = ai.find_similar_patterns(
    hex_editor.get_selection(),
    context_size=32
)

# Identify crypto/compression
crypto_analysis = ai.identify_encryption(
    offset=0x1000,
    size=256
)
```

### AI-Assisted Patching

```python
# Get patch suggestions
suggestions = ai.suggest_patches(
    goal="bypass license check",
    context=hex_editor.get_context(0x1000, 100)
)

for suggestion in suggestions:
    print(f"Offset: {suggestion['offset']}")
    print(f"Original: {suggestion['original']}")
    print(f"Patch: {suggestion['patch']}")
    print(f"Confidence: {suggestion['confidence']}")
```

## Large File Handling

### Memory-Mapped Files

```python
from intellicrack.hexview.large_file_handler import LargeFileHandler

# Open large file efficiently
handler = LargeFileHandler()
handler.open_file("10gb_file.bin", mode="mmap")

# Read chunks
chunk = handler.read_chunk(offset=0x100000000, size=4096)

# Lazy loading
hex_editor.enable_lazy_loading(chunk_size=1024*1024)
```

### Performance Optimization

```python
# Configure caching
hex_editor.set_cache_size(100 * 1024 * 1024)  # 100MB cache

# Enable background loading
hex_editor.enable_background_loading()

# Set render optimization
hex_editor.set_render_mode("virtual")  # Only render visible
```

## Highlighting and Bookmarks

### Syntax Highlighting

```python
from intellicrack.hexview.hex_highlighter import HexHighlighter

highlighter = HexHighlighter(hex_editor)

# Highlight pattern
highlighter.highlight_pattern(
    pattern="48 8B EC",
    color="#FF0000",
    name="Function Prologue"
)

# Highlight regions
highlighter.highlight_region(
    start=0x1000,
    end=0x2000,
    color="#00FF00",
    name="Code Section"
)
```

### Bookmarks

```python
# Add bookmark
hex_editor.add_bookmark(
    offset=0x1000,
    name="License Check",
    description="Main license validation routine"
)

# Navigate bookmarks
hex_editor.goto_next_bookmark()
hex_editor.goto_prev_bookmark()

# List bookmarks
bookmarks = hex_editor.get_bookmarks()
```

### Color Schemes

```python
# Apply predefined schemes
hex_editor.apply_color_scheme("executable")  # PE/ELF coloring
hex_editor.apply_color_scheme("ascii")       # ASCII highlighting

# Custom scheme
scheme = {
    "null": "#808080",
    "ascii": "#00FF00",
    "code": "#0080FF",
    "data": "#FFFF00"
}
hex_editor.set_color_scheme(scheme)
```

## Protection Integration

### Intellicrack Protection Analysis

```python
from intellicrack.hexview.intellicrack_hex_protection_integration import (
    ProtectionIntegration
)

# Analyze protection in hex view
protection = ProtectionIntegration(hex_editor)
results = protection.analyze_current_view()

# Highlight protected regions
for region in results['protected_regions']:
    hex_editor.highlight_region(
        region['start'],
        region['end'],
        color="#FF0000"
    )
```

## Keyboard Shortcuts

### Navigation
- `Ctrl+G` - Go to offset
- `Ctrl+F` - Find
- `F3` - Find next
- `Shift+F3` - Find previous
- `Page Up/Down` - Navigate by page
- `Home/End` - Go to start/end of line
- `Ctrl+Home/End` - Go to start/end of file

### Editing
- `Ctrl+Z` - Undo
- `Ctrl+Y` - Redo
- `Ctrl+C` - Copy
- `Ctrl+V` - Paste
- `Ctrl+X` - Cut
- `Insert` - Toggle insert/overwrite mode
- `Delete` - Delete byte
- `Ctrl+S` - Save

### View
- `Ctrl++` - Zoom in
- `Ctrl+-` - Zoom out
- `Ctrl+0` - Reset zoom
- `Tab` - Switch between hex/ASCII
- `Ctrl+B` - Toggle bookmarks panel
- `Ctrl+I` - Toggle data inspector

### AI Features
- `Ctrl+Shift+A` - Analyze selection with AI
- `Ctrl+Shift+P` - Get patch suggestions
- `Ctrl+Shift+S` - Find similar patterns

## Advanced Usage

### Custom Renderers

```python
from intellicrack.hexview.hex_renderer import HexRenderer

class CustomRenderer(HexRenderer):
    def render_byte(self, byte_value, offset):
        # Custom rendering logic
        if self.is_instruction_start(offset):
            return f"<b>{byte_value:02X}</b>"
        return f"{byte_value:02X}"

hex_editor.set_renderer(CustomRenderer())
```

### Plugin Development

```python
from intellicrack.hexview.hex_commands import HexCommand

class MyCommand(HexCommand):
    def __init__(self):
        super().__init__("My Custom Command")

    def execute(self, hex_editor, selection):
        # Command implementation
        data = hex_editor.read_bytes(
            selection.start,
            selection.length
        )
        # Process data
        return modified_data

# Register command
hex_editor.register_command(MyCommand())
```

### Integration with Analysis

```python
# Export to disassembler
hex_editor.export_selection_to_ghidra()
hex_editor.export_selection_to_radare2()

# Import analysis results
hex_editor.import_radare2_analysis("analysis.json")
hex_editor.apply_function_labels(functions)
```

## Best Practices

1. **Always backup** files before editing
2. **Use bookmarks** for important locations
3. **Save sessions** for complex analysis
4. **Use AI suggestions** as guidance, not absolute truth
5. **Verify patches** in controlled environment
6. **Document changes** with bookmark descriptions
7. **Use version control** for patch development

## Performance Tips

1. Enable lazy loading for files > 100MB
2. Use memory mapping for files > 1GB
3. Adjust cache size based on available RAM
4. Disable unnecessary highlighters
5. Use virtual rendering for large files
6. Close unused analysis panels

## Troubleshooting

### Common Issues

1. **Slow loading**: Enable lazy loading
2. **High memory usage**: Reduce cache size
3. **Rendering lag**: Switch to virtual rendering
4. **Search timeout**: Use indexed search for large files

### Debug Mode

```python
# Enable debug logging
hex_editor.set_debug_mode(True)

# Performance profiling
profiler = hex_editor.get_profiler()
profiler.start()
# ... operations ...
print(profiler.get_report())
```

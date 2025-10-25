# Streaming Analysis for Large Binaries

## Overview

The BinaryAnalyzer now supports production-ready streaming analysis for large binaries (firmware images, disk images, large installers) without loading entire files into memory. This implementation provides genuine chunk-based processing, memory-mapped file access, and incremental analysis capabilities for multi-GB files.

## Key Features

### 1. Automatic Streaming Mode Selection

The analyzer automatically detects when to use streaming mode based on file size:

```python
from intellicrack.core.analysis.binary_analyzer import BinaryAnalyzer

analyzer = BinaryAnalyzer()

# Automatically uses streaming for files > 50MB
results = analyzer.analyze("large_installer.exe")

# Force streaming mode
results = analyzer.analyze("any_file.exe", use_streaming=True)

# Force non-streaming mode
results = analyzer.analyze("small_file.exe", use_streaming=False)
```

### 2. Chunk-Based Processing

Files are processed in configurable chunks without loading the entire file:

```python
# Default chunk sizes
LARGE_FILE_THRESHOLD = 50 * 1024 * 1024  # 50 MB
CHUNK_SIZE = 8 * 1024 * 1024              # 8 MB
HASH_CHUNK_SIZE = 64 * 1024               # 64 KB

# Iterate through file chunks
for chunk, offset in analyzer._read_chunks(file_path):
    # Process chunk at offset
    pass
```

### 3. Memory-Mapped File Access

For efficient random access to large files:

```python
# Open file with memory mapping
file_handle, mm = analyzer._open_mmap(file_path)
try:
    # Access any byte without loading entire file
    header = mm[0:1024]
    section = mm[0x10000:0x20000]
finally:
    mm.close()
    file_handle.close()
```

### 4. Progress Tracking

Monitor analysis progress for long-running operations:

```python
def progress_callback(stage, current, total):
    percent = (current / total * 100) if total > 0 else 0
    print(f"[{percent:5.1f}%] {stage}")

results = analyzer.analyze_with_progress(
    "large_file.exe",
    progress_callback=progress_callback
)
```

Stages tracked:
- `format_detection` - Detecting file format
- `hash_calculation` - Computing file hashes
- `format_analysis` - Analyzing format-specific structures
- `string_extraction` - Extracting printable strings
- `entropy_analysis` - Analyzing entropy distribution
- `completed` - Analysis finished

### 5. Resumable Operations

Save and load analysis checkpoints for interrupted operations:

```python
# Perform analysis
results = analyzer.analyze("large_file.exe")

# Save checkpoint
analyzer.save_analysis_checkpoint(results, "checkpoint.json")

# Later, load checkpoint
loaded_results = analyzer.load_analysis_checkpoint("checkpoint.json")
```

### 6. Pattern Scanning

Scan large files for byte patterns efficiently:

```python
# Define patterns to search
patterns = [
    b"MZ",                    # PE header
    b"PE\x00\x00",           # PE signature
    b"\x7fELF",              # ELF header
    b"license key",          # License strings
]

# Scan with context
results = analyzer.scan_for_patterns_streaming(
    "firmware.bin",
    patterns=patterns,
    context_bytes=32  # Include 32 bytes before/after match
)

# Results: {pattern_hex: [matches]}
for pattern_hex, matches in results.items():
    print(f"Pattern {pattern_hex}: {len(matches)} matches")
    for match in matches:
        print(f"  Offset: 0x{match['offset']:08x}")
        print(f"  Context before: {match['context_before']}")
        print(f"  Context after: {match['context_after']}")
```

### 7. License String Scanning

Specialized scanning for licensing-related strings:

```python
# Scan for license-related strings
results = analyzer.scan_for_license_strings_streaming("software.exe")

for match in results:
    print(f"Offset 0x{match['offset']:08x}: {match['string']}")
    print(f"  Pattern matched: {match['pattern_matched']}")
```

Detected patterns:
- `serial`, `license`, `activation`, `registration`
- `product key`, `unlock code`, `trial`, `expired`
- `validate`, `authenticate`

### 8. Section Analysis

Analyze specific sections of large binaries:

```python
# Define section ranges (start_offset, end_offset)
section_ranges = [
    (0x0000, 0x1000),      # Header
    (0x1000, 0x10000),     # Code section
    (0x10000, 0x20000),    # Data section
]

results = analyzer.analyze_sections_streaming(
    "large_binary.exe",
    section_ranges
)

for section_name, data in results.items():
    print(f"\n{section_name}:")
    print(f"  Range: {data['range']}")
    print(f"  Size: {data['size']:,} bytes")
    print(f"  Entropy: {data['entropy']}")
    print(f"  Characteristics: {data['characteristics']}")
```

Section characteristics:
- `Encrypted/Compressed` - High entropy (>7.5)
- `Highly Repetitive/Padded` - Low entropy (<2.0)
- `Text/Strings` - High printable ratio (>80%)
- `Code/Binary Data` - Low printable, moderate-high entropy
- `Structured Binary` - Moderate entropy (4.0-6.0)
- `Mixed Content` - Other patterns

## Streaming Hash Calculation

Compute cryptographic hashes without loading entire file:

```python
def hash_progress(bytes_processed, total_bytes):
    percent = (bytes_processed / total_bytes * 100)
    print(f"Hashing: {percent:.1f}%")

hashes = analyzer._calculate_hashes_streaming(
    "large_file.exe",
    progress_callback=hash_progress
)

print(f"SHA256: {hashes['sha256']}")
print(f"SHA512: {hashes['sha512']}")
print(f"SHA3-256: {hashes['sha3_256']}")
print(f"BLAKE2b: {hashes['blake2b']}")
```

## Format-Specific Streaming Analysis

### PE Files (Windows Executables)

```python
# Analyze PE using memory mapping
pe_info = analyzer._analyze_pe_streaming("large.exe")

print(f"Machine: {pe_info['machine']}")
print(f"Sections: {len(pe_info['sections'])}")
for section in pe_info['sections']:
    print(f"  {section['name']}: {section['virtual_size']:,} bytes")
```

### ELF Files (Linux Executables)

```python
# Analyze ELF using memory mapping
elf_info = analyzer._analyze_elf_streaming("large_binary")

print(f"Class: {elf_info['class']}")
print(f"Type: {elf_info['type']}")
print(f"Segments: {len(elf_info['segments'])}")
```

### Mach-O Files (macOS Executables)

```python
# Analyze Mach-O using memory mapping
macho_info = analyzer._analyze_macho_streaming("large_app")

print(f"Architecture: {macho_info['architecture']}")
print(f"Commands: {macho_info['num_commands']}")
```

## Performance Characteristics

### Memory Usage

- **Non-streaming mode**: Entire file loaded into RAM
- **Streaming mode**: Only active chunk in memory (~8 MB)
- **Memory-mapped mode**: Operating system manages paging

### Processing Speed

| File Size | Non-Streaming | Streaming | Memory Mapped |
|-----------|---------------|-----------|---------------|
| 10 MB     | Fast          | Fast      | Fast          |
| 100 MB    | Slow/Crash    | Fast      | Fast          |
| 1 GB      | Crash         | Moderate  | Fast          |
| 10 GB     | Crash         | Slow      | Moderate      |

### Recommended Approaches

- **< 50 MB**: Non-streaming (default)
- **50 MB - 500 MB**: Streaming with progress tracking
- **500 MB - 2 GB**: Memory-mapped analysis
- **> 2 GB**: Streaming with checkpointing

## Use Cases

### 1. Large Software Installers

Analyze multi-GB installers without exhausting memory:

```python
analyzer = BinaryAnalyzer()
results = analyzer.analyze_with_progress(
    "adobe_installer.exe",
    progress_callback=lambda s, c, t: print(f"{s}: {c}/{t}")
)
```

### 2. Firmware Images

Extract licensing protection from firmware:

```python
# Scan firmware for license strings
license_strings = analyzer.scan_for_license_strings_streaming(
    "router_firmware.bin"
)

# Find activation patterns
activation_patterns = [
    b"activate",
    b"license",
    b"serial",
]
matches = analyzer.scan_for_patterns_streaming(
    "router_firmware.bin",
    activation_patterns
)
```

### 3. Disk Images

Analyze disk images for protection mechanisms:

```python
# Analyze specific sections of disk image
mbr_range = (0, 512)
boot_sector_range = (512, 4096)
partition_range = (0x100000, 0x200000)

sections = analyzer.analyze_sections_streaming(
    "disk.img",
    [mbr_range, boot_sector_range, partition_range]
)
```

### 4. Long-Running Analysis

Resume interrupted analysis:

```python
checkpoint_file = "analysis_checkpoint.json"

# Check for existing checkpoint
checkpoint = analyzer.load_analysis_checkpoint(checkpoint_file)

if checkpoint:
    print("Resuming from checkpoint")
    results = checkpoint
else:
    print("Starting new analysis")
    results = analyzer.analyze("huge_file.bin")

    # Save checkpoint periodically
    analyzer.save_analysis_checkpoint(results, checkpoint_file)
```

## Windows Optimization

The streaming implementation is optimized for Windows:

1. **File Handles**: Uses Windows-compatible file descriptor handling
2. **Path Handling**: Supports Windows path separators and long paths
3. **Memory Mapping**: Uses `mmap.ACCESS_READ` for Windows compatibility
4. **Binary Mode**: All file operations use binary mode (`'rb'`)

## Error Handling

All streaming methods include production-ready error handling:

```python
try:
    results = analyzer.analyze("large_file.exe")

    if "error" in results:
        print(f"Analysis failed: {results['error']}")
    else:
        print(f"Analysis succeeded: {results['analysis_status']}")

except Exception as e:
    print(f"Unexpected error: {e}")
```

## Limitations

1. **Archive Analysis**: ZIP/JAR/APK files still use in-memory extraction
2. **String Extraction**: Limited to 100 strings in streaming mode (configurable)
3. **Pattern Overlap**: Patterns spanning chunk boundaries handled with overlap buffer
4. **Memory Mapping**: Very large files (>RAM size) may cause paging on low-memory systems

## Best Practices

1. **Use automatic detection**: Let the analyzer choose streaming mode
2. **Monitor progress**: Use progress callbacks for large files
3. **Save checkpoints**: For files that take >5 minutes to analyze
4. **Chunk size tuning**: Adjust `CHUNK_SIZE` based on available RAM
5. **Pattern efficiency**: Limit number of patterns in single scan
6. **Section targeting**: Analyze specific sections rather than entire file when possible

## Example: Complete Large File Analysis

```python
from pathlib import Path
from intellicrack.core.analysis.binary_analyzer import BinaryAnalyzer

def analyze_large_binary(file_path):
    """Complete example of large binary analysis."""
    analyzer = BinaryAnalyzer()
    file_path = Path(file_path)
    checkpoint_path = file_path.with_suffix('.checkpoint.json')

    print(f"Analyzing: {file_path}")
    print(f"Size: {file_path.stat().st_size:,} bytes")

    # Check for existing checkpoint
    checkpoint = analyzer.load_analysis_checkpoint(checkpoint_path)
    if checkpoint:
        print("Loaded checkpoint from previous run")
        return checkpoint

    # Progress callback
    def progress(stage, current, total):
        percent = (current / total * 100) if total > 0 else 0
        print(f"[{percent:5.1f}%] {stage}")

    # Perform analysis
    results = analyzer.analyze_with_progress(file_path, progress)

    # Save checkpoint
    analyzer.save_analysis_checkpoint(results, checkpoint_path)

    # Scan for license strings
    print("\nScanning for license strings...")
    license_strings = analyzer.scan_for_license_strings_streaming(file_path)
    results['license_strings'] = license_strings

    # Scan for protection patterns
    print("\nScanning for protection patterns...")
    patterns = [b"VMProtect", b"Themida", b"Denuvo", b"SecuROM"]
    pattern_matches = analyzer.scan_for_patterns_streaming(file_path, patterns)
    results['protection_patterns'] = pattern_matches

    print("\nAnalysis complete!")
    print(f"Format: {results.get('format')}")
    print(f"Entropy: {results.get('entropy', {}).get('overall_entropy')}")
    print(f"License strings found: {len(license_strings)}")

    return results

# Run analysis
if __name__ == "__main__":
    results = analyze_large_binary("large_installer.exe")
```

## Technical Implementation

### Chunk Reader Implementation

```python
def _read_chunks(self, file_path: Path, chunk_size: int = None) -> Iterator[tuple[bytes, int]]:
    """Generate chunks with offset tracking."""
    if chunk_size is None:
        chunk_size = self.CHUNK_SIZE

    with open(file_path, "rb") as f:
        offset = 0
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            yield chunk, offset
            offset += len(chunk)
```

### Memory Mapping Implementation

```python
def _open_mmap(self, file_path: Path) -> tuple[Any, Any]:
    """Memory map file for efficient random access."""
    file_handle = open(file_path, "rb")
    try:
        mmap_obj = mmap.mmap(file_handle.fileno(), 0, access=mmap.ACCESS_READ)
        return file_handle, mmap_obj
    except (OSError, ValueError) as e:
        file_handle.close()
        raise RuntimeError(f"Failed to create memory map: {e}") from e
```

### Pattern Scanning with Overlap

```python
def scan_for_patterns_streaming(self, binary_path: Path, patterns: list[bytes]) -> dict:
    """Scan with overlap buffer to handle patterns spanning chunks."""
    overlap_size = max(len(p) for p in patterns) - 1
    previous_chunk_tail = b""

    for chunk, chunk_offset in self._read_chunks(binary_path):
        # Combine with previous chunk tail
        search_data = previous_chunk_tail + chunk
        search_offset = chunk_offset - len(previous_chunk_tail)

        # Search for patterns
        # ...

        # Save tail for next iteration
        previous_chunk_tail = chunk[-overlap_size:]
```

## Conclusion

The streaming analysis implementation provides production-ready capabilities for analyzing multi-GB binaries without memory constraints. All features are fully functional, tested, and optimized for Windows platforms, enabling effective security research on large-scale software installations, firmware images, and disk images.

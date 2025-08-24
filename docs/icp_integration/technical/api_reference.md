# ICP Backend API Reference

Comprehensive API documentation for the ICP (Intellicrack Protection) Engine integration with die-python.

## Overview

The ICP Backend provides native die-python integration for advanced protection detection and analysis. It replaces the legacy DIE engine integration with a modern, async-capable backend that supports multiple scan modes and provides structured protection analysis results.

## Core Classes

### ICPBackend

Main backend class providing die-python integration and analysis capabilities.

```python
from intellicrack.protection.icp_backend import ICPBackend, ScanMode

backend = ICPBackend()
```

#### Constructor

##### ICPBackend(engine_path: Optional[str] = None)

Initializes the ICP backend with die-python integration.

**Parameters:**
- `engine_path` (Optional[str]): Legacy parameter for compatibility, ignored in die-python implementation

**Raises:**
- `ICPEngineError`: If die-python library is not available

**Example:**
```python
try:
    backend = ICPBackend()
    print(f"Engine version: {backend.get_engine_version()}")
except ICPEngineError as e:
    print(f"ICP initialization failed: {e}")
```

#### Methods

##### async analyze_file(file_path: str, scan_mode: ScanMode = ScanMode.DEEP, show_entropy: bool = True, show_info: bool = True, timeout: float = 30.0) -> ICPScanResult

Analyzes a file asynchronously using die-python.

**Parameters:**
- `file_path` (str): Path to file to analyze
- `scan_mode` (ScanMode): Scan mode to use (default: ScanMode.DEEP)
- `show_entropy` (bool): Include entropy analysis (legacy compatibility, ignored)
- `show_info` (bool): Include file info (legacy compatibility, ignored)
- `timeout` (float): Maximum time to wait for analysis in seconds (default: 30.0)

**Returns:**
- `ICPScanResult`: Analysis results with detections and metadata

**Example:**
```python
import asyncio

async def analyze_binary():
    result = await backend.analyze_file("target.exe", ScanMode.DEEP)
    if result.error:
        print(f"Analysis failed: {result.error}")
    else:
        print(f"Found {len(result.all_detections)} detections")
        print(f"File is packed: {result.is_packed}")
        print(f"File is protected: {result.is_protected}")

asyncio.run(analyze_binary())
```

##### async batch_analyze(file_paths: List[str], scan_mode: ScanMode = ScanMode.NORMAL, max_concurrent: int = 4) -> Dict[str, ICPScanResult]

Analyzes multiple files concurrently.

**Parameters:**
- `file_paths` (List[str]): List of file paths to analyze
- `scan_mode` (ScanMode): Scan mode to use for all files
- `max_concurrent` (int): Maximum concurrent analyses (default: 4)

**Returns:**
- `Dict[str, ICPScanResult]`: Dictionary mapping file paths to results

**Example:**
```python
files = ["target1.exe", "target2.dll", "target3.sys"]
results = await backend.batch_analyze(files, ScanMode.NORMAL)

for file_path, result in results.items():
    if result.error:
        print(f"{file_path}: Error - {result.error}")
    else:
        print(f"{file_path}: {len(result.all_detections)} detections")
```

##### get_engine_version() -> str

Returns the ICP engine version information.

**Returns:**
- `str`: Version string in format "die-python X.Y.Z (DIE A.B.C)"

##### get_available_scan_modes() -> List[str]

Returns list of available scan mode values.

**Returns:**
- `List[str]`: List of scan mode string values

##### is_die_python_available() -> bool

Checks if die-python is available and working.

**Returns:**
- `bool`: True if die-python is functional, False otherwise

### ScanMode

Enumeration of available scan modes.

```python
from intellicrack.protection.icp_backend import ScanMode

# Available modes
ScanMode.NORMAL      # Basic scanning (flag value: 0)
ScanMode.DEEP        # Deep analysis (flag value: 1)
ScanMode.HEURISTIC   # Heuristic scanning (flag value: 2)
ScanMode.AGGRESSIVE  # Combined deep + heuristic
ScanMode.ALL         # All available scan types
```

**Mode Descriptions:**
- **NORMAL**: Fast scanning with basic detection
- **DEEP**: Thorough analysis with extended patterns
- **HEURISTIC**: Behavior-based detection algorithms
- **AGGRESSIVE**: Combines DEEP and HEURISTIC for maximum coverage
- **ALL**: Enables all scanning types and flags

### ICPScanResult

Container for analysis results with structured detection data.

```python
from intellicrack.protection.icp_backend import ICPScanResult

# Create from die-python text output
result = ICPScanResult.from_die_text("target.exe", "PE64\n    Packer: UPX")
```

#### Properties

##### file_path: str
Path to the analyzed file.

##### file_infos: List[ICPFileInfo]
List of file information objects containing detections.

##### error: Optional[str]
Error message if analysis failed, None if successful.

##### raw_json: Optional[Dict[str, Any]]
Legacy raw JSON data for compatibility.

##### is_packed: bool (property)
Returns True if file contains packer detections.

**Packer Types:** "Packer", "Protector", "Cryptor"

##### is_protected: bool (property)
Returns True if file contains protection detections.

**Protection Types:** "Protector", "License", "DRM", "Dongle", "Anti-Debug"

##### all_detections: List[ICPDetection] (property)
Returns all detections from all file infos.

#### Class Methods

##### from_die_text(file_path: str, die_text: str) -> ICPScanResult

Creates ICPScanResult from die-python text output.

**Parameters:**
- `file_path` (str): Path to analyzed file
- `die_text` (str): Text output from die.scan_file()

**Returns:**
- `ICPScanResult`: Parsed result object

**Text Format:**
```
PE64
    Unknown: Unknown
    Packer: UPX
    Protector: Themida
```

**Example:**
```python
# die-python output parsing
die_output = "PE64\n    Packer: UPX\n    Protector: VMProtect"
result = ICPScanResult.from_native_engine_text("sample.exe", icp_output_text)

print(f"File type: {result.file_infos[0].filetype}")  # "PE64"
print(f"Detections: {len(result.all_detections)}")   # 2
print(f"Is packed: {result.is_packed}")              # True
print(f"Is protected: {result.is_protected}")        # True
```

### ICPDetection

Individual detection result.

#### Properties

##### name: str
Detection name (e.g., "UPX", "VMProtect").

##### type: str
Detection type (e.g., "Packer", "Protector").

##### version: str
Version information (if available).

##### info: str
Additional information about the detection.

##### string: str
Original detection string from die-python.

##### confidence: float
Confidence score (default: 1.0).

### ICPFileInfo

File information container.

#### Properties

##### filetype: str
File format type (e.g., "PE64", "ELF64").

##### size: str
File size in bytes.

##### offset: str
File offset (default: "0").

##### parentfilepart: str
Parent file information (for embedded files).

##### detections: List[ICPDetection]
List of detections for this file.

## Utility Functions

### get_icp_backend() -> ICPBackend

Returns the singleton ICP backend instance.

```python
from intellicrack.protection.icp_backend import get_icp_backend

backend = get_icp_backend()
```

### analyze_with_icp(file_path: str) -> Optional[ICPScanResult]

Helper function for easy integration with deep scan mode.

```python
from intellicrack.protection.icp_backend import analyze_with_icp

result = await analyze_with_icp("target.exe")
if result and not result.error:
    print(f"Analysis complete: {len(result.all_detections)} detections")
```

## Error Handling

### ICPEngineError

Base exception for ICP engine-related errors.

**Common Error Scenarios:**
- die-python not installed or accessible
- Invalid file paths or permissions
- Analysis timeout exceeded
- Malformed die-python output

**Example Error Handling:**
```python
try:
    backend = ICPBackend()
    result = await backend.analyze_file("target.exe")

    if result.error:
        print(f"Analysis error: {result.error}")
    else:
        # Process successful result
        for detection in result.all_detections:
            print(f"{detection.type}: {detection.name}")

except ICPEngineError as e:
    print(f"ICP Engine error: {e}")
except Exception as e:
    print(f"Unexpected error: {e}")
```

## Integration Patterns

### GUI Integration

The ICP backend integrates with the Protection Analysis widget:

```python
from intellicrack.ui.widgets.icp_analysis_widget import ICPAnalysisWidget
from intellicrack.analysis.analysis_result_orchestrator import AnalysisResultOrchestrator

# Widget handles UI updates
icp_widget = ICPAnalysisWidget()

# Orchestrator distributes results to handlers
orchestrator = AnalysisResultOrchestrator()
orchestrator.on_icp_analysis_complete(result)
```

### Auto-trigger Integration

Files opened in the main window automatically trigger ICP analysis:

```python
def _auto_trigger_icp_analysis(self, file_path: str):
    """Auto-trigger ICP analysis when a file is opened."""
    self.icp_widget.analyze_file(file_path)
    self.tab_widget.setCurrentIndex(3)  # Protection Analysis tab
```

## Performance Considerations

### Scan Mode Selection

| Mode | Speed | Accuracy | Use Case |
|------|-------|----------|----------|
| NORMAL | Fast | Good | Quick triage |
| DEEP | Medium | High | Detailed analysis |
| HEURISTIC | Medium | High | Behavioral detection |
| AGGRESSIVE | Slow | Highest | Comprehensive scan |

### Async Best Practices

- Use appropriate timeout values (default: 30s)
- Limit concurrent analyses with batch_analyze()
- Handle timeouts gracefully in production code
- Monitor memory usage for large file sets

### Performance Benchmarks

From Phase 5 testing with die-python v0.4.0:
- Average analysis time: 0.02-0.04 seconds per file
- Memory usage: < 50MB overhead per analysis
- Concurrent limit: 4 files (configurable)

## Version Compatibility

**Supported die-python versions:** 0.4.0+
**Underlying engine compatibility:** 3.09+ (This refers to the internal dependency, not the user-facing ICP Engine)
**Python requirements:** 3.11+

## Migration from Legacy DIE

### API Changes

| Legacy DIE | ICP Backend |
|------------|-------------|
| `scan_file(path)` | `await analyze_file(path, mode)` |
| JSON output | Structured ICPScanResult |
| Synchronous | Asynchronous |
| Multiple APIs | Unified ICPBackend |

### Migration Example

```python
# Legacy DIE
import subprocess
result = subprocess.run(["die", "target.exe"], capture_output=True)

# ICP Backend
from intellicrack.protection.icp_backend import get_icp_backend, ScanMode

backend = get_icp_backend()
result = await backend.analyze_file("target.exe", ScanMode.DEEP)
```

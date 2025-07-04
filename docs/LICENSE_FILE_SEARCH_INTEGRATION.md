# License File Search Integration

This document describes how the `search_for_license_files()` method from `ai_file_tools.py` has been integrated into Intellicrack's protection analysis workflow.

## Overview

The license file search functionality helps identify potential license-related files when analyzing protected software. This is particularly useful when dealing with licensing schemes like HASP, Sentinel, FlexLM, or custom license implementations.

## Integration Points

### 1. Protection Analyzer Tool (`intellicrack/tools/protection_analyzer_tool.py`)

The `ProtectionAnalyzerTool` now automatically searches for license files when:
- License protection (LICENSE, DONGLE, or DRM types) is detected
- Detailed analysis is requested and license-related imports are found

**Key Changes:**
- Added `ai_file_tools` instance to the tool
- Integrated license file search after protection detection
- Results are included in the analysis output
- License files are displayed in the formatted report

### 2. Protection Widget UI (`intellicrack/ui/widgets/intellicrack_protection_widget.py`)

The UI widget now includes:
- Automatic license file search when license protection is detected
- "Search License Files" button for manual searches
- Display of found license files in the summary
- Progress updates during search

**Key Features:**
- Button is enabled after binary analysis completes
- Results are shown in a message box
- Summary is updated with license file count
- File details (name, size, type) are displayed

## Usage Examples

### Automatic Search During Analysis

When analyzing a binary with the Protection Analyzer Tool:

```python
from intellicrack.tools.protection_analyzer_tool import ProtectionAnalyzerTool

analyzer = ProtectionAnalyzerTool()
results = analyzer.analyze("path/to/protected.exe", detailed=True)

# License files are automatically searched if relevant
if results.get("license_files_found"):
    files = results["license_files_found"]["files_found"]
    print(f"Found {len(files)} license files")
```

### Manual Search via UI

1. Analyze a binary using the "Analyze Binary" button
2. Click "Search License Files" button (enabled after analysis)
3. View results in the popup dialog
4. Check the updated summary for license file information

### Direct API Usage

```python
from intellicrack.ai.ai_file_tools import get_ai_file_tools

ai_tools = get_ai_file_tools()
results = ai_tools.search_for_license_files("/path/to/directory")

if results["status"] == "success":
    for file_info in results["files_found"]:
        print(f"Found: {file_info['name']} ({file_info['size_str']})")
```

### Custom Pattern Search

```python
# Search for specific license file patterns
custom_patterns = ["*.hasp", "sentinel_*.dat", "license_*.xml"]
results = ai_tools.search_for_license_files("/path/to/dir", custom_patterns)
```

## File Patterns Searched

The search looks for files matching these patterns by default:

**Common License Files:**
- `license.*`, `licence.*`, `lic.*`
- `*.lic`, `*.license`, `*.licence`
- `activation.*`, `*.key`, `*.dat`

**Vendor-Specific:**
- HASP: `hasp_*.xml`, `*.hasp`, `hasp.ini`
- Sentinel: `sentinel_*.dat`, `*.sntl`
- FlexLM: `*.flexlm`, `flexlm_*.lic`
- CodeMeter: `*.wbb`, `*.cmact`

**Configuration Files:**
- `*.ini`, `*.cfg`, `*.conf`, `*.config`
- `settings.xml`, `config.json`

## Benefits

1. **Comprehensive Analysis**: Automatically identifies license files that may contain:
   - License keys or serial numbers
   - Configuration data
   - Validation rules
   - Expiration dates

2. **Bypass Research**: Found files can help understand:
   - License validation mechanisms
   - File formats used
   - Storage locations
   - Dependencies

3. **Time Saving**: Automated search eliminates manual file system exploration

## Testing

Run the test script to see the integration in action:

```bash
python test_license_file_search_integration.py
```

This will:
1. Analyze a binary and show license files found
2. Perform a direct license file search
3. Test custom pattern searching

## Future Enhancements

- Automatic content analysis of found license files
- Pattern extraction from license file contents
- Integration with bypass script generation
- License file format detection and parsing
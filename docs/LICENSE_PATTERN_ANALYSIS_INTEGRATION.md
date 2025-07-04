# License Pattern Analysis Integration

## Overview

The `analyze_license_patterns()` method from `ai_assistant_enhanced.py` has been integrated into Intellicrack's protection analysis workflow. This enhancement provides AI-driven analysis of licensing mechanisms found in binary files.

## Integration Points

### 1. Protection Analyzer Tool (`protection_analyzer_tool.py`)

The main integration point where license pattern analysis is triggered:

- **Automatic Triggering**: When license-related protections (LICENSE, DONGLE, DRM) are detected
- **Smart Detection**: Analyzes imports and compiler information to determine if license analysis would be beneficial
- **String Extraction**: Extracts license-related strings from binaries using multiple methods

#### Key Methods Added:
- `_should_analyze_license_patterns()`: Determines when to run license analysis
- `_analyze_license_patterns()`: Orchestrates the license pattern analysis
- `_extract_strings_from_binary()`: Extracts strings with focus on license patterns
- `_get_license_protection_context()`: Provides additional context about APIs and likely license files

### 2. LLM Tool Integration (`intellicrack_protection_analysis_tool.py`)

License pattern analysis is also integrated into the LLM tool for AI models:

- **Automatic Analysis**: Triggered when license protections are detected
- **Enhanced Context**: Provides network, crypto, and registry API information
- **LLM Guidance**: Offers specific guidance based on license type detected

#### Key Methods Added:
- `_analyze_license_patterns_for_llm()`: Specialized analysis for LLM consumption
- `_check_for_network_apis()`: Detects network-related imports
- `_check_for_crypto_apis()`: Detects cryptography-related imports
- `_get_license_llm_guidance()`: Provides LLM-specific guidance

## Usage

### Direct Analysis

```python
from intellicrack.tools.protection_analyzer_tool import ProtectionAnalyzerTool

analyzer = ProtectionAnalyzerTool()
result = analyzer.analyze("path/to/binary.exe", detailed=True)

# License analysis results will be in:
# result["license_pattern_analysis"]
```

### LLM Tool Usage

```python
from intellicrack.llm.tools.intellicrack_protection_analysis_tool import DIEAnalysisTool

tool = DIEAnalysisTool()
result = tool.execute(
    file_path="path/to/binary.exe",
    scan_mode="deep",
    extract_strings=True
)

# License analysis results will be in:
# result["license_pattern_analysis"]
```

## Analysis Output

The license pattern analysis provides:

1. **License Type Detection**:
   - `trial_based`: Time-limited or usage-limited trials
   - `serial_based`: Serial key validation
   - `activation_based`: Online or offline activation
   - `unknown`: Unable to determine specific type

2. **Pattern Analysis**:
   - Extracted license-related strings
   - Identified licensing patterns
   - Confidence score (0-1)

3. **Bypass Suggestions**:
   - Type-specific recommendations
   - Analysis approach guidance
   - Areas to focus investigation

4. **Protection Context**:
   - Network API usage
   - Cryptography API usage
   - Registry API usage
   - Likely license file names

## String Extraction Methods

The integration uses multiple fallback methods for string extraction:

1. **Primary**: Radare2 string analyzer (if available)
   - Comprehensive string analysis
   - Categorized string extraction
   - Advanced pattern detection

2. **Fallback**: System `strings` command
   - Basic string extraction
   - Filtered for license-related keywords

3. **Emergency**: Returns empty string set
   - Prevents analysis failure
   - Allows partial analysis to continue

## Triggering Conditions

License pattern analysis is triggered when:

1. **Explicit License Protection**: Detection of LICENSE, DONGLE, or DRM protection types
2. **License-Related Imports**: Presence of license-related DLLs or APIs
3. **Commercial Compiler**: Detection of commercial compilers (Visual Studio, Delphi, etc.)
4. **Suspicious Strings**: License-related keywords in extracted strings
5. **Detailed Analysis Mode**: When `detailed=True` parameter is passed

## Performance Considerations

- String extraction is limited to 100 license-related strings
- AI analysis input is limited to 50 strings to manage token usage
- Results are cached to avoid redundant analysis
- Timeout protection for string extraction operations

## Error Handling

The integration includes robust error handling:

- Graceful fallback when string extraction fails
- Non-blocking errors (warnings logged, analysis continues)
- Detailed error messages in analysis results
- Partial results returned even on component failures

## Testing

A test script is provided at `/mnt/c/Intellicrack/test_license_pattern_integration.py` to demonstrate the functionality.

## Future Enhancements

1. **Pattern Library**: Build a library of known license patterns
2. **Machine Learning**: Train models on license validation patterns
3. **Dynamic Analysis**: Integration with runtime license monitoring
4. **Report Generation**: Specialized license analysis reports
5. **Bypass Scripts**: Automatic generation of license bypass scripts
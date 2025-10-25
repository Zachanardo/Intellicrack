# Frida Stalker Integration for Dynamic Code Tracing

## Overview

The Frida Stalker integration provides comprehensive dynamic code tracing capabilities for analyzing software licensing protections. It enables instruction-level tracing, API monitoring, code coverage analysis, and automated detection of licensing-related routines.

## Architecture

### Components

1. **stalker_tracer.js** - JavaScript Stalker script executed in target process
2. **stalker_manager.py** - Python session management and analysis framework
3. **frida_analyzer.py** - Integration with main Intellicrack framework

### Key Capabilities

- **Instruction-Level Tracing**: Track every executed instruction with module/offset information
- **API Call Monitoring**: Intercept and log critical Windows API calls
- **Code Coverage Collection**: Identify which code blocks are executed
- **Licensing Flow Analysis**: Automatically detect licensing-related code paths
- **Function Tracing**: Deep trace specific functions with full backtrace
- **Module Coverage**: Calculate code coverage percentage for specific modules

## JavaScript Script (stalker_tracer.js)

### Features

#### 1. Automatic API Monitoring

Hooks critical Windows APIs for licensing analysis:

- **Registry**: `RegOpenKeyExW`, `RegQueryValueExW`, `RegSetValueExW`
- **File I/O**: `CreateFileW`, `ReadFile`, `WriteFile`
- **Crypto**: `CryptDecrypt`, `CryptEncrypt`, `BCryptDecrypt`, `BCryptEncrypt`
- **Network**: `InternetOpenW`, `HttpSendRequestW`, `connect`, `send`, `recv`
- **HWID**: `GetVolumeInformationW`, `GetAdaptersInfo`

#### 2. Licensing Detection

Automatically identifies licensing-related code by pattern matching:

```javascript
const licenseKeywords = [
    'license', 'serial', 'key', 'activation', 'register', 'trial',
    'validate', 'check', 'verify', 'auth', 'crack', 'protect',
];
```

Functions/modules containing these keywords are flagged and tracked separately.

#### 3. Stalker Transformer

Processes execution events in real-time:

- **Call Events**: Track function calls with module information
- **Block Events**: Identify unique code blocks for coverage
- **Performance Optimized**: Filters out system DLLs to reduce noise

#### 4. Exported RPC Functions

```javascript
rpc.exports = {
    startStalking: startStalking,           // Begin tracing current thread
    stopStalking: stopStalking,             // Stop tracing and return results
    traceFunction: traceFunction,           // Trace specific function
    collectModuleCoverage: collectModuleCoverage, // Module coverage analysis
    analyzeLicensingFlow: analyzeLicensingFlow,   // Licensing-specific analysis
    getStats: getStats,                     // Current statistics
    setConfig: setConfig,                   // Update configuration
};
```

## Python Session Manager (stalker_manager.py)

### StalkerSession Class

Main class for managing Stalker tracing sessions.

#### Initialization

```python
from intellicrack.core.analysis.stalker_manager import StalkerSession

session = StalkerSession(
    binary_path="C:\\Program Files\\App\\app.exe",
    output_dir="C:\\analysis_output",
    message_callback=print
)
```

#### Context Manager Support

```python
with StalkerSession(binary_path) as session:
    session.start_stalking()
    # ... analysis ...
    session.stop_stalking()
# Automatic cleanup on exit
```

### Core Methods

#### start() -> bool

Start Stalker session and attach to process:

```python
if session.start():
    print("Session started successfully")
```

#### start_stalking() -> bool

Begin Stalker tracing on current thread:

```python
session.start_stalking()
```

#### stop_stalking() -> bool

Stop tracing and collect results:

```python
session.stop_stalking()
stats = session.get_stats()
```

#### trace_function(module_name: str, function_name: str) -> bool

Trace specific function with deep backtrace:

```python
session.trace_function("app.exe", "ValidateLicense")
```

#### collect_module_coverage(module_name: str) -> bool

Collect code coverage for a module:

```python
session.collect_module_coverage("app.exe")
```

#### set_config(config: dict) -> bool

Update Stalker configuration:

```python
session.set_config({
    "traceInstructions": True,
    "traceAPICalls": True,
    "focusOnLicensing": True,
    "excludeModules": ["ntdll.dll", "kernel32.dll"]
})
```

### Data Retrieval Methods

#### get_stats() -> StalkerStats

Get current tracing statistics:

```python
stats = session.get_stats()
print(f"Instructions traced: {stats.total_instructions:,}")
print(f"Unique blocks: {stats.unique_blocks:,}")
print(f"Licensing routines: {stats.licensing_routines}")
```

#### get_licensing_routines() -> List[str]

Get identified licensing-related routines:

```python
routines = session.get_licensing_routines()
for routine in routines:
    print(f"Licensing routine: {routine}")
```

#### get_coverage_summary() -> dict

Get code coverage summary:

```python
coverage = session.get_coverage_summary()
print(f"Total entries: {coverage['total_entries']}")
print(f"Licensing entries: {coverage['licensing_entries']}")

for hotspot in coverage['licensing_hotspots']:
    print(f"{hotspot['module']}+{hotspot['offset']}: {hotspot['hit_count']} hits")
```

#### get_api_summary() -> dict

Get API call summary:

```python
api_summary = session.get_api_summary()
print(f"Total API calls: {api_summary['total_calls']:,}")
print(f"Licensing-related: {api_summary['licensing_calls']}")

for api in api_summary['top_apis'][:10]:
    print(f"{api['api']}: {api['count']} calls")
```

#### export_results(output_path: Optional[str] = None) -> str

Export all results to JSON:

```python
results_file = session.export_results()
print(f"Results saved to: {results_file}")
```

### Data Classes

#### TraceEvent

```python
@dataclass
class TraceEvent:
    event_type: str          # "call", "ret", "exec", "block"
    address: str             # Address as hex string
    module: Optional[str]    # Module name
    offset: Optional[str]    # Offset from module base
    timestamp: Optional[int] # Unix timestamp
    thread_id: Optional[int] # Thread ID
    depth: Optional[int]     # Call depth
    backtrace: List[str]     # Stack backtrace
```

#### APICallEvent

```python
@dataclass
class APICallEvent:
    api_name: str                # Full API name
    module: str                  # DLL name
    timestamp: int               # Unix timestamp
    thread_id: int               # Thread ID
    backtrace: List[str]         # Stack backtrace
    is_licensing_related: bool   # Licensing detection flag
```

#### CoverageEntry

```python
@dataclass
class CoverageEntry:
    module: str          # Module name
    offset: str          # Offset from base
    address: str         # Absolute address
    hit_count: int       # Execution count
    is_licensing: bool   # Licensing flag
```

#### StalkerStats

```python
@dataclass
class StalkerStats:
    total_instructions: int   # Total instructions traced
    unique_blocks: int        # Unique code blocks
    coverage_entries: int     # Coverage data points
    licensing_routines: int   # Licensing routines found
    api_calls: int           # API calls intercepted
    trace_duration: float    # Duration in seconds
```

## Integration with Intellicrack

### frida_analyzer.py Functions

#### start_stalker_session(main_app, output_dir=None) -> bool

Start Stalker session from main application:

```python
from intellicrack.core.analysis.frida_analyzer import start_stalker_session

if start_stalker_session(main_app):
    print("Stalker session active")
```

#### stop_stalker_session(main_app) -> bool

Stop session and display results:

```python
from intellicrack.core.analysis.frida_analyzer import stop_stalker_session

stop_stalker_session(main_app)
```

#### trace_function_stalker(main_app, module_name, function_name) -> bool

Trace specific function:

```python
from intellicrack.core.analysis.frida_analyzer import trace_function_stalker

trace_function_stalker(main_app, "app.exe", "CheckRegistration")
```

#### collect_module_coverage_stalker(main_app, module_name) -> bool

Collect module coverage:

```python
from intellicrack.core.analysis.frida_analyzer import collect_module_coverage_stalker

collect_module_coverage_stalker(main_app, "app.exe")
```

#### get_stalker_stats(main_app) -> Optional[dict]

Get current statistics:

```python
from intellicrack.core.analysis.frida_analyzer import get_stalker_stats

stats = get_stalker_stats(main_app)
if stats:
    print(f"Instructions: {stats['total_instructions']:,}")
```

#### get_licensing_routines_stalker(main_app) -> Optional[list]

Get licensing routines:

```python
from intellicrack.core.analysis.frida_analyzer import get_licensing_routines_stalker

routines = get_licensing_routines_stalker(main_app)
if routines:
    for routine in routines:
        print(routine)
```

## Usage Examples

### Basic Tracing

```python
from intellicrack.core.analysis.stalker_manager import StalkerSession

with StalkerSession("C:\\App\\app.exe") as session:
    session.start_stalking()
    time.sleep(10)  # Let it run
    session.stop_stalking()

    stats = session.get_stats()
    print(f"Traced {stats.total_instructions:,} instructions")
```

### Function-Specific Tracing

```python
with StalkerSession("C:\\App\\app.exe") as session:
    session.trace_function("app.exe", "ValidateLicense")
    time.sleep(15)

    # Results automatically saved to output directory
```

### Comprehensive Licensing Analysis

```python
session = StalkerSession(
    binary_path="C:\\App\\app.exe",
    output_dir="C:\\analysis"
)

session.start()

# Configure for licensing focus
session.set_config({
    "focusOnLicensing": True,
    "excludeModules": ["ntdll.dll", "kernel32.dll"]
})

session.start_stalking()
time.sleep(20)
session.stop_stalking()

# Get licensing intelligence
licensing_routines = session.get_licensing_routines()
coverage = session.get_coverage_summary()
api_calls = session.get_api_summary()

print(f"Found {len(licensing_routines)} licensing routines")
print(f"Coverage: {coverage['licensing_entries']} licensing code blocks")
print(f"API calls: {api_calls['licensing_calls']} licensing-related")

# Export complete analysis
results_file = session.export_results()
session.cleanup()
```

### Targeted Module Analysis

```python
with StalkerSession("C:\\App\\app.exe") as session:
    # Focus on specific module
    session.set_config({
        "filterByModule": "LicenseValidator.dll",
        "excludeModules": []
    })

    session.collect_module_coverage("LicenseValidator.dll")
    time.sleep(10)

    coverage = session.get_coverage_summary()
    print(f"Module coverage: {coverage['total_entries']} blocks")
```

## Output Files

Stalker sessions create JSON output files in the specified output directory:

### trace_results.json

Complete trace data:

```json
{
    "total_instructions": 1500000,
    "unique_blocks": 5432,
    "coverage_entries": 3210,
    "licensing_routines": 45,
    "api_calls": 890,
    "coverage": [...],
    "api_summary": [...],
    "licensing_functions": [...]
}
```

### function_trace_MODULE_FUNCTION.json

Function-specific traces:

```json
{
    "function": "app.exe!ValidateLicense",
    "trace": [
        {
            "type": "enter",
            "address": "0x140001000",
            "depth": 1,
            "backtrace": [...]
        },
        ...
    ]
}
```

### coverage_MODULE.json

Module coverage data:

```json
{
    "module": "app.exe",
    "base": "0x140000000",
    "size": 1048576,
    "blocks_covered": 1234,
    "coverage_percentage": 15.3,
    "blocks": [...]
}
```

### stalker_results_TIMESTAMP.json

Exported session results:

```json
{
    "binary": "app.exe",
    "timestamp": "2025-01-19 12:34:56",
    "stats": {...},
    "coverage_summary": {...},
    "api_summary": {...},
    "licensing_routines": [...]
}
```

## Performance Considerations

### Optimization Strategies

1. **Exclude System Modules**: Filter out ntdll.dll, kernel32.dll, etc.
2. **Limit Trace Duration**: Use time-based collection windows
3. **Target Specific Modules**: Focus on application modules only
4. **Adjust Event Types**: Disable unnecessary events (ret, exec)
5. **Use Filtering**: Configure module/function filters

### Configuration Example

```python
session.set_config({
    "traceInstructions": True,
    "traceAPICalls": True,
    "collectCoverage": True,
    "filterByModule": "app.exe",
    "excludeModules": [
        "ntdll.dll",
        "kernel32.dll",
        "kernelbase.dll"
    ],
    "maxTraceEvents": 1000000
})
```

## Licensing-Specific Features

### Automatic Detection

The Stalker integration automatically identifies licensing code by:

1. **Keyword Matching**: Detects license-related function/module names
2. **API Patterns**: Tracks registry, crypto, and HWID API usage
3. **Call Flow**: Maps licensing validation call chains
4. **Coverage Focus**: Highlights hot paths in licensing routines

### Licensing Hotspots

Identifies most-executed licensing code:

```python
coverage = session.get_coverage_summary()
for hotspot in coverage['licensing_hotspots']:
    print(f"{hotspot['module']}+{hotspot['offset']}: {hotspot['hit_count']} executions")
```

### API Correlation

Maps API calls to licensing routines:

```python
api_summary = session.get_api_summary()
print(f"Licensing API calls: {api_summary['licensing_calls']}")

for api in api_summary['top_apis']:
    if 'Reg' in api['api'] or 'Crypt' in api['api']:
        print(f"Licensing API: {api['api']} - {api['count']} calls")
```

## Integration with Analysis Workflow

### 1. Initial Discovery

```python
# Start comprehensive trace
with StalkerSession(binary_path) as session:
    session.start_stalking()
    time.sleep(30)
    session.stop_stalking()

    # Identify licensing routines
    routines = session.get_licensing_routines()
```

### 2. Focused Analysis

```python
# Trace specific licensing function
with StalkerSession(binary_path) as session:
    for routine in routines:
        module, func = routine.split(':')[0], routine.split(':')[1]
        session.trace_function(module, func)
        time.sleep(5)
```

### 3. Coverage Mapping

```python
# Map coverage of licensing modules
with StalkerSession(binary_path) as session:
    for module in licensing_modules:
        session.collect_module_coverage(module)
        time.sleep(10)
```

### 4. Result Export

```python
# Export for offline analysis
results = session.export_results()
print(f"Analysis complete: {results}")
```

## Troubleshooting

### Common Issues

**Session fails to start:**
- Ensure Frida is installed: `pip install frida-tools`
- Check binary exists and is accessible
- Verify sufficient permissions

**No licensing routines detected:**
- Increase trace duration
- Trigger licensing checks manually
- Adjust keyword patterns in config

**High memory usage:**
- Reduce maxTraceEvents
- Enable more aggressive module filtering
- Shorten trace duration

**Missing API calls:**
- Check module is loaded when hooking
- Verify API names are correct
- Try delayed hook installation

### Debug Mode

Enable verbose output:

```python
session = StalkerSession(
    binary_path=binary_path,
    message_callback=lambda msg: print(f"[DEBUG] {msg}")
)
```

## Advanced Usage

### Custom Event Processing

Implement custom message handler:

```python
def custom_handler(msg):
    if "licensing_event" in msg:
        # Custom licensing event processing
        pass

session = StalkerSession(
    binary_path=binary_path,
    message_callback=custom_handler
)
```

### Multi-Threading Analysis

Track all threads:

```python
# Modify stalker_tracer.js to follow all threads
# Or use multiple sessions for different threads
```

### Integration with Other Tools

Combine with radare2 for comprehensive analysis:

```python
from intellicrack.core.analysis.stalker_manager import StalkerSession
from intellicrack.utils.tools.radare2_utils import analyze_with_radare2

# Get dynamic trace
with StalkerSession(binary_path) as session:
    session.start_stalking()
    time.sleep(10)
    session.stop_stalking()
    routines = session.get_licensing_routines()

# Static analysis of discovered routines
for routine in routines:
    module, offset = routine.split(':')
    # Analyze with radare2
    analyze_with_radare2(binary_path, offset)
```

## Best Practices

1. **Start with comprehensive trace** to discover licensing routines
2. **Use targeted tracing** for detailed function analysis
3. **Export results** for offline analysis and archival
4. **Correlate with static analysis** for complete picture
5. **Monitor resource usage** during long traces
6. **Use context manager** for automatic cleanup
7. **Configure filtering** to reduce noise
8. **Focus on licensing APIs** for efficient analysis

## References

- Frida Documentation: https://frida.re/docs/
- Stalker API: https://frida.re/docs/javascript-api/#stalker
- Intellicrack: https://github.com/yourusername/intellicrack

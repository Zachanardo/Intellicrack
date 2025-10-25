# Frida Stalker Integration - Quick Start Guide

## 5-Minute Quick Start

### 1. Basic Usage

```python
from intellicrack.core.analysis.stalker_manager import StalkerSession

# Simple trace
with StalkerSession("C:\\App\\target.exe") as session:
    session.start_stalking()
    time.sleep(10)  # Let it collect data
    session.stop_stalking()

    stats = session.get_stats()
    print(f"Traced {stats.total_instructions:,} instructions")
    print(f"Found {stats.licensing_routines} licensing routines")
```

### 2. From Intellicrack UI

```python
from intellicrack.core.analysis.frida_analyzer import (
    start_stalker_session,
    stop_stalker_session,
    get_stalker_stats
)

# In your main application
start_stalker_session(main_app)

# Wait for analysis...

# Get stats
stats = get_stalker_stats(main_app)

# Stop and export
stop_stalker_session(main_app)
```

### 3. Run Example Script

```bash
# From examples directory
python stalker_usage_example.py "C:\App\target.exe" --mode comprehensive

# Or targeted analysis
python stalker_usage_example.py "C:\App\target.exe" --mode targeted --targets app.exe license.dll

# Or function trace
python stalker_usage_example.py "C:\App\target.exe" --mode function --module app.exe --function ValidateLicense
```

## Common Use Cases

### Identify Licensing Routines

```python
with StalkerSession(binary_path) as session:
    session.start_stalking()
    time.sleep(15)
    session.stop_stalking()

    # Get licensing routines
    routines = session.get_licensing_routines()
    for routine in routines:
        print(f"Licensing code: {routine}")
```

### Trace Specific Function

```python
with StalkerSession(binary_path) as session:
    session.trace_function("app.exe", "CheckRegistration")
    time.sleep(10)
    # Results auto-saved to output directory
```

### Module Coverage Analysis

```python
with StalkerSession(binary_path) as session:
    session.collect_module_coverage("license.dll")
    time.sleep(10)

    coverage = session.get_coverage_summary()
    print(f"Coverage: {coverage['total_entries']} blocks")
```

### API Call Monitoring

```python
with StalkerSession(binary_path) as session:
    session.start_stalking()
    time.sleep(10)
    session.stop_stalking()

    api_summary = session.get_api_summary()
    print(f"API calls: {api_summary['total_calls']}")
    print(f"Licensing APIs: {api_summary['licensing_calls']}")

    for api in api_summary['top_apis'][:5]:
        print(f"  {api['api']}: {api['count']} calls")
```

## Key Configuration Options

```python
session.set_config({
    "traceInstructions": True,      # Trace all instructions
    "traceAPICalls": True,          # Monitor API calls
    "collectCoverage": True,        # Collect coverage data
    "focusOnLicensing": True,       # Focus on licensing code
    "excludeModules": [             # Skip these modules
        "ntdll.dll",
        "kernel32.dll",
        "kernelbase.dll"
    ],
    "maxTraceEvents": 1000000       # Limit events
})
```

## Output Files

All output saved to `stalker_output/` directory (or custom location):

- `trace_results.json` - Complete trace data
- `function_trace_MODULE_FUNC.json` - Function-specific traces
- `coverage_MODULE.json` - Module coverage data
- `stalker_results_TIMESTAMP.json` - Exported session results

## Integration Points

### With Frida Analyzer

```python
# frida_analyzer.py functions
start_stalker_session(main_app)              # Start session
stop_stalker_session(main_app)               # Stop and export
trace_function_stalker(main_app, mod, func)  # Trace function
collect_module_coverage_stalker(main_app, mod) # Coverage
get_stalker_stats(main_app)                  # Get stats
get_licensing_routines_stalker(main_app)     # Get routines
```

### Standalone Session

```python
from intellicrack.core.analysis import StalkerSession

session = StalkerSession(binary_path)
session.start()
session.start_stalker()
# ... analysis ...
session.stop_stalker()
results = session.export_results()
session.cleanup()
```

## Performance Tips

1. **Use module filtering** - Focus on target modules only
2. **Limit trace duration** - 10-30 seconds usually sufficient
3. **Exclude system DLLs** - Reduces noise significantly
4. **Export periodically** - For long-running sessions
5. **Monitor memory** - Large traces can consume significant RAM

## Troubleshooting

**No licensing routines found?**
- Increase trace duration
- Manually trigger licensing checks in app
- Check keyword patterns match your target

**High memory usage?**
- Enable aggressive module filtering
- Reduce maxTraceEvents
- Shorten trace duration

**Session won't start?**
- Verify Frida installed: `pip install frida-tools`
- Check binary path exists
- Ensure sufficient permissions

## Next Steps

- Read full documentation: `docs/STALKER_INTEGRATION.md`
- Review examples: `examples/stalker_usage_example.py`
- Check JavaScript script: `intellicrack/scripts/frida/stalker_tracer.js`
- Explore session manager: `intellicrack/core/analysis/stalker_manager.py`

## Example Workflow

```python
# 1. Discover licensing routines
with StalkerSession(binary_path) as session:
    session.start_stalking()
    time.sleep(20)
    session.stop_stalking()
    routines = session.get_licensing_routines()

# 2. Trace each routine
for routine in routines[:5]:
    module = routine.split(':')[0]
    with StalkerSession(binary_path) as session:
        session.trace_function(module, "function_name")
        time.sleep(10)

# 3. Analyze coverage
with StalkerSession(binary_path) as session:
    for module in licensing_modules:
        session.collect_module_coverage(module)
        time.sleep(10)

    coverage = session.get_coverage_summary()
    # Analyze hotspots...

# 4. Export all results
with StalkerSession(binary_path) as session:
    # ... complete analysis ...
    results_file = session.export_results()
    print(f"Results: {results_file}")
```

## Monitored APIs (Automatic)

The Stalker automatically hooks these critical APIs:

**Registry:**
- RegOpenKeyExW
- RegQueryValueExW
- RegSetValueExW

**Cryptography:**
- CryptDecrypt / CryptEncrypt
- BCryptDecrypt / BCryptEncrypt

**Network:**
- InternetOpenW
- HttpSendRequestW
- connect / send / recv

**HWID:**
- GetVolumeInformationW
- GetAdaptersInfo

**File I/O:**
- CreateFileW
- ReadFile / WriteFile

All automatically correlated with licensing routines!

# Radare2 Integration Quick Reference

## Installation & Setup

```bash
# Install radare2 (if not already installed)
pip install radare2-r2pipe

# Install optional dependencies for full features
pip install scikit-learn numpy watchdog psutil
```

## Quick Start Examples

### 1. Basic Binary Analysis
```python
from intellicrack.core.analysis.radare2_enhanced_integration import EnhancedR2Integration

# Analyze binary
r2 = EnhancedR2Integration('/path/to/binary.exe')
results = r2.run_comprehensive_analysis()

# Print summary
print(f"Vulnerabilities: {results['components']['vulnerability']['summary']['total_vulnerabilities']}")
print(f"License functions: {len(results['components']['decompiler']['license_functions'])}")
```

### 2. Quick Vulnerability Scan
```python
from intellicrack.core.analysis.radare2_vulnerability_engine import R2VulnerabilityEngine

vuln = R2VulnerabilityEngine('/path/to/binary.exe')
results = vuln.comprehensive_vulnerability_scan()

print(f"Critical issues: {results['summary']['severity_breakdown']['critical']}")
```

### 3. License Bypass Generation
```python
from intellicrack.core.analysis.radare2_bypass_generator import R2BypassGenerator

bypass = R2BypassGenerator('/path/to/protected.exe')
strategies = bypass.generate_bypass_strategies()

print(f"Recommended: {strategies['recommended_approach']}")
print(f"Confidence: {strategies['confidence_score']*100:.0f}%")
```

### 4. Real-Time Monitoring
```python
from intellicrack.core.analysis.radare2_realtime_analyzer import create_realtime_analyzer

analyzer = create_realtime_analyzer()
analyzer.add_binary('/path/to/binary.exe')
analyzer.start_realtime_analysis()
```

### 5. UI Integration
```python
from intellicrack.ui.integrate_radare2 import add_radare2_to_intellicrack_app

# Add to existing app
success = add_radare2_to_intellicrack_app(app_instance)
```

## Common Analysis Commands

### String Analysis
```python
from intellicrack.core.analysis.radare2_strings import R2StringAnalyzer

strings = R2StringAnalyzer('/path/to/binary')
result = strings.analyze_strings()

# Find license strings
for s in result['license_strings']:
    print(f"{s['string']} at {hex(s['vaddr'])}")
```

### Function Decompilation
```python
from intellicrack.core.analysis.radare2_decompiler import R2DecompilationEngine

decomp = R2DecompilationEngine('/path/to/binary')
result = decomp.analyze_license_functions()

# Get decompiled code
for func_name, code in result['decompiled_functions'].items():
    print(f"\n{func_name}:\n{code}")
```

### Import/Export Analysis
```python
from intellicrack.core.analysis.radare2_imports import R2ImportAnalyzer

imports = R2ImportAnalyzer('/path/to/binary')
result = imports.analyze_imports_exports()

# Check for suspicious APIs
for api in result['suspicious_apis']:
    print(f"Suspicious: {api['name']} - {api['reason']}")
```

### ESIL Emulation
```python
from intellicrack.core.analysis.radare2_esil import R2ESILEngine

esil = R2ESILEngine('/path/to/binary')
result = esil.emulate_function(0x401000, {'eax': 0x1234})

print(f"Return value: {result['return_value']}")
```

## Performance Optimization

### For Large Files (>100MB)
```python
from intellicrack.core.analysis.radare2_performance_optimizer import optimize_for_large_binary

config = optimize_for_large_binary('/path/to/large.bin')
r2 = EnhancedR2Integration('/path/to/large.bin', config)
```

### Memory-Conservative Mode
```python
config = {
    'memory_limit': 500,  # MB
    'analysis_level': 'aa',  # Light analysis
    'cache_enabled': False,
    'parallel_workers': 1
}
```

## Error Handling

### With Error Context
```python
from intellicrack.core.analysis.radare2_error_handler import r2_error_context

with r2_error_context('my_analysis', binary_path='/path/to/binary'):
    # Your analysis code here
    pass  # Automatic error handling and recovery
```

### Manual Error Handling
```python
from intellicrack.core.analysis.radare2_error_handler import get_error_handler

error_handler = get_error_handler()

try:
    # Your code
    pass
except Exception as e:
    if error_handler.handle_error(e, 'operation_name', {'binary': '/path/to/binary'}):
        print("Error handled and recovered")
    else:
        print("Error could not be recovered")
```

## AI/ML Features

### License Detection
```python
from intellicrack.core.analysis.radare2_ai_integration import R2AIIntegration

ai = R2AIIntegration('/path/to/binary')
result = ai.run_ai_analysis()

if result['ai_license_detection']['confidence'] > 0.8:
    print("High confidence license protection detected")
    print(f"Type: {result['ai_license_detection']['predicted_type']}")
```

### Anomaly Detection
```python
# Detect unusual functions
anomalies = result['anomaly_detection']['anomaly_functions']
for func in anomalies:
    print(f"Anomalous function: {func['name']} (score: {func['anomaly_score']})")
```

## Binary Comparison

```python
from intellicrack.core.analysis.radare2_binary_diff import R2BinaryDiff

diff = R2BinaryDiff('/path/to/v1.exe', '/path/to/v2.exe')
result = diff.comprehensive_diff()

print(f"Modified functions: {len(result['functions']['modified_functions'])}")
print(f"New vulnerabilities: {len(result['vulnerabilities']['new_vulnerabilities'])}")
```

## Custom Scripting

### Generate Analysis Script
```python
from intellicrack.core.analysis.radare2_scripting import R2ScriptEngine

script = R2ScriptEngine('/path/to/binary')
content = script.generate_analysis_script(
    analysis_types=['functions', 'strings', 'imports'],
    output_format='json'
)

# Save script
with open('analyze.r2', 'w') as f:
    f.write(content)
```

### Execute Custom Commands
```python
result = script.execute_script("""
aaa
afl~license
pdf @ main
""", capture_output=True)

print(result['outputs'])
```

## Event Callbacks

```python
from intellicrack.core.analysis.radare2_realtime_analyzer import AnalysisEvent

# Define callbacks
def on_vulnerability(update):
    print(f"Vulnerability: {update.data}")
    # Send alert, log, etc.

def on_license_found(update):
    print(f"License pattern: {update.data}")

# Register callbacks
analyzer.register_event_callback(AnalysisEvent.VULNERABILITY_DETECTED, on_vulnerability)
analyzer.register_event_callback(AnalysisEvent.LICENSE_PATTERN_FOUND, on_license_found)
```

## Common Configuration Options

```python
config = {
    # Performance
    'analysis_level': 'aaa',      # a, aa, aaa, aaaa
    'memory_limit': 1000,         # MB
    'timeout': 600,               # seconds
    'parallel_workers': 3,        # concurrent analyses

    # Caching
    'cache_enabled': True,
    'cache_ttl': 300,            # seconds
    'max_cache_size': 100,       # entries

    # Real-time
    'real_time_monitoring': True,
    'monitoring_interval': 30,    # seconds

    # R2 flags
    'r2_flags': [
        '-e', 'anal.timeout=600',
        '-e', 'bin.cache=true'
    ]
}
```

## Useful Shortcuts

```python
# Quick comprehensive analysis
from intellicrack.core.analysis.radare2_enhanced_integration import create_enhanced_r2_integration
r2 = create_enhanced_r2_integration('/path/to/binary')
results = r2.run_comprehensive_analysis()

# Quick vulnerability scan
from intellicrack.core.analysis.radare2_vulnerability_engine import quick_vulnerability_scan
vulns = quick_vulnerability_scan('/path/to/binary')

# Quick bypass generation
from intellicrack.core.analysis.radare2_bypass_generator import quick_bypass_generation
bypass = quick_bypass_generation('/path/to/binary')

# Performance stats
stats = r2.get_performance_stats()
print(f"Cache hits: {stats['cache_hits']}")
print(f"Analysis times: {stats['analysis_times']}")

# Health check
health = r2.get_health_status()
print(f"Health: {health['overall_health']}")

# Cleanup
r2.cleanup()
```

## Environment Variables

```bash
# Set radare2 path (if not in PATH)
export R2_PATH=/usr/local/bin/radare2

# Set analysis timeout
export R2_ANALYSIS_TIMEOUT=3600

# Enable debug logging
export R2_DEBUG=1
```

## Troubleshooting Commands

```python
# Check radare2 installation
import subprocess
subprocess.run(['radare2', '-v'])

# Test r2pipe connection
import r2pipe
r2 = r2pipe.open('/bin/ls')
print(r2.cmd('i'))
r2.quit()

# Reset error handler
from intellicrack.core.analysis.radare2_error_handler import get_error_handler
error_handler = get_error_handler()
error_handler.clear_error_history()

# Clear all caches
r2.clear_cache()

# Force garbage collection
import gc
gc.collect()
```

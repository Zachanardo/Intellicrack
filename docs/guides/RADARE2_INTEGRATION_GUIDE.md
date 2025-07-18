# Radare2 Integration Guide for Intellicrack

## Table of Contents
1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Core Components](#core-components)
4. [Quick Start](#quick-start)
5. [Component Details](#component-details)
6. [Advanced Features](#advanced-features)
7. [API Reference](#api-reference)
8. [Examples](#examples)
9. [Performance Optimization](#performance-optimization)
10. [Troubleshooting](#troubleshooting)

## Overview

The Intellicrack radare2 integration provides comprehensive binary analysis capabilities through a production-grade interface to radare2. This integration transforms Intellicrack into a powerful reverse engineering platform with advanced features including:

- **Decompilation and pseudocode generation**
- **ESIL emulation for dynamic analysis**
- **Advanced vulnerability detection**
- **AI/ML-powered pattern recognition**
- **Automated license bypass generation**
- **Real-time analysis with live updates**
- **Performance optimization for large binaries**

### Key Benefits

1. **Comprehensive Analysis**: All major radare2 capabilities integrated
2. **Production-Ready**: Robust error handling and recovery
3. **High Performance**: Optimized for binaries from 10MB to >1GB
4. **Real-Time Monitoring**: Live analysis with file change detection
5. **AI-Powered**: Machine learning integration for pattern recognition

## Architecture

### Component Hierarchy

```
Intellirack Radare2 Integration
├── Core Infrastructure
│   ├── radare2_utils.py          # Session management and commands
│   ├── radare2_error_handler.py  # Error handling and recovery
│   └── radare2_performance_optimizer.py # Performance optimization
├── Analysis Engines
│   ├── radare2_decompiler.py     # Decompilation (pdc/pdg)
│   ├── radare2_esil.py           # ESIL emulation
│   ├── radare2_strings.py        # String analysis
│   ├── radare2_signatures.py     # FLIRT signatures
│   ├── radare2_imports.py        # Import/export analysis
│   ├── radare2_vulnerability_engine.py # Vulnerability detection
│   └── cfg_explorer.py           # Enhanced CFG analysis
├── Advanced Features
│   ├── radare2_ai_integration.py # ML/AI integration
│   ├── radare2_bypass_generator.py # Bypass generation
│   ├── radare2_binary_diff.py    # Binary comparison
│   ├── radare2_scripting.py      # Custom scripting
│   └── radare2_realtime_analyzer.py # Real-time analysis
├── Integration Layer
│   ├── radare2_enhanced_integration.py # Unified interface
│   ├── radare2_json_standardizer.py # JSON standardization
│   └── UI Integration
│       ├── radare2_integration_ui.py # Main UI components
│       ├── radare2_ui_manager.py     # UI management
│       └── comprehensive_integration.py # App integration
```

### Design Principles

1. **Modular Architecture**: Each component is independent and reusable
2. **Error Resilience**: Circuit breaker pattern for fault tolerance
3. **Performance First**: Adaptive optimization based on binary size
4. **Standardized Output**: JSON schema v2.0.0 for all results
5. **Thread Safety**: Concurrent analysis with proper synchronization

## Core Components

### R2Session (radare2_utils.py)

The foundation of all radare2 operations, providing session management and command execution.

```python
from intellicrack.utils.radare2_utils import R2Session

# Basic usage
with R2Session('/path/to/binary') as r2:
    # Analyze binary
    r2.analyze_all('aaa')
    
    # Get functions
    functions = r2.get_functions()
    
    # Decompile function
    decompiled = r2.decompile_function(0x1000)
```

### Error Handler (radare2_error_handler.py)

Comprehensive error handling with automatic recovery strategies.

```python
from intellicrack.core.analysis.radare2_error_handler import get_error_handler, r2_error_context

error_handler = get_error_handler()

# Use error context for automatic handling
with r2_error_context('my_operation', binary_path='/path/to/binary'):
    # Your radare2 operations here
    pass
```

### Performance Optimizer (radare2_performance_optimizer.py)

Adaptive performance optimization based on binary characteristics.

```python
from intellicrack.core.analysis.radare2_performance_optimizer import create_performance_optimizer

optimizer = create_performance_optimizer()
config = optimizer.optimize_for_binary('/path/to/large_binary')
# Returns optimized configuration for analysis
```

## Quick Start

### Basic Analysis

```python
from intellicrack.core.analysis.radare2_enhanced_integration import EnhancedR2Integration

# Create integration instance
r2_integration = EnhancedR2Integration('/path/to/binary')

# Run comprehensive analysis
results = r2_integration.run_comprehensive_analysis()

# Access specific results
vulnerabilities = results['components']['vulnerability']
license_functions = results['components']['decompiler']['license_functions']
```

### Real-Time Analysis

```python
from intellicrack.core.analysis.radare2_realtime_analyzer import create_realtime_analyzer, UpdateMode

# Create real-time analyzer
analyzer = create_realtime_analyzer(update_mode=UpdateMode.HYBRID)

# Add binary for monitoring
analyzer.add_binary('/path/to/binary')

# Register event callback
def on_vulnerability_detected(update):
    print(f"Vulnerability found: {update.data}")

analyzer.register_event_callback(AnalysisEvent.VULNERABILITY_DETECTED, on_vulnerability_detected)

# Start real-time analysis
analyzer.start_realtime_analysis()
```

### UI Integration

```python
from intellicrack.ui.integrate_radare2 import add_radare2_to_intellicrack_app

# Add radare2 features to existing IntellicrackApp
success = add_radare2_to_intellicrack_app(app_instance)
if success:
    print("Radare2 integration successful!")
```

## Component Details

### 1. Decompilation Engine

Provides license-focused decompilation using radare2's pdc/pdg commands.

**Features:**
- Function decompilation with multiple backends
- License pattern detection in decompiled code
- Validation routine identification
- Cross-reference analysis

**Example:**
```python
from intellicrack.core.analysis.radare2_decompiler import R2DecompilationEngine

decompiler = R2DecompilationEngine('/path/to/binary')
result = decompiler.analyze_license_functions()

# Access decompiled functions
for func_name, code in result['decompiled_functions'].items():
    print(f"Function {func_name}:\n{code}\n")
```

### 2. ESIL Emulation Engine

Dynamic analysis through radare2's ESIL (Evaluable Strings Intermediate Language).

**Features:**
- Function emulation with configurable inputs
- Register and memory state tracking
- Execution trace analysis
- License check behavior analysis

**Example:**
```python
from intellicrack.core.analysis.radare2_esil import R2ESILEngine

esil_engine = R2ESILEngine('/path/to/binary')

# Emulate function
result = esil_engine.emulate_function(
    func_addr=0x1000,
    test_inputs={'arg1': 0x1234, 'arg2': 'test_key'}
)

print(f"Return value: {result['return_value']}")
print(f"Execution trace: {result['trace']}")
```

### 3. String Analysis

Comprehensive string analysis with entropy calculation and pattern detection.

**Features:**
- License keyword detection
- Crypto string identification
- Entropy-based analysis
- Cross-reference mapping
- Debug/error string categorization

**Example:**
```python
from intellicrack.core.analysis.radare2_strings import R2StringAnalyzer

string_analyzer = R2StringAnalyzer('/path/to/binary')
result = string_analyzer.analyze_strings()

# High-entropy strings (possible encrypted data)
for string_info in result['string_entropy_analysis']['high_entropy_strings']:
    print(f"String: {string_info['string']}, Entropy: {string_info['entropy']}")
```

### 4. Vulnerability Detection

Multi-layered vulnerability detection with exploit generation capabilities.

**Features:**
- Buffer overflow detection
- Format string vulnerabilities
- Integer overflow analysis
- Use-after-free detection
- Race condition identification
- Automated exploit suggestions

**Example:**
```python
from intellicrack.core.analysis.radare2_vulnerability_engine import R2VulnerabilityEngine

vuln_engine = R2VulnerabilityEngine('/path/to/binary')
result = vuln_engine.comprehensive_vulnerability_scan()

print(f"Total vulnerabilities: {result['summary']['total_vulnerabilities']}")
print(f"Critical: {result['summary']['severity_breakdown']['critical']}")

# Generate exploit for specific vulnerability
if result['buffer_overflows']:
    exploit = vuln_engine.generate_exploit_suggestion(result['buffer_overflows'][0])
```

### 5. AI/ML Integration

Machine learning integration for advanced pattern recognition.

**Features:**
- License detection model (RandomForest)
- Vulnerability prediction
- Anomaly detection (IsolationForest)
- Function clustering (DBSCAN)
- Code similarity analysis

**Example:**
```python
from intellicrack.core.analysis.radare2_ai_integration import R2AIIntegration

ai_integration = R2AIIntegration('/path/to/binary')
result = ai_integration.run_ai_analysis()

# License detection confidence
print(f"License detection confidence: {result['ai_license_detection']['confidence']}")

# Vulnerability risk assessment
print(f"Overall risk score: {result['ai_vulnerability_prediction']['overall_risk_score']}")
```

### 6. Bypass Generator

Automated license bypass generation with multiple strategies.

**Features:**
- Patch-based bypasses (JMP/NOP modifications)
- Keygen algorithm generation
- Hook-based runtime bypasses
- Loader/wrapper creation
- Environment variable exploits

**Example:**
```python
from intellicrack.core.analysis.radare2_bypass_generator import R2BypassGenerator

bypass_gen = R2BypassGenerator('/path/to/binary')
result = bypass_gen.generate_bypass_strategies()

# Get recommended approach
print(f"Recommended: {result['recommended_approach']}")
print(f"Confidence: {result['confidence_score']}")

# Get patch instructions
for patch in result['bypass_strategies']['patch']['patches']:
    print(f"Patch at {hex(patch['offset'])}: {patch['description']}")
```

## Advanced Features

### Performance Optimization Strategies

```python
from intellicrack.core.analysis.radare2_performance_optimizer import (
    R2PerformanceOptimizer, OptimizationStrategy
)

# Memory-conservative strategy for systems with limited RAM
optimizer = R2PerformanceOptimizer(OptimizationStrategy.MEMORY_CONSERVATIVE)

# Speed-optimized for fast analysis
optimizer = R2PerformanceOptimizer(OptimizationStrategy.SPEED_OPTIMIZED)

# Large file specialized
optimizer = R2PerformanceOptimizer(OptimizationStrategy.LARGE_FILE_SPECIALIZED)

# Get optimization config
config = optimizer.optimize_for_binary('/path/to/huge_binary')
print(f"Recommended analysis level: {config['analysis_level']}")
print(f"Memory limit: {config['memory_limit']}MB")
```

### Real-Time Analysis Modes

```python
from intellicrack.core.analysis.radare2_realtime_analyzer import UpdateMode

# Continuous monitoring
analyzer = create_realtime_analyzer(update_mode=UpdateMode.CONTINUOUS)

# Interval-based updates (every 30 seconds)
analyzer = create_realtime_analyzer(
    update_mode=UpdateMode.INTERVAL,
    update_interval=30.0
)

# Only analyze on file changes
analyzer = create_realtime_analyzer(update_mode=UpdateMode.ON_CHANGE)

# Hybrid mode (interval + file changes)
analyzer = create_realtime_analyzer(update_mode=UpdateMode.HYBRID)
```

### Binary Diffing

```python
from intellicrack.core.analysis.radare2_binary_diff import R2BinaryDiff

diff_engine = R2BinaryDiff('/path/to/v1.exe', '/path/to/v2.exe')

# Function-level diff
func_diff = diff_engine.diff_functions()
print(f"Modified functions: {func_diff['modified_functions']}")

# String diff
string_diff = diff_engine.diff_strings()
print(f"Added strings: {string_diff['added_strings']}")

# Generate patch
patch_data = diff_engine.generate_patch()
```

### Custom Scripting

```python
from intellicrack.core.analysis.radare2_scripting import R2ScriptEngine

script_engine = R2ScriptEngine('/path/to/binary')

# Generate analysis script
script = script_engine.generate_analysis_script(
    analysis_types=['functions', 'strings', 'vulnerability'],
    output_format='json',
    custom_commands=['afl~license', 'pd 20 @ main']
)

# Execute script
result = script_engine.execute_script(script, capture_output=True)
print(f"Execution time: {result['execution_time']}s")
```

## API Reference

### Core Classes

#### R2Session
```python
class R2Session:
    def __init__(self, binary_path: str, analysis_level: str = 'aaa')
    def connect(self) -> bool
    def disconnect(self)
    def analyze_all(self, level: str = 'aaa') -> bool
    def get_functions(self) -> List[Dict[str, Any]]
    def get_strings(self) -> List[Dict[str, Any]]
    def get_imports(self) -> List[Dict[str, Any]]
    def decompile_function(self, address: int) -> str
```

#### EnhancedR2Integration
```python
class EnhancedR2Integration:
    def __init__(self, binary_path: str, config: Optional[Dict[str, Any]] = None)
    def run_comprehensive_analysis(self, analysis_types: Optional[List[str]] = None) -> Dict[str, Any]
    def get_performance_stats(self) -> Dict[str, Any]
    def get_health_status(self) -> Dict[str, Any]
    def optimize_performance(self)
    def cleanup(self)
```

#### R2RealtimeAnalyzer
```python
class R2RealtimeAnalyzer:
    def __init__(self, update_mode: UpdateMode, update_interval: float, max_concurrent_analyses: int)
    def add_binary(self, binary_path: str, analysis_config: Optional[Dict[str, Any]] = None) -> bool
    def remove_binary(self, binary_path: str) -> bool
    def start_realtime_analysis(self)
    def stop_realtime_analysis(self)
    def register_event_callback(self, event_type: AnalysisEvent, callback: Callable)
    def get_latest_results(self, binary_path: str) -> Optional[Dict[str, Any]]
```

### Enums

#### OptimizationStrategy
- `MEMORY_CONSERVATIVE`: Minimize memory usage
- `SPEED_OPTIMIZED`: Maximum analysis speed
- `BALANCED`: Balance between speed and memory
- `LARGE_FILE_SPECIALIZED`: Optimized for files >100MB

#### UpdateMode
- `CONTINUOUS`: Continuous monitoring
- `INTERVAL`: Periodic updates
- `ON_CHANGE`: Only when file changes
- `HYBRID`: Combination of interval and on_change

#### AnalysisEvent
- `FILE_MODIFIED`: File has been modified
- `ANALYSIS_STARTED`: Analysis has started
- `ANALYSIS_COMPLETED`: Analysis completed successfully
- `ANALYSIS_FAILED`: Analysis failed
- `VULNERABILITY_DETECTED`: Vulnerability found
- `LICENSE_PATTERN_FOUND`: License pattern detected

## Examples

### Example 1: Complete License Analysis Workflow

```python
from intellicrack.core.analysis.radare2_enhanced_integration import EnhancedR2Integration
from intellicrack.core.analysis.radare2_bypass_generator import R2BypassGenerator

# Step 1: Analyze binary
r2_integration = EnhancedR2Integration('/path/to/protected_software.exe')
analysis_results = r2_integration.run_comprehensive_analysis([
    'decompiler', 'strings', 'imports', 'vulnerability', 'ai'
])

# Step 2: Extract license information
license_functions = analysis_results['components']['decompiler']['license_functions']
license_strings = analysis_results['components']['strings']['license_strings']

print(f"Found {len(license_functions)} license-related functions")
print(f"Found {len(license_strings)} license-related strings")

# Step 3: Generate bypass
if license_functions:
    bypass_gen = R2BypassGenerator('/path/to/protected_software.exe')
    bypass_result = bypass_gen.generate_bypass_strategies()
    
    print(f"\nBypass Strategy: {bypass_result['recommended_approach']}")
    print(f"Confidence: {bypass_result['confidence_score']*100:.1f}%")
    
    # Apply patch if recommended
    if bypass_result['recommended_approach'] == 'patch':
        patches = bypass_result['bypass_strategies']['patch']['patches']
        print(f"\nRequired patches ({len(patches)} total):")
        for patch in patches:
            print(f"  - {hex(patch['offset'])}: {patch['description']}")

# Step 4: Verify bypass effectiveness (optional)
if 'ai' in analysis_results['components']:
    ai_confidence = analysis_results['components']['ai']['ai_license_detection']['confidence']
    print(f"\nAI License Detection Confidence: {ai_confidence*100:.1f}%")
```

### Example 2: Vulnerability Analysis and Exploit Generation

```python
from intellicrack.core.analysis.radare2_vulnerability_engine import R2VulnerabilityEngine
from intellicrack.core.analysis.radare2_ai_integration import R2AIIntegration

# Comprehensive vulnerability scan
vuln_engine = R2VulnerabilityEngine('/path/to/vulnerable_app')
vuln_results = vuln_engine.comprehensive_vulnerability_scan()

# Display summary
print(f"Vulnerability Summary:")
print(f"  Total: {vuln_results['summary']['total_vulnerabilities']}")
print(f"  Critical: {vuln_results['summary']['severity_breakdown']['critical']}")
print(f"  High: {vuln_results['summary']['severity_breakdown']['high']}")

# Focus on buffer overflows
if vuln_results['buffer_overflows']:
    print(f"\nBuffer Overflow Vulnerabilities:")
    for vuln in vuln_results['buffer_overflows']:
        print(f"  Function: {vuln['function']}")
        print(f"  Address: {hex(vuln['address'])}")
        print(f"  Severity: {vuln['severity']}")
        
        # Generate exploit suggestion
        exploit = vuln_engine.generate_exploit_suggestion(vuln)
        if exploit:
            print(f"  Exploit: {exploit['description']}")
            print(f"  Payload: {exploit['payload_template']}")

# AI-powered risk assessment
ai_integration = R2AIIntegration('/path/to/vulnerable_app')
ai_results = ai_integration.run_ai_analysis()

risk_score = ai_results['ai_vulnerability_prediction']['overall_risk_score']
print(f"\nAI Risk Assessment: {risk_score:.2f}/10")

if risk_score > 7:
    print("⚠️  HIGH RISK: Immediate patching recommended")
```

### Example 3: Real-Time Monitoring with Custom Handlers

```python
from intellicrack.core.analysis.radare2_realtime_analyzer import (
    create_realtime_analyzer, UpdateMode, AnalysisEvent, AnalysisUpdate
)
import time

# Create analyzer with hybrid mode
analyzer = create_realtime_analyzer(
    update_mode=UpdateMode.HYBRID,
    update_interval=60.0,  # Check every minute
    max_concurrent_analyses=2
)

# Custom event handlers
def on_file_modified(update: AnalysisUpdate):
    print(f"[{update.timestamp}] File modified: {update.binary_path}")
    print(f"  New hash: {update.data.get('file_hash', 'unknown')}")

def on_vulnerability_detected(update: AnalysisUpdate):
    print(f"\n🚨 VULNERABILITY DETECTED!")
    print(f"  Binary: {update.binary_path}")
    print(f"  Severity: {update.severity}")
    print(f"  Details: {update.data}")
    
    # Send alert (email, webhook, etc.)
    # send_security_alert(update)

def on_license_pattern_found(update: AnalysisUpdate):
    print(f"\n🔑 License Pattern Found!")
    print(f"  Binary: {update.binary_path}")
    strings = update.data.get('license_strings', [])
    for s in strings[:3]:  # Show first 3
        print(f"  - {s.get('string', 'unknown')}")

# Register handlers
analyzer.register_event_callback(AnalysisEvent.FILE_MODIFIED, on_file_modified)
analyzer.register_event_callback(AnalysisEvent.VULNERABILITY_DETECTED, on_vulnerability_detected)
analyzer.register_event_callback(AnalysisEvent.LICENSE_PATTERN_FOUND, on_license_pattern_found)

# Add binaries to monitor
binaries = [
    '/path/to/app1.exe',
    '/path/to/app2.exe',
    '/path/to/library.dll'
]

for binary in binaries:
    if analyzer.add_binary(binary):
        print(f"✓ Monitoring: {binary}")
    else:
        print(f"✗ Failed to add: {binary}")

# Start monitoring
print("\nStarting real-time analysis...")
analyzer.start_realtime_analysis()

try:
    # Keep running
    while True:
        time.sleep(10)
        
        # Periodically check status
        status = analyzer.get_status()
        print(f"\rActive analyses: {status['active_analyses']}, Queue: {status['queue_size']}", end='')
        
except KeyboardInterrupt:
    print("\n\nStopping analyzer...")
    analyzer.stop_realtime_analysis()
    analyzer.cleanup()
```

### Example 4: Binary Comparison and Patch Generation

```python
from intellicrack.core.analysis.radare2_binary_diff import R2BinaryDiff
from intellicrack.core.analysis.radare2_scripting import R2ScriptEngine

# Compare two versions
diff_engine = R2BinaryDiff(
    '/path/to/app_v1.0.exe',
    '/path/to/app_v2.0.exe'
)

# Comprehensive diff
print("Analyzing differences...")
full_diff = diff_engine.comprehensive_diff()

# Summary
print(f"\nDiff Summary:")
print(f"  Binary size change: {full_diff['summary']['size_change']} bytes")
print(f"  Function changes: {full_diff['summary']['function_changes']}")
print(f"  String changes: {full_diff['summary']['string_changes']}")

# Find what changed in license checking
print("\nLicense-related changes:")
for func in full_diff['functions']['modified_functions']:
    if 'license' in func['name'].lower() or 'check' in func['name'].lower():
        print(f"  {func['name']}:")
        print(f"    Old size: {func['old_size']} bytes")
        print(f"    New size: {func['new_size']} bytes")
        print(f"    Change: {func['similarity']:.1f}% similar")

# Generate analysis script for changes
script_engine = R2ScriptEngine('/path/to/app_v2.0.exe')
analysis_script = script_engine.generate_analysis_script(
    analysis_types=['functions'],
    custom_commands=[
        # Focus on modified functions
        'afl~modified',
        'pdf @ fcn.check_license',
        'pd 50 @ fcn.validate_key'
    ]
)

# Save script for later use
with open('analyze_changes.r2', 'w') as f:
    f.write(analysis_script)
print("\nAnalysis script saved to: analyze_changes.r2")
```

## Performance Optimization

### Binary Size Guidelines

| Binary Size | Recommended Strategy | Analysis Level | Memory Limit | Workers |
|-------------|---------------------|----------------|--------------|----------|
| < 10MB | SPEED_OPTIMIZED | aaaa (deep) | 500MB | 4 |
| 10-100MB | BALANCED | aaa (standard) | 1GB | 3 |
| 100MB-1GB | LARGE_FILE_SPECIALIZED | aa (light) | 2GB | 2 |
| > 1GB | MEMORY_CONSERVATIVE | a (minimal) | 4GB | 1 |

### Performance Tuning

```python
# Monitor performance
integration = EnhancedR2Integration('/path/to/binary')

# Start monitoring
integration.performance_optimizer.start_monitoring()

# Run analysis
results = integration.run_comprehensive_analysis()

# Get performance report
perf_report = integration.get_performance_stats()

print(f"Performance Report:")
print(f"  Cache hit rate: {perf_report['cache_hits']/(perf_report['cache_hits']+perf_report['cache_misses'])*100:.1f}%")
print(f"  Average analysis time: {perf_report['analysis_times']['average']:.2f}s")
print(f"  Memory peak: {perf_report['memory_peak']:.1f}MB")

# Optimize based on metrics
integration.optimize_performance()
```

### Memory Management

```python
# Configure memory limits
config = {
    'memory_limit': 1000,  # MB
    'cache_ttl': 300,      # 5 minutes
    'max_cache_size': 50,  # entries
    'chunk_size': 10 * 1024 * 1024  # 10MB chunks for large files
}

integration = EnhancedR2Integration('/path/to/large_binary', config)

# Clear cache when needed
integration.clear_cache()

# Force garbage collection
import gc
gc.collect()
```

## Troubleshooting

### Common Issues

#### 1. R2pipe Connection Errors

**Problem**: `BrokenPipeError` or `r2pipe connection failed`

**Solution**:
```python
# Check if radare2 is installed
import subprocess
try:
    result = subprocess.run(['radare2', '-v'], capture_output=True)
    print(f"Radare2 version: {result.stdout.decode()}")
except FileNotFoundError:
    print("Radare2 not found! Install with: pip install radare2-r2pipe")
```

#### 2. Memory Issues with Large Binaries

**Problem**: `MemoryError` or system slowdown

**Solution**:
```python
# Use memory-conservative strategy
from intellicrack.core.analysis.radare2_performance_optimizer import (
    create_performance_optimizer, OptimizationStrategy
)

optimizer = create_performance_optimizer(OptimizationStrategy.MEMORY_CONSERVATIVE)
config = optimizer.optimize_for_binary('/path/to/huge_binary')

# Apply configuration
integration = EnhancedR2Integration('/path/to/huge_binary', config)
```

#### 3. Analysis Timeout

**Problem**: Analysis takes too long or times out

**Solution**:
```python
# Increase timeout and reduce analysis depth
config = {
    'timeout': 3600,  # 1 hour
    'analysis_level': 'aa',  # Light analysis
    'parallel_workers': 1  # Single threaded
}
```

#### 4. Circuit Breaker Open

**Problem**: `Circuit breaker open for operation`

**Solution**:
```python
# Reset circuit breaker
error_handler = get_error_handler()
error_handler.reset_circuit_breaker('r2_vulnerability')

# Check error statistics
stats = error_handler.get_error_statistics()
print(f"Total errors: {stats['session_stats']['total_errors']}")
print(f"Recovery rate: {stats['recovery_rates']}")
```

### Debug Mode

Enable detailed logging for troubleshooting:

```python
import logging

# Set debug level
logging.getLogger('intellicrack.core.analysis').setLevel(logging.DEBUG)

# Or for specific module
logging.getLogger('intellicrack.core.analysis.radare2_decompiler').setLevel(logging.DEBUG)
```

### Health Checks

```python
# Check system health
integration = EnhancedR2Integration('/path/to/binary')
health = integration.get_health_status()

print(f"Health Status: {health['overall_health']}")
print(f"Components available: {health['components_available']}/{health['total_components']}")
print(f"Cache hit rate: {health['cache_health']['hit_rate']*100:.1f}%")
print(f"Error recovery rate: {health['error_health']['recovery_rate']*100:.1f}%")

if health['overall_health'] != 'healthy':
    print("\nRecommended actions:")
    if health['overall_health'] == 'degraded':
        print("- Clear cache: integration.clear_cache()")
        print("- Reset error handler: error_handler.clear_error_history()")
    elif health['overall_health'] == 'critical':
        print("- Restart analysis with reduced load")
        print("- Check system resources")
```

## Best Practices

1. **Always use context managers** for R2Session to ensure proper cleanup
2. **Configure optimization strategy** based on binary size and system resources
3. **Register error callbacks** for production deployments
4. **Use real-time analysis** for continuous monitoring scenarios
5. **Leverage caching** for repeated analyses of the same binary
6. **Monitor performance metrics** and adjust configuration accordingly
7. **Implement proper error handling** using the error context manager
8. **Use standardized JSON output** for integration with other tools

## Conclusion

The Intellicrack radare2 integration provides a comprehensive, production-ready solution for binary analysis. With its modular architecture, robust error handling, and advanced features like AI integration and real-time monitoring, it offers capabilities that exceed many commercial tools.

For questions or contributions, please refer to the Intellicrack project documentation or submit an issue on the project repository.
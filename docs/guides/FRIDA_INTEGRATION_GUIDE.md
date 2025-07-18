# Intellicrack Frida Integration Guide

## Overview

The Intellicrack Frida integration provides a comprehensive, production-ready system for dynamic instrumentation and protection bypass. This guide covers all features, usage patterns, and best practices.

## Table of Contents

1. [Core Components](#core-components)
2. [Getting Started](#getting-started)
3. [Frida Manager](#frida-manager)
4. [Protection Detection](#protection-detection)
5. [Performance Optimization](#performance-optimization)
6. [GUI Interface](#gui-interface)
7. [Preset Configurations](#preset-configurations)
8. [Automated Bypass Wizard](#automated-bypass-wizard)
9. [Scripting Guide](#scripting-guide)
10. [Best Practices](#best-practices)
11. [Troubleshooting](#troubleshooting)

## Core Components

### 1. FridaManager (`intellicrack/core/frida_manager.py`)
The main management class that handles:
- Process attachment and script management
- Comprehensive operation logging
- Real-time protection detection
- Performance optimization
- Hook batching and selective instrumentation

### 2. FridaOperationLogger
Advanced logging system with:
- Separate logs for operations, hooks, performance, and bypasses
- In-memory buffers for real-time analysis
- Statistics tracking and reporting
- Export capabilities for analysis

### 3. ProtectionDetector
Real-time protection detection with:
- Classification of 12 protection types
- Pattern-based detection
- API call analysis
- Automatic adaptation triggers

### 4. FridaPerformanceOptimizer
Performance optimization features:
- Resource usage monitoring
- Selective hook recommendations
- Script optimization
- Memory and CPU management

### 5. FridaBypassWizard (`intellicrack/core/frida_bypass_wizard.py`)
Automated bypass system with:
- Intelligent protection detection
- Strategy planning
- Sequential bypass application
- Success verification

## Getting Started

### Basic Usage

```python
from intellicrack.core import FridaManager

# Create manager instance
frida_manager = FridaManager()

# Attach to process
success = frida_manager.attach_to_process("target.exe")
# or by PID
success = frida_manager.attach_to_process(1234)

# Load a script
if success:
    session_id = f"target.exe_{pid}"
    frida_manager.load_script(session_id, "anti_debugger")
```

### Using the GUI

1. Open Intellicrack
2. Navigate to Tools → Frida Manager
3. Select target process from the list
4. Click "Attach to Process"
5. Load scripts or use presets

## Frida Manager

### Process Management

```python
# List available processes
processes = frida.get_local_device().enumerate_processes()

# Attach with options
frida_manager.attach_to_process(pid)

# Detach
frida_manager.sessions[session_id].detach()
```

### Script Loading

```python
# Load script with options
options = {
    'aggressive': True,
    'stealth_mode': False,
    'patch_checksums': True
}

frida_manager.load_script(session_id, "script_name", options)
```

### Operation Logging

All operations are automatically logged:

```python
# Access logger
logger = frida_manager.logger

# Get statistics
stats = logger.get_statistics()
print(f"Total operations: {stats['total_operations']}")
print(f"Success rate: {stats['operation_success_rate']}%")

# Export logs
export_dir = logger.export_logs("/path/to/export")
```

## Protection Detection

### Protection Types

The system can detect and classify these protection types:

1. **ANTI_DEBUG** - Anti-debugging techniques
2. **ANTI_VM** - Virtual machine/sandbox detection
3. **PACKING** - Packing and obfuscation
4. **LICENSE** - License verification
5. **INTEGRITY** - Code integrity checks
6. **HARDWARE** - Hardware binding (HWID)
7. **CLOUD** - Cloud-based verification
8. **TIME** - Time-based protections
9. **MEMORY** - Memory protection
10. **KERNEL** - Kernel-mode protection
11. **BEHAVIOR** - Behavioral analysis
12. **UNKNOWN** - Unclassified protections

### Detection Example

```python
# Get detected protections
detector = frida_manager.detector
protections = detector.get_detected_protections()

for prot_type, evidence in protections.items():
    print(f"{prot_type}: {evidence}")
```

### Automatic Adaptation

When protections are detected, the system automatically loads appropriate bypass scripts:

```python
# Register custom adaptation callback
def on_protection_detected(protection_type, details):
    print(f"Detected: {protection_type.value}")
    # Custom handling

detector.register_adaptation_callback(on_protection_detected)
```

## Performance Optimization

### Hook Batching

```python
# Configure batching
batcher = frida_manager.batcher
batcher.max_batch_size = 100  # hooks per batch
batcher.batch_timeout_ms = 50  # milliseconds

# Add hooks to batch
batcher.add_hook(HookCategory.MEDIUM, {
    'module': 'kernel32.dll',
    'function': 'CreateFileW',
    'priority': 50
})
```

### Selective Instrumentation

```python
# Create selective instrumentation
script = frida_manager.create_selective_instrumentation(
    target_apis=['kernel32.dll!CreateFileW', 'ntdll.dll!NtOpenFile'],
    analysis_requirements={
        'trace_api_calls': True,
        'monitor_memory': True,
        'detect_protections': True,
        'critical_apis': ['ntdll.dll!NtProtectVirtualMemory']
    }
)
```

### Resource Monitoring

```python
# Get current usage
optimizer = frida_manager.optimizer
usage = optimizer.get_current_usage()
print(f"Memory: {usage['memory_mb']} MB")
print(f"CPU: {usage['cpu_percent']}%")

# Get recommendations
recommendations = optimizer.get_optimization_recommendations()
```

## GUI Interface

### Main Features

1. **Process Management Tab**
   - Process list with search
   - Attach/detach controls
   - Session information

2. **Scripts & Hooks Tab**
   - Available scripts list
   - Loaded scripts management
   - Hook configuration
   - Batching controls

3. **Protection Detection Tab**
   - Real-time detection status
   - Evidence display
   - Manual bypass triggers
   - Adaptation settings

4. **Performance Tab**
   - Resource usage meters
   - Optimization settings
   - Performance history
   - Recommendations

5. **Presets & Wizard Tab**
   - Preset configurations
   - Automated bypass wizard
   - Custom configuration editor

6. **Logs & Analysis Tab**
   - Operation logs viewer
   - Log filtering and search
   - Statistics display
   - Export functions

### Using the Dialog

```python
from intellicrack.ui.dialogs import FridaManagerDialog

# Create and show dialog
dialog = FridaManagerDialog(parent_window)
dialog.exec_()
```

## Preset Configurations

### Available Presets

1. **Adobe Creative Cloud** - Comprehensive Adobe CC bypass
2. **Microsoft Office 365** - Office licensing bypass
3. **Autodesk Products** - AutoCAD, Maya, 3ds Max
4. **VMware Products** - VMware Workstation
5. **Anti-Virus Software** - Generic AV bypass
6. **Steam Games (CEG)** - Steam DRM bypass
7. **Denuvo Protected Games** - Advanced game protection
8. **Enterprise Software** - SAP, Oracle, IBM
9. **FlexLM/FlexNet Licensed** - Engineering software
10. **HASP/Sentinel Protected** - Dongle emulation
11. **Trial Software** - Generic trial reset
12. **Development Tools** - IDEs and dev tools
13. **Media Production** - Audio/video software
14. **Educational Software** - E-learning platforms
15. **Maximum Protection Bypass** - All available bypasses

### Using Presets

```python
from intellicrack.core.frida_presets import FRIDA_PRESETS

# Get preset
preset = FRIDA_PRESETS["Adobe Creative Cloud"]

# Apply preset scripts
for script in preset['scripts']:
    frida_manager.load_script(session_id, script, preset['options'])
```

## Automated Bypass Wizard

### Wizard Modes

1. **Safe Mode** - Conservative approach, minimal risk
2. **Balanced Mode** - Good balance of effectiveness and safety
3. **Aggressive Mode** - Maximum bypass capability
4. **Stealth Mode** - Minimize detection
5. **Analysis Only** - Detect without bypassing

### Using the Wizard

```python
from intellicrack.core import FridaBypassWizard

# Create wizard
wizard = FridaBypassWizard(frida_manager)

# Set mode
wizard.set_mode("balanced")

# Set callbacks
wizard.set_callbacks(
    progress_callback=lambda p: print(f"Progress: {p}%"),
    status_callback=lambda s: print(f"Status: {s}")
)

# Run wizard
report = await wizard.run(session_id, target_info)

# Check results
print(f"Protections detected: {report['detections']['total']}")
print(f"Bypasses successful: {report['bypasses']['successful']}")
```

### Wizard Workflow

1. **Analyze Process** - Gather information about target
2. **Detect Protections** - Identify protection mechanisms
3. **Plan Strategy** - Determine bypass order and dependencies
4. **Apply Bypasses** - Load appropriate scripts
5. **Monitor Results** - Verify bypass effectiveness

## Scripting Guide

### Script Structure

```javascript
// Intellicrack Frida Script Template

// Metadata
const SCRIPT_NAME = "custom_bypass";
const SCRIPT_VERSION = "1.0";
const PROTECTION_TYPE = "LICENSE";

// Hook example
Interceptor.attach(Module.findExportByName("kernel32.dll", "CreateFileW"), {
    onEnter: function(args) {
        // Log API call
        send({
            type: 'api_call',
            api: 'CreateFileW',
            filename: args[0].readUtf16String()
        });
    },
    onLeave: function(retval) {
        // Modify return value if needed
        if (this.filename && this.filename.includes("license")) {
            retval.replace(0x0);  // Return NULL
        }
    }
});

// Protection detection
if (Module.findExportByName("kernel32.dll", "IsDebuggerPresent")) {
    detectProtection("anti_debug", "IsDebuggerPresent found");
}
```

### Script Guidelines

1. **Always use protection detection helpers**
2. **Report performance metrics**
3. **Handle errors gracefully**
4. **Use batching for multiple hooks**
5. **Implement success indicators**

## Best Practices

### 1. Performance

- Enable hook batching for better performance
- Use selective instrumentation
- Monitor resource usage
- Apply optimization recommendations

### 2. Stealth

- Use stealth mode for anti-cheat systems
- Avoid aggressive hooks on sensitive functions
- Implement indirect hooking when possible
- Monitor for detection attempts

### 3. Reliability

- Always verify bypass success
- Use safe mode for critical applications
- Test on non-production systems first
- Keep logs for troubleshooting

### 4. Script Development

- Start with minimal hooks
- Add instrumentation gradually
- Test each protection bypass individually
- Document bypass techniques

## Troubleshooting

### Common Issues

1. **Failed to attach to process**
   - Check if process is 32/64 bit match
   - Run as administrator
   - Disable anti-virus temporarily

2. **Script loading fails**
   - Verify script syntax
   - Check for missing dependencies
   - Review error logs

3. **High resource usage**
   - Enable optimization features
   - Reduce hook scope
   - Use batching

4. **Protection still active**
   - Check detection evidence
   - Try aggressive mode
   - Manually trigger adaptation

### Debug Mode

```python
# Enable debug logging
import logging
logging.getLogger('frida').setLevel(logging.DEBUG)

# Get detailed statistics
stats = frida_manager.get_statistics()
print(json.dumps(stats, indent=2))

# Export full analysis
export_dir = frida_manager.export_analysis()
```

### Support

For issues or questions:
1. Check operation logs
2. Export analysis for review
3. Consult preset configurations
4. Use analysis-only mode to gather information

## Advanced Topics

### Custom Protection Handlers

```python
# Add custom protection type
def handle_custom_protection(details):
    # Custom bypass logic
    pass

frida_manager.protection_adaptations[ProtectionType.CUSTOM] = handle_custom_protection
```

### Script Optimization

```python
# Optimize script before loading
optimized = frida_manager.optimizer.optimize_script(script_code)
```

### Batch Operations

```python
# Batch multiple operations
with frida_manager.batch_mode():
    for script in scripts:
        frida_manager.load_script(session_id, script)
```

## Conclusion

The Intellicrack Frida integration provides a powerful, production-ready system for dynamic analysis and protection bypass. With comprehensive logging, intelligent detection, performance optimization, and an intuitive GUI, it enables both automated and manual bypass operations with professional-grade reliability.
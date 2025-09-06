# Anti-Analysis Detection Guide

## Overview

This guide covers Intellicrack's comprehensive anti-analysis detection and bypass capabilities. Learn how to identify and circumvent debugger detection, VM detection, sandbox evasion, and other anti-analysis techniques.

## Table of Contents

1. [Detection Overview](#detection-overview)
2. [Debugger Detection](#debugger-detection)
3. [VM Detection](#vm-detection)
4. [Sandbox Detection](#sandbox-detection)
5. [API Obfuscation](#api-obfuscation)
6. [Time-Based Detection](#time-based-detection)
7. [Bypass Techniques](#bypass-techniques)
8. [Automated Detection Suite](#automated-detection-suite)

## Detection Overview

### Base Detection Framework

```python
from intellicrack.core.anti_analysis.base_detector import BaseDetector

# Initialize detection engine
detector = BaseDetector()

# Run comprehensive detection
results = detector.detect_all(
    binary_path="protected.exe",
    deep_scan=True
)

# Analyze results
print(f"Debugger checks: {results['debugger_checks']}")
print(f"VM checks: {results['vm_checks']}")
print(f"Sandbox checks: {results['sandbox_checks']}")
print(f"Timing checks: {results['timing_checks']}")
```

### Detection Categories

```python
# Get all detection techniques used
techniques = detector.enumerate_techniques()

for technique in techniques:
    print(f"Category: {technique['category']}")
    print(f"Method: {technique['method']}")
    print(f"Severity: {technique['severity']}")
    print(f"Bypass difficulty: {technique['bypass_difficulty']}")
```

## Debugger Detection

### Common Debugger Checks

```python
from intellicrack.core.anti_analysis.debugger_detector import DebuggerDetector

debugger_detector = DebuggerDetector()

# Detect IsDebuggerPresent
idp_checks = debugger_detector.find_isdebugger_present(binary_path)
print(f"IsDebuggerPresent calls: {len(idp_checks)}")

# Detect CheckRemoteDebuggerPresent
crdp_checks = debugger_detector.find_check_remote_debugger(binary_path)

# Detect NtQueryInformationProcess
ntqip_checks = debugger_detector.find_ntquery_checks(binary_path)

# Detect PEB checks
peb_checks = debugger_detector.find_peb_checks(binary_path)
```

### Advanced Debugger Detection

```python
# Hardware breakpoint detection
hw_bp_checks = debugger_detector.find_hardware_bp_checks(binary_path)

# Debug register checks
dr_checks = debugger_detector.find_debug_register_checks(binary_path)

# Exception-based detection
exception_checks = debugger_detector.find_exception_checks(binary_path)

# Process name checks
process_checks = debugger_detector.find_debugger_process_checks(binary_path)
```

### Bypass Implementation

```python
# Generate Frida script to bypass debugger checks
bypass_script = debugger_detector.generate_bypass_script(
    techniques=idp_checks + crdp_checks + peb_checks
)

print(f"Frida bypass script:\n{bypass_script}")

# Apply bypass
from intellicrack.core.frida_manager import FridaManager
frida = FridaManager()
frida.attach_to_process("protected.exe")
frida.load_script(bypass_script)
```

## VM Detection

### VM Detection Techniques

```python
from intellicrack.core.anti_analysis.vm_detector import VMDetector

vm_detector = VMDetector()

# Detect CPUID-based checks
cpuid_checks = vm_detector.find_cpuid_checks(binary_path)

# Detect DMI/SMBIOS checks
dmi_checks = vm_detector.find_dmi_checks(binary_path)

# Detect driver checks
driver_checks = vm_detector.find_vm_driver_checks(binary_path)

# Detect registry checks
registry_checks = vm_detector.find_vm_registry_checks(binary_path)

# Detect MAC address checks
mac_checks = vm_detector.find_mac_address_checks(binary_path)
```

### Hypervisor Detection

```python
# Detect hypervisor bit
hypervisor_checks = vm_detector.find_hypervisor_bit_checks(binary_path)

# Detect VM-specific instructions
vm_instruction_checks = vm_detector.find_vm_instructions(binary_path)

# Detect timing discrepancies
timing_checks = vm_detector.find_vm_timing_checks(binary_path)
```

### VM Bypass Strategies

```python
# Generate comprehensive VM bypass
vm_bypass = vm_detector.generate_vm_bypass({
    "spoof_cpuid": True,
    "hide_drivers": True,
    "fake_dmi": True,
    "normalize_timing": True
})

# Apply VM hiding
from intellicrack.core.protection_bypass.vm_bypass import VMBypass
vm_hider = VMBypass()
vm_hider.apply_all_bypasses()
```

## Sandbox Detection

### Sandbox Detection Methods

```python
from intellicrack.core.anti_analysis.sandbox_detector import SandboxDetector

sandbox_detector = SandboxDetector()

# Detect environment checks
env_checks = sandbox_detector.find_environment_checks(binary_path)

# Detect sleep acceleration detection
sleep_checks = sandbox_detector.find_sleep_acceleration(binary_path)

# Detect human interaction checks
interaction_checks = sandbox_detector.find_interaction_checks(binary_path)

# Detect resource checks
resource_checks = sandbox_detector.find_resource_checks(binary_path)
```

### Advanced Sandbox Evasion

```python
# Detect file/folder checks
file_checks = sandbox_detector.find_sandbox_file_checks(binary_path)

# Detect network connectivity checks
network_checks = sandbox_detector.find_network_checks(binary_path)

# Detect API hooking detection
hook_checks = sandbox_detector.find_hook_detection(binary_path)

# Generate sandbox bypass
sandbox_bypass = sandbox_detector.generate_bypass_script(
    all_checks=env_checks + sleep_checks + interaction_checks
)
```

## API Obfuscation

### API Obfuscation Analysis

```python
from intellicrack.core.anti_analysis.api_obfuscation import APIObfuscationAnalyzer

api_analyzer = APIObfuscationAnalyzer()

# Detect dynamic API resolution
dynamic_apis = api_analyzer.find_dynamic_resolution(binary_path)

# Detect API hashing
hashed_apis = api_analyzer.find_hashed_apis(binary_path)

# Detect encrypted imports
encrypted_imports = api_analyzer.find_encrypted_imports(binary_path)

# Resolve obfuscated APIs
for api in hashed_apis:
    resolved = api_analyzer.resolve_api_hash(api['hash'])
    print(f"Hash {api['hash']:08X} -> {resolved}")
```

### Import Reconstruction

```python
# Reconstruct import table
reconstructed = api_analyzer.reconstruct_imports(binary_path)

# Generate radare2 commands
r2_commands = api_analyzer.generate_r2_commands(reconstructed)
```

## Time-Based Detection

### Timing Check Detection

```python
from intellicrack.core.anti_analysis.timing_detector import TimingDetector

timing_detector = TimingDetector()

# Detect RDTSC checks
rdtsc_checks = timing_detector.find_rdtsc_checks(binary_path)

# Detect GetTickCount checks
tick_checks = timing_detector.find_gettickcount_checks(binary_path)

# Detect QueryPerformanceCounter checks
qpc_checks = timing_detector.find_qpc_checks(binary_path)

# Generate timing normalization script
timing_bypass = timing_detector.generate_timing_bypass()
```

## Bypass Techniques

### Comprehensive Bypass Suite

```python
from intellicrack.plugins.custom_modules.anti_anti_debug_suite import AntiAntiDebugSuite

suite = AntiAntiDebugSuite()

# Apply all bypasses
suite.apply_comprehensive_bypass(
    process="protected.exe",
    options={
        "bypass_debugger": True,
        "bypass_vm": True,
        "bypass_sandbox": True,
        "bypass_timing": True,
        "unhook_apis": True
    }
)
```

### Custom Bypass Development

```python
# Create custom bypass module
class CustomBypass:
    def __init__(self):
        self.patches = []

    def add_patch(self, address, original, patch):
        self.patches.append({
            "address": address,
            "original": original,
            "patch": patch
        })

    def apply(self, process):
        for patch in self.patches:
            process.write_memory(
                patch['address'],
                patch['patch']
            )
```

### Frida-Based Bypasses

```javascript
// Comprehensive Frida bypass script
const bypasses = {
    // Bypass IsDebuggerPresent
    'kernel32.dll!IsDebuggerPresent': function() {
        return 0;
    },

    // Bypass CheckRemoteDebuggerPresent
    'kernel32.dll!CheckRemoteDebuggerPresent': function(hProcess, pbDebuggerPresent) {
        Memory.writeU8(pbDebuggerPresent, 0);
        return 1;
    },

    // Bypass NtQueryInformationProcess
    'ntdll.dll!NtQueryInformationProcess': function(handle, infoClass, info, size, ret) {
        const result = this.original(handle, infoClass, info, size, ret);
        if (infoClass === 7) {  // ProcessDebugPort
            Memory.writeU32(info, 0);
        }
        return result;
    }
};

// Apply all bypasses
Object.keys(bypasses).forEach(api => {
    Interceptor.attach(Module.findExportByName(...api.split('!')), {
        onEnter: bypasses[api]
    });
});
```

## Automated Detection Suite

### Running Comprehensive Analysis

```python
from intellicrack.plugins.custom_modules.anti_anti_debug_suite import (
    AntiAnalysisDetectionSuite
)

# Initialize suite
suite = AntiAnalysisDetectionSuite()

# Run full analysis
report = suite.analyze_binary(
    binary_path="protected.exe",
    output_format="json"
)

# Generate bypass package
bypass_package = suite.generate_bypass_package(report)

# Save bypass configuration
bypass_package.save("bypass_config.json")
```

### Integration with Main Analysis

```python
# Integrate with Intellicrack analysis pipeline
from intellicrack.core.analysis.analysis_orchestrator import AnalysisOrchestrator

orchestrator = AnalysisOrchestrator()

# Add anti-analysis detection to pipeline
orchestrator.add_analyzer(
    "anti_analysis",
    suite.analyze_binary,
    priority=1  # Run first
)

# Run analysis with automatic bypass
results = orchestrator.analyze(
    "protected.exe",
    auto_bypass=True
)
```

## Best Practices

1. **Detection Order**
   - Check for debugger detection first
   - Then VM detection
   - Finally sandbox detection
   - Apply bypasses in reverse order

2. **Stealth Considerations**
   - Minimize memory modifications
   - Use API hooking over patching
   - Restore original bytes when possible
   - Monitor for integrity checks

3. **Performance Impact**
   - Cache detection results
   - Use lazy evaluation
   - Parallelize detection where possible
   - Profile bypass overhead

## Advanced Techniques

### Machine Learning Detection

```python
from intellicrack.ml.anti_analysis_ml import AntiAnalysisML

ml_detector = AntiAnalysisML()

# Train on known samples
ml_detector.train(
    protected_samples="dataset/protected/",
    clean_samples="dataset/clean/"
)

# Detect unknown anti-analysis
predictions = ml_detector.predict(binary_path)
print(f"Anti-analysis probability: {predictions['probability']}")
print(f"Detected techniques: {predictions['techniques']}")
```

### Behavioral Analysis

```python
# Monitor runtime behavior
from intellicrack.core.analysis.dynamic_analyzer import DynamicAnalyzer

dynamic = DynamicAnalyzer()
behavior = dynamic.monitor_anti_analysis_behavior(
    binary_path,
    duration=60
)

# Identify evasion attempts
evasions = behavior.get_evasion_attempts()
for evasion in evasions:
    print(f"Time: {evasion['timestamp']}")
    print(f"Type: {evasion['type']}")
    print(f"Details: {evasion['details']}")
```

## Troubleshooting

### Common Issues

1. **Bypass Detection**
   ```python
   # Some protections detect common bypasses
   # Use polymorphic bypass generation
   bypass = suite.generate_polymorphic_bypass()
   ```

2. **Multi-Layered Protection**
   ```python
   # Handle nested protection checks
   suite.set_recursive_analysis(True)
   suite.set_max_depth(10)
   ```

3. **Self-Modifying Code**
   ```python
   # Handle dynamic protection
   suite.enable_runtime_monitoring()
   suite.set_snapshot_interval(100)  # ms
   ```

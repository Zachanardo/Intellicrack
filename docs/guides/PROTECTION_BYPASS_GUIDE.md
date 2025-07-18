# Protection Bypass Guide

## Overview

This guide covers Intellicrack's comprehensive protection detection and bypass capabilities. The system can identify and bypass various software protection mechanisms including commercial protectors, anti-analysis techniques, and licensing systems.

**⚠️ Legal Notice**: Use these features only on software you own or have permission to analyze.

## Protection Detection System

### Unified Protection Engine

The core protection detection system is located in `intellicrack/protection/`:

```python
from intellicrack.protection import UnifiedProtectionEngine

engine = UnifiedProtectionEngine()

# Comprehensive protection scan
protections = engine.analyze_binary("protected_app.exe")

# Results include:
# - Protection type and vendor
# - Version detection
# - Strength assessment
# - Bypass difficulty rating
```

### Protection Categories

#### 1. Commercial Protectors
- **Themida/WinLicense**: Advanced virtualization
- **VMProtect**: Virtual machine protection
- **Enigma Protector**: Compression + encryption
- **ASProtect**: Polymorphic protection
- **Armadillo**: Hardware locking
- **SafeEngine**: Chinese protector
- **Obsidium**: .NET and native protection

#### 2. Anti-Analysis Techniques
- **Anti-Debugging**: Debug detection/prevention
- **Anti-VM**: Virtual machine detection
- **Anti-Sandbox**: Sandbox environment detection
- **Anti-Dump**: Memory dumping prevention
- **Anti-Tampering**: Integrity checking

#### 3. Licensing Systems
- **FlexLM/FlexNet**: Industry standard
- **HASP/Sentinel**: Hardware + software
- **CodeMeter**: Wibu-Systems
- **Custom Licensing**: Proprietary systems

## Detection Methods

### Static Analysis
```python
# Protection signature scanning
from intellicrack.protection import ProtectionDetector

detector = ProtectionDetector()
signatures = detector.scan_signatures("app.exe")

# Check for:
# - Known packer signatures
# - Entry point modifications
# - Section characteristics
# - Import table anomalies
```

### Dynamic Analysis
```python
# Runtime protection detection
from intellicrack.protection import DynamicProtectionAnalyzer

analyzer = DynamicProtectionAnalyzer()

# Monitor for:
# - Exception handling hooks
# - Debug register usage
# - Timing checks
# - API hooks
results = analyzer.analyze_runtime("app.exe")
```

### ICP (Intellicrack Protection) Analysis
```python
from intellicrack.protection import ICPBackend

icp = ICPBackend()

# Advanced ML-based detection
analysis = icp.deep_analysis("protected.exe")
print(f"Protection confidence: {analysis.confidence}%")
print(f"Identified: {analysis.protection_name}")
```

## Bypass Techniques

### 1. Anti-Debugging Bypass

#### IsDebuggerPresent Bypass
```python
# Frida script generation
from intellicrack.protection.bypasses import AntiDebugBypass

bypass = AntiDebugBypass()
script = bypass.generate_frida_script([
    "IsDebuggerPresent",
    "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess"
])
```

#### Manual Bypass Example
```javascript
// Frida script
Interceptor.attach(Module.findExportByName("kernel32.dll", "IsDebuggerPresent"), {
    onLeave: function(retval) {
        retval.replace(0);  // Always return false
    }
});
```

### 2. VM Detection Bypass

```python
from intellicrack.protection import VMBypass

vm_bypass = VMBypass()

# Generate comprehensive VM hiding
patches = vm_bypass.generate_patches({
    "hide_vmware": True,
    "hide_virtualbox": True,
    "hide_hyperv": True,
    "spoof_hardware": True
})

# Apply patches
vm_bypass.apply_patches("app.exe", patches)
```

### 3. Packer Unpacking

#### Universal Unpacking
```python
from intellicrack.protection import UniversalUnpacker

unpacker = UniversalUnpacker()

# Automatic unpacking with OEP detection
unpacked = unpacker.unpack(
    "packed.exe",
    method="esp_trick",  # or "section_hop", "memory_breakpoint"
    dump_at_oep=True
)
```

#### Manual Unpacking Process
1. Find Original Entry Point (OEP)
2. Dump memory at OEP
3. Fix imports
4. Rebuild PE

### 4. License System Bypass

#### FlexLM/FlexNet Bypass
```python
from intellicrack.protection.license import FlexLMBypass

flexlm = FlexLMBypass()

# Option 1: License file generation
license_file = flexlm.generate_license(
    vendor="VENDOR_NAME",
    features=["FEATURE1", "FEATURE2"],
    expiry="permanent"
)

# Option 2: Server emulation
flexlm.start_license_server(
    port=27000,
    vendor_daemon="vendor.exe"
)
```

#### HASP/Sentinel Bypass
```python
from intellicrack.protection.license import HASPBypass

hasp = HASPBypass()

# Dongle emulation
hasp.emulate_dongle(
    dongle_id="HASP_ID",
    memory_file="dongle_memory.bin"
)

# API hooking approach
hooks = hasp.generate_api_hooks()
```

### 5. Integrity Check Bypass

```python
from intellicrack.protection import IntegrityBypass

integrity = IntegrityBypass()

# Bypass CRC/hash checks
patches = integrity.find_integrity_checks("app.exe")
for patch in patches:
    print(f"Patch at {hex(patch.address)}: {patch.description}")

# Apply all bypasses
integrity.apply_all_bypasses("app.exe")
```

### 6. Hardware Lock Bypass

```python
from intellicrack.protection import HardwareBypass

hw_bypass = HardwareBypass()

# HWID spoofing
hw_bypass.spoof_hwid({
    "cpu_id": "INTEL_CPU_ID",
    "motherboard": "ASUS_SERIAL",
    "disk_serial": "WD_SERIAL",
    "mac_address": "00:11:22:33:44:55"
})

# Generate permanent patch
hw_bypass.create_hwid_patch("app.exe")
```

## Advanced Bypass Strategies

### 1. Themida/WinLicense
```python
# Specialized Themida bypass
from intellicrack.protection.commercial import ThemidaBypass

themida = ThemidaBypass()

# Stage 1: Disable anti-debug
themida.bypass_antidebug()

# Stage 2: Dump protected sections
themida.dump_virtualized_code()

# Stage 3: Rebuild original code
themida.rebuild_original()
```

### 2. VMProtect
```python
# VMProtect devirtualization
from intellicrack.protection.commercial import VMProtectBypass

vmp = VMProtectBypass()

# Analyze VM handlers
handlers = vmp.analyze_handlers("vmp_protected.exe")

# Devirtualize critical functions
vmp.devirtualize_function(0x401000)
```

### 3. Denuvo
```python
# Denuvo bypass (games/software)
from intellicrack.protection.commercial import DenuvoBypass

denuvo = DenuvoBypass()

# Locate and patch triggers
triggers = denuvo.find_triggers("game.exe")
denuvo.patch_triggers(triggers)

# Remove online checks
denuvo.patch_online_checks()
```

## Protection Removal Workflow

### Automated Workflow
```python
# One-click protection removal
from intellicrack.protection import ProtectionRemover

remover = ProtectionRemover()

# Automatic detection and removal
result = remover.remove_all_protections(
    "protected.exe",
    output="clean.exe",
    aggressive=True
)

print(f"Removed: {result.protections_removed}")
print(f"Success rate: {result.success_rate}%")
```

### Manual Workflow

1. **Detection Phase**
   ```python
   # Identify all protections
   protections = engine.detect_all("app.exe")
   ```

2. **Analysis Phase**
   ```python
   # Analyze each protection
   for protection in protections:
       analysis = engine.analyze_protection(protection)
       print(f"{protection.name}: {analysis.bypass_difficulty}")
   ```

3. **Bypass Generation**
   ```python
   # Generate targeted bypasses
   bypasses = engine.generate_bypasses(protections)
   ```

4. **Application Phase**
   ```python
   # Apply bypasses with verification
   engine.apply_bypasses("app.exe", bypasses, verify=True)
   ```

## GUI Integration

Access protection bypass features through:

1. **Protection Tab**
   - Drag and drop binary
   - View detected protections
   - One-click bypass generation

2. **Advanced Options**
   - Custom bypass scripts
   - Manual patch points
   - Risk level settings

## Best Practices

1. **Always backup** original files
2. **Test in VM** first
3. **Use least invasive** method first
4. **Document changes** for reversibility
5. **Verify functionality** after bypass

## Common Issues

### "Protection still active"
1. Some protections have multiple layers
2. Try aggressive mode
3. Check for runtime reprotection

### "Application crashes after bypass"
1. Integrity checks may need patching
2. Some code may be virtualized
3. Try different bypass methods

### "Cannot find protection"
1. Update signature database
2. Use dynamic analysis
3. May be custom/unknown protection

## Custom Protection Handling

```python
# Add custom protection definitions
from intellicrack.protection import CustomProtection

custom = CustomProtection(
    name="CustomPacker",
    signatures=[b"\x50\x45\x00\x00", b"\xE8\x00\x00\x00\x00"],
    bypass_strategy="custom_script.js"
)

engine.register_protection(custom)
```

## Protection Bypass Scripts

Intellicrack includes pre-made bypass scripts in `plugins/frida_scripts/`:
- `anti_debug_bypass.js`
- `vm_detection_bypass.js`
- `integrity_check_bypass.js`
- `license_bypass_universal.js`

Load via GUI or CLI:
```bash
intellicrack bypass --script anti_debug_bypass.js target.exe
```
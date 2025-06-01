# Patching Guide

Learn how to modify binaries, bypass protections, and create patches using Intellicrack's powerful patching capabilities.

## Overview

Intellicrack provides multiple patching methods:
- **Hex Patching**: Direct byte modification
- **Assembly Patching**: Instruction-level changes
- **Memory Patching**: Runtime modifications
- **Automated Patching**: One-click bypass solutions

## Getting Started

### Basic Hex Patching

1. **Open the target binary** in Analysis tab
2. **Switch to Patch tab**
3. **Navigate to target offset** using hex editor
4. **Modify bytes** directly or use patch templates
5. **Save patched file** with new name

### Assembly-Level Patching

```python
# Example: Changing a conditional jump
from intellicrack.core.patching import PayloadGenerator

patcher = PayloadGenerator()
# Change JZ (74) to JMP (EB) at offset 0x1234
patcher.patch_bytes(binary_path, 0x1234, b'\xEB')
```

## Common Patching Scenarios

### License Bypass

#### Trial Period Removal

1. **Identify time check**:
   - Search for GetSystemTime, time() calls
   - Look for date comparisons
   - Find trial counter decrements

2. **Common patches**:
   ```assembly
   ; Original: Check if trial expired
   CMP EAX, 0x1E  ; 30 days
   JG error_label
   
   ; Patch: Always jump over check
   JMP continue_label
   NOP
   NOP
   ```

#### Registration Key Bypass

1. **Locate validation function**:
   - String search: "Invalid", "Wrong", "Incorrect"
   - API calls: RegQueryValue, strcmp
   - Crypto functions: MD5, SHA, CRC32

2. **Bypass methods**:
   - Force success return value
   - Skip validation entirely
   - Patch comparison result

### Anti-Debug Removal

#### IsDebuggerPresent Bypass

```python
# Automated anti-debug removal
from intellicrack.utils.patch_utils import remove_anti_debug

patched = remove_anti_debug("protected.exe", "cleaned.exe")
print(f"Removed {patched['count']} anti-debug checks")
```

#### Manual Patches

```assembly
; Original: IsDebuggerPresent check
CALL IsDebuggerPresent
TEST EAX, EAX
JNZ debugger_detected

; Patch: Always return 0 (no debugger)
XOR EAX, EAX
NOP
NOP
NOP
```

### Integrity Check Bypass

#### CRC/Checksum Patches

1. **Find checksum routine**:
   - Look for loops reading file/memory
   - Hash function signatures
   - Comparison with stored values

2. **Bypass strategies**:
   - Return expected checksum
   - Skip check entirely
   - Update stored checksum

## Advanced Patching

### Visual Patch Editor

1. **Open Visual Editor**: Tools → Visual Patch Editor
2. **Load binary** and select target function
3. **Drag-and-drop** patch blocks:
   - NOP blocks
   - Jump modifications
   - Call redirects
   - Custom assembly

### Pattern-Based Patching

```python
# Find and patch all occurrences
from intellicrack.core.patching import PatternPatcher

patcher = PatternPatcher()
patcher.add_pattern(
    name="Trial Check",
    pattern=b"\x83\x3D....\x1E",  # CMP DWORD PTR, 30
    replacement=b"\x90" * 7,       # NOP x7
)
results = patcher.apply_patches("app.exe", "app_patched.exe")
```

### Memory Patching

For protected/packed executables:

```python
# Runtime memory patching
from intellicrack.core.patching import MemoryPatcher

mp = MemoryPatcher()
mp.attach_process("target.exe")
mp.wait_for_unpack()  # Wait for code decryption
mp.patch_memory(0x401000, b"\xEB")  # Patch in memory
mp.detach()
```

## Patch Development

### Creating Patch Templates

```python
# Custom patch template
class LicenseBypasser:
    def __init__(self):
        self.name = "Generic License Bypass"
        self.patterns = [
            {
                "description": "Skip license check",
                "search": b"\x85\xC0\x74.",  # TEST EAX,EAX; JZ
                "replace": b"\x85\xC0\xEB."   # TEST EAX,EAX; JMP
            }
        ]
    
    def apply(self, binary_data):
        # Apply all patterns
        for pattern in self.patterns:
            binary_data = binary_data.replace(
                pattern["search"], 
                pattern["replace"]
            )
        return binary_data
```

### Automated Patch Generation

1. **Analyze protection scheme**
2. **Generate bypass strategy**
3. **Create reusable patch**
4. **Test on multiple versions**

## Tools and Features

### Patch Manager

- **Save/Load** patch projects
- **Version tracking** for different releases
- **Batch patching** for multiple files
- **Patch validation** and testing

### Diff Viewer

Compare original and patched:
- Hex differences
- Assembly changes
- Function modifications
- String alterations

### Patch Scripting

```python
# Scriptable patching
from intellicrack.core.patching import PatchScript

script = PatchScript()
script.load_binary("target.exe")
script.goto_function("check_license")
script.patch_instruction(0, "mov eax, 1")
script.patch_instruction(1, "ret")
script.save("target_patched.exe")
```

## Best Practices

### Safety First

1. **Always backup** original files
2. **Test patches** in isolated environment
3. **Document changes** for future reference
4. **Verify functionality** after patching

### Efficient Patching

- **Minimal changes**: Patch only what's necessary
- **Preserve alignment**: Maintain code/data alignment
- **Update headers**: Fix checksums and sizes
- **Handle relocations**: Update if base address changes

### Common Mistakes

- **Over-patching**: Modifying too much code
- **Breaking dependencies**: Other code relies on patched functions
- **Ignoring protections**: Some apps verify their own code
- **Platform issues**: x86/x64 instruction differences

## Protection-Specific Guides

### Themida/WinLicense

1. Use OllyDbg scripts for unpacking
2. Dump at OEP (Original Entry Point)
3. Fix imports with Scylla
4. Apply patches to dumped file

### VMProtect

1. Identify virtualized functions
2. Use devirtualization tools
3. Patch around VM handlers
4. Consider memory patching

### Denuvo

1. Complex multi-layer protection
2. Requires advanced techniques
3. Often easier to patch triggers
4. Memory patching recommended

## Troubleshooting

### Patch Not Working

- **Verify offset**: Ensure correct patch location
- **Check protections**: Anti-tamper may restore code
- **Runtime patches**: Some code is decrypted at runtime
- **Multiple checks**: Patch all validation points

### Crashes After Patching

- **Instruction alignment**: Ensure valid instructions
- **Stack balance**: CALL/RET must match
- **Register preservation**: Save/restore as needed
- **Exception handlers**: May need updating

## Legal Notice

Patching software may violate license agreements and laws. Use these techniques only for:
- Security research
- Personal education
- Software you own
- Authorized testing


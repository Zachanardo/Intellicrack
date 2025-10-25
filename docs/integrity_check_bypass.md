# Integrity Check Bypass System

## Overview

The Integrity Check Bypass System provides comprehensive capabilities for detecting, analyzing, and defeating software integrity protection mechanisms. This production-ready system implements genuine cryptographic checksum recalculation and sophisticated runtime hook-based bypasses.

## Features

### 1. Checksum Recalculation
- **CRC32**: Standard and zlib-accelerated implementations with lookup tables
- **MD5**: Full MD5 hash calculation for binary integrity
- **SHA-1**: SHA-1 hash computation for legacy protection systems
- **SHA-256**: Modern SHA-256 hash calculation
- **PE Checksum**: Windows PE format checksum recalculation
- **Section-level hashes**: Individual section integrity verification

### 2. Integrity Check Detection
- **API Import Analysis**: Detects Windows API calls used for integrity checking
  - `CheckSumMappedFile`, `MapFileAndCheckSum`
  - `CryptHashData`, `CryptVerifySignature`
  - `WinVerifyTrust`, `CertVerifyCertificateChainPolicy`
  - `RtlComputeCrc32`, `memcmp`, `strcmp`
- **Inline Check Detection**: Pattern matching for embedded integrity algorithms
  - CRC32 calculation patterns
  - MD5/SHA-1/SHA-256 initialization constants
  - File size verification checks
- **Anti-Tamper Detection**: Identifies self-protection mechanisms
  - High-entropy packed/encrypted sections
  - Self-modifying code patterns
  - Memory protection manipulation

### 3. Runtime Hook-Based Bypasses
Frida-based runtime interception for:
- **CRC32 Bypass**: Intercepts `RtlComputeCrc32` and `zlib.crc32`
- **Hash Bypass**: Hooks `CryptHashData` and `CryptGetHashParam`
- **Signature Bypass**: Defeats `WinVerifyTrust` and certificate verification
- **Size Check Bypass**: Manipulates `GetFileSize` and `GetFileSizeEx` returns
- **Checksum Bypass**: Intercepts PE checksum validation
- **Memory Hash Bypass**: Returns original bytes for memory integrity checks

### 4. Binary Patching
- **Inline Check Removal**: NOPs out integrity check code
- **Checksum Neutralization**: Patches CRC32/checksum functions to return success
- **PE Checksum Update**: Recalculates and updates PE header checksum
- **Section Integrity**: Maintains section-level hash integrity after patching

## Architecture

### Core Components

#### `ChecksumRecalculator`
Production-grade checksum calculation engine with optimized algorithms.

```python
from intellicrack.core.protection_bypass.integrity_check_defeat import ChecksumRecalculator

calc = ChecksumRecalculator()

# Calculate individual checksums
crc32 = calc.calculate_crc32_zlib(binary_data)
md5 = calc.calculate_md5(binary_data)
sha256 = calc.calculate_sha256(binary_data)

# Calculate PE checksum
pe_checksum = calc.recalculate_pe_checksum("program.exe")

# Calculate all hashes at once
checksums = calc.calculate_all_hashes(binary_data)
```

#### `IntegrityCheckDetector`
Sophisticated detection engine for identifying integrity protection mechanisms.

```python
from intellicrack.core.protection_bypass.integrity_check_defeat import IntegrityCheckDetector

detector = IntegrityCheckDetector()
checks = detector.detect_checks("protected.exe")

for check in checks:
    print(f"Type: {check.check_type.name}")
    print(f"Address: {hex(check.address)}")
    print(f"Function: {check.function_name}")
    print(f"Confidence: {check.confidence:.1%}")
```

#### `IntegrityBypassEngine`
Frida-based runtime hooking engine for dynamic bypass.

```python
from intellicrack.core.protection_bypass.integrity_check_defeat import IntegrityBypassEngine

bypasser = IntegrityBypassEngine()

# Attach to running process and install hooks
bypasser.bypass_checks("protected.exe", detected_checks)
```

#### `BinaryPatcher`
Static binary modification with checksum recalculation.

```python
from intellicrack.core.protection_bypass.integrity_check_defeat import BinaryPatcher

patcher = BinaryPatcher()

# Patch binary and recalculate checksums
success, checksums = patcher.patch_integrity_checks(
    "protected.exe",
    detected_checks,
    output_path="protected.patched.exe"
)

print(f"Original CRC32: {hex(checksums.original_crc32)}")
print(f"Patched CRC32: {hex(checksums.patched_crc32)}")
print(f"PE Checksum: {hex(checksums.pe_checksum)}")
```

#### `IntegrityCheckDefeatSystem`
Complete end-to-end system integrating all components.

```python
from intellicrack.core.protection_bypass.integrity_check_defeat import IntegrityCheckDefeatSystem

system = IntegrityCheckDefeatSystem()

# Full defeat workflow
result = system.defeat_integrity_checks(
    binary_path="protected.exe",
    process_name="protected.exe",  # For runtime bypass
    patch_binary=True              # Also create patched version
)

print(f"Checks detected: {result['checks_detected']}")
print(f"Checks bypassed: {result['checks_bypassed']}")
print(f"Binary patched: {result['binary_patched']}")
```

## Usage Examples

### Example 1: Detect Integrity Checks

```python
from intellicrack.core.protection_bypass.integrity_check_defeat import IntegrityCheckDefeatSystem

system = IntegrityCheckDefeatSystem()
result = system.defeat_integrity_checks("software.exe")

for detail in result['details']:
    print(f"{detail['type']} at {detail['address']}")
    print(f"  Function: {detail['function']}")
    print(f"  Bypass: {detail['bypass_method']}")
```

### Example 2: Generate Frida Bypass Script

```python
system = IntegrityCheckDefeatSystem()
script = system.generate_bypass_script("software.exe")

# Save script for manual use
with open("bypass.js", "w") as f:
    f.write(script)

# Or use with Frida directly
import frida
session = frida.attach("software.exe")
script_obj = session.create_script(script)
script_obj.load()
```

### Example 3: Patch Binary with Checksum Recalculation

```python
system = IntegrityCheckDefeatSystem()

result = system.defeat_integrity_checks(
    "software.exe",
    patch_binary=True
)

if result['binary_patched']:
    cs = result['checksums']
    print(f"Original: MD5={cs['original_md5']}")
    print(f"Patched:  MD5={cs['patched_md5']}")
    print(f"PE Checksum: {cs['pe_checksum']}")
```

### Example 4: Recalculate Checksums for Comparison

```python
system = IntegrityCheckDefeatSystem()

checksums = system.recalculate_checksums(
    "original.exe",
    "modified.exe"
)

print("Comparison:")
print(f"Original CRC32: {hex(checksums.original_crc32)}")
print(f"Modified CRC32: {hex(checksums.patched_crc32)}")
print(f"Original SHA256: {checksums.original_sha256}")
print(f"Modified SHA256: {checksums.patched_sha256}")
```

## Command-Line Interface

```bash
# Detect integrity checks
pixi run python -m intellicrack.core.protection_bypass.integrity_check_defeat software.exe

# Generate bypass script
pixi run python -m intellicrack.core.protection_bypass.integrity_check_defeat software.exe --script

# Patch binary
pixi run python -m intellicrack.core.protection_bypass.integrity_check_defeat software.exe --patch

# Runtime bypass on running process
pixi run python -m intellicrack.core.protection_bypass.integrity_check_defeat software.exe -p software.exe

# Verbose output
pixi run python -m intellicrack.core.protection_bypass.integrity_check_defeat software.exe -v
```

## Supported Protection Mechanisms

### Checksum Algorithms
- ✅ CRC32 (standard polynomial 0xEDB88320)
- ✅ MD5 (128-bit hash)
- ✅ SHA-1 (160-bit hash)
- ✅ SHA-256 (256-bit hash)
- ✅ PE Checksum (Windows executable checksum)

### Integrity Check Types
- ✅ Embedded checksums in binary
- ✅ External checksum validation
- ✅ Code signing verification
- ✅ Certificate chain validation
- ✅ File size verification
- ✅ Timestamp validation
- ✅ Memory integrity checks
- ✅ Self-modifying code detection
- ✅ Anti-tamper mechanisms

### Bypass Methods
- ✅ Runtime API hooking (Frida)
- ✅ Static binary patching (NOP/neutralization)
- ✅ Checksum recalculation and replacement
- ✅ Hash value replacement at runtime
- ✅ Memory region protection
- ✅ Original bytes restoration

## Technical Implementation

### CRC32 Algorithm

The system implements production-grade CRC32 calculation using:
- Standard polynomial: 0xEDB88320
- Lookup table optimization (256 entries)
- zlib-accelerated computation for large data
- Both forward and reversed table generation

### PE Checksum Calculation

Implements the official Microsoft PE checksum algorithm:
1. Sum all DWORDs in the file (excluding checksum field)
2. Add high word to low word for carry
3. Add file size to final checksum
4. Proper handling of odd-length files

### Hash Algorithms

Uses Python's `hashlib` for cryptographically secure hash calculations:
- MD5: `hashlib.md5()`
- SHA-1: `hashlib.sha1()`
- SHA-256: `hashlib.sha256()`

All implementations use efficient streaming for large files.

## Performance Considerations

- **Memory-mapped I/O**: Large binaries use memory mapping
- **Lookup tables**: CRC32 uses pre-computed 256-entry table
- **zlib acceleration**: CRC32 uses optimized C implementation when available
- **Efficient binary parsing**: Uses `pefile` and `lief` for optimized PE/ELF parsing
- **Caching**: Original bytes cached to avoid repeated file reads

## Security Research Use Cases

1. **License Protection Testing**: Evaluate strength of licensing integrity checks
2. **Anti-Tamper Analysis**: Assess effectiveness of self-protection mechanisms
3. **Bypass Resistance**: Test how well protection survives modification
4. **Checksum Security**: Verify proper cryptographic hash implementation
5. **Code Signing Validation**: Ensure signature verification works correctly

## Limitations

- Requires appropriate permissions for binary modification
- Runtime bypasses require process injection capabilities
- Some packed binaries may need unpacking first
- Advanced virtualization-based protections may require additional analysis
- Code signing bypass may trigger OS security warnings

## Related Modules

- `binary_patcher.py`: Binary modification and code injection
- `anti_debugging.py`: Anti-debugging defeat mechanisms
- `virtualization_bypass.py`: VM-based protection defeat
- `license_key_generator.py`: License key generation for testing

## References

- CRC32 Algorithm: ISO 3309, ITU-T V.42
- PE Format: Microsoft Portable Executable Specification
- Hash Functions: FIPS 180-4 (SHA), RFC 1321 (MD5)
- Frida: Dynamic instrumentation framework

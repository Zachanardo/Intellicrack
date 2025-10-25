# TPM Bypass Implementation - Complete Documentation

## Overview

The TPM (Trusted Platform Module) Bypass implementation in Intellicrack provides comprehensive capabilities for defeating hardware-based software licensing protections that rely on TPM 1.2 and TPM 2.0 chips.

## Purpose

This tool enables security researchers to test and improve their own software licensing protections by understanding how TPM-based protections can be defeated. It helps developers identify weaknesses in their licensing implementations before attackers do.

## Architecture

### Core Components

```
TPMBypassEngine
├── Static Analysis
│   ├── TPM Detection
│   ├── Protection Analysis
│   └── Binary Patching
│
├── Runtime Bypass (Frida)
│   ├── Command Interception
│   ├── PCR Manipulation
│   └── Dynamic Hooking
│
├── Key Extraction
│   ├── NVRAM Access
│   ├── Memory Extraction
│   └── Persistent Keys
│
├── Attestation Bypass
│   ├── Quote Forging
│   ├── Signature Generation
│   └── AIK Certificates
│
└── Platform-Specific
    ├── BitLocker VMK
    ├── Windows Hello
    └── Measured Boot
```

## Capabilities Matrix

### TPM 1.2 Support
- ✅ PCR Read/Extend operations
- ✅ OIAP/OSAP auth sessions
- ✅ Quote/Quote2 operations
- ✅ Seal/Unseal operations
- ✅ LoadKey2 operations
- ✅ NV Storage access

### TPM 2.0 Support
- ✅ All TPM 2.0 command codes
- ✅ SHA1, SHA256, SHA384, SHA512 PCR banks
- ✅ RSA, ECC, and ECDSA algorithms
- ✅ Policy-based authorization
- ✅ Enhanced authorization (HMAC/Policy)
- ✅ Hierarchy management

### Runtime Bypass (Frida)
- ✅ Windows TBS (TPM Base Services) hooking
- ✅ NCrypt TPM provider interception
- ✅ DeviceIoControl TPM access monitoring
- ✅ Real-time PCR value spoofing
- ✅ PCR extend operation blocking
- ✅ Command modification and injection
- ✅ Secure Boot bypass
- ✅ Measured Boot bypass

## Implementation Details

### 1. TPM Command Interception

The engine can intercept TPM commands at multiple levels:

**Windows TBS Layer:**
```python
engine = TPMBypassEngine()
engine.attach_to_process_frida("protected_app.exe")
engine.inject_tpm_command_interceptor()
```

This hooks:
- `Tbsip_Submit_Command` - Main command submission
- `Tbsi_Context_Create` - Context creation
- `NCryptOpenStorageProvider` - TPM storage provider
- `NCryptOpenKey` - TPM key access
- `DeviceIoControl` - Direct TPM device access

**Direct TPM Device:**
```python
command = struct.pack(">HII", 0x8001, 14, TPM2CommandCode.PCR_Read)
response = engine.send_tpm_command(command)
```

### 2. PCR Manipulation

**Static PCR Spoofing:**
```python
engine = TPMBypassEngine()

pcr_values = {
    0: bytes.fromhex("0" * 64),  # BIOS measurement
    7: bytes.fromhex("a7c06b3f8f927ce2276d0f72093af41c1ac8fac416236ddc88035c135f34c2bb"),  # Secure Boot
}

engine.manipulate_pcr_values(pcr_values)
```

**Runtime PCR Spoofing (Frida):**
```python
engine.attach_to_process_frida("app.exe")
engine.inject_pcr_manipulator()

engine.spoof_pcr_runtime(7, bytes.fromhex("a7c06b3f8f927ce2276d0f72093af41c1ac8fac416236ddc88035c135f34c2bb"))

engine.block_pcr_extend_runtime(0)
```

**Preset Bypass Methods:**
```python
engine.bypass_secure_boot_runtime()

engine.bypass_measured_boot_runtime()
```

### 3. Key Unsealing

The engine implements multiple unsealing techniques:

**TPM 2.0 Private Blob Unsealing:**
- Parses `TPM2B_PRIVATE` structure
- Bypasses PCR policy checks
- Tries common authorization values
- Decrypts AES-CBC encrypted sensitive data
- Handles PKCS#7 padding

**TPM 2.0 Credential Blob Unsealing:**
- Handles `TPM2B_ID_OBJECT` structures
- Implements credential activation bypass
- Uses PBKDF2 key derivation
- Supports multiple encryption modes

**Generic Blob Unsealing:**
- Pattern-based blob detection
- Multiple authorization attempts
- AES CBC/ECB mode support
- Entropy-based validation

**Example:**
```python
engine = TPMBypassEngine()

sealed_blob = load_sealed_license_blob()

pcr_policy = {
    0: expected_pcr0_value,
    7: expected_pcr7_value,
}

unsealed_key = engine.unseal_tpm_key(
    sealed_blob=sealed_blob,
    auth_value=b"",
    pcr_policy=pcr_policy
)
```

### 4. Attestation Bypass

**Quote Forging:**
```python
engine = TPMBypassEngine()

nonce = server_challenge_nonce
pcr_selection = [0, 1, 2, 3, 7, 11, 14]

attestation = engine.bypass_attestation(nonce, pcr_selection)

response = {
    'magic': attestation.magic,
    'type': attestation.type,
    'signature': attestation.signature,
    'attested_data': attestation.attested_data,
}
```

**Complete Remote Attestation:**
```python
expected_pcrs = {
    0: bios_measurement,
    7: secure_boot_pcr,
    10: ima_log_pcr,
}

attestation_response = engine.spoof_remote_attestation(
    nonce=server_nonce,
    expected_pcrs=expected_pcrs,
    aik_handle=0x81010001
)

send_to_license_server(attestation_response)
```

### 5. Platform-Specific Attacks

**BitLocker VMK Extraction:**
```python
engine = TPMBypassEngine()

vmk = engine.extract_bitlocker_vmk()

if vmk:
    unlock_bitlocker_volume(vmk)
```

**Windows Hello Bypass:**
```python
engine = TPMBypassEngine()

hello_keys = engine.bypass_windows_hello()

biometric_template = hello_keys['biometric_template']
pin_unlock_key = hello_keys['pin_unlock']
```

**Cold Boot Attack:**
```python
engine = TPMBypassEngine()

secrets = engine.cold_boot_attack()

rsa_keys = {k: v for k, v in secrets.items() if 'rsa' in k}
ecc_keys = {k: v for k, v in secrets.items() if 'ecc' in k}
```

### 6. Binary Patching

**Detection:**
```python
from intellicrack.core.protection_bypass.tpm_bypass import detect_tpm_usage, analyze_tpm_protection

if detect_tpm_usage("protected.exe"):
    analysis = analyze_tpm_protection("protected.exe")
    print(f"TPM APIs: {analysis['tpm_apis']}")
    print(f"Strength: {analysis['protection_strength']}")
```

**Patching:**
```python
from intellicrack.core.protection_bypass.tpm_bypass import bypass_tpm_protection

success = bypass_tpm_protection(
    binary_path="protected.exe",
    output_path="protected_cracked.exe"
)
```

This patches:
- TPM API import strings
- Conditional jumps near TPM calls
- Returns from TPM validation functions

## Frida Script Integration

### TPM Command Interceptor (`tpm_command_interceptor.js`)

**Features:**
- Hooks `Tbsip_Submit_Command`
- Parses TPM 2.0 command packets
- Logs all TPM operations
- Identifies Unseal, Quote, PCR_Extend operations
- Hooks `NCryptOpenStorageProvider` for TPM keys
- Monitors `DeviceIoControl` for direct TPM access

**RPC Exports:**
```javascript
{
    getSummary: () => {...},
    getInterceptedCommands: () => {...},
    clearCommands: () => {...}
}
```

**Usage:**
```python
engine.attach_to_process_frida("app.exe")
engine.inject_tpm_command_interceptor()

commands = engine.get_intercepted_commands_frida()

for cmd in commands:
    print(f"Command: {cmd['command']['commandName']}")
    print(f"Time: {cmd['timestamp']}")
```

### PCR Manipulator (`tpm_pcr_manipulator.js`)

**Features:**
- Spoofs PCR_Read responses
- Blocks PCR_Extend operations
- Bypasses PolicyPCR checks
- Predefined Secure Boot spoofing
- Predefined clean boot state

**RPC Exports:**
```javascript
{
    setSpoofedPCR: (index, hexValue) => {...},
    blockPCR: (index) => {...},
    unblockPCR: (index) => {...},
    spoofSecureBoot: () => {...},
    spoofCleanBoot: () => {...},
    blockAll: () => {...},
    getSummary: () => {...}
}
```

**Usage:**
```python
engine.attach_to_process_frida("app.exe")
engine.inject_pcr_manipulator()

engine.spoof_pcr_runtime(7, secure_boot_value)
engine.block_pcr_extend_runtime(0)

operations = engine.get_pcr_operations_frida()
```

## Real-World Attack Scenarios

### Scenario 1: Software with TPM-Sealed License

**Protection:**
- License key sealed with TPM
- Requires specific PCR values
- Hardware-bound to machine

**Attack:**
```python
engine = TPMBypassEngine()

analysis = engine.analyze_tpm_protection("licensed_app.exe")

for nvram_idx in analysis['nvram_indices']:
    license_blob = engine.read_nvram_raw(nvram_idx, b"")

    if license_blob:
        pcr_policy = {}
        for pcr in analysis['pcr_usage']:
            pcr_policy[pcr] = bytes(32)

        license_key = engine.unseal_tpm_key(
            sealed_blob=license_blob,
            auth_value=b"",
            pcr_policy=pcr_policy
        )

        if license_key:
            print(f"License key unsealed: {license_key.hex()}")
            break
```

### Scenario 2: Cloud License Validation with Attestation

**Protection:**
- Remote attestation required
- Server validates TPM quote
- Checks Secure Boot state

**Attack:**
```python
engine = TPMBypassEngine()

server_challenge = receive_challenge_from_server()

expected_pcrs = {
    7: bytes.fromhex("a7c06b3f8f927ce2276d0f72093af41c1ac8fac416236ddc88035c135f34c2bb"),
}

for pcr_num, pcr_value in expected_pcrs.items():
    engine.manipulate_pcr_values({pcr_num: pcr_value})

attestation = engine.spoof_remote_attestation(
    nonce=server_challenge,
    expected_pcrs=expected_pcrs
)

send_attestation_to_server(attestation)
```

### Scenario 3: Runtime License Check Bypass

**Protection:**
- Periodic TPM checks at runtime
- Validates PCR state
- Checks for tampering

**Attack:**
```python
engine = TPMBypassEngine()

engine.attach_to_process_frida("app.exe")
engine.inject_pcr_manipulator()

engine.bypass_secure_boot_runtime()
engine.bypass_measured_boot_runtime()

for i in range(8):
    engine.block_pcr_extend_runtime(i)

print("Runtime bypass active - application will see spoofed TPM state")

input("Press Enter to detach...")
engine.detach_frida()
```

### Scenario 4: Subscription Software with TPM Binding

**Protection:**
- Subscription key bound to TPM
- Monthly validation with attestation
- Hardware fingerprinting

**Attack:**
```python
engine = TPMBypassEngine()

subscription_keys = engine.extract_sealed_keys()

for key_name, key_blob in subscription_keys.items():
    if "subscription" in key_name.lower():
        subscription_data = engine.unseal_tpm_key(key_blob)

        if subscription_data:
            modify_subscription_expiry(subscription_data)
            break

def monthly_check_hook(command):
    """Hook monthly attestation check."""
    fake_attestation = engine.bypass_attestation(
        challenge=extract_challenge(command),
        pcr_selection=[0, 7, 11]
    )
    return create_quote_response(fake_attestation)

engine.intercept_tpm_command(TPM2CommandCode.Quote, monthly_check_hook)
```

## Advanced Techniques

### Memory-Level Attack

```python
engine = TPMBypassEngine()

tpm_memory_regions = {
    "tpm_control": 0xFED40000,
    "tpm_buffers": 0xFED40080,
    "tpm_data_fifo": 0xFED40024,
}

for region_name, address in tpm_memory_regions.items():
    mem_data = engine.read_physical_memory(address, 0x1000)

    if mem_data and b"\x00\x01\x00\x00" in mem_data:
        rsa_key_offset = mem_data.find(b"\x00\x01\x00\x00")
        rsa_key = mem_data[rsa_key_offset:rsa_key_offset+256]
        print(f"Found RSA key in {region_name}: {rsa_key.hex()[:32]}...")
```

### Bus-Level Interception

```python
engine = TPMBypassEngine()

captured_unseal = engine.perform_bus_attack(TPM2CommandCode.Unseal)

if captured_unseal:
    print(f"Captured unsealed key via bus: {captured_unseal.hex()}")
```

### TPM Reset Attack

```python
engine = TPMBypassEngine()

if engine.reset_tpm_lockout():
    print("TPM lockout counter reset")

    for attempt in range(100):
        unsealed = try_unseal_with_auth(attempt)
        if unsealed:
            print(f"Success on attempt {attempt}")
            break

if engine.clear_tpm_ownership():
    print("TPM ownership cleared - can now take control")
    reinitialize_tpm_with_custom_auth()
```

## Best Practices

### For Security Researchers

1. **Always test in isolated environment**
2. **Document bypass techniques discovered**
3. **Report vulnerabilities to software vendors**
4. **Use for defensive security research only**

### For Developers

1. **Implement defense in depth** - Don't rely solely on TPM
2. **Use multiple PCRs** - Include PCRs 0-7, 11, 14
3. **Implement anti-tampering** - Detect binary modification
4. **Use policy-based authorization** - More secure than password
5. **Validate attestation signatures** - Check against known good AIK
6. **Monitor for suspicious behavior** - Detect hooking attempts
7. **Update regularly** - Patch known TPM bypass techniques

## Limitations

### What This Tool CANNOT Do

- ❌ Break properly implemented TPM hardware security
- ❌ Extract keys from functioning TPM without vulnerabilities
- ❌ Bypass attestation when proper signature validation exists
- ❌ Defeat TPM 2.0 with perfect implementation

### What This Tool CAN Do

- ✅ Exploit implementation weaknesses in TPM usage
- ✅ Bypass software-level TPM checks
- ✅ Manipulate PCR values in virtualized/emulated TPMs
- ✅ Intercept and modify TPM commands at API level
- ✅ Extract keys from improperly secured NVRAM
- ✅ Forge attestation when signature validation is weak

## Performance Characteristics

| Operation | Typical Time | Notes |
|-----------|-------------|-------|
| TPM Detection | < 100ms | Binary string scanning |
| Protection Analysis | < 500ms | Deep binary analysis |
| Binary Patching | < 1s | Depends on binary size |
| PCR Spoofing | < 10ms | Direct memory write |
| Key Extraction | 100ms - 2s | NVRAM enumeration |
| Key Unsealing | 50ms - 500ms | Per auth attempt |
| Attestation Forging | < 100ms | Cryptographic operations |
| Frida Attachment | 500ms - 2s | Process spawn/attach |
| Runtime Bypass | < 50ms | Per operation |

## Dependencies

### Required
- Python 3.12+
- `pycryptodome` - Cryptographic operations
- `pywin32` (Windows only) - Win32 API access

### Optional
- `frida` - Runtime instrumentation and hooking
- `frida-tools` - Frida CLI utilities

### Install
```bash
pip install pycryptodome pywin32 frida frida-tools
```

## API Reference

### Class: TPMBypassEngine

**Initialization:**
```python
engine = TPMBypassEngine()
```

**Key Methods:**

| Method | Description | Returns |
|--------|-------------|---------|
| `detect_tpm_version()` | Detect TPM version | str: "1.2" or "2.0" |
| `extract_sealed_keys(auth)` | Extract all sealed keys | Dict[str, bytes] |
| `unseal_tpm_key(blob, auth, policy)` | Unseal specific key | Optional[bytes] |
| `bypass_attestation(nonce, pcrs)` | Forge attestation | AttestationData |
| `spoof_remote_attestation(...)` | Full attestation response | Dict |
| `manipulate_pcr_values(pcrs)` | Spoof PCR values | None |
| `extract_bitlocker_vmk()` | Extract BitLocker VMK | Optional[bytes] |
| `bypass_windows_hello()` | Bypass Windows Hello | Dict[str, bytes] |
| `attach_to_process_frida(target)` | Attach Frida to process | bool |
| `inject_tpm_command_interceptor()` | Inject interceptor script | bool |
| `inject_pcr_manipulator(config)` | Inject PCR script | bool |
| `spoof_pcr_runtime(index, value)` | Spoof PCR at runtime | bool |
| `block_pcr_extend_runtime(index)` | Block PCR extend | bool |
| `bypass_secure_boot_runtime()` | Bypass Secure Boot | bool |
| `bypass_measured_boot_runtime()` | Bypass measured boot | bool |
| `get_intercepted_commands_frida()` | Get intercepted commands | List[Dict] |
| `detach_frida()` | Detach Frida session | None |

**Standalone Functions:**

| Function | Description | Returns |
|----------|-------------|---------|
| `detect_tpm_usage(path)` | Detect TPM in binary | bool |
| `analyze_tpm_protection(path)` | Analyze TPM protection | dict |
| `bypass_tpm_protection(in, out)` | Patch binary | bool |
| `tpm_research_tools()` | Get tool info | dict |

## Examples

See `D:\Intellicrack\examples\tpm_bypass_example.py` for comprehensive examples covering:

1. TPM Detection
2. BitLocker VMK Extraction
3. Windows Hello Bypass
4. PCR Value Spoofing
5. Sealed Key Extraction
6. Key Unsealing
7. Remote Attestation Spoofing
8. Binary Patching
9. Command Interception
10. Full Commercial Software Bypass

## Conclusion

The TPM Bypass implementation provides comprehensive capabilities for security researchers to test TPM-based licensing protections. It combines static analysis, runtime manipulation, cryptographic operations, and platform-specific attacks to defeat various TPM protection schemes.

**Use Responsibly:**
- Only for security research and testing your own software
- Never use for unauthorized access to commercial software
- Report discovered vulnerabilities to vendors
- Help improve software security through responsible disclosure

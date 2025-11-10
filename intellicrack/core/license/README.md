# License Keygen Module

## Quick Start

```python
from intellicrack.core.license import LicenseKeygen

# Initialize keygen
keygen = LicenseKeygen()

# Generate Microsoft-style product key
key = keygen.generate_key_from_algorithm("microsoft")
print(key.serial)  # BCDFG-HJKMP-QRTVW-XY234-6789

# Generate hardware-locked license
hw_key = keygen.generate_hardware_locked_key(
    hardware_id="MACHINE-12345",
    product_id="MyProduct-2024"
)
print(hw_key.serial)  # ABC12-DEF34-GHI56-JKL78-AB12

# Generate time-limited trial key (30 days)
trial_key = keygen.generate_time_limited_key(
    product_id="MyProduct-2024",
    days_valid=30
)
print(trial_key.serial)
```

## Binary Analysis

```python
# Analyze binary and generate working keys
keygen = LicenseKeygen("path/to/protected.exe")
keys = keygen.crack_license_from_binary(count=10)

for key in keys:
    print(f"{key.serial} (confidence: {key.confidence:.1%})")
```

## Reverse Engineering

```python
# Learn algorithm from valid keys
valid_keys = ["KEY1-1234", "KEY2-5678", "KEY3-9012"]
analysis = keygen.reverse_engineer_keygen(valid_keys)

print(f"Algorithm: {analysis['algorithm']}")
print(f"Format: {analysis['format']}")
print(f"Generated samples: {analysis['generated_samples']}")
```

## Advanced Features

### Volume Licensing

```python
# Generate 1000 enterprise licenses
licenses = keygen.generate_volume_license("Product-2024", count=1000)
```

### Feature Encoding

```python
# Generate key with specific features
key = keygen.generate_feature_key(
    base_product="MyProduct",
    features=["pro", "enterprise", "unlimited"]
)
```

### Brute Force Recovery

```python
# Recover full key from partial
partial = "ABCD-****-EFGH-5678"
missing = [5, 6, 7, 8]  # Positions of asterisks

def validate(k):
    return custom_validation_check(k)

recovered = keygen.brute_force_key(partial, missing, validate)
```

## Architecture

- **ConstraintExtractor** - Analyzes binaries, extracts validation requirements
- **ValidationAnalyzer** - Identifies algorithms (CRC, MD5, SHA, etc.)
- **KeySynthesizer** - Generates keys satisfying constraints
- **LicenseKeygen** - High-level interface combining all capabilities

## Supported Algorithms

- Microsoft product keys (5x5 format)
- UUID v4 licenses
- Luhn checksum keys
- CRC16/CRC32 validation
- MD5/SHA1/SHA256 hashing
- RSA-2048 signed licenses
- ECDSA signed licenses
- Time-based (TOTP-like) keys
- Hardware-locked licenses
- Feature-encoded keys
- Custom polynomial checksums
- Modular arithmetic validation

## Data Structures

All generated keys return `GeneratedSerial` objects with:

- `serial` - The license key string
- `algorithm` - Algorithm used
- `confidence` - Reliability score (0.0 to 1.0)
- `hardware_id` - Hardware binding (if applicable)
- `expiration` - Expiration timestamp (if applicable)
- `features` - Enabled features (if applicable)

## Windows Compatibility

All functionality is designed for Windows as the primary platform:

- PE format analysis optimized
- Windows path handling
- Registry analysis support
- Hardware ID extraction

## Dependencies

Required external libraries:

- `lief` - Binary parsing
- `capstone` - Disassembly
- `z3-solver` - Constraint solving
- `cryptography` - RSA/ECC operations

## Examples

See `KEYGEN_IMPLEMENTATION_REPORT.md` for detailed examples and usage patterns.

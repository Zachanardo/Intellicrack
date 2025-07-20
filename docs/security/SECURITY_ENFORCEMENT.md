# Security Enforcement Module

## Overview

The Intellicrack Security Enforcement module provides comprehensive runtime security controls through monkey-patching of Python standard library functions. It enforces security policies defined in `intellicrack_config.json` without requiring modifications to existing code.

## Features

### 1. Subprocess Protection
- **Blocks `shell=True`** by default to prevent shell injection attacks
- **Whitelist support** for approved shell commands
- **Applies to all subprocess variants**: `run()`, `Popen()`, `call()`, `check_call()`, `check_output()`

### 2. Serialization Safety
- **Pickle restriction** - redirects to JSON when possible
- **Automatic fallback** - uses pickle only for non-JSON-serializable objects
- **Security warnings** for pickle operations

### 3. Hashing Enforcement
- **Blocks MD5 for security** - automatically upgrades to SHA256
- **Configurable default algorithm**
- **Applies to**: `hashlib.md5()` and `hashlib.new('md5')`

### 4. File Input Validation
- **Path traversal detection**
- **File size limits** (when configured)
- **Extension whitelisting** (when configured)
- **Strict mode enforcement**

## Configuration

Edit `config/intellicrack_config.json`:

```json
{
  "security": {
    "sandbox_analysis": true,
    "allow_network_access": false,
    "log_sensitive_data": false,
    "encrypt_config": false,
    "hashing": {
      "default_algorithm": "sha256",
      "allow_md5_for_security": false
    },
    "subprocess": {
      "allow_shell_true": false,
      "shell_whitelist": ["echo", "dir", "ls"]
    },
    "serialization": {
      "default_format": "json",
      "restrict_pickle": true
    },
    "input_validation": {
      "strict_mode": true,
      "max_file_size": 10485760,  // 10MB in bytes
      "allowed_extensions": [".txt", ".py", ".json", ".exe", ".dll"]
    }
  }
}
```

## Usage

### Automatic Enforcement

Security is automatically enforced when Intellicrack starts:
- Imported early in `intellicrack/main.py`
- Imported early in `intellicrack/__main__.py`
- Imported in `intellicrack/core/__init__.py`

### Manual Import

```python
from intellicrack.core import security_enforcement

# Check security status
status = security_enforcement.get_security_status()
print(f"Security active: {status['initialized']}")
print(f"Patches applied: {status['patches_applied']}")
```

### Emergency Bypass

For critical operations that require bypassing security:

```python
from intellicrack.core.security_enforcement import _security

# Enable bypass
_security.enable_bypass()

# Perform critical operation
subprocess.run("dangerous command", shell=True)  # Now allowed

# Re-enable security
_security.disable_bypass()
```

### File Validation

```python
from intellicrack.core.security_enforcement import validate_file_input, secure_open

# Validate file before processing
try:
    validate_file_input("/path/to/file.exe")
except SecurityError as e:
    print(f"File validation failed: {e}")

# Use secure_open for automatic validation
with secure_open("/path/to/file.txt", 'r') as f:
    content = f.read()
```

## Security Policies

### Subprocess Security

**Default**: `shell=True` is blocked

```python
# This will raise SecurityError
subprocess.run("echo test", shell=True)

# This is allowed
subprocess.run(["echo", "test"])

# Enable shell=True in config
"subprocess": {
  "allow_shell_true": true
}
```

### Pickle Security

**Default**: JSON preferred over pickle

```python
# Automatically uses JSON for compatible data
data = {"key": "value"}
serialized = pickle.dumps(data)  # Returns JSON bytes

# Falls back to pickle for complex objects
obj = CustomClass()
serialized = pickle.dumps(obj)  # Uses pickle with warning
```

### Hashing Security

**Default**: MD5 blocked, SHA256 used instead

```python
# This returns SHA256 hash
h = hashlib.md5(b"data")
print(h.hexdigest())  # SHA256 hash, not MD5

# Enable MD5 in config (not recommended)
"hashing": {
  "allow_md5_for_security": true
}
```

## Logging

Security events are logged with appropriate levels:
- **INFO**: Initialization, patches applied
- **WARNING**: Blocked operations, security concerns
- **ERROR**: Configuration errors, patch failures
- **DEBUG**: Detailed operation logs

## Testing

Run security tests:

```bash
# Direct test (no dependencies)
python tests/test_security_direct.py

# Full test suite
python tests/test_security_enforcement.py
```

## Best Practices

1. **Never disable security in production**
2. **Use bypass mode sparingly** and re-enable immediately
3. **Configure whitelists carefully** - be specific
4. **Monitor security logs** for blocked operations
5. **Test thoroughly** after configuration changes

## Troubleshooting

### Import Errors

If security doesn't initialize:
1. Check `intellicrack_config.json` syntax
2. Verify file permissions
3. Check Python path configuration

### Patches Not Applied

```python
# Verify patches
status = security_enforcement.get_security_status()
for patch, applied in status['patches_applied'].items():
    print(f"{patch}: {applied}")
```

### Configuration Not Loading

The module searches for config in order:
1. `<project>/config/intellicrack_config.json`
2. `<cwd>/config/intellicrack_config.json`
3. `~/.intellicrack/intellicrack_config.json`
4. Falls back to secure defaults

## Security Considerations

- **Monkey-patching limitations**: New subprocess imports after initialization won't be patched
- **Bypass mode risk**: Can disable all security temporarily
- **Performance impact**: Minimal overhead for security checks
- **Compatibility**: Works with Python 3.8+

## Future Enhancements

Planned improvements:
- Network operation hooks
- File system operation monitoring
- Dynamic configuration reloading
- Security audit reporting
- Integration with OS security features
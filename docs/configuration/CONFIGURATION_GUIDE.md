# Intellicrack Configuration Guide

## Task 20.2.1: Complete Configuration Documentation

This guide documents the consolidated configuration system implemented in Intellicrack v4.0, which centralizes all configuration management through a single `IntellicrackConfig` class.

## Table of Contents

1. [Overview](#overview)
2. [Configuration Structure](#configuration-structure)
3. [Using the Configuration System](#using-the-configuration-system)
4. [Configuration Sections](#configuration-sections)
5. [API Reference](#api-reference)
6. [Examples](#examples)

## Overview

The Intellicrack configuration system provides:

- **Centralized Management**: Single source of truth for all configuration
- **Thread-Safe Access**: Safe concurrent read/write operations
- **Automatic Migration**: Seamless migration from legacy configurations
- **Backup & Recovery**: Automatic backups and recovery mechanisms
- **Type Safety**: Validated configuration with schema enforcement
- **Performance**: Optimized for fast access with caching

## Configuration Structure

The configuration is stored as a JSON file at:
- **Windows**: `%APPDATA%\Intellicrack\config.json`
- **Linux/Mac**: `~/.config/intellicrack/config.json`

### File Structure

```json
{
  "version": "3.0",
  "created": "2024-01-01T00:00:00",
  "platform": "windows",
  "application": {
    "name": "Intellicrack",
    "version": "4.0.0"
  },
  // ... additional sections
}
```

## Using the Configuration System

### Basic Usage

```python
from intellicrack.core.config_manager import get_config

# Get configuration instance (singleton)
config = get_config()

# Read configuration
value = config.get("application.name")
theme = config.get("ui_preferences.theme")

# Write configuration
config.set("ui_preferences.theme", "dark")
config.set("qemu_testing.default_preference", "always")

# Check if key exists
if config.has("llm_configuration.models.gpt4"):
    model_config = config.get("llm_configuration.models.gpt4")
```

### Nested Access

The configuration system supports dot notation for nested access:

```python
# Access nested values
config.get("llm_configuration.models.gpt4.temperature")
config.set("cli_configuration.profiles.default.verbosity", "debug")

# Get entire sections
qemu_config = config.get("qemu_testing")
font_sizes = config.get("font_configuration.font_sizes")
```

### Default Values

```python
# Get with default value if key doesn't exist
timeout = config.get("analysis_settings.timeout", default=300)
theme = config.get("ui_preferences.theme", default="light")
```

## Configuration Sections

### Core Sections

#### Application Configuration

```python
config.get("application")
# Returns:
{
    "name": "Intellicrack",
    "version": "4.0.0",
    "build": "release",
    "debug_mode": false
}
```

#### Directories

```python
config.get("directories")
# Returns:
{
    "workspace": "path/to/workspace",
    "plugins": "path/to/plugins",
    "temp": "path/to/temp",
    "logs": "path/to/logs"
}
```

### Feature-Specific Sections

#### QEMU Testing Configuration

Controls QEMU sandbox testing preferences and settings.

```python
config.get("qemu_testing")
# Returns:
{
    "default_preference": "ask",  # "always", "never", "ask"
    "script_type_preferences": {
        "python": "sandbox",
        "javascript": "ask",
        "binary": "never"
    },
    "trusted_binaries": ["safe.exe"],
    "execution_history": [],
    "qemu_timeout": 300,
    "qemu_memory": 2048,
    "enable_logging": true
}

# Set QEMU preferences
config.set("qemu_testing.default_preference", "always")
config.set("qemu_testing.qemu_memory", 4096)
```

#### Font Configuration

Manages font settings for UI and code display.

```python
config.get("font_configuration")
# Returns:
{
    "monospace_fonts": {
        "primary": ["JetBrains Mono", "Consolas"],
        "fallback": ["Courier New", "monospace"]
    },
    "ui_fonts": {
        "primary": ["Segoe UI", "Arial"],
        "fallback": ["sans-serif"]
    },
    "font_sizes": {
        "ui_default": 10,
        "ui_small": 9,
        "ui_large": 12,
        "code_default": 11,
        "code_small": 9,
        "code_large": 13,
        "hex_view": 9
    },
    "available_fonts": []
}

# Set font preferences
config.set("font_configuration.font_sizes.code_default", 12)
config.set("font_configuration.monospace_fonts.primary", ["Fira Code", "Consolas"])
```

#### Environment Variables

Manages environment variables and .env file loading.

```python
config.get("environment")
# Returns:
{
    "variables": {
        "OPENAI_API_KEY": "sk-...",
        "ANTHROPIC_API_KEY": "sk-ant-..."
    },
    "env_files": [".env", ".env.local"],
    "auto_load_env": true,
    "override_system_env": false,
    "expand_variables": true,
    "case_sensitive": false,
    "backup_original": true,
    "env_file_encoding": "utf-8"
}

# Set environment variables
config.set("environment.variables.CUSTOM_VAR", "value")
config.set("environment.env_files", [".env", ".env.production"])
```

#### Secrets Management

Handles encryption and secure storage of sensitive data.

```python
config.get("secrets")
# Returns:
{
    "encryption_enabled": true,
    "keyring_backend": "windows",  # "windows", "macos", "linux"
    "encrypted_keys": ["api_key", "token"],
    "use_system_keyring": true,
    "fallback_to_env": true,
    "mask_in_logs": true,
    "rotation_enabled": false,
    "rotation_days": 90,
    "audit_access": false,
    "allowed_keys": [],
    "denied_keys": []
}

# Configure secrets
config.set("secrets.encryption_enabled", true)
config.set("secrets.encrypted_keys", ["openai_key", "anthropic_key"])
```

#### LLM Configuration

Manages Large Language Model configurations and profiles.

```python
config.get("llm_configuration")
# Returns:
{
    "models": {
        "gpt4": {
            "provider": "openai",
            "model_id": "gpt-4",
            "api_key": "encrypted_ref",
            "temperature": 0.7,
            "max_tokens": 2048
        }
    },
    "profiles": {
        "code_generation": {
            "settings": {
                "temperature": 0.3,
                "top_p": 0.95
            },
            "recommended_models": ["gpt4", "claude"]
        }
    },
    "metrics": {
        "total_requests": 0,
        "total_tokens": 0,
        "total_cost": 0.0,
        "model_usage": {},
        "error_count": 0,
        "average_response_time": 0.0
    }
}

# Configure LLM models
config.set("llm_configuration.models.claude", {
    "provider": "anthropic",
    "model_id": "claude-3",
    "api_key": "sk-ant-..."
})
```

#### CLI Configuration

Manages command-line interface settings and profiles.

```python
config.get("cli_configuration")
# Returns:
{
    "profiles": {
        "default": {
            "output_format": "json",
            "verbosity": "info",
            "color_output": true,
            "progress_bars": true,
            "auto_save": true,
            "confirm_actions": true
        }
    },
    "default_profile": "default",
    "aliases": {
        "ll": "list --long",
        "gs": "git status"
    },
    "history_file": "~/.intellicrack_history",
    "max_history": 1000,
    "autocomplete": true,
    "show_hints": true
}

# Set CLI preferences
config.set("cli_configuration.profiles.verbose", {
    "verbosity": "debug",
    "color_output": false
})
```

#### VM Framework Configuration

Controls virtual machine and emulation settings.

```python
config.get("vm_framework")
# Returns:
{
    "qemu_defaults": {
        "memory_mb": 2048,
        "cpu_cores": 2,
        "enable_kvm": true,
        "graphics_enabled": false,
        "network_enabled": true,
        "timeout": 300
    },
    "base_images": {
        "linux": ["ubuntu-20.04.qcow2"],
        "windows": ["win10.qcow2"]
    },
    "qiling_rootfs": {
        "linux": ["/opt/qiling/rootfs/x86_linux"],
        "windows": ["/opt/qiling/rootfs/x86_windows"]
    }
}
```

#### Security Configuration

Security settings and policies.

```python
config.get("security")
# Returns:
{
    "hashing": {
        "default_algorithm": "sha256",
        "salt_length": 32,
        "allow_md5_for_security": false
    },
    "subprocess": {
        "allow_shell_true": false,
        "shell_whitelist": ["bash", "sh", "cmd"],
        "max_process_timeout": 300
    },
    "serialization": {
        "default_format": "json",
        "restrict_pickle": true,
        "allowed_formats": ["json", "yaml", "xml"]
    },
    "input_validation": {
        "strict_mode": true,
        "max_file_size": 104857600,
        "allowed_extensions": [".py", ".js", ".json"]
    }
}
```

## API Reference

### Core Methods

#### `get_config() -> IntellicrackConfig`

Returns the singleton configuration instance.

```python
from intellicrack.core.config_manager import get_config
config = get_config()
```

#### `config.get(key: str, default: Any = None) -> Any`

Retrieves a configuration value.

```python
value = config.get("application.name")
value = config.get("missing.key", default="fallback")
```

#### `config.set(key: str, value: Any) -> None`

Sets a configuration value.

```python
config.set("ui_preferences.theme", "dark")
config.set("analysis_settings.timeout", 600)
```

#### `config.has(key: str) -> bool`

Checks if a configuration key exists.

```python
if config.has("llm_configuration.models.gpt4"):
    # Key exists
```

#### `config.delete(key: str) -> None`

Removes a configuration key.

```python
config.delete("deprecated.setting")
```

#### `config.reset() -> None`

Resets configuration to defaults.

```python
config.reset()  # Reset all
config.reset("qemu_testing")  # Reset section
```

### Migration Methods

#### `config.migrate_from_legacy() -> bool`

Automatically migrates from legacy configuration systems.

```python
success = config.migrate_from_legacy()
```

## Examples

### Complete Configuration Example

```python
from intellicrack.core.config_manager import get_config

# Initialize configuration
config = get_config()

# Configure application settings
config.set("application.debug_mode", True)
config.set("logging.level", "DEBUG")

# Configure QEMU testing
config.set("qemu_testing.default_preference", "ask")
config.set("qemu_testing.trusted_binaries", ["myapp.exe"])

# Configure LLM models
config.set("llm_configuration.models.local_llm", {
    "provider": "local",
    "model_path": "/models/llama2.bin",
    "temperature": 0.5
})

# Configure UI preferences
config.set("ui_preferences.theme", "dark")
config.set("ui_preferences.window_geometry", {
    "x": 100,
    "y": 100,
    "width": 1920,
    "height": 1080
})

# Save configuration (automatic on set, but can force save)
config._save_config()
```

### Reading Complex Configurations

```python
# Get all QEMU settings
qemu_settings = config.get("qemu_testing")
print(f"QEMU preference: {qemu_settings['default_preference']}")

# Get specific LLM model configuration
if config.has("llm_configuration.models.gpt4"):
    gpt4_config = config.get("llm_configuration.models.gpt4")
    print(f"GPT-4 temperature: {gpt4_config['temperature']}")

# Iterate through CLI profiles
cli_profiles = config.get("cli_configuration.profiles", {})
for profile_name, profile_settings in cli_profiles.items():
    print(f"Profile {profile_name}: verbosity={profile_settings.get('verbosity')}")
```

### Thread-Safe Configuration Access

```python
import threading

def worker(thread_id):
    config = get_config()  # Safe singleton access

    # Thread-safe read
    value = config.get(f"thread_data.{thread_id}")

    # Thread-safe write
    config.set(f"thread_data.{thread_id}", {
        "status": "running",
        "timestamp": datetime.now().isoformat()
    })

# Create multiple threads
threads = []
for i in range(10):
    t = threading.Thread(target=worker, args=(i,))
    threads.append(t)
    t.start()

for t in threads:
    t.join()
```

## Migration from Legacy Systems

The configuration system automatically migrates from:

1. **QSettings** (PyQt-based configurations)
2. **LLM Config Manager** (separate LLM configurations)
3. **CLI Configuration** (command-line profiles)
4. **INI Files** (legacy settings.ini)
5. **Environment Files** (.env files)

Migration happens automatically on first run, with full backup of original configurations.

## Performance Considerations

- **Caching**: Frequently accessed values are cached in memory
- **Lazy Loading**: Configuration sections load on-demand
- **Batch Operations**: Use batch sets for multiple updates
- **File I/O**: Saves are debounced to reduce disk writes

## Troubleshooting

### Configuration Not Loading

```python
# Check configuration file location
config = get_config()
print(f"Config path: {config._config_file}")

# Verify file exists and is valid JSON
import json
with open(config._config_file, 'r') as f:
    data = json.load(f)  # Will raise error if invalid
```

### Reset to Defaults

```python
# Full reset
config.reset()

# Partial reset
config.reset("qemu_testing")
config.reset("ui_preferences")
```

### Manual Backup

```python
from intellicrack.core.config_migration_handler import MigrationBackup

backup = MigrationBackup(backup_dir="./backups")
backup_path = backup.create_backup(
    config._config_file,
    backup_type="manual"
)
print(f"Backup created: {backup_path}")
```

## Best Practices

1. **Always use dot notation** for nested access
2. **Check existence** before accessing optional keys
3. **Use defaults** for optional configuration values
4. **Batch updates** when changing multiple values
5. **Don't access _config directly** - use get/set methods
6. **Let auto-save handle persistence** - avoid manual saves

## Version History

- **v3.0**: Initial consolidated configuration system
- **v3.1**: Added thread safety and performance optimizations
- **v4.0**: Full migration from all legacy systems complete

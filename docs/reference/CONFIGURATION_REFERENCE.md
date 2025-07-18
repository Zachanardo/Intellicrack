# Configuration Reference

## Overview

This document provides a complete reference for all Intellicrack configuration options, including config files, environment variables, and runtime settings.

## Configuration Files

### Main Configuration File

**Location**: `~/.intellicrack/config.json` (Linux/Mac) or `%APPDATA%\intellicrack\config.json` (Windows)

```json
{
  "general": {
    "theme": "dark",
    "language": "en",
    "auto_update": true,
    "telemetry": false,
    "first_run_complete": false
  },
  "paths": {
    "workspace": "~/intellicrack_workspace",
    "temp": "/tmp/intellicrack",
    "cache": "~/.intellicrack/cache",
    "plugins": "~/.intellicrack/plugins"
  },
  "analysis": {
    "default_timeout": 300,
    "max_file_size": 1073741824,
    "thread_count": 8,
    "enable_gpu": true
  },
  "ai": {
    "default_provider": "openai",
    "model_cache_size": 10737418240,
    "enable_local_models": true,
    "api_timeout": 60
  },
  "network": {
    "proxy": "",
    "ssl_verify": true,
    "timeout": 30
  },
  "security": {
    "sandbox_enabled": true,
    "encrypt_api_keys": true,
    "secure_mode": false
  }
}
```

### API Keys Configuration

**Location**: `~/.intellicrack/.env` (encrypted)

```bash
# AI Provider API Keys
OPENAI_API_KEY=sk-...
ANTHROPIC_API_KEY=sk-ant-...
GOOGLE_API_KEY=AIza...
GROQ_API_KEY=gsk_...
REPLICATE_API_KEY=r8_...
TOGETHER_API_KEY=...
PERPLEXITY_API_KEY=pplx-...
COHERE_API_KEY=...
HUGGINGFACE_API_KEY=hf_...
ANYSCALE_API_KEY=...
DEEPINFRA_API_KEY=...
OPENROUTER_API_KEY=...

# Azure Configuration
AZURE_OPENAI_ENDPOINT=https://...
AZURE_OPENAI_API_KEY=...
AZURE_OPENAI_DEPLOYMENT=...

# AWS Configuration
AWS_ACCESS_KEY_ID=...
AWS_SECRET_ACCESS_KEY=...
AWS_REGION=us-east-1

# Tool Paths
GHIDRA_PATH=/opt/ghidra
RADARE2_PATH=/usr/bin/r2
FRIDA_PATH=/usr/local/bin/frida
```

## Environment Variables

### Core Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `INTELLICRACK_HOME` | Installation directory | Auto-detected |
| `INTELLICRACK_WORKSPACE` | Default workspace | `~/intellicrack_workspace` |
| `INTELLICRACK_CONFIG` | Config file path | `~/.intellicrack/config.json` |
| `INTELLICRACK_LOG_LEVEL` | Logging level | `INFO` |
| `INTELLICRACK_DEBUG` | Enable debug mode | `0` |

### GPU Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `INTELLICRACK_GPU_BACKEND` | GPU backend (cuda/rocm/directml) | Auto-detected |
| `CUDA_VISIBLE_DEVICES` | CUDA device selection | All devices |
| `ROCM_VISIBLE_DEVICES` | ROCm device selection | All devices |
| `INTELLICRACK_GPU_MEMORY_FRACTION` | GPU memory limit | `0.9` |
| `INTELLICRACK_ENABLE_GPU` | Force enable/disable GPU | Auto-detected |

### Network Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `HTTP_PROXY` | HTTP proxy URL | None |
| `HTTPS_PROXY` | HTTPS proxy URL | None |
| `NO_PROXY` | Proxy exceptions | `localhost,127.0.0.1` |
| `INTELLICRACK_SSL_VERIFY` | SSL verification | `true` |

## Runtime Configuration

### Command Line Arguments

```bash
intellicrack [options] [file]

Options:
  --config FILE       Use custom config file
  --workspace DIR     Set workspace directory
  --theme THEME      Set UI theme (dark/light)
  --gpu-backend TYPE  Force GPU backend
  --no-gpu           Disable GPU acceleration
  --debug            Enable debug mode
  --safe-mode        Start in safe mode
  --reset-config     Reset to default config
```

### Config Manager API

```python
from intellicrack.core.config_manager import ConfigManager

config = ConfigManager()

# Get configuration values
theme = config.get("general.theme")
gpu_enabled = config.get("analysis.enable_gpu")

# Set configuration values
config.set("general.theme", "light")
config.set("ai.default_provider", "anthropic")

# Save configuration
config.save()
```

## Feature-Specific Configuration

### Analysis Engine

```json
{
  "analysis": {
    "engines": {
      "static": {
        "enabled": true,
        "timeout": 300,
        "max_memory": 4294967296
      },
      "dynamic": {
        "enabled": true,
        "sandbox": "qemu",
        "timeout": 600
      },
      "symbolic": {
        "enabled": false,
        "max_states": 1000,
        "timeout": 1800
      }
    },
    "file_types": {
      "pe": true,
      "elf": true,
      "mach-o": true,
      "apk": true,
      "firmware": true
    }
  }
}
```

### AI Model Configuration

```json
{
  "ai": {
    "providers": {
      "openai": {
        "enabled": true,
        "models": ["gpt-4", "gpt-3.5-turbo"],
        "temperature": 0.7,
        "max_tokens": 4000
      },
      "local": {
        "enabled": true,
        "model_path": "~/.intellicrack/models",
        "quantization": "int8",
        "context_size": 4096
      }
    },
    "features": {
      "script_generation": true,
      "code_analysis": true,
      "vulnerability_detection": true,
      "auto_suggestions": true
    }
  }
}
```

### Plugin System

```json
{
  "plugins": {
    "enabled": true,
    "auto_load": true,
    "directories": [
      "~/.intellicrack/plugins",
      "./plugins"
    ],
    "blacklist": [],
    "settings": {
      "plugin_name": {
        "option1": "value1",
        "option2": "value2"
      }
    }
  }
}
```

### Security Settings

```json
{
  "security": {
    "sandbox": {
      "enabled": true,
      "backend": "firejail",
      "network": false,
      "filesystem": "readonly"
    },
    "encryption": {
      "api_keys": true,
      "workspace": false,
      "algorithm": "AES-256-GCM"
    },
    "limits": {
      "max_file_size": 1073741824,
      "max_memory": 8589934592,
      "max_cpu_time": 3600
    }
  }
}
```

## Performance Tuning

### Memory Configuration

```json
{
  "performance": {
    "memory": {
      "heap_size": 4294967296,
      "cache_size": 1073741824,
      "buffer_size": 67108864
    },
    "threading": {
      "worker_threads": 8,
      "io_threads": 4,
      "max_concurrent_tasks": 16
    }
  }
}
```

### Caching Configuration

```json
{
  "cache": {
    "analysis_cache": {
      "enabled": true,
      "size": 5368709120,
      "ttl": 86400,
      "location": "~/.intellicrack/cache/analysis"
    },
    "model_cache": {
      "enabled": true,
      "size": 10737418240,
      "location": "~/.intellicrack/cache/models"
    }
  }
}
```

## Tool Integration

### Ghidra Configuration

```json
{
  "tools": {
    "ghidra": {
      "path": "/opt/ghidra",
      "headless": true,
      "max_memory": "4G",
      "timeout": 600,
      "scripts": [
        "~/.intellicrack/ghidra_scripts"
      ]
    }
  }
}
```

### Radare2 Configuration

```json
{
  "tools": {
    "radare2": {
      "path": "/usr/bin/r2",
      "plugins": [
        "~/.intellicrack/r2_plugins"
      ],
      "options": {
        "anal.depth": 256,
        "anal.timeout": 300,
        "asm.syntax": "intel"
      }
    }
  }
}
```

### Frida Configuration

```json
{
  "tools": {
    "frida": {
      "path": "/usr/local/bin/frida",
      "device": "local",
      "timeout": 30,
      "scripts": [
        "~/.intellicrack/frida_scripts"
      ]
    }
  }
}
```

## UI Configuration

### Theme Settings

```json
{
  "ui": {
    "theme": {
      "name": "dark",
      "custom_css": "~/.intellicrack/custom.css",
      "font_family": "Consolas",
      "font_size": 12
    },
    "layout": {
      "show_toolbar": true,
      "show_statusbar": true,
      "sidebar_position": "left",
      "default_tab": "dashboard"
    }
  }
}
```

### Window Settings

```json
{
  "ui": {
    "window": {
      "width": 1600,
      "height": 900,
      "maximized": false,
      "position": {
        "x": 100,
        "y": 100
      }
    }
  }
}
```

## Logging Configuration

```json
{
  "logging": {
    "level": "INFO",
    "file": "~/.intellicrack/intellicrack.log",
    "max_size": 10485760,
    "backup_count": 5,
    "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    "modules": {
      "intellicrack.core": "DEBUG",
      "intellicrack.ai": "INFO",
      "intellicrack.ui": "WARNING"
    }
  }
}
```

## Migration and Backup

### Backup Configuration

```bash
# Backup all configuration
intellicrack config backup --output backup.tar.gz

# Restore configuration
intellicrack config restore --input backup.tar.gz
```

### Export/Import Settings

```python
# Export configuration
config = ConfigManager()
config.export_config("settings_export.json")

# Import configuration
config.import_config("settings_export.json", merge=True)
```

## Troubleshooting

### Reset Configuration

```bash
# Reset to defaults
intellicrack --reset-config

# Reset specific section
intellicrack config reset --section ai
```

### Validate Configuration

```python
from intellicrack.core.config_manager import ConfigValidator

validator = ConfigValidator()
errors = validator.validate_config("config.json")

if errors:
    for error in errors:
        print(f"Error: {error}")
```

### Common Issues

1. **Missing API Keys**
   - Check `.env` file exists and is readable
   - Verify encryption key in keyring

2. **Invalid JSON**
   - Use JSON validator
   - Check for trailing commas

3. **Permission Errors**
   - Check file ownership
   - Verify directory permissions

4. **Path Issues**
   - Use absolute paths
   - Expand ~ to home directory
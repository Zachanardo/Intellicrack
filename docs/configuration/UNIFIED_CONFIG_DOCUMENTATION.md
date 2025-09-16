# Intellicrack Unified Configuration Documentation

## Overview

This document provides comprehensive documentation for Intellicrack's unified configuration system. The unified configuration consolidates all application settings into a single `config.json` file located at `C:/Intellicrack/config/config.json`.

## Configuration Structure

### Core Properties

#### `version` (string, required)

**Purpose:** Tracks the configuration schema version for migration compatibility.
**Format:** Semantic versioning (e.g., "3.0.0")
**Example:** `"version": "3.0.0"`

#### `initialized` (boolean)

**Purpose:** Indicates whether the configuration has been properly initialized.
**Default:** `false`
**Example:** `"initialized": true`

#### `emergency_mode` (boolean)

**Purpose:** Emergency fallback flag for critical system recovery.
**Default:** `false`
**Example:** `"emergency_mode": false`

---

## Configuration Sections

### 1. Directories Section

**Purpose:** Centralizes all directory path configurations for Intellicrack operations.

**Key Properties:**

- `cache`: Cache directory for temporary files and data
- `config`: Configuration files directory
- `logs`: Log files storage location
- `output`: Analysis results and output files
- `temp`: Temporary processing files
- `plugins`: Plugin modules directory
- `downloads`: Model and update downloads
- `models`: AI/ML models storage
- `backup`: Backup files location
- `workspace`: User workspace directory

**Migration Notes:**

- Merges `log_dir`, `output_dir`, `temp_dir` from legacy configs
- Standardizes path format across Windows/Linux
- Adds new structured directories for better organization

**Example:**

```json
{
  "directories": {
    "cache": "C:/Users/zachf/AppData/Roaming/Intellicrack/cache",
    "config": "C:/Intellicrack/config",
    "logs": "C:/Users/zachf/AppData/Roaming/Intellicrack/logs",
    "output": "C:/Users/zachf/AppData/Roaming/Intellicrack/output",
    "temp": "C:/Users/zachf/AppData/Local/Temp",
    "plugins": "C:/Intellicrack/plugins",
    "downloads": "C:/Users/zachf/AppData/Roaming/Intellicrack/downloads",
    "models": "C:/Users/zachf/AppData/Roaming/Intellicrack/models",
    "backup": "C:/Users/zachf/AppData/Roaming/Intellicrack/backup",
    "workspace": "C:/Users/zachf/AppData/Roaming/Intellicrack/workspace"
  }
}
```

### 2. Tools Section

**Purpose:** Configures reverse engineering tool integrations and paths.

**Key Properties:**

- `ghidra`: Ghidra reverse engineering tool configuration
- `radare2`: Radare2 binary analysis framework
- `frida`: Frida dynamic instrumentation toolkit
- `qemu`: QEMU virtualization platform
- `python3`: Python 3 interpreter configuration

**Migration Notes:**

- Consolidates scattered tool path configurations
- Adds advanced tool-specific settings (timeouts, heap sizes)

- Supports auto-discovery and validation

**Example:**

```json
{
  "tools": {
    "ghidra": {
      "path": "C:/Program Files/Ghidra/ghidraRun.bat",
      "headless_path": "C:/Program Files/Ghidra/support/analyzeHeadless.bat",
      "project_dir": "C:/Users/zachf/AppData/Roaming/Intellicrack/ghidra_projects",
      "heap_size": "4g",
      "timeout": 600,
      "auto_analyze": true
    },
    "radare2": {
      "path": "C:/ProgramData/chocolatey/bin/r2.EXE",
      "project_dir": "C:/Users/zachf/AppData/Roaming/Intellicrack/r2_projects",
      "timeout": 300,
      "auto_analyze": true
    }
  }
}
```

### 3. Analysis Section

**Purpose:** Controls binary analysis behavior, performance, and feature enablement.

**Key Properties:**

- `default_timeout`: Global analysis timeout
- `max_file_size`: Maximum analyzable file size
- `enable_deep_analysis`: Comprehensive analysis features
- `enable_symbolic_execution`: Symbolic execution analysis
- `enable_dynamic_analysis`: Runtime analysis capabilities
- `enable_network_analysis`: Network traffic monitoring
- `detect_protections`: Software protection detection
- `parallel_threads`: Concurrent analysis threads
- `cache_results`: Result caching system
- `enable_ml_analysis`: Machine learning features
- `enable_ai_features`: AI-powered analysis

**Migration Notes:**

- Merges analysis settings from multiple legacy configs

- Adds new ML/AI configuration options
- Standardizes timeout and performance settings

**Example:**

```json
{
  "analysis": {
    "default_timeout": 300,
    "max_file_size": 104857600,
    "enable_deep_analysis": true,
    "enable_symbolic_execution": false,
    "enable_dynamic_analysis": true,
    "enable_network_analysis": true,
    "detect_protections": true,
    "auto_detect_format": true,
    "parallel_threads": 4,
    "cache_results": true,
    "cache_ttl": 3600,
    "enable_ml_analysis": true,
    "enable_ai_features": true,
    "save_intermediate_results": true
  }
}
```

### 4. Patching Section

**Purpose:** Configures binary patching operations and safety measures.

**Key Properties:**

- `enable_memory_patching`: In-memory patching capability
- `backup_before_patch`: Automatic backup creation
- `verify_patches`: Patch integrity verification
- `max_patch_attempts`: Retry limit for failed patches
- `patch_timeout`: Individual patch operation timeout
- `generate_launcher`: Create launcher for patched binaries
- `launcher_template`: Template type for launchers
- `max_patch_size`: Size limit for patches
- `patch_format`: Patch file format

**Migration Notes:**

- Consolidates patching settings from legacy configs
- Adds safety and verification features
- Supports multiple patch formats

**Example:**

```json
{
  "patching": {
    "enable_memory_patching": true,
    "backup_before_patch": true,
    "backup_original": true,
    "verify_patches": true,
    "max_patch_attempts": 3,
    "patch_timeout": 60,
    "generate_launcher": true,
    "launcher_template": "default",
    "max_patch_size": "10MB",
    "patch_format": "binary"
  }
}
```

### 5. Network Section

**Purpose:** Manages network analysis, proxy configuration, and SSL interception.

**Key Properties:**

- `enable_ssl_interception`: SSL/TLS traffic interception
- `proxy_enabled`: Proxy server activation
- `proxy_port`: Proxy listening port
- `proxy_host`: Proxy server hostname
- `capture_interface`: Network interface for capture
- `capture_filter`: Traffic filtering rules
- `save_captures`: Persistent capture storage
- `max_capture_size`: Capture file size limit
- `ssl_verify`: SSL certificate verification

- `timeout`: Network operation timeout

**Migration Notes:**

- Merges network settings from multiple sources
- Adds SSL interception capabilities
- Standardizes proxy configuration

**Example:**

```json
{
  "network": {
    "enable_ssl_interception": true,
    "proxy_enabled": false,
    "proxy_port": 8080,
    "proxy_host": "",
    "capture_interface": "any",
    "capture_filter": "",
    "save_captures": true,
    "max_capture_size": 52428800,
    "ssl_verify": true,
    "timeout": 30
  }
}
```

### 6. UI Section

**Purpose:** Controls user interface appearance, behavior, and layout.

**Key Properties:**

- `theme`: UI color theme selection
- `window_size`: Default window dimensions
- `show_splash`: Splash screen display
- `auto_save_layout`: Automatic layout preservation
- `confirm_exit`: Exit confirmation dialog
- `show_tooltips`: Tooltip display system
- `font_size`: UI font size
- `hex_columns`: Hex viewer column count
- `animation_speed`: UI animation timing
- `toolbar_style`: Toolbar appearance
- `status_bar`: Status bar visibility

- `recent_files_count`: Recent files limit

**Migration Notes:**

- Consolidates UI settings from legacy configs
- Adds new theming and customization options
- Standardizes font and layout configurations

**Example:**

```json
{
  "ui": {
    "theme": "dark",
    "window_size": [1200, 800],
    "show_splash": true,
    "auto_save_layout": true,
    "confirm_exit": true,
    "show_tooltips": true,
    "font_size": 10,
    "hex_columns": 16,
    "animation_speed": "normal",
    "toolbar_style": "both",
    "status_bar": true,
    "recent_files_count": 10
  }
}
```

### 7. Logging Section

**Purpose:** Configures application logging behavior, levels, and output destinations.

**Key Properties:**

- `level`: Global logging level
- `enable_file_logging`: File-based logging
- `enable_console_logging`: Console output
- `max_log_size`: Log file size limit
- `log_rotation`: Number of rotated log files
- `verbose_logging`: Detailed logging mode
- `enable_comprehensive_logging`: Full system logging
- `log_format`: Log message format

- `timestamp_format`: Timestamp display format
- `rotate_on_startup`: Startup rotation behavior

**Migration Notes:**

- Merges logging configurations from all sources
- Adds new formatting and rotation options
- Standardizes log level management

**Example:**

```json
{
  "logging": {
    "level": "INFO",
    "enable_file_logging": true,
    "enable_console_logging": true,
    "max_log_size": 10485760,
    "log_rotation": 5,
    "verbose_logging": false,
    "enable_comprehensive_logging": false,
    "log_format": "standard",
    "timestamp_format": "%Y-%m-%d %H:%M:%S",
    "rotate_on_startup": false
  }
}
```

### 8. Security Section

**Purpose:** Manages security policies, validation, and protection mechanisms.

**Key Properties:**

- `verify_signatures`: Digital signature verification
- `sandbox_plugins`: Plugin execution sandboxing
- `sandbox_analysis`: Analysis operation sandboxing
- `scan_downloads`: Downloaded file scanning
- `block_suspicious`: Suspicious activity blocking
- `quarantine_malware`: Malware quarantine system
- `allow_network_access`: Network access during analysis
- `log_sensitive_data`: Sensitive data logging policy
- `encrypt_config`: Configuration encryption
- `hashing`: Hash algorithm configuration

- `subprocess`: Subprocess security policies
- `serialization`: Data serialization security
- `input_validation`: Input validation rules

**Migration Notes:**

- Consolidates security settings from legacy configs
- Adds comprehensive security policy framework
- Implements modern security best practices

**Example:**

```json
{
  "security": {
    "verify_signatures": true,
    "sandbox_plugins": true,
    "sandbox_analysis": true,
    "scan_downloads": true,
    "block_suspicious": true,
    "quarantine_malware": true,
    "allow_network_access": false,
    "log_sensitive_data": false,
    "encrypt_config": false,
    "hashing": {
      "default_algorithm": "sha256",
      "allow_md5_for_security": false
    },
    "subprocess": {
      "allow_shell_true": false,
      "shell_whitelist": []
    },
    "serialization": {
      "default_format": "json",
      "restrict_pickle": true
    },
    "input_validation": {
      "strict_mode": true,
      "max_file_size": false,
      "allowed_extensions": false
    }
  }
}
```

### 9. Performance Section

**Purpose:** Optimizes application performance, memory usage, and resource allocation.

**Key Properties:**

- `max_memory_usage`: Memory usage limit in MB
- `enable_gpu_acceleration`: GPU computation support
- `cache_size`: General cache size in MB

- `chunk_size`: Data processing chunk size
- `enable_multiprocessing`: Parallel processing
- `thread_pool_size`: Thread pool configuration
- `io_buffer_size`: I/O buffer size
- `enable_profiling`: Performance profiling

**Migration Notes:**

- Merges performance settings from legacy configs

- Adds new optimization features
- Standardizes resource allocation

**Example:**

```json
{
  "performance": {
    "max_memory_usage": 2048,
    "enable_gpu_acceleration": true,
    "cache_size": 100,
    "chunk_size": 4096,
    "enable_multiprocessing": true,
    "thread_pool_size": 4,
    "io_buffer_size": 65536,
    "enable_profiling": false
  }
}
```

### 10. Runtime Section

**Purpose:** Controls runtime monitoring, interception, and process management.

**Key Properties:**

- `max_runtime_monitoring`: Monitoring duration limit
- `runtime_interception`: Runtime interception system
- `hook_delay`: Hook insertion delay

- `monitor_child_processes`: Child process monitoring
- `enable_memory_monitoring`: Memory usage tracking
- `enable_api_monitoring`: API call monitoring
- `snapshot_interval`: Monitoring snapshot frequency

**Migration Notes:**

- Consolidates runtime settings from legacy configs

- Adds comprehensive monitoring capabilities
- Supports advanced hooking and interception

**Example:**

```json
{
  "runtime": {
    "max_runtime_monitoring": 30000,
    "runtime_interception": true,
    "hook_delay": 100,
    "monitor_child_processes": true,
    "enable_memory_monitoring": true,
    "enable_api_monitoring": true,
    "snapshot_interval": 1000
  }
}
```

### 11. Plugins Section

**Purpose:** Manages plugin system configuration, loading, and security.

**Key Properties:**

- `default_plugins`: Automatically loaded plugins

- `auto_load`: Automatic plugin loading
- `check_updates`: Plugin update checking
- `allow_third_party`: Third-party plugin support
- `plugin_timeout`: Plugin execution timeout
- `enable_plugin_api`: Plugin API access
- `plugin_isolation`: Plugin isolation level

**Migration Notes:**

- Merges plugin settings from legacy configs
- Adds security and isolation features
- Supports plugin lifecycle management

**Example:**

```json
{
  "plugins": {
    "default_plugins": ["HWID Spoofer", "Anti-Debugger"],
    "auto_load": true,
    "check_updates": true,
    "allow_third_party": true,
    "plugin_timeout": 60,
    "enable_plugin_api": true,
    "plugin_isolation": "process"
  }
}
```

### 12. General Section

**Purpose:** Contains general application settings and user preferences.

**Key Properties:**

- `first_run_completed`: First-run setup status
- `auto_backup`: Automatic backup system
- `auto_save_results`: Automatic result saving
- `check_for_updates`: Update checking
- `send_analytics`: Anonymous analytics
- `language`: Application language
- `startup_checks`: Startup integrity checks
- `crash_reporting`: Crash reporting system

**Migration Notes:**

- Merges general settings from all legacy configs
- Adds new system and user preference options
- Standardizes application behavior settings

**Example:**

```json
{
  "general": {
    "first_run_completed": true,
    "auto_backup": true,
    "auto_save_results": true,
    "check_for_updates": true,
    "send_analytics": false,
    "language": "en",
    "startup_checks": true,
    "crash_reporting": true
  }
}
```

### 13. AI Section

**Purpose:** Configures AI features, model selection, and API integration.

**Key Properties:**

- `enabled`: AI features activation
- `model_provider`: AI service provider
- `context_size`: AI context window size

- `temperature`: AI creativity setting
- `top_p`: AI nucleus sampling
- `max_tokens`: Maximum response tokens
- `selected_model_path`: Local model path
- `enable_ai_suggestions`: AI-powered suggestions
- `cache_responses`: Response caching
- `background_loading`: Background model loading
- `retry_attempts`: API retry configuration

**Migration Notes:**

- Consolidates AI settings from legacy configs
- Adds new provider and model management
- Supports multiple AI service integrations

**Example:**

```json
{
  "ai": {
    "enabled": true,
    "model_provider": "auto",
    "context_size": 8192,
    "temperature": 0.7,
    "top_p": 0.95,
    "max_tokens": 2048,
    "selected_model_path": null,
    "enable_ai_suggestions": true,
    "cache_responses": true,
    "background_loading": true,
    "retry_attempts": 3
  }
}
```

### 14. ML Section

**Purpose:** Manages machine learning features and model configuration.

**Key Properties:**

- `enable_ml_features`: ML features activation
- `model_cache_size`: ML model cache size
- `prediction_threshold`: Confidence threshold
- `auto_load_models`: Automatic model loading

- `model_update_interval`: Update check frequency
- `enable_online_training`: Online learning
- `gpu_acceleration`: GPU support for ML

**Migration Notes:**

- Merges ML settings from legacy configs
- Adds new learning and caching features
- Supports GPU acceleration for ML workloads

**Example:**

```json
{
  "ml": {
    "enable_ml_features": true,
    "model_cache_size": 100,
    "prediction_threshold": 0.7,
    "auto_load_models": true,
    "model_update_interval": 86400,
    "enable_online_training": false,
    "gpu_acceleration": true
  }
}
```

### 15. Preferences Section

**Purpose:** User-specific preferences and Qt settings migration.

**Key Properties:**

- `log_level`: Preferred logging level
- `auto_save_interval`: Auto-save frequency

- `backup_count`: Number of backups to maintain
- `workspace_layout`: Preferred workspace layout
- `hotkeys`: Custom keyboard shortcuts

**Migration Notes:**

- Migrates Qt application settings
- Consolidates user preference data
- Supports custom hotkey mappings

**Example:**

```json
{
  "preferences": {
    "log_level": "WARNING",
    "auto_save_interval": 300,
    "backup_count": 5,
    "workspace_layout": "default",
    "hotkeys": {
      "new_analysis": "Ctrl+N",
      "save_project": "Ctrl+S",
      "export_results": "Ctrl+E"
    }
  }
}
```

### 16. Fonts Section

**Purpose:** Font configuration for UI and code display.

**Key Properties:**

- `monospace_fonts`: Code and hex view fonts
- `ui_fonts`: General UI fonts
- `font_sizes`: Size configurations for different contexts
- `available_fonts`: System-available font files

**Migration Notes:**

- Migrates font settings from font_config.json
- Adds size and fallback management
- Supports Windows 11 font selection

**Example:**

```json
{
  "fonts": {
    "monospace_fonts": {
      "primary": ["JetBrains Mono", "JetBrainsMono-Regular"],
      "fallback": ["Consolas", "Source Code Pro", "Courier New", "monospace"]
    },
    "ui_fonts": {
      "primary": ["Segoe UI", "Roboto", "Arial"],
      "fallback": ["Helvetica Neue", "Helvetica", "sans-serif"]
    },
    "font_sizes": {
      "ui_default": 10,
      "ui_small": 9,
      "ui_large": 12,
      "code_default": 10,
      "code_small": 9,
      "code_large": 11,
      "hex_view": 11
    },
    "available_fonts": ["JetBrainsMono-Regular.ttf", "JetBrainsMono-Bold.ttf"]
  }
}
```

### 17. LLM Configs Section

**Purpose:** Large Language Model provider configurations and profiles.

**Key Properties:**

- `profiles`: Named LLM configuration profiles
- `model_repositories`: Provider-specific configurations
- `api_cache`: API response caching settings

**Migration Notes:**

- Consolidates LLM provider settings from model_repositories
- Adds profile management system
- Supports multiple API providers

**Example:**

```json
{
  "llm_configs": {
    "profiles": {
      "default_openai": {
        "name": "OpenAI GPT-4",
        "provider": "openai",
        "model": "gpt-4",
        "temperature": 0.7,
        "max_tokens": 2048,
        "enabled": true
      }
    },
    "model_repositories": {
      "local": {
        "type": "local",
        "enabled": true,
        "models_directory": "C:/Users/zachf/AppData/Roaming/Intellicrack/models"
      },
      "openai": {
        "type": "openai",
        "enabled": false,
        "api_key": "",
        "endpoint": "https://api.openai.com/v1",
        "timeout": 60,
        "proxy": "",
        "rate_limit": {
          "requests_per_minute": 60,
          "requests_per_day": 1000
        }
      }
    },
    "api_cache": {
      "enabled": true,
      "ttl": 3600,
      "max_size_mb": 100
    }
  }
}
```

### 18. CLI Section

**Purpose:** Command-line interface specific configuration and profiles.

**Key Properties:**

- `profiles`: User skill-level based CLI profiles
- `default_profile`: Default profile selection
- `output`: Output formatting configuration
- `shell_integration`: Shell completion and history
- `theme`: CLI color and style themes
- `plugins`: CLI-specific plugin system
- `security`: CLI security settings
- `performance`: CLI performance optimization

**Migration Notes:**

- Migrates CLI settings from ~/.intellicrack/config.json
- Adds comprehensive profile system
- Supports rich CLI customization

**Example:**

```json
{
  "cli": {
    "profiles": {
      "beginner": {
        "description": "Beginner-friendly profile with detailed help",
        "help_level": "detailed",
        "confirmation_prompts": true,
        "default_options": {
          "verbose": true,
          "safe_mode": true
        },
        "available_commands": ["analyze", "help", "version"]
      },
      "expert": {
        "description": "Expert profile with minimal prompts",
        "help_level": "minimal",
        "confirmation_prompts": false,
        "default_options": {
          "verbose": false,
          "safe_mode": false
        },
        "available_commands": ["analyze", "patch", "script", "advanced"]
      }
    },
    "default_profile": "beginner",
    "output": {
      "format": "human",
      "verbosity": 1,
      "colors": true,
      "paging": true
    },
    "shell_integration": {
      "completion": true,
      "history": true,
      "aliases": {
        "ic": "intellicrack",
        "analyze": "intellicrack analyze",
        "patch": "intellicrack patch"
      }
    },
    "theme": {
      "colors": {
        "primary": "#0066cc",
        "success": "#00cc66",
        "warning": "#ff9900",
        "error": "#cc0000"
      },
      "style": "standard"
    },
    "plugins": {
      "enabled": [],
      "auto_discovery": true
    },
    "security": {
      "confirm_destructive": true,
      "command_logging": true
    },
    "performance": {
      "parallel_jobs": 4,
      "timeout": 300
    }
  }
}
```

---

## Configuration Migration Strategy

### Phase 1: Legacy Config Detection
1. Scan for existing configuration files
2. Identify configuration format and version
3. Create backup of existing configurations

### Phase 2: Data Migration
1. Parse legacy configuration data
2. Map to unified schema structure
3. Validate migrated data against schema
4. Apply data transformations and defaults

### Phase 3: Validation and Cleanup
1. Verify configuration completeness
2. Test configuration loading
3. Archive legacy configuration files
4. Update application to use unified config

### Configuration Validation

The unified configuration system includes comprehensive JSON schema validation:

- **Type Checking:** Ensures all values match expected types
- **Range Validation:** Validates numeric ranges and constraints
- **Pattern Matching:** Validates strings against regex patterns
- **Required Fields:** Enforces mandatory configuration properties
- **Additional Properties:** Controls schema extensibility

### Best Practices

1. **Backup Before Migration:** Always backup existing configurations
2. **Gradual Migration:** Migrate configurations in phases
3. **Validation Testing:** Test configurations after migration
4. **Documentation Updates:** Update user documentation after changes
5. **Version Tracking:** Maintain configuration version for compatibility

### Troubleshooting

**Common Issues:**

- **Invalid Paths:** Check directory separators and permissions
- **Missing Tools:** Verify tool installations and paths
- **Permission Errors:** Ensure write access to configuration directory
- **Schema Validation:** Check configuration against JSON schema
- **Legacy Conflicts:** Remove or rename legacy configuration files

**Recovery Procedures:**

- Use emergency_mode flag for critical recovery
- Restore from automatic backups
- Reset to default configuration
- Manual configuration repair using schema documentation

# Configuration Development Guidelines

## Task 20.2.3: Development Guidelines for Configuration Usage

This document provides comprehensive guidelines for developers working with the Intellicrack configuration system. Follow these practices to ensure consistent, maintainable, and performant configuration usage across the codebase.

## Table of Contents

1. [Core Principles](#core-principles)
2. [Getting Started](#getting-started)
3. [Best Practices](#best-practices)
4. [Code Patterns](#code-patterns)
5. [Anti-Patterns to Avoid](#anti-patterns-to-avoid)
6. [Testing Guidelines](#testing-guidelines)
7. [Performance Optimization](#performance-optimization)
8. [Security Considerations](#security-considerations)

## Core Principles

### 1. Single Source of Truth

**Always use the central configuration system:**

```python
# ✅ CORRECT
from intellicrack.core.config_manager import get_config
config = get_config()
theme = config.get("ui_preferences.theme")

# ❌ WRONG - Direct file access
import json
with open("config.json", 'r') as f:
    config = json.load(f)

# ❌ WRONG - Using legacy systems
from PyQt6.QtCore import QSettings
settings = QSettings()
```

### 2. Singleton Pattern

**Use the singleton instance:**

```python
# ✅ CORRECT - Get singleton
config = get_config()

# ❌ WRONG - Creating new instance
config = IntellicrackConfig()  # Don't do this
```

### 3. Thread Safety

**The configuration system is thread-safe by default:**

```python
# ✅ Safe for concurrent access
def worker_thread():
    config = get_config()
    value = config.get("some.key")  # Thread-safe read
    config.set("other.key", value)  # Thread-safe write
```

## Getting Started

### Basic Setup in New Modules

```python
"""
Module: intellicrack/new_feature/manager.py
Configuration-aware module template
"""

from intellicrack.core.config_manager import get_config
import logging

logger = logging.getLogger(__name__)


class FeatureManager:
    """Manages new feature with configuration support."""

    def __init__(self):
        """Initialize with configuration."""
        self.config = get_config()
        self._load_settings()

    def _load_settings(self):
        """Load feature-specific settings."""
        # Get with defaults
        self.enabled = self.config.get("new_feature.enabled", default=True)
        self.timeout = self.config.get("new_feature.timeout", default=30)
        self.options = self.config.get("new_feature.options", default={})

        logger.info(f"Feature initialized: enabled={self.enabled}")

    def update_setting(self, key: str, value: any):
        """Update a feature setting."""
        full_key = f"new_feature.{key}"
        self.config.set(full_key, value)

        # Reload settings if needed
        self._load_settings()
```

### Adding New Configuration Sections

When adding new features, extend the default configuration:

```python
# In intellicrack/core/config_manager.py - _get_default_config()

@staticmethod
def _get_default_config() -> dict:
    """Get default configuration with new section."""
    return {
        # ... existing sections ...

        "new_feature": {
            "enabled": True,
            "timeout": 30,
            "max_retries": 3,
            "options": {
                "auto_save": True,
                "verbose": False
            },
            "advanced": {
                "cache_size": 100,
                "parallel_workers": 4
            }
        }
    }
```

## Best Practices

### 1. Use Dot Notation for Nested Access

```python
# ✅ GOOD - Clear and concise
config.get("llm_configuration.models.gpt4.temperature")

# ❌ AVOID - Multiple calls
llm_config = config.get("llm_configuration")
models = llm_config.get("models")
gpt4 = models.get("gpt4")
temp = gpt4.get("temperature")
```

### 2. Always Provide Defaults

```python
# ✅ GOOD - Graceful fallback
timeout = config.get("analysis.timeout", default=300)
retries = config.get("network.max_retries", default=3)

# ❌ BAD - May raise KeyError
timeout = config.get("analysis.timeout")  # Could be None
```

### 3. Check Existence for Optional Keys

```python
# ✅ GOOD - Safe access
if config.has("experimental.new_feature"):
    feature_config = config.get("experimental.new_feature")
    # Use feature

# ❌ BAD - Assumes key exists
feature_config = config.get("experimental.new_feature")
if feature_config:  # Could be None vs not existing
    # Use feature
```

### 4. Batch Updates for Performance

```python
# ✅ GOOD - Single save operation
config.set("ui.theme", "dark")
config.set("ui.font_size", 12)
config.set("ui.show_toolbar", True)
# Auto-save handles persistence

# ❌ LESS EFFICIENT - Multiple saves
config.set("ui.theme", "dark")
config._save_config()
config.set("ui.font_size", 12)
config._save_config()
```

### 5. Use Type Hints

```python
from typing import Optional, Dict, Any

def get_model_config(model_id: str) -> Optional[Dict[str, Any]]:
    """Get model configuration with proper typing."""
    config = get_config()
    return config.get(f"llm_configuration.models.{model_id}")

def set_preference(key: str, value: Any) -> None:
    """Set user preference with type hints."""
    config = get_config()
    config.set(f"preferences.{key}", value)
```

## Code Patterns

### Configuration-Aware Class Pattern

```python
class ConfigurableComponent:
    """Base class for configuration-aware components."""

    CONFIG_NAMESPACE = "component"  # Override in subclasses

    def __init__(self):
        self.config = get_config()
        self._config_cache = {}
        self._load_config()

    def _load_config(self):
        """Load component configuration."""
        self._config_cache = self.config.get(
            self.CONFIG_NAMESPACE,
            default={}
        )

    def get_setting(self, key: str, default=None):
        """Get component setting."""
        return self._config_cache.get(key, default)

    def set_setting(self, key: str, value: Any):
        """Set component setting."""
        full_key = f"{self.CONFIG_NAMESPACE}.{key}"
        self.config.set(full_key, value)
        self._config_cache[key] = value
```

### Observer Pattern for Config Changes

```python
from typing import Callable, List

class ConfigObserver:
    """Observe configuration changes."""

    def __init__(self):
        self.config = get_config()
        self._observers: Dict[str, List[Callable]] = {}

    def watch(self, key: str, callback: Callable):
        """Watch a configuration key for changes."""
        if key not in self._observers:
            self._observers[key] = []
        self._observers[key].append(callback)

    def set_and_notify(self, key: str, value: Any):
        """Set value and notify observers."""
        old_value = self.config.get(key)
        self.config.set(key, value)

        # Notify observers
        if key in self._observers:
            for callback in self._observers[key]:
                callback(key, old_value, value)

# Usage
observer = ConfigObserver()
observer.watch("ui_preferences.theme", lambda k, o, n: print(f"Theme changed: {o} -> {n}"))
observer.set_and_notify("ui_preferences.theme", "dark")
```

### Factory Pattern with Configuration

```python
class AnalyzerFactory:
    """Create analyzers based on configuration."""

    @staticmethod
    def create_analyzer(analyzer_type: str):
        """Create analyzer based on config."""
        config = get_config()

        # Get analyzer configuration
        analyzer_config = config.get(
            f"analyzers.{analyzer_type}",
            default={}
        )

        # Select implementation based on config
        if analyzer_config.get("engine") == "radare2":
            from intellicrack.analyzers import Radare2Analyzer
            return Radare2Analyzer(**analyzer_config)
        elif analyzer_config.get("engine") == "ghidra":
            from intellicrack.analyzers import GhidraAnalyzer
            return GhidraAnalyzer(**analyzer_config)
        else:
            raise ValueError(f"Unknown analyzer engine: {analyzer_config.get('engine')}")
```

## Anti-Patterns to Avoid

### ❌ Direct File Access

```python
# WRONG - Bypasses configuration system
import json

def load_settings():
    with open("settings.json", 'r') as f:
        return json.load(f)
```

### ❌ Hardcoded Paths

```python
# WRONG - Platform-specific hardcoded path
config_file = "C:\\Users\\user\\AppData\\Roaming\\Intellicrack\\config.json"

# CORRECT - Use configuration system
config = get_config()
config_path = config._config_file  # Automatically handles platform differences
```

### ❌ Global Configuration Variables

```python
# WRONG - Global mutable state
GLOBAL_CONFIG = {}

def init_config():
    global GLOBAL_CONFIG
    GLOBAL_CONFIG = load_config()

# CORRECT - Use singleton
config = get_config()
```

### ❌ Synchronous File Watching

```python
# WRONG - Blocks execution
import time

while True:
    check_config_changes()
    time.sleep(1)

# CORRECT - Use event-driven approach
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
```

## Testing Guidelines

### Unit Testing Configuration

```python
import pytest
from unittest.mock import patch, MagicMock
from intellicrack.core.config_manager import IntellicrackConfig

class TestFeatureWithConfig:
    """Test feature with configuration mocking."""

    @pytest.fixture
    def mock_config(self):
        """Create mock configuration."""
        with patch('intellicrack.core.config_manager.get_config') as mock_get:
            mock_config = MagicMock(spec=IntellicrackConfig)
            mock_config.get.return_value = "test_value"
            mock_config.has.return_value = True
            mock_get.return_value = mock_config
            yield mock_config

    def test_feature_uses_config(self, mock_config):
        """Test that feature properly uses configuration."""
        from intellicrack.features import MyFeature

        feature = MyFeature()
        result = feature.process()

        # Verify configuration was accessed
        mock_config.get.assert_called_with("feature.setting", default=None)
```

### Integration Testing

```python
from tests.base_test import IntellicrackTestBase

class TestConfigIntegration(IntellicrackTestBase):
    """Integration tests with real configuration."""

    def test_feature_with_real_config(self, temp_workspace):
        """Test feature with actual configuration system."""
        from intellicrack.core.config_manager import IntellicrackConfig

        # Use temp workspace for isolation
        with patch.object(IntellicrackConfig, '_get_user_config_dir',
                         return_value=temp_workspace):
            config = IntellicrackConfig()

            # Set test configuration
            config.set("feature.enabled", True)
            config.set("feature.timeout", 10)

            # Test feature behavior
            from intellicrack.features import MyFeature
            feature = MyFeature()

            assert feature.is_enabled()
            assert feature.timeout == 10
```

## Performance Optimization

### 1. Cache Frequently Accessed Values

```python
class OptimizedComponent:
    """Component with configuration caching."""

    def __init__(self):
        self.config = get_config()
        self._cache = {}
        self._cache_ttl = {}
        self._cache_duration = 60  # seconds

    def get_cached_setting(self, key: str, default=None):
        """Get setting with caching."""
        import time

        now = time.time()
        if key in self._cache:
            if now - self._cache_ttl.get(key, 0) < self._cache_duration:
                return self._cache[key]

        # Cache miss - fetch from config
        value = self.config.get(key, default=default)
        self._cache[key] = value
        self._cache_ttl[key] = now
        return value
```

### 2. Lazy Loading

```python
class LazyConfigLoader:
    """Load configuration sections on demand."""

    def __init__(self):
        self._config = None
        self._sections = {}

    @property
    def config(self):
        """Lazy load configuration."""
        if self._config is None:
            self._config = get_config()
        return self._config

    def get_section(self, section: str):
        """Lazy load configuration section."""
        if section not in self._sections:
            self._sections[section] = self.config.get(section, default={})
        return self._sections[section]
```

### 3. Batch Operations

```python
def update_multiple_settings(updates: Dict[str, Any]):
    """Update multiple settings efficiently."""
    config = get_config()

    # Batch all updates
    for key, value in updates.items():
        config.set(key, value)

    # Single save operation happens automatically
```

## Security Considerations

### 1. Never Log Sensitive Configuration

```python
import logging

logger = logging.getLogger(__name__)

def log_config_safely():
    """Log configuration without sensitive data."""
    config = get_config()

    # Define sensitive keys
    sensitive_keys = ["api_key", "password", "token", "secret"]

    # Get all config for logging
    all_config = config._config.copy()

    # Mask sensitive values
    def mask_sensitive(obj, path=""):
        if isinstance(obj, dict):
            for key, value in obj.items():
                if any(s in key.lower() for s in sensitive_keys):
                    obj[key] = "***MASKED***"
                elif isinstance(value, dict):
                    mask_sensitive(value, f"{path}.{key}")
        return obj

    safe_config = mask_sensitive(all_config)
    logger.debug(f"Configuration: {safe_config}")
```

### 2. Validate Configuration Input

```python
def set_validated_config(key: str, value: Any):
    """Set configuration with validation."""
    config = get_config()

    # Define validation rules
    validators = {
        "network.timeout": lambda v: isinstance(v, int) and 0 < v <= 3600,
        "security.key_length": lambda v: isinstance(v, int) and v >= 256,
        "paths.workspace": lambda v: Path(v).exists() if isinstance(v, str) else False
    }

    # Validate if rule exists
    if key in validators:
        if not validators[key](value):
            raise ValueError(f"Invalid value for {key}: {value}")

    config.set(key, value)
```

### 3. Encrypt Sensitive Configuration

```python
from intellicrack.utils.secrets_manager import SecretsManager

def store_api_key(service: str, api_key: str):
    """Store API key securely."""
    config = get_config()
    secrets = SecretsManager(config)

    # Encrypt and store
    encrypted_ref = secrets.encrypt_value(api_key)
    config.set(f"api_keys.{service}", encrypted_ref)

    # Mark as sensitive
    encrypted_keys = config.get("secrets.encrypted_keys", default=[])
    if service not in encrypted_keys:
        encrypted_keys.append(service)
        config.set("secrets.encrypted_keys", encrypted_keys)
```

## Migration Guidelines

When updating existing code to use the new configuration system:

### Step 1: Identify Legacy Usage

```bash
# Find QSettings usage
rg "QSettings" --type py

# Find direct config file access
rg "open.*config" --type py
rg "json.load.*config" --type py
```

### Step 2: Replace with Central Config

```python
# Before (QSettings)
from PyQt6.QtCore import QSettings
settings = QSettings("Intellicrack", "Application")
theme = settings.value("theme", "light")

# After (Central Config)
from intellicrack.core.config_manager import get_config
config = get_config()
theme = config.get("ui_preferences.theme", default="light")
```

### Step 3: Update Tests

```python
# Update test mocks
@patch('intellicrack.core.config_manager.get_config')
def test_with_config(mock_get_config):
    mock_config = MagicMock()
    mock_config.get.return_value = "test_value"
    mock_get_config.return_value = mock_config

    # Run test
    result = function_under_test()
    assert result == "expected"
```

## Summary

Key takeaways for developers:

1. **Always use `get_config()`** - Never access configuration files directly
2. **Use dot notation** - For clean nested access
3. **Provide defaults** - For optional configuration values
4. **Cache when appropriate** - For frequently accessed values
5. **Validate input** - For configuration that affects security or stability
6. **Test thoroughly** - Both unit and integration tests
7. **Document new sections** - When adding configuration options
8. **Follow security practices** - Never log sensitive configuration

By following these guidelines, you ensure consistent, maintainable, and secure configuration usage throughout the Intellicrack codebase.

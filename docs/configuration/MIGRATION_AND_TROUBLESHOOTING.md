# Configuration Migration and Troubleshooting Guide

## Task 20.2.2: Migration Process Documentation and Troubleshooting

This guide covers the migration process from legacy configuration systems to the new consolidated IntellicrackConfig system, along with comprehensive troubleshooting steps.

## Table of Contents

1. [Migration Overview](#migration-overview)
2. [Automatic Migration Process](#automatic-migration-process)
3. [Manual Migration](#manual-migration)
4. [Troubleshooting Common Issues](#troubleshooting-common-issues)
5. [Recovery Procedures](#recovery-procedures)
6. [Validation and Verification](#validation-and-verification)
7. [FAQ](#faq)

## Migration Overview

The migration system automatically detects and migrates configurations from:

- **QSettings** (PyQt-based configurations)
- **LLM Configuration Manager** (AI model configurations)
- **CLI Configuration** (command-line profiles and aliases)
- **Legacy INI files** (settings.ini, preferences.ini)
- **Environment files** (.env, .env.local)
- **VM Framework configs** (QEMU/Qiling settings)

### Migration Priority Order

1. Central config (if exists) - No migration needed
2. QSettings configurations
3. LLM configurations
4. CLI configurations
5. Legacy INI files
6. Environment variables

## Automatic Migration Process

### How It Works

When Intellicrack starts, it automatically:

1. **Detects** legacy configuration files
2. **Backs up** all existing configurations
3. **Migrates** data to the central system
4. **Validates** the migrated configuration
5. **Cleans up** old files (with user confirmation)

### Migration Locations Checked

```python
# Windows
%APPDATA%\Intellicrack\
%LOCALAPPDATA%\Intellicrack\
C:\Users\{username}\.intellicrack\

# Linux/Mac
~/.config/intellicrack/
~/.intellicrack/
~/Library/Application Support/Intellicrack/
```

### Automatic Migration Code

```python
from intellicrack.core.config_manager import get_config
from intellicrack.core.config_migration_handler import ConfigMigrationHandler

# This happens automatically on first run
config = get_config()
migration_handler = ConfigMigrationHandler(config)

# Automatic migration sequence
if migration_handler.needs_migration():
    success = migration_handler.migrate_all()
    if success:
        print("Migration completed successfully")
    else:
        print("Migration failed - check logs")
```

## Manual Migration

### Step-by-Step Manual Migration

If automatic migration fails or you need to migrate specific configurations:

#### 1. Migrate QSettings

```python
from intellicrack.core.config_migration_handler import ConfigMigrationHandler
from intellicrack.core.config_manager import get_config

config = get_config()
handler = ConfigMigrationHandler(config)

# Migrate QSettings
qsettings_path = Path.home() / ".config" / "intellicrack" / "qsettings.json"
if qsettings_path.exists():
    handler.migrate_legacy_config(qsettings_path)
```

#### 2. Migrate LLM Configurations

```python
# Migrate LLM configurations
llm_config_path = Path.home() / ".intellicrack" / "llm_config.json"
if llm_config_path.exists():
    handler.migrate_llm_config(llm_config_path)
```

#### 3. Migrate CLI Configurations

```python
# Migrate CLI configurations
cli_config_path = Path.home() / ".intellicrack" / "cli_config.json"
if cli_config_path.exists():
    handler.migrate_cli_config(cli_config_path)
```

#### 4. Migrate Environment Variables

```python
# Migrate from .env files
env_file = Path.cwd() / ".env"
if env_file.exists():
    from intellicrack.utils.env_file_manager import EnvFileManager
    env_manager = EnvFileManager(config)
    env_manager.load_env_file(str(env_file))
```

### Selective Migration

To migrate only specific sections:

```python
# Migrate only UI preferences
handler.migrate_section(
    source_config=old_config,
    section_name="ui_preferences",
    target_key="ui_preferences"
)

# Migrate only QEMU settings
handler.migrate_section(
    source_config=old_config,
    section_name="qemu_testing",
    target_key="qemu_testing"
)
```

## Troubleshooting Common Issues

### Issue 1: Configuration Not Loading

**Symptoms:**
- Application uses default settings
- Custom configurations not applied
- Error messages about missing config

**Solution:**

```python
# Check configuration file location
from intellicrack.core.config_manager import get_config
config = get_config()
print(f"Config file: {config._config_file}")
print(f"Exists: {config._config_file.exists()}")

# Verify JSON validity
import json
try:
    with open(config._config_file, 'r') as f:
        data = json.load(f)
    print("Config is valid JSON")
except json.JSONDecodeError as e:
    print(f"Invalid JSON: {e}")
    # Restore from backup
    handler.restore_from_backup()
```

### Issue 2: Migration Fails Silently

**Symptoms:**
- Old configurations still being used
- No error messages
- Migration appears to complete but data is missing

**Solution:**

```python
# Enable verbose logging
import logging
logging.basicConfig(level=logging.DEBUG)

# Run migration with detailed output
handler = ConfigMigrationHandler(config, verbose=True)
result = handler.migrate_all()

# Check migration log
log_file = Path.home() / ".intellicrack" / "migration.log"
if log_file.exists():
    print(log_file.read_text())
```

### Issue 3: Corrupted Configuration File

**Symptoms:**
- Application crashes on startup
- JSON parsing errors
- Missing configuration sections

**Solution:**

```python
# Automatic recovery
from intellicrack.core.config_migration_handler import MigrationBackup

backup_manager = MigrationBackup(backup_dir=Path.home() / ".intellicrack" / "backups")

# List available backups
backups = backup_manager.list_backups()
for backup in backups:
    print(f"Backup: {backup}")

# Restore latest backup
if backups:
    latest_backup = max(backups, key=lambda p: p.stat().st_mtime)
    backup_manager.restore_backup(latest_backup, config._config_file)
    print(f"Restored from: {latest_backup}")
```

### Issue 4: Permission Denied Errors

**Symptoms:**
- Cannot write configuration file
- Access denied errors
- Migration fails with permission errors

**Solution:**

```bash
# Windows (Run as Administrator)
icacls "%APPDATA%\Intellicrack" /grant %USERNAME%:F /T

# Linux/Mac
chmod -R 755 ~/.config/intellicrack
chown -R $USER:$USER ~/.config/intellicrack
```

### Issue 5: Duplicate Configurations

**Symptoms:**
- Settings appear twice
- Conflicting configurations
- Unexpected behavior

**Solution:**

```python
# Remove duplicates
config = get_config()

# Clean up duplicate keys
def remove_duplicates(config_dict):
    seen = set()
    cleaned = {}
    for key, value in config_dict.items():
        if key not in seen:
            seen.add(key)
            cleaned[key] = value
    return cleaned

config._config = remove_duplicates(config._config)
config._save_config()
```

## Recovery Procedures

### Full Recovery from Backup

```python
from pathlib import Path
from intellicrack.core.config_migration_handler import ConfigMigrationHandler

# 1. Locate backups
backup_dir = Path.home() / ".intellicrack" / "backups"
backups = sorted(backup_dir.glob("*.json"), key=lambda p: p.stat().st_mtime)

# 2. Show available backups
for backup in backups[-10:]:  # Last 10 backups
    print(f"{backup.name} - {backup.stat().st_mtime}")

# 3. Restore specific backup
handler = ConfigMigrationHandler(get_config())
handler.restore_backup(backups[-1])  # Restore most recent
```

### Reset to Factory Defaults

```python
# Complete reset
config = get_config()
config.reset()

# Partial reset
config.reset("qemu_testing")
config.reset("ui_preferences")
config.reset("llm_configuration")
```

### Manual Recovery

If automated recovery fails:

1. **Locate default configuration:**
```python
from intellicrack.core.config_manager import IntellicrackConfig
defaults = IntellicrackConfig._get_default_config()

# Save defaults as new config
import json
config_path = Path.home() / ".config" / "intellicrack" / "config.json"
with open(config_path, 'w') as f:
    json.dump(defaults, f, indent=2)
```

2. **Merge with existing data:**
```python
# Load corrupted config carefully
corrupted = {}
try:
    with open(config_path, 'r') as f:
        content = f.read()
        # Try to extract valid JSON portions
        import re
        valid_sections = re.findall(r'"(\w+)":\s*{[^}]+}', content)
        # Reconstruct partial config
except:
    pass

# Merge with defaults
final_config = {**defaults, **corrupted}
```

## Validation and Verification

### Configuration Validation

```python
from intellicrack.core.config_migration_handler import MigrationValidator

validator = MigrationValidator(get_config())

# Validate structure
is_valid = validator.validate_config_structure(config._config)
print(f"Configuration valid: {is_valid}")

# Check required fields
required_fields = ["version", "application", "directories"]
missing = validator.check_required_fields(config._config, required_fields)
if missing:
    print(f"Missing fields: {missing}")
```

### Migration Verification

```python
# Verify all sections migrated
def verify_migration():
    config = get_config()
    required_sections = [
        "qemu_testing",
        "font_configuration",
        "environment",
        "secrets",
        "llm_configuration",
        "cli_configuration",
        "vm_framework"
    ]

    missing = []
    for section in required_sections:
        if not config.has(section):
            missing.append(section)

    if missing:
        print(f"Missing sections: {missing}")
        return False
    return True

success = verify_migration()
```

### Performance Verification

```python
import time

config = get_config()

# Test read performance
start = time.time()
for _ in range(10000):
    config.get("application.name")
read_time = time.time() - start
print(f"10,000 reads: {read_time:.3f}s")

# Test write performance
start = time.time()
for i in range(1000):
    config.set(f"test.value_{i}", i)
write_time = time.time() - start
print(f"1,000 writes: {write_time:.3f}s")

# Performance should be:
# - Reads: < 0.5s for 10,000 operations
# - Writes: < 0.5s for 1,000 operations
```

## FAQ

### Q: Where are my old configurations backed up?

**A:** Backups are stored in:
- Windows: `%APPDATA%\Intellicrack\backups\`
- Linux/Mac: `~/.intellicrack/backups/`

### Q: Can I revert to the old configuration system?

**A:** Yes, you can restore from backup:
```python
handler = ConfigMigrationHandler(get_config())
handler.restore_legacy_system()  # Restores all old config files
```

### Q: How do I know if migration completed successfully?

**A:** Check the migration log:
```python
log_path = Path.home() / ".intellicrack" / "migration.log"
if log_path.exists():
    log_content = log_path.read_text()
    if "Migration completed successfully" in log_content:
        print("Migration successful")
```

### Q: What happens to my API keys during migration?

**A:** API keys are:
1. Automatically detected and marked as sensitive
2. Migrated to the `secrets` section
3. Encrypted if encryption is enabled
4. Original values are backed up before migration

### Q: Can I migrate configurations from another machine?

**A:** Yes:
```python
# Export configuration
config = get_config()
export_path = Path("/path/to/export.json")
config.export_config(export_path)

# On new machine, import
config = get_config()
config.import_config(export_path)
```

### Q: How do I clean up old configuration files?

**A:** After successful migration:
```python
handler = ConfigMigrationHandler(get_config())
handler.cleanup_migrated_files(confirm=True)  # Asks for confirmation
```

### Q: What if I have custom configuration sections?

**A:** Custom sections are preserved:
```python
# Custom sections are automatically migrated
old_config = {"custom_plugin": {"setting": "value"}}
handler.migrate_custom_sections(old_config)
```

## Support

If you encounter issues not covered here:

1. Check the [GitHub Issues](https://github.com/zachanardo/intellicrack/issues)
2. Review migration logs in `~/.intellicrack/migration.log`
3. Create a bug report with:
   - Error messages
   - Migration log
   - System information
   - Steps to reproduce

## Summary

The migration system is designed to be:
- **Automatic**: Works without user intervention
- **Safe**: Creates backups before any changes
- **Recoverable**: Can restore from any backup
- **Validated**: Checks data integrity
- **Comprehensive**: Migrates all configuration types

Follow this guide for smooth migration and quick resolution of any issues.

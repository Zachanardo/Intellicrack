# Intellicrack v4.0 Configuration Migration Guide for Users

## Task 20.2.4: User Migration Guide

Welcome to Intellicrack v4.0! This guide will help you smoothly transition from previous versions to the new consolidated configuration system.

## What's New in v4.0

Intellicrack v4.0 introduces a **unified configuration system** that:
- ✨ Consolidates all settings into one place
- 🔒 Improves security with encrypted secrets
- ⚡ Enhances performance with optimized access
- 🔄 Provides automatic backup and recovery
- 🌍 Works consistently across all platforms

## Quick Start

### Automatic Migration

**Most users don't need to do anything!** When you first launch Intellicrack v4.0:

1. **Launch Intellicrack** normally
2. **Automatic detection** finds your existing settings
3. **Backup creation** saves your current configuration
4. **Migration** transfers all settings to the new system
5. **Validation** ensures everything works correctly

### What Gets Migrated

All your existing settings are automatically migrated:

- ✅ **UI Preferences** (theme, window size, layout)
- ✅ **Analysis Settings** (timeouts, tools configuration)
- ✅ **API Keys** (OpenAI, Anthropic, etc.)
- ✅ **QEMU/VM Settings** (memory, CPU, images)
- ✅ **CLI Profiles** (aliases, output formats)
- ✅ **Recent Files** and workspace paths
- ✅ **Custom Scripts** and plugin settings
- ✅ **Font Preferences** and display settings

## Step-by-Step Guide

### Step 1: Backup Your Current Settings (Optional but Recommended)

Before upgrading, you can manually backup your settings:

**Windows:**
```cmd
xcopy "%APPDATA%\Intellicrack" "%USERPROFILE%\Desktop\Intellicrack_Backup" /E /I
```


### Step 2: Install Intellicrack v4.0

Download and install the latest version from:
- [Official Website](https://intellicrack.com/download)
- [GitHub Releases](https://github.com/zachanardo/intellicrack/releases)

### Step 3: First Launch

When you first launch v4.0, you'll see a migration dialog:

```
╔════════════════════════════════════════╗
║     Configuration Migration Wizard     ║
╠════════════════════════════════════════╣
║                                        ║
║  Found existing configuration from:    ║
║  • Intellicrack v3.5                  ║
║  • 45 custom settings                 ║
║  • 3 API keys                         ║
║                                        ║
║  [Migrate Now]  [Skip]  [Learn More]  ║
╚════════════════════════════════════════╝
```

Click **"Migrate Now"** to proceed.

### Step 4: Review Migration Results

After migration, you'll see a summary:

```
✅ Migration Complete!

Successfully migrated:
• UI Settings: 12 preferences
• API Keys: 3 keys (now encrypted)
• QEMU Settings: Custom configuration
• CLI Profiles: 2 profiles
• Recent Files: 10 files

Your old configuration has been backed up to:
C:\Users\YourName\AppData\Roaming\Intellicrack\backups\

[Continue to Intellicrack]
```

## Verifying Your Settings

### Check UI Preferences

1. Open **Edit → Preferences** (or press `Ctrl+,`)
2. Verify your theme, fonts, and layout are correct
3. Check that window positions are preserved

### Verify API Keys

1. Go to **Tools → AI Configuration**
2. Confirm your API keys are present (shown as `***`)
3. Test with a simple AI operation

### Test QEMU/VM Settings

1. Open **Analysis → QEMU Settings**
2. Check memory and CPU allocations
3. Verify VM images are still referenced

## Troubleshooting

### Issue: "Configuration Not Found"

If the migration wizard doesn't find your settings:

1. **Check the old location manually:**
   - Windows: `%APPDATA%\Intellicrack\`
    - Mac: `~/Library/Application Support/Intellicrack/`

2. **Point to your configuration:**
   ```
   Tools → Import Configuration → Browse...
   ```
   Navigate to your old config file and select it.

### Issue: "Some Settings Missing"

If certain settings didn't migrate:

1. **Check the migration log:**
   ```
   Help → View Logs → Migration Log
   ```

2. **Manually import specific settings:**
   ```python
   # In the Python console (Tools → Python Console)
   from intellicrack.core.config_manager import get_config
   config = get_config()

   # Set missing value
   config.set("missing.setting", "your_value")
   ```

### Issue: "API Keys Not Working"

If your API keys aren't functioning:

1. **Re-enter API keys:**
   ```
   Tools → AI Configuration → Manage API Keys
   ```

2. **Check encryption settings:**
   ```
   Edit → Preferences → Security → Secrets Management
   ```
   Ensure "Encryption Enabled" is checked.

### Issue: "UI Layout Reset"

If your window layout was reset:

1. **Restore from backup:**
   ```
   View → Window → Restore Layout from Backup
   ```

2. **Manually adjust and save:**
   - Arrange windows as desired
   - Select `View → Window → Save Current Layout`

## Manual Migration

If automatic migration fails, you can manually migrate:

### Export from Old Version

1. In your old Intellicrack version:
   ```
   File → Export → Export All Settings...
   ```
   Save as `intellicrack_export.json`

### Import to v4.0

1. In Intellicrack v4.0:
   ```
   File → Import → Import Settings...
   ```
   Select your exported file.

### Using Command Line

```bash
# Export old settings
intellicrack --export-config old_config.json

# Import to new version
intellicrack --import-config old_config.json
```

## New Features to Explore

### Enhanced Security

Your API keys and sensitive data are now encrypted:

1. Go to **Edit → Preferences → Security**
2. Enable **"Encrypt Sensitive Data"**
3. Set up **Key Rotation** for automatic key refresh

### Profile Management

Create different configuration profiles:

1. **Edit → Preferences → Profiles**
2. Click **"New Profile"**
3. Name it (e.g., "Development", "Production")
4. Switch profiles from the status bar

### Cloud Sync (Premium)

Sync settings across machines:

1. **Tools → Cloud Sync**
2. Sign in with your account
3. Enable **"Auto Sync Settings"**

## Rollback Instructions

If you need to revert to your old configuration:

### Automatic Rollback

1. **Tools → Configuration → Restore Backup**
2. Select the pre-migration backup
3. Click **"Restore"**
4. Restart Intellicrack

### Manual Rollback

**Windows:**
```cmd
rmdir /s "%APPDATA%\Intellicrack\config.json"
xcopy "%APPDATA%\Intellicrack\backups\pre_migration_*" "%APPDATA%\Intellicrack\" /E
```

```bash
rm ~/.config/intellicrack/config.json
cp ~/.intellicrack/backups/pre_migration_* ~/.config/intellicrack/
```

## FAQ

### Q: Will I lose any settings during migration?

**A:** No! All settings are preserved. The migration system creates a complete backup before making any changes.

### Q: Can I use both old and new versions?

**A:** Yes, but not simultaneously. The new version uses a different configuration format, so changes in v4.0 won't affect older versions.

### Q: Where is my configuration stored now?

**A:**
- **Windows:** `%APPDATA%\Intellicrack\config.json`
- **Mac:** `~/Library/Application Support/Intellicrack/config.json`

### Q: How do I backup my new configuration?

**A:**
- **Automatic:** Backups are created daily
- **Manual:** `File → Backup → Backup Configuration`
- **Location:** Check `Help → About → Backup Location`

### Q: Can I edit the configuration file directly?

**A:** Yes, but it's not recommended. Use the UI or Python console instead. If you must edit directly:
1. Close Intellicrack
2. Edit the JSON file
3. Validate JSON syntax
4. Restart Intellicrack

### Q: What if I have custom scripts that read configuration?

**A:** Update your scripts to use the new API:

**Old way:**
```python
import json
with open("config.json") as f:
    config = json.load(f)
theme = config["theme"]
```

**New way:**
```python
from intellicrack.core.config_manager import get_config
config = get_config()
theme = config.get("ui_preferences.theme")
```

## Getting Help

If you encounter issues:

1. **Check the Documentation:**
   - Help → Documentation → Configuration Guide
   - [Online Docs](https://docs.intellicrack.com/configuration)

2. **View Migration Logs:**
   - Help → View Logs → Migration Log
   - Share this when reporting issues

3. **Community Support:**
   - [Discord Server](https://discord.gg/intellicrack)
   - [GitHub Issues](https://github.com/zachanardo/intellicrack/issues)
   - [User Forum](https://forum.intellicrack.com)

4. **Contact Support:**
   - Email: support@intellicrack.com
   - Include your migration log and system info

## Tips for a Smooth Migration

1. ✅ **Run migration when you have time** - It only takes a minute, but review afterward
2. ✅ **Keep the backup** - Don't delete old configurations for at least a week
3. ✅ **Test critical features** - Verify your most-used features work correctly
4. ✅ **Report issues early** - Help us improve the migration process
5. ✅ **Explore new features** - Take advantage of the improved configuration system

## Summary

The migration to Intellicrack v4.0 is designed to be:

- **🚀 Automatic** - No manual intervention needed
- **🔒 Safe** - Full backups before any changes
- **✨ Complete** - All settings transferred
- **🔄 Reversible** - Can rollback if needed
- **💻 Windows 11 Optimized** - Built specifically for Windows 11

Welcome to Intellicrack v4.0! Enjoy the improved configuration system and enhanced features.

---

*Last updated: January 2024 | Version 4.0.0*

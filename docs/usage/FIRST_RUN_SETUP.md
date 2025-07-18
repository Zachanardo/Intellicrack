# First-Run Setup Guide

## Welcome to Intellicrack

This guide will walk you through the initial setup and configuration of Intellicrack. Follow these steps to get started quickly and securely.

## Table of Contents

1. [System Requirements](#system-requirements)
2. [Initial Launch](#initial-launch)
3. [Setup Wizard](#setup-wizard)
4. [API Key Configuration](#api-key-configuration)
5. [Tool Integration](#tool-integration)
6. [GPU Setup](#gpu-setup)
7. [Security Configuration](#security-configuration)
8. [Workspace Setup](#workspace-setup)
9. [Verification](#verification)
10. [Next Steps](#next-steps)

## System Requirements

### Minimum Requirements
- **OS**: Windows 10/11, Ubuntu 20.04+, macOS 11+
- **CPU**: 4 cores, 2.5GHz
- **RAM**: 8GB
- **Storage**: 20GB free space
- **Python**: 3.8 or higher

### Recommended Requirements
- **OS**: Windows 11, Ubuntu 22.04+
- **CPU**: 8+ cores, 3.0GHz+
- **RAM**: 16GB+
- **Storage**: 50GB+ free space (SSD recommended)
- **GPU**: NVIDIA GPU with 8GB+ VRAM (for AI features)

## Initial Launch

### Windows

1. **Run as Administrator** (recommended for full functionality):
   ```batch
   RUN_INTELLICRACK.bat
   ```

2. **Safe Mode** (if encountering issues):
   ```batch
   cd dev\scripts
   RUN_INTELLICRACK_SAFE.bat
   ```

### Linux/macOS

1. **Standard launch**:
   ```bash
   python launch_intellicrack.py
   ```

2. **With specific Python**:
   ```bash
   python3.9 launch_intellicrack.py
   ```

## Setup Wizard

On first launch, Intellicrack will guide you through initial configuration:

### Step 1: Welcome Screen

The welcome screen provides:
- Overview of Intellicrack capabilities
- Legal disclaimer
- Option to skip wizard (not recommended)

Click **"Begin Setup"** to continue.

### Step 2: License Agreement

- Read the GPL-3.0 license terms
- Check "I accept the terms"
- Click **"Continue"**

### Step 3: Installation Type

Choose your installation type:

1. **Standard** (Recommended)
   - Full feature set
   - Default security settings
   - Automatic updates

2. **Custom**
   - Select specific features
   - Advanced security options
   - Manual update control

3. **Minimal**
   - Core features only
   - No network features
   - Manual configuration

## API Key Configuration

### Step 4: AI Provider Setup

Configure AI providers for enhanced features:

#### OpenAI
```
API Key: sk-...
Organization ID: org-... (optional)
```

#### Anthropic
```
API Key: sk-ant-...
```

#### Google AI
```
API Key: AIza...
```

#### Local Models
- Check "Enable local models"
- Select model directory
- Choose default model

**Note**: You can add more providers later in Settings.

### Secure Storage

API keys are encrypted and stored in:
- Windows: `%APPDATA%\intellicrack\.env`
- Linux/macOS: `~/.intellicrack/.env`

## Tool Integration

### Step 5: External Tools

Configure paths to external tools:

#### Ghidra
```
Path: C:\ghidra_10.4_PUBLIC
☑ Download if not found
```

#### Radare2
```
Path: C:\Program Files\radare2
☑ Add to PATH
```

#### Frida
```
☑ Install via pip
Version: Latest
```

### Automatic Detection

Click **"Auto-Detect"** to find installed tools automatically.

## GPU Setup

### Step 6: GPU Configuration

If you have a compatible GPU:

#### NVIDIA
```
☑ Enable CUDA acceleration
Memory Limit: 90%
Compute Mode: Default
```

#### AMD
```
☑ Enable ROCm acceleration
Memory Limit: 90%
```

#### Intel Arc
```
☑ Enable Intel GPU acceleration
Backend: DirectML
```

### Verification

Click **"Test GPU"** to verify configuration:
```
GPU: NVIDIA GeForce RTX 4090
VRAM: 24GB
CUDA: 12.1
Status: ✓ Ready
```

## Security Configuration

### Step 7: Security Settings

Configure security features:

#### Sandbox
```
☑ Enable sandboxing for analysis
Backend: firejail (Linux) / Windows Sandbox
Network: Disabled
Filesystem: Read-only
```

#### Encryption
```
☑ Encrypt workspace files
☑ Encrypt API keys
Algorithm: AES-256-GCM
```

#### Network
```
☐ Allow network analysis features
☐ Enable update checks
Proxy: (leave blank for direct)
```

## Workspace Setup

### Step 8: Workspace Configuration

Set up your working directory:

```
Location: ~/intellicrack_workspace
☑ Create if not exists
☑ Set as default

Structure:
├── projects/
├── analysis/
├── exports/
├── plugins/
└── temp/
```

### Project Templates

Choose default project templates:
- ☑ Malware Analysis
- ☑ Vulnerability Research
- ☑ Binary Patching
- ☐ Forensics Investigation

## Verification

### Step 9: System Check

The wizard performs final verification:

```
✓ Python environment
✓ Required packages
✓ GPU drivers
✓ External tools
✓ Workspace permissions
✓ Network connectivity

Status: Ready to use!
```

### Troubleshooting

If any checks fail:

1. **Missing Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

2. **GPU Issues**
   - Update drivers
   - Check GPU compatibility
   - Try CPU-only mode

3. **Permission Errors**
   - Run as administrator/sudo
   - Check antivirus settings

## First Run Complete

### Configuration Summary

Your configuration is saved to:
```
~/.intellicrack/config.json
```

Key settings:
- Theme: Dark
- GPU: Enabled
- AI Providers: 3 configured
- Tools: All detected
- Security: Sandbox enabled

### Quick Start Tutorial

After setup, you'll see the main interface with:

1. **Dashboard Tab**
   - System status
   - Recent projects
   - Quick actions

2. **Analysis Tab**
   - Drag & drop files
   - Select analysis type
   - View results

3. **AI Assistant Tab**
   - Chat interface
   - Code generation
   - Script assistance

4. **Tools Tab**
   - External tool launchers
   - Integrated features

## Next Steps

### Recommended Actions

1. **Create First Project**
   ```
   File → New Project → Binary Analysis
   ```

2. **Test AI Features**
   - Open AI Assistant tab
   - Try: "Generate a Frida script to hook CreateFile"

3. **Analyze Sample File**
   - Drag a PE file to Analysis tab
   - Select "Quick Analysis"
   - Review results

### Learning Resources

1. **Built-in Tutorials**
   ```
   Help → Interactive Tutorial
   ```

2. **Documentation**
   ```
   Help → Documentation
   ```

3. **Sample Projects**
   ```
   File → Open Sample Project
   ```

### Tips for New Users

1. **Start Simple**
   - Use Quick Analysis first
   - Try basic features before advanced
   - Read tooltips (hover over buttons)

2. **Keyboard Shortcuts**
   - `Ctrl+N` - New project
   - `Ctrl+O` - Open file
   - `F1` - Context help
   - `Ctrl+Shift+P` - Command palette

3. **Safe Practices**
   - Always work in sandbox
   - Keep backups of targets
   - Use isolated VMs for malware

## Advanced Configuration

### Custom Settings

Edit `~/.intellicrack/config.json` for advanced options:

```json
{
  "general": {
    "check_updates": false,
    "telemetry": false
  },
  "analysis": {
    "thread_count": 16,
    "timeout": 600
  },
  "ui": {
    "font_size": 12,
    "show_tips": false
  }
}
```

### Environment Variables

Set custom paths:
```bash
export INTELLICRACK_HOME=/opt/intellicrack
export INTELLICRACK_WORKSPACE=~/workspace
export INTELLICRACK_PLUGINS=~/.intellicrack/plugins
```

## Getting Help

### Built-in Help
- Press `F1` for context-sensitive help
- Hover over any element for tooltips
- Check Help menu for guides

### Community Resources
- GitHub Issues for bug reports
- Discussions for questions
- Wiki for advanced topics

### Troubleshooting First Run

Common issues and solutions:

1. **"First run not complete" error**
   ```python
   # Force complete first run
   python -c "from intellicrack.core.config_manager import ConfigManager; ConfigManager().set('general.first_run_complete', True)"
   ```

2. **Wizard doesn't appear**
   - Delete `~/.intellicrack/config.json`
   - Restart application

3. **GPU not detected**
   - Update drivers
   - Check `nvidia-smi` or `rocm-smi`
   - Disable GPU in settings

Remember: The setup wizard only appears once. To reconfigure, use **Settings → Preferences** or delete your config file to start fresh.
# Intellicrack Dependencies

## Installation

Run the main installer:

```powershell
.\Install.ps1
```

Or from the project root:
```batch
INSTALL.bat
```

## What's in this folder?

### Main Installer
- **`Install.ps1`** - Complete PowerShell installer that handles everything:
  - Installs Python 3.11 if needed
  - Detects GPU and configures accordingly
  - Installs all Python packages
  - Installs system tools
  - Full environment setup

### Specialized Scripts (for manual fixes only)
- **`Fix_Angr_Dependencies.bat`** - Fixes angr installation issues
- **`Install_System_Tools.bat`** - Installs only system tools (Ghidra, Radare2, etc.)
- **`Install_Ghidra_Decompiler.bat`** - Installs only Ghidra
- **`Install_Radare2_Disassembler.bat`** - Installs only Radare2
- **`Verify_Installation_Status.bat`** - Checks installation status

### Documentation
- **`docs/`** - Detailed documentation
- **`logs/`** - Installation logs
- **`requirements.txt`** - Python package list (if different from main)

## Notes

The `Install.ps1` script:
- Auto-elevates to Administrator
- Checks system requirements
- Has network connectivity check
- Supports resume if interrupted
- Shows progress for all operations
- Runs GPU benchmark after installation
- Creates full installation log

No other scripts are needed for normal installation.
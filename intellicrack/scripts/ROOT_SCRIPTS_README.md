# Intellicrack Scripts

This directory contains utility scripts for Intellicrack setup and operation.

## Directory Structure

### `radare2/`
Scripts for radare2 setup and configuration:
- `setup_radare2.bat` - Guide for installing and configuring radare2
- `use_local_radare2.bat` - Launch terminal with local radare2 in PATH

### Python Scripts


- `test_imports.py` - Test import functionality
- `test_integration.py` - Integration testing

## Usage

### Quick Setup
From the project root, run:
```batch
setup_tools.bat
```

This provides a menu to access all setup scripts.

### Individual Scripts
You can also run scripts directly:

```batch
# Setup radare2
scripts\radare2\setup_radare2.bat

# Use local radare2 environment
scripts\radare2\use_local_radare2.bat
```

## Adding New Scripts

When adding new utility scripts:
1. Place them in appropriate subdirectories by category
2. Update the main `setup_tools.bat` if they need menu integration
3. Document them in this README

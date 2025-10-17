# Intellicrack Scripts

This directory contains utility scripts for Intellicrack setup and operation.

## Directory Structure

### `frida/`

Frida-related scripts and integration.

### `radare2/`

Radare2 integration scripts:

- `radare2_keygen_assistant.py` - Key generation assistant
- `radare2_license_analyzer.py` - License analysis tools

### Python Scripts

- `run_analysis_cli.py` - Command-line analysis interface

### Other Directories

- `ai_generated/` - AI-generated scripts
- `ai_scripts/` - AI script templates
- `generated/` - Generated analysis scripts
- `qiling/` - Qiling emulator scripts
- `setup/` - Setup and configuration scripts
- `unicorn/` - Unicorn engine scripts
- `utils/` - Utility scripts
- `versions/` - Version-specific scripts

## Usage

### Quick Setup

Run setup scripts from the `scripts/setup/` directory.

### Individual Scripts

You can also run scripts directly:

```python
# Run command-line analysis interface
python scripts/run_analysis_cli.py
```

## Adding New Scripts

When adding new utility scripts:

1. Place them in appropriate subdirectories by category
2. Ensure proper error handling and logging
3. Document them in this README

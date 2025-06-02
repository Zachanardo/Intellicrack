# Intellicrack Tools Directory

This directory is used for storing installed analysis tools and their configurations.

## Purpose

This directory serves as the installation location for various binary analysis tools used by Intellicrack:

- **radare2/**: Local radare2 installation
- **ghidra/**: Bundled Ghidra installation  
- Other analysis tools as needed

To set up tools, use:
```batch
dependencies\install_all_dependencies.bat
```

Or for individual tool setup:
```batch
dependencies\setup_radare2.bat
dependencies\setup_ghidra.bat
dependencies\setup_intellicrack.bat
```

## Directory Structure

When tools are installed, the structure will be:
```
tools/
├── README.md (this file)
├── radare2/
│   └── radare2-5.9.8-w64/
│       └── bin/
│           └── radare2.exe
├── ghidra/
│   └── ghidra_11.3.2_PUBLIC/
│       └── ghidraRun.bat
└── [other tools as installed]
```

## Important Notes

1. Tools installed here are detected automatically by the setup scripts
2. The setup scripts in `dependencies/` will create subdirectories here as needed
3. Log files from setup processes are stored in `dependencies/logs/`

## See Also

- `dependencies/README.md` - Complete documentation for all setup scripts
- `dependencies/setup_intellicrack.bat` - Main comprehensive setup
- `INSTALLATION.md` - Overall installation guide
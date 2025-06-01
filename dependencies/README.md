# Intellicrack Dependencies Installation

This folder contains all the scripts and tools needed to install Intellicrack's dependencies.

## Quick Installation

1. **Run the installer:**
   ```batch
   INSTALL.bat
   ```
   This will launch the PowerShell installer with administrator privileges.

2. **Fix tool paths (if needed):**
   ```batch
   python fix_tool_paths.py
   ```
   Run this after installation to ensure Intellicrack can find all installed tools.

## What Gets Installed

### Python Packages (100+)
- Core analysis libraries (pefile, pyelftools, lief, capstone)
- Symbolic execution (angr, manticore, z3-solver)
- Machine learning (torch, tensorflow, scikit-learn)
- Network analysis (scapy, pyshark, mitmproxy)
- Dynamic instrumentation (frida, qiling)
- GPU acceleration (cuda/opencl support based on hardware)
- And many more...

### System Tools
- **Ghidra** - Advanced reverse engineering framework
- **Radare2** - Command-line reverse engineering toolkit
- **QEMU** - System emulation
- **Docker** - Container platform
- **Wireshark** - Network protocol analyzer (for pyshark)
- **Git** - Version control

### Directory Structure Created
```
C:\Intellicrack\
├── logs\       # Application logs
├── config\     # Configuration files
├── tools\      # External tools
├── data\       # Signatures and templates
├── reports\    # Generated reports
├── plugins\    # Plugin directory
├── models\     # ML models
└── cache\      # Temporary cache
```

## Installation Options

### Full Installation (Default)
```batch
INSTALL.bat
```
Installs everything including GPU support and system tools.

### Skip GPU Detection
```powershell
powershell -ExecutionPolicy Bypass -File Install.ps1 -SkipGPU
```
Skips GPU detection and GPU-specific packages.

### Skip System Tools
```powershell
powershell -ExecutionPolicy Bypass -File Install.ps1 -SkipSystemTools
```
Only installs Python and packages, skips Ghidra, Radare2, etc.

## Post-Installation

After installation completes:

1. **Verify paths are correct:**
   ```batch
   python fix_tool_paths.py
   ```

2. **Run Intellicrack:**
   ```batch
   cd ..
   RUN_INTELLICRACK.bat
   ```

## Troubleshooting

### Tools Not Found
If Intellicrack can't find Ghidra or Radare2 after installation:
1. Run `fix_tool_paths.py` to auto-detect and configure paths
2. Check that tools are in your PATH
3. Manually edit `intellicrack_config.json` if needed

### GPU Not Detected
- NVIDIA: Ensure CUDA drivers are installed
- Intel: Intel GPU drivers must be up to date
- AMD: OpenCL support will be used

### Installation Logs
Check logs in `C:\Intellicrack\logs\` for detailed installation information.

## Manual Tool Installation

If automatic installation fails for any tool:

### Ghidra
Download from: https://ghidra-sre.org/
Install to: `C:\Program Files\Ghidra\`

### Radare2
Download from: https://rada.re/n/radare2.html
Or use the bundled version in the project.

### QEMU
Download from: https://www.qemu.org/download/
Add to PATH after installation.

## Requirements

- Windows 10 or higher
- 8GB RAM (recommended)
- 5GB free disk space
- Internet connection for downloads
- Administrator privileges
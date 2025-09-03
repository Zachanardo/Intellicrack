# Intellicrack Installation Guide

## Prerequisites

### System Requirements
- **Operating System**: Windows 10/11, Linux (Ubuntu 20.04+), macOS 10.15+
- **Python**: 3.8 or higher (3.10+ recommended)
- **RAM**: 8GB minimum (16GB recommended for large binary analysis)
- **Disk Space**: 2GB for base installation, additional space for models and analysis data
- **GPU** (Optional): NVIDIA, AMD, or Intel GPU for acceleration features

### Required Software
- **Git**: For cloning the repository
- **Python**: Python 3.8+ with pip
- **Virtual Environment**: venv (included with Python)

## Platform-Specific Installation

### Windows Installation

```batch
# Navigate to the Intellicrack directory
cd intellicrack

# The virtual environment should already exist as .venv_windows
# If not, create it:
python -m venv .venv_windows

# Activate virtual environment
.venv_windows\Scripts\activate

# Install dependencies using UV (recommended)
pip install uv
uv pip install -r requirements/requirements_windows.txt

# Or using standard pip
pip install -r requirements/requirements_windows.txt

# Launch Intellicrack
RUN_INTELLICRACK.bat
```

### Linux/WSL Installation

```bash
# Navigate to the Intellicrack directory
cd intellicrack

# The virtual environment should already exist as .venv_wsl
# If not, create it:
python3 -m venv .venv_wsl

# Activate virtual environment
source .venv_wsl/bin/activate

# Install dependencies
pip install -r requirements/requirements.txt

# Launch Intellicrack
python launch_intellicrack.py
```

### macOS Installation

```bash
# Navigate to the Intellicrack directory
cd intellicrack

# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements/requirements.txt

# Launch Intellicrack
python launch_intellicrack.py
```

## Important Notes on Virtual Environments

**⚠️ CRITICAL**: Different environments for different contexts:
- **Windows users**: Use `.venv_windows`
- **WSL/Linux users**: Use `.venv_wsl`
- **NEVER cross-use environments** - This can cause dependency conflicts

## Dependency Management

### Using UV (Recommended for Windows)

UV is a fast Python package installer that's particularly useful on Windows:

```batch
# Install UV
pip install uv

# Install dependencies with UV
uv pip install -r requirements/requirements_windows.txt
```

### Standard pip Installation

```bash
# Core requirements
pip install -r requirements/requirements.txt

# Windows-specific requirements
pip install -r requirements/requirements_windows.txt
```

## GPU Support Configuration

### Intel GPU (Arc B580)

Intellicrack includes automatic Intel GPU support. The `RUN_INTELLICRACK.bat` file sets:
- `CUDA_VISIBLE_DEVICES=-1` (disables CUDA)
- `INTELLICRACK_GPU_TYPE=intel`
- Qt rendering settings for Intel GPUs

### NVIDIA GPU

```bash
# Install PyTorch with CUDA support
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu121
```

### AMD GPU

```bash
# ROCm support (Linux only)
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/rocm5.4.2
```

## Symbolic Execution Engines

Intellicrack supports multiple symbolic execution engines:

1. **angr** (Primary - All Platforms)
   - Full Windows, Linux, and macOS support
   - Installed by default with core dependencies
   - Recommended for all users

2. **manticore** (Secondary - Linux Only)
   - Linux/Unix only - requires specific kernel features
   - NOT available on Windows
   - Optional installation via `pip install manticore[native]`

3. **Built-in fallback**
   - Automatically used when other engines unavailable
   - Limited features compared to angr/manticore

## External Tool Installation (Optional)

### Ghidra
1. Download from <https://ghidra-sre.org/>
2. Extract to a directory
3. Set in Intellicrack settings or environment variable

### radare2

```bash
# Windows (using Chocolatey)
choco install radare2

# Linux
sudo apt-get install radare2

# macOS
brew install radare2
```

### Frida

```bash
pip install frida-tools
```

## Verification

### Test Installation

```bash
# Quick test
python -c "import intellicrack; print('Intellicrack imported successfully')"

# Launch the application
python launch_intellicrack.py
```

### Check Components

```bash
# Check Python version
python --version

# Check PyQt6 installation
python -c "from PyQt6.QtCore import QT_VERSION_STR; print(f'Qt version: {QT_VERSION_STR}')"

# Check if virtual environment is activated
echo %VIRTUAL_ENV%  # Windows
echo $VIRTUAL_ENV   # Linux/macOS
```

## Troubleshooting

### Common Issues

#### 1. "Module not found" errors
- Ensure you're in the correct virtual environment
- Windows: `.venv_windows\Scripts\activate`
- Linux/WSL: `source .venv_wsl/bin/activate`

#### 2. PyQt6 Issues

```bash
# Reinstall PyQt6 components
pip install --force-reinstall PyQt6 PyQt6-WebEngine PyQt6-Charts
```

#### 3. GPU Not Detected
- This is normal in WSL/VMs
- CPU fallback will be used automatically
- Check the Logs tab for GPU detection status

#### 4. Qt Platform Plugin Errors

The `RUN_INTELLICRACK.bat` file already sets the necessary Qt environment variables. If running manually:

```batch
set QT_QPA_PLATFORM=windows
set QT_OPENGL=software
```

#### 5. "Manticore not available" on Windows

This is expected behavior. Manticore is Linux-only. Use angr for symbolic execution on Windows.

### Environment Variables

These are automatically set by `RUN_INTELLICRACK.bat` but can be set manually:

```batch
# Intel GPU settings
set CUDA_VISIBLE_DEVICES=-1
set INTELLICRACK_GPU_TYPE=intel

# Qt settings
set QT_OPENGL=software
set QT_ANGLE_PLATFORM=warp
set QT_QPA_PLATFORM=windows
```

## Configuration Files

Intellicrack uses several configuration files:
- `config/intellicrack_config.json` - Main configuration
- Model configurations in the Settings tab
- Plugin configurations in `plugins/` directory

## Updating Intellicrack

```bash
# Pull latest changes
git pull origin main

# Update dependencies
pip install -r requirements/requirements.txt --upgrade

# For Windows
pip install -r requirements/requirements_windows.txt --upgrade
```

## Project Structure

Key directories:
- `intellicrack/` - Main source code
- `config/` - Configuration files
- `plugins/` - Plugin modules
- `docs/` - Documentation
- `tests/` - Test suite
- `examples/` - Example scripts and binaries

## Next Steps

1. Launch Intellicrack using `RUN_INTELLICRACK.bat` (Windows) or `python launch_intellicrack.py`
2. Configure AI providers in Settings → AI Configuration
3. Load a binary file and start analyzing
4. Check the User Guide documentation for detailed usage instructions

## Troubleshooting Help

If you encounter issues:
1. Check the Logs tab in Intellicrack for error messages
2. Ensure you're using the correct virtual environment
3. Verify all dependencies are installed
4. Review error logs in the application

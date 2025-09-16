# Intellicrack Installation Guide

## Overview

Intellicrack is an advanced binary analysis and security research platform optimized for Windows systems. All dependencies are managed through `pyproject.toml`, providing a unified installation experience with 336+ pre-configured packages for comprehensive offensive security research.

## System Requirements

### Required
- **Windows 10/11** (primary platform, full compatibility)
- **Python 3.12** (exact version required)
- **Git** for repository cloning
- **8GB+ RAM** recommended for analysis operations
- **20GB+ free disk space** for tools and cache

### Optional but Recommended
- **Intel GPU** for hardware acceleration (XPU support)
- **Visual Studio Build Tools 2022** for compiling native extensions
- **Windows Terminal** or **PowerShell 7+** for better CLI experience

## Quick Installation (Recommended)

### Method 1: Automated PowerShell Installation

```powershell
# Clone the repository
git clone https://github.com/Zachanardo/Intellicrack.git
cd Intellicrack

# Run automated installer
.\install.ps1
```

### Method 2: Manual Installation with pip

```powershell
# Clone the repository
git clone https://github.com/Zachanardo/Intellicrack.git
cd Intellicrack

# Create Python 3.12 virtual environment
python -m venv intellicrack_env

# Activate environment
.\intellicrack_env\Scripts\Activate.ps1

# Upgrade pip and install build tools
python -m pip install --upgrade pip setuptools wheel

# Install Intellicrack with all dependencies
pip install -e .

# Optional: Install development dependencies
pip install -e .[dev]
```

### Method 3: Using uv (Ultra-fast Python Package Installer)

```powershell
# Install uv if not already installed
pip install uv

# Clone and enter repository
git clone https://github.com/Zachanardo/Intellicrack.git
cd Intellicrack

# Create virtual environment with Python 3.12
uv venv --python 3.12

# Activate environment
.\venv\Scripts\Activate.ps1

# Install all dependencies
uv pip install -e .
```

## Advanced Installation Options

### Using Mamba/Conda (for scientific computing optimization)

If you prefer conda/mamba for better binary package management:

```powershell
# Create minimal mamba environment
mamba create -n intellicrack python=3.12 pip -y
mamba activate intellicrack

# Install all packages via pip/pyproject.toml
pip install -e .
```

### Intel XPU Support (for hardware acceleration)

For systems with Intel GPUs:

```powershell
# After base installation, add Intel XPU support
pip install torch==2.5.0 torchvision==0.20.0 torchaudio==2.5.0 --index-url https://download.pytorch.org/whl/xpu
pip install intel-extension-for-pytorch==2.5.0+xpu --extra-index-url https://pytorch-extension.intel.com/release-whl/stable/xpu/us/
```

### Development Installation

For contributors and developers:

```powershell
# Clone with SSH (if you have write access)
git clone git@github.com:Zachanardo/Intellicrack.git
cd Intellicrack

# Create development environment
python -m venv dev_env
.\dev_env\Scripts\Activate.ps1

# Install in editable mode with all extras
pip install -e .[dev,test,docs]

# Install pre-commit hooks
pre-commit install
```

## Verifying Installation

### Basic Verification

```powershell
# Check Python version
python --version  # Should show Python 3.12.x

# Verify Intellicrack import
python -c "import intellicrack; print(intellicrack.__version__)"

# Check for dependency conflicts
pip check
```

### Comprehensive Verification

```powershell
# Run full installation verification
python -c "
import intellicrack
from intellicrack.core import BinaryAnalyzer
from intellicrack.ui import IntellicrackMainWindow
print('✓ Core modules loaded')

# Check critical dependencies
import frida
import angr
import capstone
import keystone
import unicorn
import pwntools
print('✓ Binary analysis tools loaded')

import torch
import tensorflow
print('✓ ML frameworks loaded')

print('\nInstallation successful!')
"
```

## Dependency Overview

Intellicrack includes 336+ carefully selected packages:

### Core Binary Analysis
- **angr** - Binary analysis framework
- **frida** - Dynamic instrumentation toolkit
- **capstone** - Multi-architecture disassembly framework
- **keystone-engine** - Multi-architecture assembler framework
- **unicorn** - CPU emulator framework
- **radare2** - Reverse engineering framework
- **pwntools** - CTF framework and exploit development
- **ROPgadget** - ROP chain generation

### Machine Learning & AI
- **torch** - PyTorch deep learning
- **tensorflow** - TensorFlow ML framework
- **transformers** - State-of-the-art NLP models
- **scikit-learn** - Machine learning algorithms
- **xgboost** - Gradient boosting

### Network & Protocol Analysis
- **scapy** - Packet manipulation
- **mitmproxy** - HTTPS proxy for analysis
- **pyshark** - Wireshark packet analysis
- **requests** - HTTP library
- **aiohttp** - Async HTTP client/server

### GUI & Visualization
- **PyQt6** - Modern Qt6 GUI framework
- **matplotlib** - Plotting library
- **plotly** - Interactive visualizations
- **pyqtgraph** - Scientific graphics

### Security & Cryptography
- **cryptography** - Cryptographic recipes
- **pycryptodome** - Cryptographic library
- **hashlib** - Secure hashes
- **pyOpenSSL** - OpenSSL wrapper

## Troubleshooting

### Common Issues and Solutions

#### 1. Python Version Mismatch
```powershell
# Error: Python 3.13 or other version detected
# Solution: Install Python 3.12 specifically
winget install Python.Python.3.12
```

#### 2. Missing Visual C++ Compiler
```powershell
# Error: Microsoft Visual C++ 14.0 or greater is required
# Solution: Install Build Tools
winget install Microsoft.VisualStudio.2022.BuildTools
```

#### 3. pip SSL Certificate Error
```powershell
# Temporary workaround (use with caution)
pip install --trusted-host pypi.org --trusted-host files.pythonhosted.org <package>

# Better solution: Update certificates
python -m pip install --upgrade certifi
```

#### 4. Memory Error During Installation
```powershell
# Install packages in smaller batches
pip install --no-cache-dir -e .
```

#### 5. Permission Denied Errors
```powershell
# Run PowerShell as Administrator
# Or install to user directory
pip install --user -e .
```

### Dependency Conflict Resolution

If you encounter dependency conflicts:

1. **Clear pip cache**:
   ```powershell
   pip cache purge
   # Or with uv
   uv cache clean
   ```

2. **Reinstall in fresh environment**:
   ```powershell
   # Remove old environment
   Remove-Item -Recurse -Force intellicrack_env

   # Create new environment
   python -m venv intellicrack_env
   .\intellicrack_env\Scripts\Activate.ps1
   pip install -e .
   ```

3. **Use constraint file** (if provided):
   ```powershell
   pip install -c constraints.txt -e .
   ```

## Package Management

### Updating Dependencies

```powershell
# Update all packages
pip install --upgrade -e .

# Update specific package
pip install --upgrade package_name

# Update pip itself
python -m pip install --upgrade pip
```

### Adding New Dependencies

Dependencies should be added to `pyproject.toml`:

```toml
[project]
dependencies = [
    "new_package>=1.0.0",
    # Add new dependency here
]
```

Then reinstall:
```powershell
pip install -e .
```

## CI/CD Configuration

For GitHub Actions, the workflow now uses:

```yaml
- name: Set up Python
  uses: actions/setup-python@v4
  with:
    python-version: '3.12'

- name: Install dependencies
  run: |
    python -m pip install --upgrade pip setuptools wheel
    pip install -e .
    pip install -e .[dev]
```

## File Structure

```
Intellicrack/
├── pyproject.toml          # All 336+ dependencies (single source of truth)
├── environment.yml         # Minimal config for CI/CD (Python 3.12 + pip only)
├── install.ps1            # Automated installation script
├── INSTALL.md             # This file
├── intellicrack/          # Source code
│   ├── core/             # Core binary analysis engine
│   ├── ui/               # Qt6 GUI components
│   ├── ai/               # ML/AI capabilities
│   └── utils/            # Utility functions
└── tests/                # Test suite
```

## Support

For installation issues:

1. **Check existing issues**: https://github.com/Zachanardo/Intellicrack/issues
2. **Verify Python 3.12**: `python --version`
3. **Review error logs**: Check `pip install -v` output
4. **Community Discord**: [Join for real-time help]

## License

Intellicrack is licensed under GPL-3.0. See LICENSE file for details.

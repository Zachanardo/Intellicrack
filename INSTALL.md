# Intellicrack Installation Guide

## Overview

Intellicrack uses a hybrid package management approach:
- **Mamba/Micromamba** for core scientific and system packages (better binary compatibility on Windows)
- **Pip** for specialized security/RE tools not available in conda-forge
- **Special installation** for PyTorch with Intel XPU support

## Prerequisites

1. **Windows 10/11** (primary platform)
2. **Python 3.10-3.13**
3. **Git** for cloning the repository
4. **Micromamba** or **Mambaforge** for environment management

## Installation Methods

### Method 1: Using Micromamba (Recommended)

#### Step 1: Install Micromamba

```powershell
# Download and install Micromamba for Windows
Invoke-WebRequest -Uri https://micro.mamba.pm/api/micromamba/win-64/latest -OutFile micromamba.tar.bz2
# Extract and add to PATH (or use installer from https://mamba.readthedocs.io)
```

#### Step 2: Create Environment from environment.yml

```powershell
# Clone the repository
git clone https://github.com/zacharyflint/intellicrack.git
cd intellicrack

# Create environment from file
micromamba env create -f environment.yml

# Activate the environment
micromamba activate intellicrack
```

#### Step 3: Install PyTorch with Intel XPU Support

```powershell
# CRITICAL: Must use specific index URL for Intel XPU
pip install torch==2.8.0 torchvision==0.23.0 torchaudio==2.8.0 --index-url https://download.pytorch.org/whl/xpu
```

#### Step 4: Verify Installation

```powershell
# Check environment is active
python --version  # Should show Python 3.10.x

# Verify PyTorch with XPU
python -c "import torch; print(f'PyTorch: {torch.__version__}'); print(f'XPU available: {torch.xpu.is_available()}')"

# Check for dependency conflicts
pip check
```

### Method 2: Manual Installation (If Micromamba Unavailable)

#### Step 1: Create Virtual Environment

```powershell
# Create Python virtual environment
python -m venv intellicrack_env
.\intellicrack_env\Scripts\activate
```

#### Step 2: Install Dependencies

```powershell
# Install all dependencies via pip (slower, may have build issues)
pip install -r requirements.txt

# Install PyTorch with Intel XPU
pip install torch==2.8.0 torchvision==0.23.0 torchaudio==2.8.0 --index-url https://download.pytorch.org/whl/xpu
```

### Method 3: Developer Installation (Editable)

```powershell
# After creating mamba environment
micromamba activate intellicrack

# Install in editable mode for development
pip install -e .

# Install development dependencies
micromamba install -c conda-forge --file environment-dev.yml
pip install -r requirements-dev.txt
```

## Package Management Strategy

### Mamba-Managed Packages (environment.yml)

These packages are installed via mamba/conda-forge for better binary compatibility:
- Core: numpy, pandas, scipy, scikit-learn
- ML/AI: transformers, tensorflow, onnx
- System: cryptography, capstone, lief
- GUI: PyQt6, pillow, pyqtgraph
- Web: requests, flask, fastapi

### Pip-Only Packages (requirements-pip.txt)

These specialized tools are only available via pip:
- Binary Analysis: angr, frida, r2pipe, volatility3
- Security: mitmproxy, scapy, pyshark
- RE Tools: keystone-engine, qiling, z3-solver

### Special Cases

**PyTorch with Intel XPU**: Always install separately with the Intel index URL:
```powershell
pip install torch==2.8.0 torchvision==0.23.0 torchaudio==2.8.0 --index-url https://download.pytorch.org/whl/xpu
```

## Updating Dependencies

### Update Mamba Packages
```powershell
micromamba update package_name
# Or update all
micromamba update --all
```

### Update Pip Packages
```powershell
pip install --upgrade package_name
# Or from requirements
pip install --upgrade -r requirements-pip.txt
```

### Resolving Conflicts

If you encounter dependency conflicts:

1. **Check current status**:
   ```powershell
   pip check
   micromamba list
   ```

2. **For MKL conflicts** (common with Intel packages):
   ```powershell
   pip uninstall mkl-dpcpp mkl-dpcpp-sycl
   ```

3. **Rebuild environment if needed**:
   ```powershell
   micromamba env remove -n intellicrack
   micromamba env create -f environment.yml
   ```

## CI/CD Integration

For GitHub Actions or other CI systems:

```yaml
- name: Setup Micromamba
  uses: mamba-org/setup-micromamba@v1
  with:
    environment-file: environment.yml
    environment-name: intellicrack

- name: Install PyTorch XPU
  run: |
    pip install torch==2.8.0 torchvision==0.23.0 torchaudio==2.8.0 --index-url https://download.pytorch.org/whl/xpu
```

## Troubleshooting

### Mamba not recognized in PowerShell
```powershell
# Initialize micromamba for PowerShell
C:\path\to\micromamba.exe shell init -s powershell
# Restart PowerShell
```

### PyTorch XPU not available
- Ensure Intel GPU drivers are installed
- Install Intel Extension for PyTorch if needed

### Build failures on Windows
- Use mamba for packages with C extensions (numpy, cryptography, etc.)
- Install Visual Studio Build Tools if required

## File Structure

```
intellicrack/
├── environment.yml          # Mamba/conda dependencies
├── requirements-pip.txt     # Pip-only dependencies
├── requirements/
│   └── base.txt            # Generated from pyproject.toml
├── pyproject.toml          # Package metadata (pip-only deps)
└── INSTALL.md              # This file
```

## Support

For installation issues:
1. Check existing issues: https://github.com/zacharyflint/intellicrack/issues
2. Verify all prerequisites are installed
3. Try the manual installation method as fallback
# Intellicrack Quick Start Guide

## First Time Setup (Windows)

```powershell
# 1. Install Mambaforge from https://github.com/conda-forge/miniforge

# 2. Clone and setup
git clone https://github.com/yourusername/intellicrack.git
cd intellicrack

# 3. Create mamba environment
mamba create -n intellicrack python=3.12 -y
mamba activate intellicrack

# 4. Install UV and dependencies
pip install uv
uv pip install -r requirements.txt

# 5. For Intel GPU support (Arc/Iris)
# Install PyTorch XPU version
uv pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/xpu
# Install IPEX
uv pip install intel-extension-for-pytorch==2.7.10+xpu --extra-index-url https://pytorch-extension.intel.com/release-whl/stable/xpu/us/
```

## First Time Setup (Linux)

```bash
# 1. Install Mambaforge
wget https://github.com/conda-forge/miniforge/releases/latest/download/Miniforge3-Linux-x86_64.sh
bash Miniforge3-Linux-x86_64.sh

# 2. Clone and setup
git clone https://github.com/yourusername/intellicrack.git
cd intellicrack

# 3. Create mamba environment
mamba create -n intellicrack python=3.12 -y
mamba activate intellicrack

# 4. Install UV and dependencies
pip install uv
uv pip install -r requirements.txt

# 5. For Intel GPU support (if applicable)
# See setup/INTEL_GPU_SETUP_GUIDE.md
```

## Daily Commands

```bash
# Activate environment (or use direnv for auto-activation)
mamba activate intellicrack

# Install new package
uv pip install package-name

# Run tests
pytest

# Format code
black .

# Lint
ruff check .

# Run application
python -m intellicrack

# Run with Intel GPU
python -m intellicrack --gpu intel
```

## Auto-Activation Setup

### Using direnv (Recommended - Cross-platform)

1. Install direnv:
   - Windows: `scoop install direnv` or `choco install direnv`
   - Linux/Mac: `curl -sfL https://direnv.net/install.sh | bash`

2. Hook into your shell (add to ~/.bashrc, ~/.zshrc, or PowerShell profile):
   ```bash
   # Bash
   eval "$(direnv hook bash)"
   
   # PowerShell
   Invoke-Expression (& direnv hook pwsh)
   ```

3. Allow the .envrc in project:
   ```bash
   cd /path/to/intellicrack
   direnv allow
   ```

Now the environment activates automatically when you enter the project!

### Alternative: Windows PowerShell Profile

Add to your `$PROFILE`:
```powershell
# Auto-activate when entering intellicrack directory
function prompt {
    if ($PWD.Path -like "*\intellicrack*") {
        if ($env:CONDA_DEFAULT_ENV -ne "intellicrack") {
            mamba activate intellicrack
        }
    }
    "PS $($PWD.Path)> "
}
```

## Project Structure
- `intellicrack/` - Main package
- `tests/` - Test files  
- `requirements/` - Dependencies
- `environment.yml` - Mamba config

## Need Help?
- Full guide: `DEVELOPMENT_SETUP.md`
- Project docs: `docs/`
# Intellicrack Requirements Structure

This directory contains the dependency management files for Intellicrack.

## Files

- **pyproject.toml** - Main project configuration with dependencies for Linux/WSL
- **pyproject_wsl.toml** - WSL-specific project configuration  
- **requirements.txt** - Pip-installable requirements (generated from pyproject.toml)
- **requirements_windows.txt** - Windows-specific requirements
- **requirements.lock** - Locked dependencies (pip format)
- **uv.lock** - UV package manager lock file for reproducible installs

## Installation

### For Development (with UV)

1. Install UV package manager:
   ```bash
   curl -LsSf https://astral.sh/uv/install.sh | sh  # Linux/WSL
   # or
   powershell -c "irm https://astral.sh/uv/install.ps1 | iex"  # Windows
   ```

2. Create virtual environment:
   ```bash
   # From project root
   uv venv .venv_wsl    # Linux/WSL
   uv venv .venv_windows  # Windows
   ```

3. Install dependencies:
   ```bash
   # From project root
   uv pip install -r requirements/requirements.txt
   ```

### For Intel GPU Support

Intel Arc GPU support requires a conda environment:

```bash
# Run from project root
dev\scripts\setup_intel_gpu.bat
```

Then launch with:
```bash
RUN_INTELLICRACK.bat --intel-gpu
```

## Note on Directory Location

The requirements files are in `/requirements/` instead of the project root to:
1. Keep the root directory clean
2. Support multiple requirement configurations (WSL, Windows, etc.)
3. Allow for future expansion with additional requirement sets

When cloning the project, developers should:
1. Check `/requirements/` for dependency files
2. Use UV with the lock file for reproducible builds
3. Follow platform-specific instructions above
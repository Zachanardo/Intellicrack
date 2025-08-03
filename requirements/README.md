# Intellicrack Requirements Structure

This directory contains dependency management files for the Intellicrack project.

## 🚀 **NEW STRUCTURE (August 2025)**

The project now uses a **modern, consolidated dependency management approach** with exact version pins for reproducible builds.

### **Canonical Files (Use These)**

- **`../pyproject.toml`** - **CANONICAL** project configuration (moved to root)
- **`requirements.lock`** - **PRODUCTION LOCK** with 364 exact pins (==) for reproducible builds

### **Legacy Files (Deprecated)**

- ~~`requirements.txt`~~ - **DEPRECATED** - Mixed pinning, inconsistent
- ~~`requirements_windows.txt`~~ - **DEPRECATED** - Content moved to requirements.lock
- `pyproject_wsl.toml` - **REFERENCE ONLY** - WSL/Linux variant (kept for comparison)

## ✅ **Installation Instructions**

### **Method 1: Standard Installation (Recommended)**

```bash
# From project root (C:\Intellicrack\)
pip install .
```

This uses the canonical `pyproject.toml` with modern PEP 518/621 standards.

### **Method 2: Exact Version Lock (Production)**

```bash
# From project root
pip install -r requirements/requirements.lock
```

This installs exactly the same versions as the working environment (364 exact pins).

### **Method 3: Development Installation**

```bash
# From project root  
pip install -e .[dev]
```

This installs Intellicrack in editable mode with development dependencies.

## 🔧 **Key Improvements**

1. **Reproducible Builds**: All 364 dependencies now use exact pins (`==`)
2. **Single Source**: `pyproject.toml` is the canonical dependency definition
3. **Modern Standards**: Uses PEP 518/621 for packaging
4. **Platform Support**: Proper Windows-specific conditions (`sys_platform`)
5. **Optional Extras**: Structured extras for `[dev]`, `[nvidia-gpu]`, `[ai-local]`

## 📋 **Migration Notes**

- **OLD**: Multiple conflicting requirements files
- **NEW**: Single `pyproject.toml` + exact `requirements.lock`
- **Benefit**: Eliminates "works-on-my-machine" dependency issues

## 🛠 **For Maintainers**

To update the lock file:

```bash
pip-tools pip-compile --generate-hashes --output-file=requirements/requirements.lock pyproject.toml
```

## 🔍 **Architecture Decision**

This structure eliminates the previous fragmentation where 5+ different files competed to define dependencies, causing installation failures and non-reproducible builds.
# Pixi Setup Guide

## Installation Options

### Local Development (Default - Intel XPU)
```bash
pixi install
```
**Uses `default` environment with Intel XPU support:**
- Installs Python 3.12, Rust, Node.js, and all dependencies
- Installs **Intel XPU PyTorch** (torch 2.8.0+xpu, torchvision, torchaudio)
- Runs linters installation
- **Default for local development on Intel hardware**

### CI/Testing (CPU-only)
```bash
pixi install --environment ci
```
**Uses `ci` environment without Intel XPU:**
- Installs Python 3.12, Rust, Node.js, and all dependencies
- Uses **CPU-only PyTorch** from PyPI (no Intel XPU packages)
- Compatible with GitHub Actions runners
- Runs linters installation

### Full Local Setup (Intel XPU + Rust Launcher)
```bash
pixi run setup-local
```
- Everything from default environment, PLUS:
- Installs **Intel Extension for PyTorch** (IPEX 2.8.10+xpu)
- Builds **Rust launcher** in release mode
- Creates **Intellicrack.lnk** desktop shortcut with icon
- Runs XPU sanity test

## Individual Tasks

### Intel XPU PyTorch (local only)
```bash
pixi run install-intel-xpu
```
Installs Intel XPU-optimized PyTorch and runs hardware detection test.

### Rust Launcher Build
```bash
pixi run build-rust-launcher
```
Builds release Rust launcher and creates desktop shortcut.

### Linters
```bash
pixi run install-linters
```
Installs ESLint and markdownlint via npm.

## PyTorch Configuration

Pixi uses **environment features** to manage PyTorch versions:

| Environment | PyTorch Source | Use Case |
|-------------|----------------|----------|
| **default** | Intel XPU (from Intel index) | Local development on Intel hardware |
| **ci** | CPU PyTorch (from PyPI) | GitHub Actions, testing on any hardware |

## GitHub Actions Compatibility

GitHub Actions workflows use `pixi install --environment ci` which:
- ✅ Works on runners without Intel XPU hardware
- ✅ Installs CPU-compatible PyTorch automatically from PyPI
- ✅ Skips Intel XPU packages that require specific hardware
- ✅ Completes in reasonable time
- ✅ Uses same dependencies as local dev (except PyTorch variant)

## Troubleshooting

**"No XPU devices detected"**: Normal on non-Intel hardware. Use `pixi install` for CPU-only setup.

**"Failed to build Rust launcher"**: Missing dlltool. Install via `pixi run setup-local` or build manually.

**CI failures**: Ensure workflow uses `pixi install` (not `pixi run setup-local`).

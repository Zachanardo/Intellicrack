# Installation and Setup Guide

## System Requirements

### Minimum Requirements

- **Operating System**: Windows 11 Pro/Enterprise
- **Python**: Version 3.8 or higher
- **RAM**: 4GB minimum, 8GB recommended
- **Storage**: 500MB free space for installation and analysis files
- **Display**: 1280x720 minimum resolution (for GUI)

### Recommended Requirements

- **Python**: Version 3.9 or higher
- **RAM**: 16GB or more
- **CPU**: Multi-core processor (4+ cores)
- **GPU**: NVIDIA/AMD GPU with CUDA support (optional, for ML features)

## Installation Methods

### Method 1: From Source (Recommended)

1. **Clone the repository:**
   ```bash
   git clone https://github.com/your-repo/intellicrack.git
   cd intellicrack
   ```

2. **Create virtual environment (optional but recommended):**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install core dependencies:**
   ```bash
   pip install psutil requests pefile capstone keystone unicorn lief yara cryptography
   ```

### Method 2: Using Requirements File

If a `requirements.txt` file is available:
```bash
pip install -r requirements.txt
```

### Method 3: Full Installation with GUI

For complete installation including GUI and optional features:
```bash
# Core dependencies
pip install psutil requests pefile capstone keystone unicorn lief yara cryptography

# GUI dependencies
pip install PyQt6

# Optional analysis tools
pip install numpy scikit-learn matplotlib networkx frida angr
```

## Platform-Specific Setup

### Windows

1. **Install Python 3.8+** from [python.org](https://python.org)
2. **Add Python to PATH** during installation
3. **Install Microsoft Visual C++ Redistributable** (required for some dependencies)
4. **For Frida support:** Install Frida tools:
   ```bash
   pip install frida-tools
   ```


## Optional Components Setup

### Machine Learning Features

```bash
pip install numpy scikit-learn matplotlib
```

### Dynamic Analysis (Frida)

```bash
pip install frida frida-tools
```

### Symbolic Execution (Angr)

```bash
pip install angr
```


### Development Tools

```bash
pip install pytest black flake8 mypy
```

## Verification

After installation, verify the setup:

1. **Check Python version:**
   ```bash
   python --version
   ```

2. **Verify core imports:**
   ```bash
   python -c "import psutil, requests, pefile, capstone"
   ```

3. **Test GUI (if installed):**
   ```bash
   python -c "import PyQt6"
   ```

## Running Intellicrack

1. **Navigate to installation directory:**
   ```bash
   cd /path/to/intellicrack
   ```

2. **Activate virtual environment (if used):**
   ```bash
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Launch the application:**
   ```bash
   python main.py
   ```

4. **On first run:**
   - The application will perform startup checks
   - Dependencies will be verified
   - GUI will launch if available

## Troubleshooting Installation

### Common Issues

1. **Permission Errors:**
   ```bash
   pip install --user <package>  # Install to user directory
   ```

2. **Compilation Errors:**
   ```batch
   REM Install Visual C++ Build Tools
   winget install Microsoft.VisualStudio.2022.BuildTools
   ```

3. **Qt Platform Issues:**
   - Ensure graphics drivers are up to date
   - Install latest Visual C++ Redistributables

4. **GPU Issues:**
   - For Intel Arc: Force software rendering with `QT_OPENGL=software`
   - For NVIDIA: Install CUDA toolkit if using GPU features

### Dependency Conflicts

If you encounter conflicts:
```bash
pip install --upgrade pip
pip install --force-reinstall <conflicting-package>
```

### Firewall/Antivirus

Some antivirus software may flag the application. Add exceptions for:
- The Intellicrack installation directory
- Python executable
- Analysis tools (Frida, etc.)

## Configuration

After installation, you can configure Intellicrack by:
- Editing `utils/config.py`
- Using the Settings tab in the GUI
- Setting environment variables

## Updating

To update Intellicrack:
```bash
git pull origin main
pip install --upgrade <updated-dependencies>
```

## Uninstalling

To uninstall:
```bash
pip uninstall psutil requests pefile capstone keystone unicorn lief yara cryptography PyQt6
rm -rf /path/to/intellicrack  # Remove source directory
```

## Support

If you encounter issues during installation:
- Check the [FAQ](../faq.md) for common solutions
- Review the logs in `logs/` directory
- Ensure your system meets minimum requirements
- Try installing in a clean virtual environment

For additional help, refer to the [Getting Started Guide](../user-guide/getting-started.md).

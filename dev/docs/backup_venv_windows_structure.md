# Windows Virtual Environment Structure Analysis

## Python Version and Configuration
- **Python Version**: 3.11.9
- **Base Python Location**: C:\Python311
- **Virtual Environment Path**: C:\Intellicrack\venv_windows
- **Include System Site-Packages**: false
- **Executable**: C:\Python311\python.exe

## Special Package Configurations

### pypykatz-0.6.11 Configuration
**Distribution Info Location**: `/venv_windows/pypykatz-0.6.11.dist-info/`
- METADATA file present with version 0.6.11
- RECORD file present

**Module Location**: `/venv_windows/Lib/site-packages/pypykatz/`
- Full module directory with complete implementation
- Contains: __init__.py, __main__.py, pypykatz.py, and multiple subdirectories
- Subdirectories: alsadecryptor, commons, dpapi, example, kerberos, ldap, lsadecryptor, parsers, plugins, rdp, registry, remote, smb, utils

### python_fx-0.3.2 Configuration
**Shim Location**: `/venv_windows/python_fx/`
- Custom compatibility shim implementation
- __init__.py with minimal Fx class implementation
- Basic pipe and apply function implementations

**Distribution Info Location**: `/venv_windows/python_fx-0.3.2.dist-info/`
- METADATA: Name: python-fx, Version: 0.3.2, Summary: Fake python-fx for compatibility
- top_level.txt: contains "python_fx"

## Directory Structure

### Root Level (venv_windows/)
```
Include/
Lib/
Scripts/
bin/
pypykatz-0.6.11.dist-info/
python_fx/
python_fx-0.3.2.dist-info/
pyvenv.cfg
readme.rst
share/
```

### Include Directory
```
Include/
└── site/
    └── python3.11/
```

### Scripts Directory
Contains 400+ executable files including:
- Python executables: python.exe, pythonw.exe
- Activation scripts: activate.bat, Activate.ps1, deactivate.bat
- Package entry points: pypykatz.exe, pip.exe, etc.
- Development tools: black.exe, pylint.exe, pytest.exe, etc.

### bin Directory
- z3.exe (Z3 theorem prover)

### share Directory
```
share/
├── doc/
└── man/
```

## Notable Package Structure Differences

1. **pypykatz** is installed as a full package in site-packages (not just a shim)
2. **python_fx** is implemented as a custom shim in the root venv directory
3. Both packages have proper dist-info directories for pip management
4. The virtual environment includes both Windows (.exe) and Unix-style executables

## Virtual Environment Isolation
- System site-packages are excluded (include-system-site-packages = false)
- Complete isolation from system Python installation
- All dependencies contained within the virtual environment
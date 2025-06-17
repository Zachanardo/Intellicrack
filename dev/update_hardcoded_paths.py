#!/usr/bin/env python3
"""
Update all hardcoded paths in dependency scripts to use dynamic discovery.

This script updates batch files and PowerShell scripts to use the new
path discovery system instead of hardcoded paths.
"""

import os
import re
import sys

def update_dependency_scripts():
    """Update all dependency scripts to use dynamic path discovery."""
    
    # Path to the dependencies directory
    deps_dir = os.path.join(os.path.dirname(__file__), 'dependencies')
    
    updates = {
        # Pattern to replace -> Replacement
        r'C:\\Program Files\\Ghidra\\ghidraRun\.bat': '%GHIDRA_PATH%',
        r'C:\\ghidra\\ghidraRun\.bat': '%GHIDRA_PATH%',
        r'C:\\Tools\\ghidra\\ghidraRun\.bat': '%GHIDRA_PATH%',
        r'C:\\Program Files\\Docker\\Docker\\resources\\bin\\docker\.exe': '%DOCKER_PATH%',
        r'C:\\Program Files\\Git\\bin\\git\.exe': '%GIT_PATH%',
        r'C:\\Program Files\\Python311\\python\.exe': '%PYTHON_PATH%',
        r'C:\\Program Files\\Wireshark\\Wireshark\.exe': '%WIRESHARK_PATH%',
        r'C:\\Program Files\\qemu\\qemu-system-x86_64\.exe': '%QEMU_PATH%',
        r'C:\\Program Files\\wkhtmltopdf\\bin\\wkhtmltopdf\.exe': '%WKHTMLTOPDF_PATH%',
        r'C:\\Program Files\\NVIDIA GPU Computing Toolkit\\CUDA\\v11\.8': '%CUDA_PATH%',
    }
    
    # Process batch files
    for filename in os.listdir(deps_dir):
        if filename.endswith('.bat') or filename.endswith('.ps1'):
            filepath = os.path.join(deps_dir, filename)
            
            # Read file content
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Check if file needs updating
            original_content = content
            
            # Apply replacements
            for pattern, replacement in updates.items():
                content = re.sub(pattern, replacement, content, flags=re.IGNORECASE)
            
            # Only write if changed
            if content != original_content:
                print(f"Updating {filename}...")
                
                # Create backup
                backup_path = filepath + '.bak'
                with open(backup_path, 'w', encoding='utf-8') as f:
                    f.write(original_content)
                
                # Write updated content
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(content)
                
                print(f"  - Created backup: {backup_path}")
                print(f"  - Updated: {filepath}")
    
    # Create a path discovery wrapper script
    wrapper_script = """@echo off
REM Path Discovery Wrapper for Intellicrack Dependencies
REM This script sets up environment variables using dynamic path discovery

echo Setting up tool paths using dynamic discovery...

REM Run Python path discovery
python -c "from intellicrack.utils.core.path_discovery import find_tool, get_cuda_path; import os; print('SET GHIDRA_PATH=' + (find_tool('ghidra') or '')); print('SET RADARE2_PATH=' + (find_tool('radare2') or '')); print('SET PYTHON_PATH=' + (find_tool('python') or '')); print('SET DOCKER_PATH=' + (find_tool('docker') or '')); print('SET GIT_PATH=' + (find_tool('git') or '')); print('SET WIRESHARK_PATH=' + (find_tool('wireshark') or '')); print('SET QEMU_PATH=' + (find_tool('qemu') or '')); print('SET WKHTMLTOPDF_PATH=' + (find_tool('wkhtmltopdf') or '')); print('SET CUDA_PATH=' + (get_cuda_path() or ''))" > %TEMP%\\paths.bat

REM Execute the generated path settings
call %TEMP%\\paths.bat
del %TEMP%\\paths.bat

REM Display discovered paths
echo.
echo Discovered paths:
echo   GHIDRA_PATH=%GHIDRA_PATH%
echo   RADARE2_PATH=%RADARE2_PATH%
echo   PYTHON_PATH=%PYTHON_PATH%
echo   DOCKER_PATH=%DOCKER_PATH%
echo   GIT_PATH=%GIT_PATH%
echo   WIRESHARK_PATH=%WIRESHARK_PATH%
echo   QEMU_PATH=%QEMU_PATH%
echo   WKHTMLTOPDF_PATH=%WKHTMLTOPDF_PATH%
echo   CUDA_PATH=%CUDA_PATH%
echo.
"""
    
    wrapper_path = os.path.join(deps_dir, 'setup_paths.bat')
    with open(wrapper_path, 'w', encoding='utf-8') as f:
        f.write(wrapper_script)
    
    print(f"\nCreated path discovery wrapper: {wrapper_path}")
    print("\nDependency scripts can now use environment variables instead of hardcoded paths.")
    print("Run 'setup_paths.bat' before running dependency installers to set up paths dynamically.")

if __name__ == '__main__':
    update_dependency_scripts()
    print("\nPath update complete!")
#!/usr/bin/env python3
"""
Fix tool path mismatches between Install.ps1 and Intellicrack expectations.

This script updates the intellicrack_config.json file with the actual paths
where tools were installed by Install.ps1.
"""

import json
import os
import sys
import subprocess
import shutil
from pathlib import Path


def find_ghidra_installation():
    """Find Ghidra installation from various sources."""

    # 1. Check GHIDRA_HOME environment variable (set by Install.ps1)
    ghidra_home = os.environ.get('GHIDRA_HOME')
    if ghidra_home and os.path.exists(ghidra_home):
        ghidra_run = os.path.join(ghidra_home, 'ghidraRun.bat')
        if os.path.exists(ghidra_run):
            print(f"Found Ghidra via GHIDRA_HOME: {ghidra_run}")
            return ghidra_run

    # 2. Check Chocolatey installation path
    choco_ghidra = r"C:\ProgramData\chocolatey\lib\ghidra\tools"
    if os.path.exists(choco_ghidra):
        # Find the ghidra_* directory
        for item in os.listdir(choco_ghidra):
            if item.startswith('ghidra_') and os.path.isdir(os.path.join(choco_ghidra, item)):
                ghidra_run = os.path.join(choco_ghidra, item, 'ghidraRun.bat')
                if os.path.exists(ghidra_run):
                    print(f"Found Ghidra via Chocolatey: {ghidra_run}")
                    return ghidra_run

    # 3. Check direct download location (tools folder)
    tools_ghidra = r"C:\Intellicrack\tools\ghidra"
    if os.path.exists(tools_ghidra):
        for item in os.listdir(tools_ghidra):
            if item.startswith('ghidra_') and os.path.isdir(os.path.join(tools_ghidra, item)):
                ghidra_run = os.path.join(tools_ghidra, item, 'ghidraRun.bat')
                if os.path.exists(ghidra_run):
                    print(f"Found Ghidra in tools folder: {ghidra_run}")
                    return ghidra_run

    # 4. Check default installation paths
    default_paths = [
        r"C:\Program Files\Ghidra\ghidraRun.bat",
        r"C:\ghidra\ghidraRun.bat",
        r"C:\Tools\ghidra\ghidraRun.bat"
    ]

    for path in default_paths:
        if os.path.exists(path):
            print(f"Found Ghidra at default location: {path}")
            return path

    print("WARNING: Ghidra installation not found!")
    return None


def find_radare2_installation():
    """Find radare2 installation from various sources."""

    # 1. Check if r2 is in PATH (Chocolatey adds it)
    try:
        result = subprocess.run(['where', 'r2'], capture_output=True, text=True)
        if result.returncode == 0:
            r2_path = result.stdout.strip().split('\n')[0]
            if os.path.exists(r2_path):
                print(f"Found radare2 in PATH: {r2_path}")
                return r2_path
    except:
        pass

    # 2. Check R2_HOME environment variable
    r2_home = os.environ.get('R2_HOME')
    if r2_home:
        r2_exe = os.path.join(r2_home, 'bin', 'radare2.exe')
        if os.path.exists(r2_exe):
            print(f"Found radare2 via R2_HOME: {r2_exe}")
            return r2_exe

    # 3. Check Chocolatey installation
    choco_r2_paths = [
        r"C:\ProgramData\chocolatey\bin\r2.exe",
        r"C:\ProgramData\chocolatey\lib\radare2\tools\radare2\bin\radare2.exe"
    ]

    for path in choco_r2_paths:
        if os.path.exists(path):
            print(f"Found radare2 via Chocolatey: {path}")
            return path

    # 4. Check direct download location (tools folder)
    tools_r2 = r"C:\Intellicrack\tools\radare2"
    if os.path.exists(tools_r2):
        r2_exe = os.path.join(tools_r2, "bin", "radare2.exe")
        if os.path.exists(r2_exe):
            print(f"Found radare2 in tools folder: {r2_exe}")
            return r2_exe

    # 5. Check bundled location (expected by Intellicrack)
    script_dir = os.path.dirname(os.path.abspath(__file__))
    bundled_r2 = os.path.join(script_dir, "radare2", "radare2-5.9.8-w64", "bin", "radare2.exe")
    if os.path.exists(bundled_r2):
        print(f"Found bundled radare2: {bundled_r2}")
        return bundled_r2

    print("WARNING: radare2 installation not found!")
    return None


def find_docker_installation():
    """Find Docker installation."""
    # Check if docker is in PATH
    docker_path = shutil.which('docker')
    if docker_path:
        print(f"Found Docker in PATH: {docker_path}")
        return docker_path

    # Check standard Docker Desktop installation paths
    docker_paths = [
        r"C:\Program Files\Docker\Docker\resources\bin\docker.exe",
        r"C:\Program Files\Docker\Docker\Docker Desktop.exe"
    ]

    for path in docker_paths:
        if os.path.exists(path):
            print(f"Found Docker at: {path}")
            return path

    print("WARNING: Docker installation not found!")
    return None


def find_git_installation():
    """Find Git installation."""
    # Check if git is in PATH
    git_path = shutil.which('git')
    if git_path:
        print(f"Found Git in PATH: {git_path}")
        return git_path

    # Check standard Git installation paths
    git_paths = [
        r"C:\Program Files\Git\bin\git.exe",
        r"C:\Program Files (x86)\Git\bin\git.exe"
    ]

    for path in git_paths:
        if os.path.exists(path):
            print(f"Found Git at: {path}")
            return path

    print("WARNING: Git installation not found!")
    return None


def find_qemu_installation():
    """Find QEMU installation."""
    # Check if qemu-system-x86_64 is in PATH
    qemu_path = shutil.which('qemu-system-x86_64')
    if qemu_path:
        print(f"Found QEMU in PATH: {qemu_path}")
        return qemu_path

    # Check Chocolatey installation
    choco_qemu = r"C:\ProgramData\chocolatey\lib\qemu\tools"
    if os.path.exists(choco_qemu):
        qemu_exe = os.path.join(choco_qemu, "qemu-system-x86_64.exe")
        if os.path.exists(qemu_exe):
            print(f"Found QEMU via Chocolatey: {qemu_exe}")
            return qemu_exe

    # Check standard QEMU installation paths
    qemu_paths = [
        r"C:\Program Files\qemu\qemu-system-x86_64.exe",
        r"C:\qemu\qemu-system-x86_64.exe"
    ]

    for path in qemu_paths:
        if os.path.exists(path):
            print(f"Found QEMU at: {path}")
            return path

    print("WARNING: QEMU installation not found!")
    return None


def find_wireshark_installation():
    """Find Wireshark installation."""
    # Check standard Wireshark installation paths
    wireshark_paths = [
        r"C:\Program Files\Wireshark\Wireshark.exe",
        r"C:\Program Files (x86)\Wireshark\Wireshark.exe"
    ]

    for path in wireshark_paths:
        if os.path.exists(path):
            print(f"Found Wireshark at: {path}")
            return path

    # Check for tshark (command line version)
    tshark_paths = [
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe"
    ]

    for path in tshark_paths:
        if os.path.exists(path):
            print(f"Found tshark at: {path}")
            return path

    print("WARNING: Wireshark installation not found!")
    return None


def find_python_installation():
    """Find Python installation."""
    # Check current Python executable
    current_python = sys.executable
    if current_python and os.path.exists(current_python):
        print(f"Found current Python: {current_python}")
        return current_python

    # Check if python is in PATH
    python_path = shutil.which('python')
    if python_path:
        print(f"Found Python in PATH: {python_path}")
        return python_path

    # Check standard Python installation paths
    python_paths = [
        r"C:\Python311\python.exe",
        r"C:\Program Files\Python311\python.exe",
        r"C:\Program Files (x86)\Python311\python.exe"
    ]

    for path in python_paths:
        if os.path.exists(path):
            print(f"Found Python at: {path}")
            return path

    print("WARNING: Python installation not found!")
    return None


def update_config_file(config_path="intellicrack_config.json"):
    """Update the configuration file with correct tool paths."""

    # Load existing config or create new one
    config = {}
    if os.path.exists(config_path):
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
            print(f"Loaded existing config from {config_path}")
        except Exception as e:
            print(f"Error loading config: {e}")
            config = {}

    # Find and update all tool paths
    print("\nDetecting all installed tools...")

    ghidra_path = find_ghidra_installation()
    if ghidra_path:
        config['ghidra_path'] = ghidra_path
        print(f"Updated ghidra_path: {ghidra_path}")

    radare2_path = find_radare2_installation()
    if radare2_path:
        config['radare2_path'] = radare2_path
        print(f"Updated radare2_path: {radare2_path}")

    docker_path = find_docker_installation()
    if docker_path:
        config['docker_path'] = docker_path
        print(f"Updated docker_path: {docker_path}")

    git_path = find_git_installation()
    if git_path:
        config['git_path'] = git_path
        print(f"Updated git_path: {git_path}")

    qemu_path = find_qemu_installation()
    if qemu_path:
        config['qemu_path'] = qemu_path
        print(f"Updated qemu_path: {qemu_path}")

    wireshark_path = find_wireshark_installation()
    if wireshark_path:
        config['wireshark_path'] = wireshark_path
        print(f"Updated wireshark_path: {wireshark_path}")

    python_path = find_python_installation()
    if python_path:
        config['python_path'] = python_path
        print(f"Updated python_path: {python_path}")

    # Frida should work via pip install
    config['frida_path'] = 'frida'

    # Add tool and data directories
    config['tools_directory'] = r'C:\Intellicrack\tools'
    config['data_directory'] = r'C:\Intellicrack\data'
    config['plugins_directory'] = r'C:\Intellicrack\plugins'
    config['logs_directory'] = r'C:\Intellicrack\logs'

    # Save updated config
    try:
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=2)
        print(f"\nSuccessfully updated {config_path}")
        return True
    except Exception as e:
        print(f"Error saving config: {e}")
        return False


def create_path_discovery_patch():
    """Create a patch for config.py to add dynamic path discovery."""

    patch_content = '''
# Dynamic path discovery for tools
def find_tool_path(tool_name, default_path):
    """Dynamically find tool installation path."""

    if tool_name == "ghidra":
        # Check GHIDRA_HOME first
        ghidra_home = os.environ.get('GHIDRA_HOME')
        if ghidra_home:
            ghidra_run = os.path.join(ghidra_home, 'ghidraRun.bat' if os.name == 'nt' else 'ghidraRun')
            if os.path.exists(ghidra_run):
                return ghidra_run

        # Check Chocolatey
        choco_path = r"C:\\ProgramData\\chocolatey\\lib\\ghidra\\tools"
        if os.path.exists(choco_path):
            for item in os.listdir(choco_path):
                if item.startswith('ghidra_'):
                    ghidra_run = os.path.join(choco_path, item, 'ghidraRun.bat')
                    if os.path.exists(ghidra_run):
                        return ghidra_run

    elif tool_name == "radare2":
        # Check if r2 is in PATH
        import shutil
        r2_path = shutil.which('r2')
        if r2_path:
            return r2_path

        # Check R2_HOME
        r2_home = os.environ.get('R2_HOME')
        if r2_home:
            r2_exe = os.path.join(r2_home, 'bin', 'radare2.exe' if os.name == 'nt' else 'radare2')
            if os.path.exists(r2_exe):
                return r2_exe

    # Return default if nothing found
    return default_path

# Update DEFAULT_CONFIG to use dynamic discovery
DEFAULT_CONFIG["ghidra_path"] = find_tool_path("ghidra", DEFAULT_CONFIG["ghidra_path"])
DEFAULT_CONFIG["radare2_path"] = find_tool_path("radare2", DEFAULT_CONFIG["radare2_path"])
'''

    with open("config_path_discovery.patch", "w") as f:
        f.write(patch_content)
    print("Created config_path_discovery.patch for dynamic path discovery")


if __name__ == "__main__":
    print("Tool Path Fixer for Intellicrack")
    print("=" * 50)

    # Update the config file
    if update_config_file():
        print("\n✅ Configuration updated successfully!")
        print("Intellicrack should now find the tools installed by Install.ps1")
    else:
        print("\n❌ Failed to update configuration")
        print("You may need to manually edit intellicrack_config.json")

    # Optionally create the patch file
    print("\nCreating path discovery patch...")
    create_path_discovery_patch()

    print("\nDone!")
#!/usr/bin/env python3
"""
Fix tool paths after installation to match actual locations.
This script updates intellicrack_config.json with the correct paths
for tools installed by Install.ps1 (Chocolatey) or other methods.
"""

import json
import os
import sys
import subprocess
from pathlib import Path

def find_ghidra():
    """Find Ghidra installation path."""
    paths_to_check = [
        # Chocolatey installation
        r"C:\ProgramData\chocolatey\lib\ghidra\tools",
        # Standard installation
        r"C:\Program Files\Ghidra",
        # Environment variable
        os.environ.get("GHIDRA_HOME", ""),
    ]
    
    for base_path in paths_to_check:
        if not base_path or not os.path.exists(base_path):
            continue
            
        # Look for ghidraRun.bat
        if base_path.endswith("tools"):
            # Chocolatey structure: tools/ghidra_11.0_PUBLIC/ghidraRun.bat
            for subdir in os.listdir(base_path):
                ghidra_run = os.path.join(base_path, subdir, "ghidraRun.bat")
                if os.path.exists(ghidra_run):
                    return ghidra_run
        else:
            # Direct structure: Ghidra/ghidraRun.bat
            ghidra_run = os.path.join(base_path, "ghidraRun.bat")
            if os.path.exists(ghidra_run):
                return ghidra_run
    
    return None

def find_radare2():
    """Find Radare2 installation path."""
    paths_to_check = [
        # Bundled with Intellicrack
        os.path.join(os.path.dirname(__file__), "..", "radare2", "radare2-5.9.8-w64", "bin", "radare2.exe"),
        # Chocolatey installation
        r"C:\ProgramData\chocolatey\bin\r2.exe",
        r"C:\ProgramData\chocolatey\lib\radare2\tools\radare2\bin\radare2.exe",
        # System PATH
        "r2.exe",
        "radare2.exe",
    ]
    
    for path in paths_to_check:
        if path in ["r2.exe", "radare2.exe"]:
            # Check if in PATH
            try:
                result = subprocess.run(["where", path], capture_output=True, text=True)
                if result.returncode == 0:
                    return result.stdout.strip().split('\n')[0]
            except:
                pass
        elif os.path.exists(path):
            return os.path.abspath(path)
    
    return None

def find_qemu():
    """Find QEMU installation."""
    # Check if qemu-system-x86_64 is in PATH
    try:
        result = subprocess.run(["where", "qemu-system-x86_64"], capture_output=True, text=True)
        if result.returncode == 0:
            return os.path.dirname(result.stdout.strip().split('\n')[0])
    except:
        pass
    
    # Check common installation paths
    paths_to_check = [
        r"C:\Program Files\qemu",
        r"C:\Program Files (x86)\qemu",
    ]
    
    for path in paths_to_check:
        if os.path.exists(os.path.join(path, "qemu-system-x86_64.exe")):
            return path
    
    return None

def update_config():
    """Update intellicrack_config.json with correct tool paths."""
    config_path = os.path.join(os.path.dirname(__file__), "..", "intellicrack_config.json")
    
    # Load existing config or create new one
    if os.path.exists(config_path):
        with open(config_path, 'r') as f:
            config = json.load(f)
    else:
        config = {}
    
    # Find tools
    print("Searching for installed tools...")
    
    ghidra_path = find_ghidra()
    if ghidra_path:
        print(f"✓ Found Ghidra: {ghidra_path}")
        config["ghidra_path"] = ghidra_path
    else:
        print("✗ Ghidra not found")
    
    radare2_path = find_radare2()
    if radare2_path:
        print(f"✓ Found Radare2: {radare2_path}")
        config["radare2_path"] = radare2_path
    else:
        print("✗ Radare2 not found")
    
    qemu_path = find_qemu()
    if qemu_path:
        print(f"✓ Found QEMU: {qemu_path}")
        config["qemu_path"] = qemu_path
    else:
        print("✗ QEMU not found")
    
    # Ensure frida is set (it's installed via pip)
    config["frida_path"] = "frida"
    print("✓ Frida: Using pip-installed version")
    
    # Write updated config
    with open(config_path, 'w') as f:
        json.dump(config, f, indent=4)
    
    print(f"\nConfiguration updated: {config_path}")
    
    # Also update C:\Intellicrack\config\intellicrack.json if it exists
    system_config = r"C:\Intellicrack\config\intellicrack.json"
    if os.path.exists(system_config):
        print(f"\nUpdating system config: {system_config}")
        with open(system_config, 'r') as f:
            sys_config = json.load(f)
        
        if "tools" not in sys_config:
            sys_config["tools"] = {}
            
        if ghidra_path:
            sys_config["tools"]["ghidra"] = os.path.dirname(ghidra_path)
        if radare2_path:
            sys_config["tools"]["radare2"] = os.path.dirname(radare2_path)
        if qemu_path:
            sys_config["tools"]["qemu"] = qemu_path
            
        with open(system_config, 'w') as f:
            json.dump(sys_config, f, indent=4)
        
        print("✓ System configuration updated")

def main():
    print("Intellicrack Tool Path Fixer")
    print("=" * 40)
    update_config()
    print("\nTool path configuration complete!")
    print("\nIf any tools were not found, please install them and run this script again.")

if __name__ == "__main__":
    main()
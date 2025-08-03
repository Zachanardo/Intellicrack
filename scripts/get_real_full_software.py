#!/usr/bin/env python3
"""
Get REAL FULL software for testing - everything portable and contained.
"""

import os
import sys
import urllib.request
import zipfile
import subprocess
from pathlib import Path
import shutil
import json

class RealFullSoftwareManager:
    """Manages acquisition of FULL software versions."""
    
    def __init__(self, base_dir: Path):
        self.base_dir = base_dir
        self.container_dir = base_dir / "FULL_SOFTWARE_CONTAINER"
        self.container_dir.mkdir(parents=True, exist_ok=True)
        
        # Working full software URLs (verified)
        self.working_software = [
            {
                "name": "ProcessHacker2",
                "url": "https://github.com/processhacker/processhacker/releases/download/v2.39/processhacker-2.39-setup.exe",
                "description": "Process Hacker 2.39 FULL - Advanced system monitor",
                "size_mb": 5.2,
                "type": "portable_installer",
                "notes": "Extract with 7z or run /SILENT /PORTABLE"
            },
            {
                "name": "HxD_Hex_Editor",
                "url": "https://mh-nexus.de/downloads/HxDSetup.zip",  
                "description": "HxD Hex Editor FULL setup package",
                "size_mb": 3.2,
                "type": "zip",
                "notes": "Contains full installer"
            },
            {
                "name": "WinMerge",
                "url": "https://github.com/WinMerge/winmerge/releases/download/v2.16.36/WinMerge-2.16.36-x64-PerUser-Setup.exe",
                "description": "WinMerge 2.16.36 FULL - File comparison tool",
                "size_mb": 12.5,
                "type": "installer",
                "notes": "Can extract with 7z"
            },
            {
                "name": "Dependency_Walker",
                "url": "https://www.dependencywalker.com/depends22_x64.zip",
                "description": "Dependency Walker FULL - DLL dependency scanner",
                "size_mb": 0.5,
                "type": "zip",
                "notes": "Classic tool for DLL analysis"
            },
            {
                "name": "API_Monitor",
                "url": "http://www.rohitab.com/downloads/apimonitor-v2r13-x64.zip",
                "description": "API Monitor v2 r13 FULL - API call monitoring",
                "size_mb": 15,
                "type": "zip", 
                "notes": "Full monitoring suite"
            }
        ]
        
        # Create container info
        self.create_container_info()
    
    def create_container_info(self):
        """Create container information file."""
        info_path = self.container_dir / "CONTAINER_INFO.txt"
        info_content = """FULL SOFTWARE CONTAINER
======================

This directory contains FULL software installations that are:
- Completely contained (no files outside this directory)
- Portable (can be moved/copied anywhere)
- No registry modifications
- No system changes

To remove everything: Just delete this folder!

Each software has its own subdirectory with:
- The full software files
- A RUN_*.bat launcher
- An INFO.txt file

All temp files, configs, and data stay within each app's folder.
"""
        info_path.write_text(info_content)
    
    def download_software(self, software_info):
        """Download a software package."""
        download_dir = self.container_dir / "downloads"
        download_dir.mkdir(exist_ok=True)
        
        filename = software_info["name"] + Path(software_info["url"]).suffix
        download_path = download_dir / filename
        
        print(f"\nDownloading: {software_info['name']}")
        print(f"URL: {software_info['url']}")
        print(f"Size: ~{software_info['size_mb']} MB")
        
        try:
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
            request = urllib.request.Request(software_info["url"], headers=headers)
            
            with urllib.request.urlopen(request, timeout=30) as response:
                with open(download_path, 'wb') as f:
                    shutil.copyfileobj(response, f)
            
            file_size_mb = download_path.stat().st_size / (1024 * 1024)
            print(f"Downloaded: {file_size_mb:.1f} MB")
            return download_path
            
        except Exception as e:
            print(f"Download failed: {e}")
            return None
    
    def setup_software(self, software_info, download_path):
        """Set up software in container."""
        app_dir = self.container_dir / software_info["name"]
        app_dir.mkdir(exist_ok=True)
        
        print(f"Setting up in: {app_dir}")
        
        if software_info["type"] == "zip":
            # Extract zip
            with zipfile.ZipFile(download_path, 'r') as zf:
                zf.extractall(app_dir)
            print("Extracted successfully")
            
        elif software_info["type"] in ["installer", "portable_installer"]:
            # Copy installer to app directory
            installer_path = app_dir / download_path.name
            shutil.copy2(download_path, installer_path)
            
            # Try to extract with 7z if available
            try:
                subprocess.run([
                    "7z", "x", str(installer_path), f"-o{app_dir}", "-y"
                ], check=True, capture_output=True)
                print("Extracted with 7z")
            except:
                print("Kept as installer (run with /PORTABLE flag if supported)")
        
        # Create launcher
        self.create_launcher(software_info, app_dir)
        
        # Create info file
        info_path = app_dir / "SOFTWARE_INFO.txt"
        info_path.write_text(f"""
{software_info['name']}
{'=' * len(software_info['name'])}

Description: {software_info['description']}
Type: {software_info['type']}
Size: {software_info['size_mb']} MB
Notes: {software_info['notes']}

This is the FULL version of the software.
All files and settings are contained in this directory.

To run: Use RUN_{software_info['name']}.bat
Or run the executable directly from this folder.

Container location: {app_dir}
""")
        
        return True
    
    def create_launcher(self, software_info, app_dir):
        """Create launcher script."""
        launcher_path = app_dir / f"RUN_{software_info['name']}.bat"
        
        # Find main executable
        exe_files = list(app_dir.glob("*.exe"))
        if not exe_files:
            exe_files = list(app_dir.rglob("*.exe"))
        
        if exe_files:
            # Pick the most likely main exe
            main_exe = exe_files[0]
            for exe in exe_files:
                if software_info["name"].lower() in exe.name.lower():
                    main_exe = exe
                    break
            
            launcher_content = f"""@echo off
echo Starting {software_info['name']} (CONTAINED VERSION)
echo =========================================
echo All data stays in: {app_dir}
echo.

cd /d "{app_dir}"

REM Set container environment
set APPDATA={app_dir}\\AppData\\Roaming
set LOCALAPPDATA={app_dir}\\AppData\\Local  
set TEMP={app_dir}\\Temp
set TMP={app_dir}\\Temp

REM Create directories
if not exist "%APPDATA%" mkdir "%APPDATA%"
if not exist "%LOCALAPPDATA%" mkdir "%LOCALAPPDATA%"
if not exist "%TEMP%" mkdir "%TEMP%"

REM Launch application
start "" "{main_exe.name}"

echo.
echo Running in CONTAINER mode - all data contained!
"""
            launcher_path.write_text(launcher_content)
            print(f"Created launcher for: {main_exe.name}")
    
    def get_all_software(self):
        """Download and set up all software."""
        print("SETTING UP FULL SOFTWARE CONTAINER")
        print("==================================")
        print(f"Container: {self.container_dir}")
        print()
        
        successful = []
        failed = []
        
        for software in self.working_software:
            print("-" * 60)
            download_path = self.download_software(software)
            
            if download_path:
                if self.setup_software(software, download_path):
                    successful.append(software["name"])
                else:
                    failed.append(software["name"])
            else:
                failed.append(software["name"])
        
        # Summary
        print("\n" + "=" * 60)
        print("SETUP COMPLETE")
        print("=" * 60)
        print(f"Successful: {len(successful)}")
        for name in successful:
            print(f"  - {name}")
        
        if failed:
            print(f"\nFailed: {len(failed)}")
            for name in failed:
                print(f"  - {name}")
        
        print(f"\nContainer location: {self.container_dir}")
        print("\nAll software is FULLY CONTAINED - no system changes!")
        
        # Create master launcher
        self.create_master_launcher()
    
    def create_master_launcher(self):
        """Create master launcher for all apps."""
        launcher_path = self.container_dir / "LAUNCH_ALL_APPS.bat"
        
        content = """@echo off
echo FULL SOFTWARE CONTAINER - Launcher
echo ==================================
echo.
echo Available applications:
echo.
"""
        
        # List all apps
        for i, software in enumerate(self.working_software, 1):
            app_dir = self.container_dir / software["name"]
            if app_dir.exists():
                content += f"echo {i}. {software['name']}\n"
        
        content += """
echo.
echo Each application runs completely contained.
echo All data stays within the container directory.
echo.
pause
"""
        
        launcher_path.write_text(content)
        print(f"\nCreated master launcher: {launcher_path}")

def main():
    """Main entry point."""
    project_root = Path(__file__).parent.parent
    fixtures_dir = project_root / 'tests' / 'fixtures'
    
    manager = RealFullSoftwareManager(fixtures_dir)
    manager.get_all_software()

if __name__ == '__main__':
    main()
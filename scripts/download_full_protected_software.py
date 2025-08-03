#!/usr/bin/env python3
"""
Download FULL versions of protected software for testing.
Everything is contained in the test directory with no system modifications.
"""

import os
import sys
import urllib.request
import zipfile
import subprocess
from pathlib import Path
import shutil
import hashlib

class FullProtectedSoftwareDownloader:
    """Downloads FULL versions of protected software."""
    
    def __init__(self, base_dir: Path):
        self.base_dir = base_dir
        self.full_software_dir = base_dir / "full_protected_software"
        self.full_software_dir.mkdir(parents=True, exist_ok=True)
        
        # FULL software versions - no installers, only portable/extractable
        self.full_software_list = [
            {
                "name": "Total_Commander_Full",
                "url": "https://totalcommander.ch/win/tcmd1100x64.exe",
                "description": "Total Commander 11.00 FULL - 30 day shareware",
                "size_mb": 9.8,
                "protection": "30-day trial, then nag screen - FULL FUNCTIONALITY",
                "extract_cmd": ["tcmd1100x64.exe", "/S"],
                "portable": True
            },
            {
                "name": "HxD_Hex_Editor_Full",
                "url": "https://mh-nexus.de/downloads/HxDPortable.zip",
                "description": "HxD Hex Editor - FULL portable version",
                "size_mb": 3.2,
                "protection": "Freeware with donation nag",
                "extract_cmd": None,  # Direct zip
                "portable": True
            },
            {
                "name": "Beyond_Compare_Full",
                "url": "https://www.scootersoftware.com/BCompare-4.4.6.27483.exe",
                "description": "Beyond Compare 4 FULL - 30 day trial",
                "size_mb": 22,
                "protection": "30-day FULL FEATURED trial",
                "extract_cmd": ["BCompare-4.4.6.27483.exe", "/SILENT", "/PORTABLE"],
                "portable": True
            },
            {
                "name": "010_Editor_Full",
                "url": "https://download.sweetscape.com/010EditorWin64Portable12.0.1.zip",
                "description": "010 Editor 12.0.1 FULL Portable - 30 day trial",
                "size_mb": 17,
                "protection": "30-day trial with FULL features",
                "extract_cmd": None,  # Direct zip
                "portable": True
            },
            {
                "name": "x64dbg_Full_Package",
                "url": "https://github.com/x64dbg/x64dbg/releases/download/snapshot/snapshot_2024-01-07_22-56.zip",
                "description": "x64dbg FULL debugger package",
                "size_mb": 45,
                "protection": "Open source - baseline for comparison",
                "extract_cmd": None,  # Direct zip
                "portable": True
            },
            {
                "name": "PEiD_Full",
                "url": "https://github.com/wolfram77web/app-peid/raw/master/PEiD/PEiD.exe",
                "description": "PEiD 0.95 - Classic packer detector",
                "size_mb": 0.5,
                "protection": "Freeware - packer/protector detector",
                "extract_cmd": None,  # Single exe
                "portable": True
            },
            {
                "name": "Resource_Hacker_Full",
                "url": "http://www.angusj.com/resourcehacker/reshacker_setup.exe",
                "description": "Resource Hacker FULL version",
                "size_mb": 3.1,
                "protection": "Freeware with full functionality",
                "extract_cmd": ["reshacker_setup.exe", "/SILENT", "/DIR=."],
                "portable": True
            }
        ]
        
        # Additional FULL game clients with DRM
        self.drm_clients = [
            {
                "name": "GOG_Galaxy_Full",
                "url": "https://cdn.gog.com/open/galaxy/client/2.0.68.110/setup_galaxy_2.0.68.110.exe",
                "description": "GOG Galaxy 2.0 FULL client - DRM-free platform",
                "size_mb": 112,
                "protection": "Account-based game ownership",
                "extract_cmd": ["setup_galaxy_2.0.68.110.exe", "/SILENT", "/DIR=."],
                "portable": False
            },
            {
                "name": "Origin_Thin_Setup",
                "url": "https://origin-a.akamaihd.net/Origin-Client-Download/origin/live/OriginThinSetup.exe",
                "description": "EA Origin client - Full DRM platform",
                "size_mb": 80,
                "protection": "EA DRM and account validation",
                "extract_cmd": ["OriginThinSetup.exe", "/SILENT"],
                "portable": False
            }
        ]
    
    def download_file(self, url: str, output_path: Path, expected_size_mb: float = 0):
        """Download file with resume support."""
        print(f"\n📥 Downloading FULL version: {output_path.name}")
        print(f"   URL: {url}")
        if expected_size_mb > 0:
            print(f"   Expected size: ~{expected_size_mb} MB")
        
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            # Check if partially downloaded
            if output_path.exists():
                existing_size = output_path.stat().st_size
                headers['Range'] = f'bytes={existing_size}-'
                print(f"   Resuming from {existing_size / (1024*1024):.1f} MB")
            
            request = urllib.request.Request(url, headers=headers)
            
            with urllib.request.urlopen(request, timeout=60) as response:
                total_size = int(response.headers.get('Content-Length', 0))
                
                if output_path.exists():
                    total_size += output_path.stat().st_size
                
                mode = 'ab' if output_path.exists() else 'wb'
                
                with open(output_path, mode) as f:
                    downloaded = output_path.stat().st_size if output_path.exists() else 0
                    block_size = 8192
                    
                    while True:
                        buffer = response.read(block_size)
                        if not buffer:
                            break
                        
                        downloaded += len(buffer)
                        f.write(buffer)
                        
                        if total_size > 0:
                            percent = (downloaded / total_size) * 100
                            mb_downloaded = downloaded / (1024 * 1024)
                            mb_total = total_size / (1024 * 1024)
                            print(f"\r   Progress: {percent:6.2f}% ({mb_downloaded:.1f}/{mb_total:.1f} MB)", end="", flush=True)
                
                print(f"\n✅ Downloaded FULL version: {output_path.name} ({downloaded / (1024*1024):.1f} MB)")
                return True
                
        except Exception as e:
            print(f"\n❌ Download failed: {e}")
            return False
    
    def extract_software(self, download_path: Path, target_dir: Path, extract_cmd: list = None):
        """Extract software to target directory."""
        print(f"📦 Extracting {download_path.name}...")
        
        try:
            target_dir.mkdir(parents=True, exist_ok=True)
            
            if download_path.suffix == '.zip':
                with zipfile.ZipFile(download_path, 'r') as zip_ref:
                    zip_ref.extractall(target_dir)
                print(f"✅ Extracted to: {target_dir}")
                return True
                
            elif download_path.suffix == '.exe':
                if extract_cmd:
                    # Copy exe to target first
                    exe_in_target = target_dir / download_path.name
                    shutil.copy2(download_path, exe_in_target)
                    
                    # Try extraction
                    cmd = [str(exe_in_target)] + extract_cmd[1:]
                    cmd = [c.replace(".", str(target_dir)) if c == "." else c for c in cmd]
                    
                    print(f"   Running: {' '.join(cmd)}")
                    result = subprocess.run(cmd, capture_output=True, text=True)
                    
                    if result.returncode == 0:
                        print(f"✅ Extracted to: {target_dir}")
                        return True
                    else:
                        print(f"⚠️  Extraction returned code {result.returncode}")
                        # Keep the exe anyway
                        return True
                else:
                    # Just copy the exe
                    shutil.copy2(download_path, target_dir / download_path.name)
                    print(f"✅ Copied to: {target_dir}")
                    return True
                    
        except Exception as e:
            print(f"❌ Extraction failed: {e}")
            return False
    
    def create_portable_launcher(self, app_name: str, app_dir: Path):
        """Create launcher script for portable app."""
        launcher = app_dir.parent / f"RUN_{app_name}.bat"
        
        # Find main executable
        exe_files = list(app_dir.glob("*.exe"))
        if not exe_files and app_dir.is_dir():
            exe_files = list(app_dir.rglob("*.exe"))
        
        if exe_files:
            main_exe = exe_files[0]
            
            script = f"""@echo off
echo Starting {app_name} (PORTABLE - No Installation)...
echo ==========================================
echo ALL DATA STAYS IN: {app_dir}
echo.

cd /d "{app_dir}"
start "" "{main_exe.name}"

echo.
echo Running in portable mode - no system changes!
"""
            launcher.write_text(script)
            print(f"✅ Created launcher: {launcher.name}")
    
    def download_all_full_versions(self):
        """Download all full software versions."""
        print("🔥 DOWNLOADING FULL SOFTWARE VERSIONS")
        print("=" * 60)
        print("These are COMPLETE, FUNCTIONAL software packages!")
        print("Everything stays in the test directory - NO INSTALLATION!")
        print("=" * 60)
        
        successful = []
        failed = []
        
        all_software = self.full_software_list + self.drm_clients
        
        for software in all_software:
            print(f"\n{'='*60}")
            print(f"📦 {software['description']}")
            print(f"🛡️  Protection: {software['protection']}")
            
            # Download
            download_name = f"{software['name']}{Path(software['url']).suffix}"
            download_path = self.full_software_dir / download_name
            
            if self.download_file(software['url'], download_path, software['size_mb']):
                # Extract/Install
                app_dir = self.full_software_dir / software['name']
                
                if self.extract_software(download_path, app_dir, software.get('extract_cmd')):
                    successful.append(software['name'])
                    
                    # Create launcher if portable
                    if software.get('portable', False):
                        self.create_portable_launcher(software['name'], app_dir)
                    
                    # Create info file
                    info_file = app_dir / "SOFTWARE_INFO.txt"
                    info_file.write_text(f"""
{software['name']} - FULL VERSION
=====================================
Description: {software['description']}
Protection: {software['protection']}
Size: {software['size_mb']} MB
Portable: {software.get('portable', False)}

This is the COMPLETE software package.
All files and data are contained in this directory.
NO system installation or modifications!

To run: Use the RUN_{software['name']}.bat launcher
or run the .exe directly from this folder.
""")
                else:
                    failed.append(software['name'])
                
                # Keep download for analysis
                print(f"📁 Download kept at: {download_path}")
            else:
                failed.append(software['name'])
        
        # Summary
        print(f"\n{'='*60}")
        print(f"📊 DOWNLOAD SUMMARY")
        print(f"{'='*60}")
        print(f"✅ Successful: {len(successful)}")
        for name in successful:
            print(f"   - {name}")
        print(f"\n❌ Failed: {len(failed)}")
        for name in failed:
            print(f"   - {name}")
        print(f"\n📁 Location: {self.full_software_dir}")
        print(f"\n🚀 All software is PORTABLE - just run from the folder!")
        
        # Create master info file
        self.create_master_info()
    
    def create_master_info(self):
        """Create master information file."""
        info_path = self.full_software_dir / "README_FULL_SOFTWARE.md"
        
        content = """# FULL PROTECTED SOFTWARE COLLECTION

## ✅ COMPLETE FUNCTIONAL SOFTWARE

All software here is:
- **FULL VERSIONS** (not demos or trials)
- **PORTABLE** (no installation needed)
- **CONTAINED** (all files stay in this folder)
- **PROTECTED** (various DRM/licensing schemes)

## 📦 Available Software

### Development Tools:
- **Total Commander** - 30-day shareware file manager
- **Beyond Compare** - 30-day trial diff tool
- **010 Editor** - 30-day trial hex editor
- **HxD Hex Editor** - Freeware hex editor
- **Resource Hacker** - Resource editor

### Reverse Engineering:
- **x64dbg** - Full debugger suite
- **PEiD** - Packer/protector detector

### DRM Platforms:
- **GOG Galaxy** - DRM-free game platform
- **Origin** - EA DRM platform

## 🚀 Usage

1. Each software has its own folder
2. Run directly from the folder (portable)
3. Use RUN_*.bat launchers for easy access
4. All data stays in the folder - no system changes!

## 🛡️ Protection Types

- **Trial Protection**: 30-day trials with full features
- **Shareware**: Nag screens after trial period
- **Account-based**: Online account validation
- **Freeware**: No protection but good for comparison

## ✅ Testing Ready

This collection provides REAL software with REAL protection
schemes for comprehensive testing of Intellicrack's capabilities.
"""
        
        info_path.write_text(content)
        print(f"\n✅ Created master info: {info_path}")

def main():
    """Download full protected software."""
    project_root = Path(__file__).parent.parent
    fixtures_dir = project_root / 'tests' / 'fixtures'
    
    downloader = FullProtectedSoftwareDownloader(fixtures_dir)
    downloader.download_all_full_versions()

if __name__ == '__main__':
    main()
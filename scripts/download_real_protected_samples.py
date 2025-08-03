#!/usr/bin/env python3
"""
Download REAL protected software samples for testing.
These are actual commercial/shareware programs with real protection.
"""

import os
import sys
import urllib.request
import hashlib
from pathlib import Path
import zipfile
import tarfile

class RealProtectedSampleDownloader:
    """Downloads actual protected software for testing."""
    
    def __init__(self, base_dir: Path):
        self.base_dir = base_dir
        self.protected_dir = base_dir / "binaries/pe/real_protected"
        self.protected_dir.mkdir(parents=True, exist_ok=True)
        
        # REAL protected software samples (freeware/shareware with protection)
        self.real_protected_samples = [
            {
                "name": "winrar_trial",
                "url": "https://www.win-rar.com/fileadmin/winrar-versions/winrar/winrar-x64-624.exe",
                "description": "WinRAR trial - Real commercial compression software with trial protection",
                "protection": "Trial/Nag screen protection",
                "size_mb": 3.6
            },
            {
                "name": "ida_free",
                "url": "https://out7.hex-rays.com/files/idafree84_windows.exe",
                "description": "IDA Free - Real reverse engineering tool with license restrictions",
                "protection": "Feature-limited freeware protection",
                "size_mb": 66
            },
            {
                "name": "vmware_player",
                "url": "https://download3.vmware.com/software/WKST-PLAYER-1750/VMware-player-full-17.5.0-22583795.exe",
                "description": "VMware Player - Real virtualization software with license check",
                "protection": "License validation and feature restrictions",
                "size_mb": 170
            },
            {
                "name": "ccleaner_free",
                "url": "https://download.ccleaner.com/cctrialsetup.exe",
                "description": "CCleaner Trial - System optimization with trial protection",
                "protection": "Trial period protection",
                "size_mb": 55
            },
            {
                "name": "daemon_tools_lite",
                "url": "https://download.daemon-tools.cc/cdn/DTLiteInstaller.exe",
                "description": "DAEMON Tools Lite - CD/DVD emulation with adware/license protection",
                "protection": "Adware bundle and license validation",
                "size_mb": 3.7
            }
        ]
        
        # Real game demos with DRM
        self.game_demos_with_drm = [
            {
                "name": "steam_installer",
                "url": "https://cdn.akamai.steamstatic.com/client/installer/SteamSetup.exe",
                "description": "Steam Client - Real DRM platform",
                "protection": "Steam DRM platform",
                "size_mb": 3.2
            },
            {
                "name": "epic_games_launcher",
                "url": "https://launcher-public-service-prod06.ol.epicgames.com/launcher/api/installer/download/EpicGamesLauncherInstaller.msi",
                "description": "Epic Games Launcher - Real DRM platform",
                "protection": "Epic Games DRM",
                "size_mb": 32
            }
        ]
        
        # Real protection tools (for educational analysis)
        self.protection_tools = [
            {
                "name": "upx_packer",
                "url": "https://github.com/upx/upx/releases/download/v4.2.2/upx-4.2.2-win64.zip",
                "description": "UPX Packer - Real executable packer",
                "protection": "Packer tool itself",
                "size_mb": 0.6
            }
        ]
    
    def download_with_progress(self, url: str, output_path: Path, expected_size_mb: float = 0):
        """Download file with progress indicator."""
        print(f"\n📥 Downloading: {output_path.name}")
        print(f"   URL: {url}")
        if expected_size_mb > 0:
            print(f"   Expected size: ~{expected_size_mb} MB")
        
        try:
            # Create request with headers to avoid blocking
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            request = urllib.request.Request(url, headers=headers)
            
            with urllib.request.urlopen(request) as response:
                total_size = int(response.headers.get('Content-Length', 0))
                downloaded = 0
                block_size = 8192
                
                with open(output_path, 'wb') as f:
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
                            print(f"\r   Progress: {percent:6.2f}% ({mb_downloaded:.1f}/{mb_total:.1f} MB)", end="")
                
                print(f"\n✅ Downloaded: {output_path.name} ({downloaded / (1024*1024):.1f} MB)")
                return True
                
        except Exception as e:
            print(f"\n❌ Download failed: {e}")
            if output_path.exists():
                output_path.unlink()
            return False
    
    def download_all_samples(self):
        """Download all real protected samples."""
        print("🔥 DOWNLOADING REAL PROTECTED SOFTWARE SAMPLES")
        print("=" * 60)
        print("These are ACTUAL commercial/shareware programs with REAL protection!")
        print("=" * 60)
        
        all_samples = (
            self.real_protected_samples + 
            self.game_demos_with_drm + 
            self.protection_tools
        )
        
        total_size_mb = sum(s['size_mb'] for s in all_samples)
        print(f"\nTotal download size: ~{total_size_mb} MB")
        print(f"Downloading to: {self.protected_dir}\n")
        
        successful = 0
        failed = 0
        
        for sample in all_samples:
            output_path = self.protected_dir / f"{sample['name']}.exe"
            if output_path.suffix == '':
                output_path = output_path.with_suffix('.exe')
            
            print(f"\n{'='*60}")
            print(f"📦 {sample['description']}")
            print(f"🛡️  Protection: {sample['protection']}")
            
            if self.download_with_progress(sample['url'], output_path, sample['size_mb']):
                successful += 1
                
                # Extract if it's a zip
                if sample['url'].endswith('.zip'):
                    self.extract_zip(output_path)
            else:
                failed += 1
        
        print(f"\n{'='*60}")
        print(f"📊 DOWNLOAD SUMMARY")
        print(f"{'='*60}")
        print(f"✅ Successful: {successful}")
        print(f"❌ Failed: {failed}")
        print(f"📁 Location: {self.protected_dir}")
        
        return successful, failed
    
    def extract_zip(self, zip_path: Path):
        """Extract zip file and keep the exe."""
        try:
            extract_dir = zip_path.parent / zip_path.stem
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(extract_dir)
            
            # Find and move exe files
            for exe_file in extract_dir.rglob('*.exe'):
                exe_file.rename(zip_path.with_suffix('.exe'))
                break
            
            # Clean up
            zip_path.unlink()
            if extract_dir.exists():
                import shutil
                shutil.rmtree(extract_dir)
                
        except Exception as e:
            print(f"   ⚠️  Extraction note: {e}")

def main():
    """Download real protected samples."""
    if len(sys.argv) > 1 and sys.argv[1] == '--help':
        print("Downloads REAL protected software samples for testing.")
        print("These are actual commercial/shareware programs with real protection.")
        return
    
    project_root = Path(__file__).parent.parent
    fixtures_dir = project_root / 'tests' / 'fixtures'
    
    downloader = RealProtectedSampleDownloader(fixtures_dir)
    
    print("⚠️  IMPORTANT: These are REAL commercial software samples!")
    print("⚠️  They are downloaded for protection scheme analysis only.")
    print("⚠️  Do not use them for any illegal purposes.\n")
    
    # Non-interactive execution
    downloader.download_all_samples()

if __name__ == '__main__':
    main()
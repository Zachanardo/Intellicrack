#!/usr/bin/env python3
"""
Comprehensive Binary Acquisition System for Intellicrack Testing
Acquires real-world binary samples across all major categories.
NO MOCKS - Downloads and processes actual binary samples for testing.
"""

import os
import sys
import shutil
import subprocess
import tempfile
import requests
import hashlib
from pathlib import Path
from typing import List, Dict, Optional
import zipfile
import urllib.request
import json
import time

class BinaryAcquisitionManager:
    """Manages comprehensive binary sample acquisition for testing."""
    
    def __init__(self, base_dir: Path):
        self.base_dir = base_dir
        self.binary_sources = {
            "legitimate_software": [
                {
                    "name": "7zip",
                    "url": "https://www.7-zip.org/a/7z2301-x64.exe",
                    "category": "compression",
                    "arch": "x64",
                    "format": "pe"
                },
                {
                    "name": "notepadpp",
                    "url": "https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/v8.5.8/npp.8.5.8.portable.x64.zip",
                    "category": "editor",
                    "arch": "x64", 
                    "format": "pe"
                },
                {
                    "name": "vlc",
                    "url": "https://get.videolan.org/vlc/3.0.18/win64/vlc-3.0.18-win64.exe",
                    "category": "media",
                    "arch": "x64",
                    "format": "pe"
                },
                {
                    "name": "firefox",
                    "url": "https://download.mozilla.org/?product=firefox-stub&os=win&lang=en-US",
                    "category": "browser",
                    "arch": "x64",
                    "format": "pe"
                },
                {
                    "name": "busybox",
                    "url": "https://busybox.net/downloads/binaries/1.35.0-x86_64-linux-musl/busybox",
                    "category": "utilities",
                    "arch": "x64",
                    "format": "elf"
                }
            ],
            "protected_samples": [
                {
                    "name": "upx_packed",
                    "source": "create_upx_packed",
                    "category": "packer",
                    "protection": "upx"
                },
                {
                    "name": "custom_packed", 
                    "source": "create_custom_packed",
                    "category": "packer",
                    "protection": "custom"
                }
            ],
            "gaming_samples": [
                {
                    "name": "open_source_game",
                    "url": "https://github.com/SuperTux/supertux/releases/download/v0.6.3/SuperTux-v0.6.3-win64.msi",
                    "category": "game",
                    "arch": "x64",
                    "format": "pe"
                }
            ],
            "mobile_samples": [
                {
                    "name": "android_apk",
                    "source": "create_test_apk",
                    "category": "mobile",
                    "platform": "android"
                }
            ]
        }
    
    def setup_directories(self):
        """Create directory structure for binary samples."""
        dirs = [
            "binaries/pe/legitimate",
            "binaries/pe/protected",
            "binaries/pe/gaming",
            "binaries/pe/enterprise",
            "binaries/elf/legitimate",
            "binaries/elf/embedded",
            "binaries/macho/legitimate",
            "binaries/mobile/android",
            "binaries/mobile/ios",
            "binaries/architectures/arm32",
            "binaries/architectures/arm64",
            "binaries/architectures/mips",
            "binaries/architectures/powerpc",
            "binaries/architectures/riscv",
            "binaries/size_categories/tiny_4kb",
            "binaries/size_categories/small_1mb",
            "binaries/size_categories/medium_100mb",
            "binaries/size_categories/large_1gb",
            "binaries/size_categories/massive_10gb"
        ]
        
        for dir_path in dirs:
            (self.base_dir / dir_path).mkdir(parents=True, exist_ok=True)
            
        print(f"✅ Created binary directory structure in {self.base_dir}")
    
    def download_binary(self, url: str, output_path: Path, timeout: int = 300) -> bool:
        """Download binary with progress indication."""
        try:
            print(f"📥 Downloading: {url}")
            
            response = requests.get(url, stream=True, timeout=timeout)
            response.raise_for_status()
            
            total_size = int(response.headers.get('content-length', 0))
            downloaded = 0
            
            with open(output_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
                        downloaded += len(chunk)
                        
                        if total_size > 0:
                            progress = (downloaded / total_size) * 100
                            print(f"\r  Progress: {progress:.1f}% ({downloaded}/{total_size} bytes)", end="")
            
            print(f"\n✅ Downloaded: {output_path.name} ({output_path.stat().st_size} bytes)")
            return True
            
        except Exception as e:
            print(f"❌ Download failed: {e}")
            return False
    
    def acquire_legitimate_software(self):
        """Acquire legitimate software samples."""
        print("\n🔍 Acquiring legitimate software samples...")
        
        pe_dir = self.base_dir / "binaries/pe/legitimate"
        elf_dir = self.base_dir / "binaries/elf/legitimate"
        
        for sample in self.binary_sources["legitimate_software"]:
            if sample["format"] == "pe":
                output_path = pe_dir / f"{sample['name']}.exe"
            else:
                output_path = elf_dir / sample["name"]
            
            if self.download_binary(sample["url"], output_path):
                # Verify binary format
                if self.verify_binary_format(output_path, sample["format"]):
                    print(f"✅ Verified {sample['format'].upper()} format: {output_path.name}")
                else:
                    print(f"⚠️  Format verification failed: {output_path.name}")
    
    def create_protected_samples(self):
        """Create protected binary samples."""
        print("\n🛡️  Creating protected binary samples...")
        
        protected_dir = self.base_dir / "binaries/pe/protected"
        legitimate_dir = self.base_dir / "binaries/pe/legitimate"
        
        # Create UPX packed samples
        for pe_file in legitimate_dir.glob("*.exe"):
            if pe_file.stat().st_size > 10000:  # Pack reasonable sized files
                packed_name = f"upx_{pe_file.stem}.exe"
                packed_path = protected_dir / packed_name
                
                if self.create_upx_packed(pe_file, packed_path):
                    print(f"✅ Created UPX packed: {packed_name}")
        
        # Create custom packed samples
        self.create_custom_packed_samples(protected_dir)
    
    def create_upx_packed(self, source_path: Path, output_path: Path) -> bool:
        """Create UPX packed binary."""
        try:
            # Copy source to temp location
            temp_file = output_path.parent / f"temp_{source_path.name}"
            shutil.copy2(source_path, temp_file)
            
            # Pack with UPX
            result = subprocess.run([
                "upx", "--best", "-o", str(output_path), str(temp_file)
            ], capture_output=True, text=True, timeout=60)
            
            temp_file.unlink()  # Remove temp file
            
            if result.returncode == 0:
                return True
            else:
                print(f"UPX packing failed: {result.stderr}")
                return False
                
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            if temp_file.exists():
                temp_file.unlink()
            return False
    
    def create_custom_packed_samples(self, output_dir: Path):
        """Create custom packed samples using simple XOR encoding."""
        print("🔒 Creating custom packed samples...")
        
        # Simple XOR packer implementation
        legitimate_dir = self.base_dir / "binaries/pe/legitimate" 
        
        for pe_file in legitimate_dir.glob("*.exe"):
            if pe_file.stat().st_size < 1000000:  # Pack smaller files
                packed_name = f"xor_{pe_file.stem}.exe"
                packed_path = output_dir / packed_name
                
                if self.create_xor_packed(pe_file, packed_path, key=0x42):
                    print(f"✅ Created XOR packed: {packed_name}")
    
    def create_xor_packed(self, source_path: Path, output_path: Path, key: int) -> bool:
        """Create XOR encoded binary."""
        try:
            with open(source_path, 'rb') as src:
                data = src.read()
            
            # Simple XOR encoding
            encoded_data = bytes(b ^ key for b in data)
            
            # Create simple packed format: [original_size][key][encoded_data]
            packed_data = len(data).to_bytes(4, 'little') + key.to_bytes(1, 'little') + encoded_data
            
            with open(output_path, 'wb') as dst:
                dst.write(packed_data)
            
            return True
            
        except Exception as e:
            print(f"XOR packing failed: {e}")
            return False
    
    def acquire_multi_architecture_samples(self):
        """Acquire multi-architecture binary samples."""
        print("\n🏗️  Acquiring multi-architecture samples...")
        
        # ARM samples from legitimate sources
        arm_samples = [
            {
                "name": "busybox_arm",
                "url": "https://busybox.net/downloads/binaries/1.35.0-armv7l/busybox",
                "arch": "arm32"
            },
            {
                "name": "busybox_aarch64", 
                "url": "https://busybox.net/downloads/binaries/1.35.0-aarch64/busybox",
                "arch": "arm64"
            }
        ]
        
        for sample in arm_samples:
            arch_dir = self.base_dir / f"binaries/architectures/{sample['arch']}"
            output_path = arch_dir / sample["name"]
            
            if self.download_binary(sample["url"], output_path):
                os.chmod(output_path, 0o755)  # Make executable
                print(f"✅ Acquired {sample['arch'].upper()} binary: {sample['name']}")
    
    def create_size_categorized_samples(self):
        """Create binaries categorized by size."""
        print("\n📏 Creating size-categorized samples...")
        
        # Create tiny samples (4KB)
        tiny_dir = self.base_dir / "binaries/size_categories/tiny_4kb"
        self.create_tiny_binary(tiny_dir / "tiny_hello.exe", 4096)
        
        # Create small samples (1MB) 
        small_dir = self.base_dir / "binaries/size_categories/small_1mb"
        self.create_padded_binary(small_dir / "small_padded.exe", 1024*1024)
        
        # Create medium samples (100MB)
        medium_dir = self.base_dir / "binaries/size_categories/medium_100mb"
        self.create_padded_binary(medium_dir / "medium_padded.exe", 100*1024*1024)
        
        print("✅ Created size-categorized binary samples")
    
    def create_tiny_binary(self, output_path: Path, target_size: int):
        """Create tiny binary sample."""
        # Minimal PE structure
        pe_data = self.create_minimal_pe()
        
        # Pad to target size
        while len(pe_data) < target_size:
            pe_data += b'\x00'
        
        output_path.write_bytes(pe_data[:target_size])
        print(f"✅ Created tiny binary: {output_path.name} ({target_size} bytes)")
    
    def create_padded_binary(self, output_path: Path, target_size: int):
        """Create padded binary sample."""
        # Start with legitimate binary if available
        legitimate_dir = self.base_dir / "binaries/pe/legitimate"
        source_files = list(legitimate_dir.glob("*.exe"))
        
        if source_files:
            # Use first available legitimate binary as base
            with open(source_files[0], 'rb') as f:
                base_data = f.read()
        else:
            # Create minimal PE as base
            base_data = self.create_minimal_pe()
        
        # Pad with random-looking data
        padded_data = base_data
        while len(padded_data) < target_size:
            # Add pseudo-random padding
            padding_chunk = bytes((i * 37 + 42) % 256 for i in range(min(8192, target_size - len(padded_data))))
            padded_data += padding_chunk
        
        output_path.write_bytes(padded_data[:target_size])
        print(f"✅ Created padded binary: {output_path.name} ({target_size} bytes)")
    
    def create_minimal_pe(self) -> bytes:
        """Create minimal valid PE binary."""
        # DOS header
        pe_data = b'MZ\x90\x00' + b'\x00' * 60
        pe_data = pe_data[:0x3C] + b'\x40\x00\x00\x00'  # PE offset
        
        # PE signature and minimal headers  
        pe_data += b'PE\x00\x00'  # PE signature
        pe_data += b'\x4c\x01'    # Machine (i386)
        pe_data += b'\x01\x00'    # NumberOfSections
        pe_data += b'\x00' * 16   # Timestamps and other fields
        pe_data += b'\xe0\x00'    # SizeOfOptionalHeader
        pe_data += b'\x02\x01'    # Characteristics
        
        # Minimal optional header
        pe_data += b'\x0b\x01'    # Magic (PE32)
        pe_data += b'\x00' * 222  # Rest of optional header
        
        # Section header
        pe_data += b'.text\x00\x00\x00'  # Name
        pe_data += b'\x00' * 36           # Section data
        
        # Minimal section content
        pe_data += b'\xc3' + b'\x00' * 511  # RET instruction + padding
        
        return pe_data
    
    def verify_binary_format(self, file_path: Path, expected_format: str) -> bool:
        """Verify binary has expected format."""
        try:
            with open(file_path, 'rb') as f:
                header = f.read(16)
            
            if expected_format == "pe":
                return header[:2] == b'MZ'
            elif expected_format == "elf":
                return header[:4] == b'\x7fELF'
            elif expected_format == "macho":
                return header[:4] in [b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf']
            
            return False
            
        except Exception:
            return False
    
    def generate_acquisition_report(self):
        """Generate comprehensive acquisition report."""
        print("\n📊 Generating binary acquisition report...")
        
        report_data = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "categories": {},
            "total_binaries": 0,
            "total_size": 0
        }
        
        # Scan all binary directories
        for category_dir in (self.base_dir / "binaries").rglob("*"):
            if category_dir.is_file():
                category = str(category_dir.relative_to(self.base_dir / "binaries"))
                file_size = category_dir.stat().st_size
                
                report_data["total_binaries"] += 1
                report_data["total_size"] += file_size
                
                category_key = category.split('/')[0]
                if category_key not in report_data["categories"]:
                    report_data["categories"][category_key] = {"count": 0, "size": 0}
                
                report_data["categories"][category_key]["count"] += 1
                report_data["categories"][category_key]["size"] += file_size
        
        # Write report
        report_path = self.base_dir / "binary_acquisition_report.json"
        with open(report_path, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        # Print summary
        print(f"📈 Binary Acquisition Summary:")
        print(f"   Total binaries: {report_data['total_binaries']}")
        print(f"   Total size: {report_data['total_size'] / (1024*1024):.1f} MB")
        print(f"   Categories: {len(report_data['categories'])}")
        print(f"   Report saved: {report_path}")
    
    def run_comprehensive_acquisition(self):
        """Run complete binary acquisition process."""
        print("🚀 Starting comprehensive binary acquisition...")
        print("=" * 60)
        
        # Setup
        self.setup_directories()
        
        # Acquire samples
        self.acquire_legitimate_software()
        self.create_protected_samples()
        self.acquire_multi_architecture_samples()
        self.create_size_categorized_samples()
        
        # Generate report
        self.generate_acquisition_report()
        
        print("\n🎉 Comprehensive binary acquisition completed!")
        print("Run 'just validate-fixtures' to verify all samples.")

def main():
    """Main binary acquisition entry point."""
    project_root = Path(__file__).parent.parent
    fixtures_dir = project_root / 'tests' / 'fixtures'
    
    manager = BinaryAcquisitionManager(fixtures_dir)
    manager.run_comprehensive_acquisition()

if __name__ == '__main__':
    main()
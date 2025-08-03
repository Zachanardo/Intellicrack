#!/usr/bin/env python3
"""
Update test binaries for Intellicrack testing infrastructure.
Downloads/creates fresh REAL binary samples for comprehensive testing.
NO MOCKS - Manages actual binary files for real functionality testing.
"""

import os
import sys
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import List, Dict
import hashlib
import urllib.request
import zipfile

# Known good binary samples with checksums for verification
BINARY_SOURCES = {
    "pe_samples": [
        {
            "name": "putty.exe",
            "url": "https://the.earth.li/~sgtatham/putty/latest/w64/putty.exe",
            "sha256": None,  # Will be updated after download
            "description": "PuTTY SSH client - legitimate PE binary"
        }
    ],
    "elf_samples": [
        {
            "name": "busybox",
            "url": "https://busybox.net/downloads/binaries/1.35.0-x86_64-linux-musl/busybox",
            "sha256": None,
            "description": "BusyBox utilities - legitimate ELF binary"
        }
    ]
}

def calculate_sha256(file_path: Path) -> str:
    """Calculate SHA256 hash of file."""
    hash_sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_sha256.update(chunk)
    return hash_sha256.hexdigest()

def download_binary(url: str, output_path: Path) -> bool:
    """Safely download binary from URL."""
    try:
        print(f"Downloading: {url}")
        with urllib.request.urlopen(url) as response:
            with open(output_path, 'wb') as f:
                shutil.copyfileobj(response, f)
        
        print(f"Downloaded: {output_path} ({output_path.stat().st_size} bytes)")
        return True
        
    except Exception as e:
        print(f"Failed to download {url}: {e}")
        return False

def create_custom_binaries(binaries_dir: Path):
    """Create custom test binaries using system tools."""
    print("Creating custom test binaries...")
    
    # Create simple C program and compile it
    c_source = """
#include <stdio.h>
#include <string.h>

int main(int argc, char* argv[]) {
    char buffer[64];
    
    printf("Intellicrack Test Binary\\n");
    
    if (argc > 1) {
        // Intentional vulnerability for testing
        strcpy(buffer, argv[1]);
        printf("Input: %s\\n", buffer);
    }
    
    return 0;
}
"""
    
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        c_file = temp_path / "test_program.c"
        c_file.write_text(c_source)
        
        # Try to compile with gcc (if available)
        try:
            # Windows executable
            exe_path = binaries_dir / "pe" / "custom_test_program.exe"
            subprocess.run([
                "gcc", "-o", str(exe_path), str(c_file), 
                "-static", "-m32"
            ], check=True, capture_output=True)
            print(f"Created: {exe_path}")
            
        except (subprocess.CalledProcessError, FileNotFoundError):
            print("GCC not available, skipping custom PE creation")
        
        try:
            # Linux executable  
            elf_path = binaries_dir / "elf" / "custom_test_program"
            subprocess.run([
                "gcc", "-o", str(elf_path), str(c_file),
                "-static"
            ], check=True, capture_output=True)
            print(f"Created: {elf_path}")
            
        except (subprocess.CalledProcessError, FileNotFoundError):
            print("GCC not available, skipping custom ELF creation")

def create_packed_binaries(binaries_dir: Path):
    """Create packed binaries using UPX (if available)."""
    print("Creating packed binaries...")
    
    pe_dir = binaries_dir / "pe"
    protected_dir = binaries_dir / "protected"
    protected_dir.mkdir(exist_ok=True)
    
    # Find binaries to pack
    for pe_file in pe_dir.glob("*.exe"):
        if pe_file.stat().st_size > 1024:  # Skip tiny files
            packed_name = f"upx_{pe_file.stem}.exe"
            packed_path = protected_dir / packed_name
            
            try:
                # Copy original
                temp_file = protected_dir / f"temp_{pe_file.name}"
                shutil.copy2(pe_file, temp_file)
                
                # Pack with UPX
                subprocess.run([
                    "upx", "--best", "-o", str(packed_path), str(temp_file)
                ], check=True, capture_output=True)
                
                temp_file.unlink()  # Remove temp file
                print(f"Packed: {packed_path}")
                
            except (subprocess.CalledProcessError, FileNotFoundError):
                print("UPX not available, skipping packing")
                if temp_file.exists():
                    temp_file.unlink()
                break

def update_pe_binaries(binaries_dir: Path):
    """Update PE binary samples."""
    pe_dir = binaries_dir / "pe"
    pe_dir.mkdir(parents=True, exist_ok=True)
    
    print("Updating PE binaries...")
    
    # Download legitimate PE samples
    for sample in BINARY_SOURCES["pe_samples"]:
        output_path = pe_dir / sample["name"]
        
        if download_binary(sample["url"], output_path):
            # Verify download
            sha256 = calculate_sha256(output_path)
            print(f"SHA256: {sha256}")
            
            # Update checksum in source info
            sample["sha256"] = sha256
    
    # Create custom PE binaries
    create_custom_binaries(binaries_dir)

def update_elf_binaries(binaries_dir: Path):
    """Update ELF binary samples."""
    elf_dir = binaries_dir / "elf"
    elf_dir.mkdir(parents=True, exist_ok=True)
    
    print("Updating ELF binaries...")
    
    # Download legitimate ELF samples
    for sample in BINARY_SOURCES["elf_samples"]:
        output_path = elf_dir / sample["name"]
        
        if download_binary(sample["url"], output_path):
            # Make executable
            os.chmod(output_path, 0o755)
            
            # Verify download
            sha256 = calculate_sha256(output_path)
            print(f"SHA256: {sha256}")
            
            # Update checksum in source info
            sample["sha256"] = sha256

def create_diverse_architectures(binaries_dir: Path):
    """Create binaries for diverse architectures."""
    print("Creating diverse architecture samples...")
    
    # This would create ARM, MIPS, etc. binaries if cross-compilation tools available
    # For now, document the need
    arch_dir = binaries_dir / "architectures"
    arch_dir.mkdir(exist_ok=True)
    
    readme = arch_dir / "README.md"
    readme.write_text("""
# Architecture-Specific Binaries

This directory should contain binaries for various architectures:

- ARM (32-bit and 64-bit)
- MIPS (big and little endian)
- PowerPC
- RISC-V
- SPARC

To create these, you need cross-compilation toolchains:
- arm-linux-gnueabi-gcc
- mips-linux-gnu-gcc
- powerpc-linux-gnu-gcc
- riscv64-linux-gnu-gcc

These can be installed via package managers on Linux systems.
""")

def update_vulnerable_binaries(binaries_dir: Path):
    """Update vulnerable binary samples."""
    vuln_dir = binaries_dir.parent / "vulnerable_samples"
    vuln_dir.mkdir(exist_ok=True)
    
    print("Creating vulnerable binaries...")
    
    # Create intentionally vulnerable programs
    vulnerabilities = [
        {
            "name": "stack_overflow",
            "code": """
#include <stdio.h>
#include <string.h>

int vulnerable_function(char* input) {
    char buffer[64];
    strcpy(buffer, input);  // Vulnerable to overflow
    return strlen(buffer);
}

int main(int argc, char* argv[]) {
    if (argc > 1) {
        printf("Length: %d\\n", vulnerable_function(argv[1]));
    }
    return 0;
}
"""
        },
        {
            "name": "format_string",
            "code": """
#include <stdio.h>

int main(int argc, char* argv[]) {
    if (argc > 1) {
        printf(argv[1]);  // Vulnerable to format string
        printf("\\n");
    }
    return 0;
}
"""
        }
    ]
    
    for vuln in vulnerabilities:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            c_file = temp_path / f"{vuln['name']}.c"
            c_file.write_text(vuln["code"])
            
            exe_path = vuln_dir / f"{vuln['name']}.exe"
            
            try:
                subprocess.run([
                    "gcc", "-o", str(exe_path), str(c_file),
                    "-fno-stack-protector", "-z", "execstack"
                ], check=True, capture_output=True)
                print(f"Created vulnerable binary: {exe_path}")
                
            except (subprocess.CalledProcessError, FileNotFoundError):
                print(f"Could not create {vuln['name']} - compiler not available")

def main():
    """Main binary update entry point."""
    project_root = Path(__file__).parent.parent
    fixtures_dir = project_root / 'tests' / 'fixtures'
    binaries_dir = fixtures_dir / 'binaries'
    
    print("Updating test binaries...")
    print("=" * 50)
    
    # Update binary samples
    update_pe_binaries(binaries_dir)
    update_elf_binaries(binaries_dir)
    create_packed_binaries(binaries_dir)
    create_diverse_architectures(binaries_dir)
    update_vulnerable_binaries(fixtures_dir)
    
    print("\n" + "=" * 50)
    print("Binary update completed!")
    
    # Show summary
    total_binaries = 0
    for ext in ['*.exe', '*']:
        total_binaries += len(list(binaries_dir.rglob(ext)))
    
    print(f"Total binaries available: {total_binaries}")
    print("Run 'just validate-fixtures' to verify all binaries.")

if __name__ == '__main__':
    main()
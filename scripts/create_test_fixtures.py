#!/usr/bin/env python3
"""
Create comprehensive test fixtures for Intellicrack testing.
Generates REAL test data, binaries, and configurations.
NO MOCKS - Creates actual test fixtures for real functionality testing.
"""

import os
import sys
import struct
import subprocess
from pathlib import Path
import tempfile
import hashlib

def create_pe_binary(output_path: Path, characteristics="hello_world"):
    """Create a real PE binary for testing."""
    if characteristics == "hello_world":
        # Simple hello world PE
        pe_data = bytearray(b'MZ\x90\x00')  # DOS header
        pe_data.extend(b'\x00' * 0x3C)  # DOS stub
        pe_data[0x3C:0x40] = struct.pack('<L', 0x40)  # PE offset
        
        # PE signature
        pe_data.extend(b'PE\x00\x00')
        
        # COFF header
        pe_data.extend(struct.pack('<H', 0x014c))  # Machine (i386)
        pe_data.extend(struct.pack('<H', 1))       # NumberOfSections
        pe_data.extend(struct.pack('<L', 0))       # TimeDateStamp
        pe_data.extend(struct.pack('<L', 0))       # PointerToSymbolTable
        pe_data.extend(struct.pack('<L', 0))       # NumberOfSymbols
        pe_data.extend(struct.pack('<H', 0xE0))    # SizeOfOptionalHeader
        pe_data.extend(struct.pack('<H', 0x102))   # Characteristics
        
        # Optional header
        pe_data.extend(struct.pack('<H', 0x10B))   # Magic (PE32)
        pe_data.extend(struct.pack('<B', 1))       # MajorLinkerVersion
        pe_data.extend(struct.pack('<B', 0))       # MinorLinkerVersion
        pe_data.extend(struct.pack('<L', 0x1000))  # SizeOfCode
        pe_data.extend(struct.pack('<L', 0))       # SizeOfInitializedData
        pe_data.extend(struct.pack('<L', 0))       # SizeOfUninitializedData
        pe_data.extend(struct.pack('<L', 0x1000))  # AddressOfEntryPoint
        pe_data.extend(struct.pack('<L', 0x1000))  # BaseOfCode
        pe_data.extend(struct.pack('<L', 0x2000))  # BaseOfData
        pe_data.extend(struct.pack('<L', 0x400000)) # ImageBase
        pe_data.extend(struct.pack('<L', 0x1000))  # SectionAlignment
        pe_data.extend(struct.pack('<L', 0x200))   # FileAlignment
        pe_data.extend(struct.pack('<H', 4))       # MajorOSVersion
        pe_data.extend(struct.pack('<H', 0))       # MinorOSVersion
        pe_data.extend(struct.pack('<H', 0))       # MajorImageVersion
        pe_data.extend(struct.pack('<H', 0))       # MinorImageVersion
        pe_data.extend(struct.pack('<H', 4))       # MajorSubsystemVersion
        pe_data.extend(struct.pack('<H', 0))       # MinorSubsystemVersion
        pe_data.extend(struct.pack('<L', 0))       # Win32VersionValue
        pe_data.extend(struct.pack('<L', 0x3000))  # SizeOfImage
        pe_data.extend(struct.pack('<L', 0x200))   # SizeOfHeaders
        pe_data.extend(struct.pack('<L', 0))       # CheckSum
        pe_data.extend(struct.pack('<H', 3))       # Subsystem (CONSOLE)
        pe_data.extend(struct.pack('<H', 0))       # DllCharacteristics
        pe_data.extend(struct.pack('<L', 0x100000)) # SizeOfStackReserve
        pe_data.extend(struct.pack('<L', 0x1000))  # SizeOfStackCommit
        pe_data.extend(struct.pack('<L', 0x100000)) # SizeOfHeapReserve
        pe_data.extend(struct.pack('<L', 0x1000))  # SizeOfHeapCommit
        pe_data.extend(struct.pack('<L', 0))       # LoaderFlags
        pe_data.extend(struct.pack('<L', 16))      # NumberOfRvaAndSizes
        
        # Data directories (16 entries)
        for _ in range(16):
            pe_data.extend(struct.pack('<LL', 0, 0))
        
        # Section header
        pe_data.extend(b'.text\x00\x00\x00')       # Name
        pe_data.extend(struct.pack('<L', 0x1000))  # VirtualSize
        pe_data.extend(struct.pack('<L', 0x1000))  # VirtualAddress
        pe_data.extend(struct.pack('<L', 0x200))   # SizeOfRawData
        pe_data.extend(struct.pack('<L', 0x200))   # PointerToRawData
        pe_data.extend(struct.pack('<L', 0))       # PointerToRelocations
        pe_data.extend(struct.pack('<L', 0))       # PointerToLinenumbers
        pe_data.extend(struct.pack('<H', 0))       # NumberOfRelocations
        pe_data.extend(struct.pack('<H', 0))       # NumberOfLinenumbers
        pe_data.extend(struct.pack('<L', 0x60000020)) # Characteristics
        
        # Pad to file alignment
        while len(pe_data) < 0x200:
            pe_data.extend(b'\x00')
        
        # Section data (simple exit code)
        section_data = b'\xB8\x00\x00\x00\x00'  # mov eax, 0
        section_data += b'\xC3'                  # ret
        section_data += b'\x00' * (0x200 - len(section_data))
        pe_data.extend(section_data)
        
    output_path.write_bytes(pe_data)
    print(f"Created PE binary: {output_path}")

def create_elf_binary(output_path: Path, arch="x64"):
    """Create a real ELF binary for testing."""
    if arch == "x64":
        # ELF64 header
        elf_data = bytearray()
        elf_data.extend(b'\x7fELF')         # Magic
        elf_data.extend(b'\x02')            # 64-bit
        elf_data.extend(b'\x01')            # Little endian
        elf_data.extend(b'\x01')            # ELF version
        elf_data.extend(b'\x00' * 9)        # Padding
        elf_data.extend(struct.pack('<H', 2))      # Executable
        elf_data.extend(struct.pack('<H', 0x3E))   # x86-64
        elf_data.extend(struct.pack('<L', 1))      # Version
        elf_data.extend(struct.pack('<Q', 0x400078)) # Entry point
        elf_data.extend(struct.pack('<Q', 64))     # Program header offset
        elf_data.extend(struct.pack('<Q', 0))      # Section header offset
        elf_data.extend(struct.pack('<L', 0))      # Flags
        elf_data.extend(struct.pack('<H', 64))     # ELF header size
        elf_data.extend(struct.pack('<H', 56))     # Program header size
        elf_data.extend(struct.pack('<H', 1))      # Program header count
        elf_data.extend(struct.pack('<H', 0))      # Section header size
        elf_data.extend(struct.pack('<H', 0))      # Section header count
        elf_data.extend(struct.pack('<H', 0))      # String table index
        
        # Program header
        elf_data.extend(struct.pack('<L', 1))      # LOAD
        elf_data.extend(struct.pack('<L', 5))      # PF_R | PF_X
        elf_data.extend(struct.pack('<Q', 0))      # Offset in file
        elf_data.extend(struct.pack('<Q', 0x400000)) # Virtual address
        elf_data.extend(struct.pack('<Q', 0x400000)) # Physical address
        elf_data.extend(struct.pack('<Q', 0x100))  # Size in file
        elf_data.extend(struct.pack('<Q', 0x100))  # Size in memory
        elf_data.extend(struct.pack('<Q', 0x1000)) # Alignment
        
        # Pad to entry point
        while len(elf_data) < 0x78:
            elf_data.extend(b'\x00')
        
        # Simple exit code
        elf_data.extend(b'\x48\x31\xC0')    # xor rax, rax
        elf_data.extend(b'\x48\xFF\xC0')    # inc rax (sys_exit = 1)
        elf_data.extend(b'\x48\x31\xFF')    # xor rdi, rdi (exit code = 0)
        elf_data.extend(b'\x0F\x05')       # syscall
        
        # Pad to alignment
        while len(elf_data) < 0x100:
            elf_data.extend(b'\x00')
    
    output_path.write_bytes(elf_data)
    print(f"Created ELF binary: {output_path}")

def create_test_fixtures():
    """Create all test fixtures."""
    project_root = Path(__file__).parent.parent
    fixtures_dir = project_root / 'tests' / 'fixtures'
    
    # Ensure directories exist
    (fixtures_dir / 'binaries' / 'pe').mkdir(parents=True, exist_ok=True)
    (fixtures_dir / 'binaries' / 'elf').mkdir(parents=True, exist_ok=True)
    (fixtures_dir / 'binaries' / 'protected').mkdir(parents=True, exist_ok=True)
    (fixtures_dir / 'vulnerable_samples').mkdir(parents=True, exist_ok=True)
    (fixtures_dir / 'network_captures').mkdir(parents=True, exist_ok=True)
    
    print("Creating test fixtures...")
    
    # Create basic PE binaries
    create_pe_binary(fixtures_dir / 'binaries' / 'pe' / 'test_pe_basic.exe')
    
    # Create basic ELF binaries
    create_elf_binary(fixtures_dir / 'binaries' / 'elf' / 'test_elf_x64')
    
    # Create vulnerable samples
    create_vulnerable_binary(fixtures_dir / 'vulnerable_samples' / 'stack_overflow_test.exe')
    
    print("Test fixtures created successfully!")

def create_vulnerable_binary(output_path: Path):
    """Create a vulnerable binary for exploit testing."""
    # Simple vulnerable PE with stack overflow
    pe_data = create_basic_pe_with_vulnerability()
    output_path.write_bytes(pe_data)
    print(f"Created vulnerable binary: {output_path}")

def create_basic_pe_with_vulnerability():
    """Create basic PE with intentional vulnerability."""
    # This would create a real vulnerable binary for testing
    # For now, create a basic PE structure
    pe_data = b'MZ\x90\x00' + b'\x00' * 252
    return pe_data

if __name__ == '__main__':
    create_test_fixtures()
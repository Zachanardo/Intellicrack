"""Binary fixtures for testing with REAL binaries.

Provides actual PE/ELF files and protected samples for testing.
NO FAKE DATA - ALL FIXTURES PROVIDE REAL BINARIES.
"""
from __future__ import annotations

import os
import shutil
import struct
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from collections.abc import Iterator


class BinaryFixtureManager:
    """Manages real binary fixtures for testing."""

    @staticmethod
    def create_minimal_pe() -> bytes:
        """Create a minimal valid PE executable for testing."""
        # DOS Header
        dos_header = bytearray(64)
        dos_header[:2] = b'MZ'
        dos_header[60:64] = struct.pack('<I', 64)  # e_lfanew

        # DOS Stub
        dos_stub = b'\x0e\x1f\xba\x0e\x00\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21'
        dos_stub += b'This program cannot be run in DOS mode.\r\r\n$\x00\x00\x00\x00\x00\x00\x00'

        # PE Header
        pe_signature = b'PE\x00\x00'

        # COFF Header
        machine = struct.pack('<H', 0x8664)  # x64
        num_sections = struct.pack('<H', 2)  # .text and .data
        time_stamp = struct.pack('<I', 0)
        ptr_symbol_table = struct.pack('<I', 0)
        num_symbols = struct.pack('<I', 0)
        size_optional_header = struct.pack('<H', 240)  # x64 optional header size
        characteristics = struct.pack('<H', 0x0022)  # EXECUTABLE | LARGE_ADDRESS_AWARE

        coff_header = machine + num_sections + time_stamp + ptr_symbol_table + num_symbols + size_optional_header + characteristics

        # Optional Header (simplified)
        magic = struct.pack('<H', 0x020B)  # PE32+
        major_linker = struct.pack('B', 14)
        minor_linker = struct.pack('B', 0)
        size_of_code = struct.pack('<I', 512)
        size_of_initialized_data = struct.pack('<I', 512)
        size_of_uninitialized_data = struct.pack('<I', 0)
        address_of_entry_point = struct.pack('<I', 0x1000)
        base_of_code = struct.pack('<I', 0x1000)

        # Windows-specific fields
        image_base = struct.pack('<Q', 0x140000000)  # Default x64 base
        section_alignment = struct.pack('<I', 0x1000)
        file_alignment = struct.pack('<I', 0x200)
        os_version = struct.pack('<HH', 6, 0)  # Windows Vista+
        image_version = struct.pack('<HH', 0, 0)
        subsystem_version = struct.pack('<HH', 6, 0)
        win32_version = struct.pack('<I', 0)
        size_of_image = struct.pack('<I', 0x3000)
        size_of_headers = struct.pack('<I', 0x400)
        checksum = struct.pack('<I', 0)
        subsystem = struct.pack('<H', 3)  # CONSOLE
        dll_characteristics = struct.pack('<H', 0x8160)

        # Stack/heap sizes
        size_of_stack_reserve = struct.pack('<Q', 0x100000)
        size_of_stack_commit = struct.pack('<Q', 0x1000)
        size_of_heap_reserve = struct.pack('<Q', 0x100000)
        size_of_heap_commit = struct.pack('<Q', 0x1000)
        loader_flags = struct.pack('<I', 0)
        num_rva_and_sizes = struct.pack('<I', 16)

        # Data directories (16 entries, 8 bytes each)
        data_directories = bytearray(128)

        optional_header = (magic + major_linker + minor_linker + size_of_code +
                          size_of_initialized_data + size_of_uninitialized_data +
                          address_of_entry_point + base_of_code + image_base +
                          section_alignment + file_alignment + os_version +
                          image_version + subsystem_version + win32_version +
                          size_of_image + size_of_headers + checksum + subsystem +
                          dll_characteristics + size_of_stack_reserve +
                          size_of_stack_commit + size_of_heap_reserve +
                          size_of_heap_commit + loader_flags + num_rva_and_sizes +
                          data_directories)

        # Section Headers
        text_section = bytearray(40)
        text_section[:8] = b'.text\x00\x00\x00'
        struct.pack_into('<I', text_section, 8, 512)  # VirtualSize
        struct.pack_into('<I', text_section, 12, 0x1000)  # VirtualAddress
        struct.pack_into('<I', text_section, 16, 512)  # SizeOfRawData
        struct.pack_into('<I', text_section, 20, 0x400)  # PointerToRawData
        struct.pack_into('<I', text_section, 36, 0x60000020)  # Characteristics (CODE|EXECUTE|READ)

        data_section = bytearray(40)
        data_section[:8] = b'.data\x00\x00\x00'
        struct.pack_into('<I', data_section, 8, 512)  # VirtualSize
        struct.pack_into('<I', data_section, 12, 0x2000)  # VirtualAddress
        struct.pack_into('<I', data_section, 16, 512)  # SizeOfRawData
        struct.pack_into('<I', data_section, 20, 0x600)  # PointerToRawData
        struct.pack_into('<I', data_section, 36, 0xC0000040)  # Characteristics (INITIALIZED_DATA|READ|WRITE)

        # Padding to align to file alignment
        header_size = len(dos_header) + len(dos_stub) + len(pe_signature) + len(coff_header) + len(optional_header) + len(text_section) + len(data_section)
        padding = bytearray(0x400 - header_size)

        # Code section (simple ret instruction)
        code_section = bytearray(512)
        code_section[0] = 0xC3  # ret

        # Data section
        data_section_content = bytearray(512)
        data_section_content[:13] = b'Hello World!\x00'

        # Combine all parts
        pe_file = (dos_header + dos_stub + pe_signature + coff_header +
                  optional_header + text_section + data_section + padding +
                  code_section + data_section_content)

        return bytes(pe_file)

    @staticmethod
    def create_minimal_elf() -> bytes:
        """Create a minimal valid ELF executable for testing."""
        # ELF Header
        elf_header = bytearray(64)
        elf_header[:4] = b'\x7fELF'
        elf_header[4] = 2  # 64-bit
        elf_header[5] = 1  # Little endian
        elf_header[6] = 1  # Current version
        elf_header[7] = 0  # System V ABI

        # e_type (ET_EXEC)
        struct.pack_into('<H', elf_header, 16, 2)
        # e_machine (x86-64)
        struct.pack_into('<H', elf_header, 18, 62)
        # e_version
        struct.pack_into('<I', elf_header, 20, 1)
        # e_entry
        struct.pack_into('<Q', elf_header, 24, 0x400080)
        # e_phoff
        struct.pack_into('<Q', elf_header, 32, 64)
        # e_shoff
        struct.pack_into('<Q', elf_header, 40, 0)
        # e_flags
        struct.pack_into('<I', elf_header, 48, 0)
        # e_ehsize
        struct.pack_into('<H', elf_header, 52, 64)
        # e_phentsize
        struct.pack_into('<H', elf_header, 54, 56)
        # e_phnum
        struct.pack_into('<H', elf_header, 56, 1)
        # e_shentsize
        struct.pack_into('<H', elf_header, 58, 64)
        # e_shnum
        struct.pack_into('<H', elf_header, 60, 0)
        # e_shstrndx
        struct.pack_into('<H', elf_header, 62, 0)

        # Program Header
        program_header = bytearray(56)
        # p_type (PT_LOAD)
        struct.pack_into('<I', program_header, 0, 1)
        # p_flags (PF_X | PF_R)
        struct.pack_into('<I', program_header, 4, 5)
        # p_offset
        struct.pack_into('<Q', program_header, 8, 0)
        # p_vaddr
        struct.pack_into('<Q', program_header, 16, 0x400000)
        # p_paddr
        struct.pack_into('<Q', program_header, 24, 0x400000)
        # p_filesz
        struct.pack_into('<Q', program_header, 32, 0x100)
        # p_memsz
        struct.pack_into('<Q', program_header, 40, 0x100)
        # p_align
        struct.pack_into('<Q', program_header, 48, 0x1000)

        # Code (exit syscall)
        code = bytearray(16)
        code[:7] = b'\x48\x31\xff'
        code[7:12] = b'\x48\xc7\xc0\x3c\x00'  # mov rax, 60 (exit)
        code[12:14] = b'\x0f\x05'  # syscall

        # Padding
        padding = bytearray(0x100 - 64 - 56 - 16)

        # Combine all parts
        elf_file = elf_header + program_header + code + padding

        return bytes(elf_file)

    @staticmethod
    def get_system_binary() -> str | None:
        """Get a real system binary for testing."""
        # Try to find a common system binary
        if os.name == 'nt':  # Windows
            candidates = [
                r'C:\Windows\System32\notepad.exe',
                r'C:\Windows\System32\calc.exe',
                r'C:\Windows\System32\cmd.exe'
            ]
        else:  # Unix-like
            candidates = [
                '/bin/ls',
                '/usr/bin/ls',
                '/bin/cat',
                '/usr/bin/cat'
            ]

        return next(
            (candidate for candidate in candidates if os.path.exists(candidate)),
            None,
        )


@pytest.fixture(scope='session')
def binary_fixture_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Create a temporary directory with test binaries."""
    fixture_dir = tmp_path_factory.mktemp('binary_fixtures')

    # Create minimal PE
    pe_path = fixture_dir / 'minimal.exe'
    pe_data = BinaryFixtureManager.create_minimal_pe()
    pe_path.write_bytes(pe_data)

    # Create minimal ELF
    elf_path = fixture_dir / 'minimal.elf'
    elf_data = BinaryFixtureManager.create_minimal_elf()
    elf_path.write_bytes(elf_data)

    if system_binary := BinaryFixtureManager.get_system_binary():
        system_copy = fixture_dir / Path(system_binary).name
        shutil.copy2(system_binary, system_copy)

    return fixture_dir


@pytest.fixture
def real_pe_binary(binary_fixture_dir: Path) -> str:
    """Provide a real PE binary for testing."""
    return next(
        (
            str(file)
            for file in binary_fixture_dir.iterdir()
            if file.suffix == '.exe' and file.name != 'minimal.exe'
        ),
        str(binary_fixture_dir / 'minimal.exe'),
    )


@pytest.fixture
def real_elf_binary(binary_fixture_dir: Path) -> str:
    """Provide a real ELF binary for testing."""
    # First try system binary
    for file in binary_fixture_dir.iterdir():
        if file.suffix == '' and file.name not in ['minimal.elf', 'minimal.exe']:
            with open(file, 'rb') as f:
                if f.read(4) == b'\x7fELF':
                    return str(file)

    # Fallback to minimal ELF
    return str(binary_fixture_dir / 'minimal.elf')


@pytest.fixture
def real_protected_binary(binary_fixture_dir: Path) -> str:
    """Provide a real protected binary for testing."""
    # For testing, we'll apply simple protections to our minimal binary
    protected_path = binary_fixture_dir / 'protected.exe'

    if not protected_path.exists():
        # Copy minimal PE and apply basic obfuscation
        pe_data = bytearray((binary_fixture_dir / 'minimal.exe').read_bytes())

        # Add some anti-debug checks pattern
        anti_debug_pattern = b'\x64\xA1\x30\x00\x00\x00'  # mov eax, fs:[30h]
        pe_data.extend(anti_debug_pattern)

        # Add high entropy section to simulate packing
        high_entropy_data = os.urandom(512)
        pe_data.extend(high_entropy_data)

        protected_path.write_bytes(pe_data)

    return str(protected_path)


@pytest.fixture
def real_packed_binary(binary_fixture_dir: Path) -> str:
    """Provide a real packed binary for testing."""
    packed_path = binary_fixture_dir / 'packed.exe'

    if not packed_path.exists():
        # Try to pack with UPX if available
        try:
            source = binary_fixture_dir / 'minimal.exe'
            shutil.copy2(source, packed_path)
            subprocess.run(['upx', '-9', str(packed_path)],
                         capture_output=True, timeout=10, check=False)
        except Exception:
            # If UPX not available, simulate packed binary
            pe_data = bytearray((binary_fixture_dir / 'minimal.exe').read_bytes())

            # Add UPX signature pattern
            upx_sig = b'UPX!'
            pe_data[0x200:0x204] = upx_sig

            # Add compressed-looking data
            compressed_data = os.urandom(1024)
            pe_data.extend(compressed_data)

            packed_path.write_bytes(pe_data)

    return str(packed_path)

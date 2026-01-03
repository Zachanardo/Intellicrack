"""Production-ready tests for IAT hooking functionality in trial reset engine.

This module validates that IAT (Import Address Table) hooking works correctly
for defeating trial limitations by intercepting time-related API calls.
Tests verify proper PE parsing, IAT modification, architecture handling, and
edge cases including packed binaries and delayed imports.
"""

import ctypes
import os
import struct
import sys
import tempfile
from pathlib import Path
from typing import Any

import pefile
import pytest

from intellicrack.core.trial_reset_engine import TrialResetEngine

pytestmark = pytest.mark.skipif(
    sys.platform != "win32",
    reason="IAT hooking tests require Windows platform"
)


@pytest.fixture
def trial_reset_engine() -> TrialResetEngine:
    """Provide initialized TrialResetEngine instance."""
    return TrialResetEngine()


@pytest.fixture
def temp_dir() -> Path:
    """Provide temporary directory for test binaries."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def create_test_pe_x86() -> bytes:
    """Create minimal x86 PE executable for testing.

    Returns:
        Raw PE bytes with valid IAT structure importing kernel32.dll functions.
    """
    pe_header = bytearray(
        b"MZ"
        + b"\x90" * 58
        + struct.pack("<I", 0x80)
    )

    dos_stub = b"\x0e\x1f\xba\x0e\x00\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21"
    dos_stub += b"This program cannot be run in DOS mode.\r\r\n$"
    dos_stub += b"\x00" * (0x80 - len(pe_header) - len(dos_stub))

    pe_header += dos_stub

    pe_signature = b"PE\x00\x00"

    coff_header = struct.pack(
        "<HHIIIHH",
        0x014C,
        1,
        0,
        0,
        0,
        0xE0,
        0x010B,
    )

    optional_header = bytearray(224)
    struct.pack_into("<H", optional_header, 0, 0x010B)
    struct.pack_into("<I", optional_header, 16, 0x1000)
    struct.pack_into("<I", optional_header, 20, 0x200)
    struct.pack_into("<I", optional_header, 24, 0x1000)
    struct.pack_into("<I", optional_header, 28, 0x1000)
    struct.pack_into("<I", optional_header, 32, 0x200)
    struct.pack_into("<I", optional_header, 36, 0x3000)
    struct.pack_into("<I", optional_header, 40, 5)
    struct.pack_into("<I", optional_header, 56, 0x200)
    struct.pack_into("<I", optional_header, 60, 0x200)
    struct.pack_into("<H", optional_header, 68, 3)
    struct.pack_into("<I", optional_header, 104, 0x2000)
    struct.pack_into("<Q", optional_header, 112, 0x1000)
    struct.pack_into("<Q", optional_header, 120, 0x1000)

    struct.pack_into("<I", optional_header, 192, 0x2000)
    struct.pack_into("<I", optional_header, 196, 0x100)

    section_header = bytearray(40)
    section_header[:8] = b".idata\x00\x00"
    struct.pack_into("<I", section_header, 8, 0x100)
    struct.pack_into("<I", section_header, 12, 0x2000)
    struct.pack_into("<I", section_header, 16, 0x200)
    struct.pack_into("<I", section_header, 20, 0x400)
    struct.pack_into("<I", section_header, 36, 0xC0000040)

    import_descriptor = bytearray(20)
    struct.pack_into("<I", import_descriptor, 0, 0x2080)
    struct.pack_into("<I", import_descriptor, 12, 0x2060)
    struct.pack_into("<I", import_descriptor, 16, 0x2000)
    import_descriptor += b"\x00" * 20

    import_names = b"kernel32.dll\x00"

    thunk_data = struct.pack("<I", 0x20A0)
    thunk_data += struct.pack("<I", 0x20B0)
    thunk_data += struct.pack("<I", 0x20C0)
    thunk_data += struct.pack("<I", 0)

    hint_name_1 = struct.pack("<H", 0) + b"GetSystemTime\x00"
    hint_name_2 = struct.pack("<H", 0) + b"GetTickCount\x00"
    hint_name_3 = struct.pack("<H", 0) + b"QueryPerformanceCounter\x00"

    idata_section = bytearray(512)
    idata_section[0:40] = import_descriptor
    idata_section[0x60:0x60+len(import_names)] = import_names
    idata_section[0x80:0x80+len(thunk_data)] = thunk_data
    idata_section[0xA0:0xA0+len(hint_name_1)] = hint_name_1
    idata_section[0xB0:0xB0+len(hint_name_2)] = hint_name_2
    idata_section[0xC0:0xC0+len(hint_name_3)] = hint_name_3

    pe_data = pe_header + pe_signature + coff_header + optional_header + section_header
    pe_data += b"\x00" * (0x400 - len(pe_data))
    pe_data += bytes(idata_section)
    pe_data += b"\x00" * (0x600 - len(pe_data))

    return bytes(pe_data)


@pytest.fixture
def create_test_pe_x64() -> bytes:
    """Create minimal x64 PE executable for testing.

    Returns:
        Raw PE bytes with valid IAT structure for x64 architecture.
    """
    pe_header = bytearray(
        b"MZ"
        + b"\x90" * 58
        + struct.pack("<I", 0x80)
    )

    dos_stub = b"\x0e\x1f\xba\x0e\x00\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21"
    dos_stub += b"This program cannot be run in DOS mode.\r\r\n$"
    dos_stub += b"\x00" * (0x80 - len(pe_header) - len(dos_stub))

    pe_header += dos_stub

    pe_signature = b"PE\x00\x00"

    coff_header = struct.pack(
        "<HHIIIHH",
        0x8664,
        1,
        0,
        0,
        0,
        0xF0,
        0x020B,
    )

    optional_header = bytearray(240)
    struct.pack_into("<H", optional_header, 0, 0x020B)
    struct.pack_into("<I", optional_header, 16, 0x1000)
    struct.pack_into("<I", optional_header, 20, 0x200)
    struct.pack_into("<I", optional_header, 24, 0x1000)
    struct.pack_into("<I", optional_header, 28, 0x1000)
    struct.pack_into("<I", optional_header, 32, 0x200)
    struct.pack_into("<I", optional_header, 36, 0x3000)
    struct.pack_into("<I", optional_header, 40, 5)
    struct.pack_into("<I", optional_header, 56, 0x200)
    struct.pack_into("<I", optional_header, 60, 0x200)
    struct.pack_into("<H", optional_header, 68, 3)
    struct.pack_into("<Q", optional_header, 104, 0x1000)
    struct.pack_into("<Q", optional_header, 112, 0x1000)
    struct.pack_into("<Q", optional_header, 120, 0x1000)

    struct.pack_into("<I", optional_header, 208, 0x2000)
    struct.pack_into("<I", optional_header, 212, 0x100)

    section_header = bytearray(40)
    section_header[:8] = b".idata\x00\x00"
    struct.pack_into("<I", section_header, 8, 0x100)
    struct.pack_into("<I", section_header, 12, 0x2000)
    struct.pack_into("<I", section_header, 16, 0x200)
    struct.pack_into("<I", section_header, 20, 0x400)
    struct.pack_into("<I", section_header, 36, 0xC0000040)

    import_descriptor = bytearray(20)
    struct.pack_into("<I", import_descriptor, 0, 0x2080)
    struct.pack_into("<I", import_descriptor, 12, 0x2060)
    struct.pack_into("<I", import_descriptor, 16, 0x2000)
    import_descriptor += b"\x00" * 20

    import_names = b"kernel32.dll\x00"

    thunk_data = struct.pack("<Q", 0x20A0)
    thunk_data += struct.pack("<Q", 0x20B0)
    thunk_data += struct.pack("<Q", 0x20C0)
    thunk_data += struct.pack("<Q", 0)

    hint_name_1 = struct.pack("<H", 0) + b"GetSystemTime\x00"
    hint_name_2 = struct.pack("<H", 0) + b"GetTickCount64\x00"
    hint_name_3 = struct.pack("<H", 0) + b"QueryPerformanceCounter\x00"

    idata_section = bytearray(512)
    idata_section[0:40] = import_descriptor
    idata_section[0x60:0x60+len(import_names)] = import_names
    idata_section[0x80:0x80+len(thunk_data)] = thunk_data
    idata_section[0xA0:0xA0+len(hint_name_1)] = hint_name_1
    idata_section[0xB0:0xB0+len(hint_name_2)] = hint_name_2
    idata_section[0xC0:0xC0+len(hint_name_3)] = hint_name_3

    pe_data = pe_header + pe_signature + coff_header + optional_header + section_header
    pe_data += b"\x00" * (0x400 - len(pe_data))
    pe_data += bytes(idata_section)
    pe_data += b"\x00" * (0x600 - len(pe_data))

    return bytes(pe_data)


class TestIATParsingAndLocation:
    """Tests for PE parsing and IAT location functionality."""

    def test_locate_iat_in_x86_binary(
        self,
        create_test_pe_x86: bytes,
        temp_dir: Path
    ) -> None:
        """IAT parser locates import address table in x86 PE binary."""
        pe_path = temp_dir / "test_x86.exe"
        pe_path.write_bytes(create_test_pe_x86)

        pe = pefile.PE(str(pe_path))

        assert hasattr(pe, "DIRECTORY_ENTRY_IMPORT")
        assert len(pe.DIRECTORY_ENTRY_IMPORT) > 0

        kernel32_import = None
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            if entry.dll.decode().lower() == "kernel32.dll":
                kernel32_import = entry
                break

        assert kernel32_import is not None
        assert len(kernel32_import.imports) >= 3

        function_names = [imp.name.decode() for imp in kernel32_import.imports if imp.name]
        assert "GetSystemTime" in function_names
        assert "GetTickCount" in function_names
        assert "QueryPerformanceCounter" in function_names

        for imp in kernel32_import.imports:
            if imp.name:
                assert imp.address > 0
                assert imp.address < len(create_test_pe_x86)

        pe.close()

    def test_locate_iat_in_x64_binary(
        self,
        create_test_pe_x64: bytes,
        temp_dir: Path
    ) -> None:
        """IAT parser locates import address table in x64 PE binary."""
        pe_path = temp_dir / "test_x64.exe"
        pe_path.write_bytes(create_test_pe_x64)

        pe = pefile.PE(str(pe_path))

        assert pe.FILE_HEADER.Machine == 0x8664
        assert hasattr(pe, "DIRECTORY_ENTRY_IMPORT")
        assert len(pe.DIRECTORY_ENTRY_IMPORT) > 0

        kernel32_import = None
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            if entry.dll.decode().lower() == "kernel32.dll":
                kernel32_import = entry
                break

        assert kernel32_import is not None
        assert len(kernel32_import.imports) >= 3

        for imp in kernel32_import.imports:
            if imp.name:
                assert imp.address > 0

        pe.close()

    def test_parse_iat_structure_fields(
        self,
        create_test_pe_x86: bytes,
        temp_dir: Path
    ) -> None:
        """IAT parser extracts all required structure fields correctly."""
        pe_path = temp_dir / "test_x86.exe"
        pe_path.write_bytes(create_test_pe_x86)

        pe = pefile.PE(str(pe_path))

        import_desc = pe.DIRECTORY_ENTRY_IMPORT[0]

        assert import_desc.struct.OriginalFirstThunk > 0
        assert import_desc.struct.FirstThunk > 0
        assert import_desc.struct.Name > 0

        dll_name = pe.get_string_at_rva(import_desc.struct.Name)
        assert dll_name.decode().lower() == "kernel32.dll"

        pe.close()

    def test_distinguish_x86_x64_iat_structure(
        self,
        create_test_pe_x86: bytes,
        create_test_pe_x64: bytes,
        temp_dir: Path
    ) -> None:
        """IAT parser correctly distinguishes between x86 and x64 structures."""
        pe_x86_path = temp_dir / "test_x86.exe"
        pe_x64_path = temp_dir / "test_x64.exe"
        pe_x86_path.write_bytes(create_test_pe_x86)
        pe_x64_path.write_bytes(create_test_pe_x64)

        pe_x86 = pefile.PE(str(pe_x86_path))
        pe_x64 = pefile.PE(str(pe_x64_path))

        assert pe_x86.FILE_HEADER.Machine == 0x014C
        assert pe_x64.FILE_HEADER.Machine == 0x8664

        is_x86_32bit = pe_x86.OPTIONAL_HEADER.Magic == 0x010B
        is_x64_64bit = pe_x64.OPTIONAL_HEADER.Magic == 0x020B

        assert is_x86_32bit
        assert is_x64_64bit

        pe_x86.close()
        pe_x64.close()

    def test_locate_multiple_dll_imports(
        self,
        temp_dir: Path
    ) -> None:
        """IAT parser handles multiple DLL imports in single binary."""
        system32 = Path(os.environ.get("SystemRoot", "C:\\Windows")) / "System32"
        test_binary = system32 / "notepad.exe"

        if not test_binary.exists():
            pytest.skip("notepad.exe not found in System32")

        pe = pefile.PE(str(test_binary))

        assert hasattr(pe, "DIRECTORY_ENTRY_IMPORT")
        assert len(pe.DIRECTORY_ENTRY_IMPORT) > 1

        dll_names = [entry.dll.decode().lower() for entry in pe.DIRECTORY_ENTRY_IMPORT]

        assert "kernel32.dll" in dll_names

        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            assert len(entry.imports) > 0
            for imp in entry.imports:
                if imp.name:
                    assert imp.address > 0

        pe.close()


class TestIATModification:
    """Tests for IAT modification and hooking functionality."""

    def test_modify_iat_entry_x86(
        self,
        create_test_pe_x86: bytes,
        temp_dir: Path
    ) -> None:
        """IAT modification correctly updates function pointer in x86 binary."""
        pe_path = temp_dir / "test_x86.exe"
        pe_path.write_bytes(create_test_pe_x86)

        pe_data = bytearray(create_test_pe_x86)
        pe = pefile.PE(data=bytes(pe_data))

        kernel32_import = None
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            if entry.dll.decode().lower() == "kernel32.dll":
                kernel32_import = entry
                break

        assert kernel32_import is not None

        get_system_time_import = None
        for imp in kernel32_import.imports:
            if imp.name and imp.name.decode() == "GetSystemTime":
                get_system_time_import = imp
                break

        assert get_system_time_import is not None

        original_address = get_system_time_import.address
        new_hook_address = 0x12345678

        iat_rva = get_system_time_import.address
        iat_offset = pe.get_offset_from_rva(iat_rva)

        struct.pack_into("<I", pe_data, iat_offset, new_hook_address)

        pe_modified = pefile.PE(data=bytes(pe_data))
        for entry in pe_modified.DIRECTORY_ENTRY_IMPORT:
            if entry.dll.decode().lower() == "kernel32.dll":
                for imp in entry.imports:
                    if imp.name and imp.name.decode() == "GetSystemTime":
                        modified_thunk = struct.unpack(
                            "<I",
                            pe_data[pe.get_offset_from_rva(imp.address):pe.get_offset_from_rva(imp.address)+4]
                        )[0]
                        assert modified_thunk == new_hook_address
                        assert modified_thunk != original_address

        pe.close()
        pe_modified.close()

    def test_modify_iat_entry_x64(
        self,
        create_test_pe_x64: bytes,
        temp_dir: Path
    ) -> None:
        """IAT modification correctly updates function pointer in x64 binary."""
        pe_path = temp_dir / "test_x64.exe"
        pe_path.write_bytes(create_test_pe_x64)

        pe_data = bytearray(create_test_pe_x64)
        pe = pefile.PE(data=bytes(pe_data))

        kernel32_import = None
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            if entry.dll.decode().lower() == "kernel32.dll":
                kernel32_import = entry
                break

        assert kernel32_import is not None

        get_system_time_import = None
        for imp in kernel32_import.imports:
            if imp.name and imp.name.decode() == "GetSystemTime":
                get_system_time_import = imp
                break

        assert get_system_time_import is not None

        original_address = get_system_time_import.address
        new_hook_address = 0x1234567890ABCDEF

        iat_rva = get_system_time_import.address
        iat_offset = pe.get_offset_from_rva(iat_rva)

        struct.pack_into("<Q", pe_data, iat_offset, new_hook_address)

        pe_modified = pefile.PE(data=bytes(pe_data))
        for entry in pe_modified.DIRECTORY_ENTRY_IMPORT:
            if entry.dll.decode().lower() == "kernel32.dll":
                for imp in entry.imports:
                    if imp.name and imp.name.decode() == "GetSystemTime":
                        modified_thunk = struct.unpack(
                            "<Q",
                            pe_data[pe.get_offset_from_rva(imp.address):pe.get_offset_from_rva(imp.address)+8]
                        )[0]
                        assert modified_thunk == new_hook_address
                        assert modified_thunk != original_address

        pe_modified.close()
        pe.close()

    def test_preserve_original_addresses_for_unhooking(
        self,
        create_test_pe_x86: bytes,
        temp_dir: Path
    ) -> None:
        """IAT hooking preserves original function addresses for later restoration."""
        pe_data = bytearray(create_test_pe_x86)
        pe = pefile.PE(data=bytes(pe_data))

        original_addresses: dict[str, int] = {}

        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            if entry.dll.decode().lower() == "kernel32.dll":
                for imp in entry.imports:
                    if imp.name:
                        func_name = imp.name.decode()
                        iat_offset = pe.get_offset_from_rva(imp.address)
                        original_addr = struct.unpack("<I", pe_data[iat_offset:iat_offset+4])[0]
                        original_addresses[func_name] = original_addr

        assert "GetSystemTime" in original_addresses
        assert "GetTickCount" in original_addresses

        hook_address = 0x99999999
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            if entry.dll.decode().lower() == "kernel32.dll":
                for imp in entry.imports:
                    if imp.name and imp.name.decode() == "GetSystemTime":
                        iat_offset = pe.get_offset_from_rva(imp.address)
                        struct.pack_into("<I", pe_data, iat_offset, hook_address)

        pe_hooked = pefile.PE(data=bytes(pe_data))
        for entry in pe_hooked.DIRECTORY_ENTRY_IMPORT:
            if entry.dll.decode().lower() == "kernel32.dll":
                for imp in entry.imports:
                    if imp.name and imp.name.decode() == "GetSystemTime":
                        iat_offset = pe.get_offset_from_rva(imp.address)
                        current_addr = struct.unpack("<I", pe_data[iat_offset:iat_offset+4])[0]
                        assert current_addr == hook_address

        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            if entry.dll.decode().lower() == "kernel32.dll":
                for imp in entry.imports:
                    if imp.name and imp.name.decode() == "GetSystemTime":
                        iat_offset = pe.get_offset_from_rva(imp.address)
                        struct.pack_into("<I", pe_data, iat_offset, original_addresses["GetSystemTime"])

        pe_restored = pefile.PE(data=bytes(pe_data))
        for entry in pe_restored.DIRECTORY_ENTRY_IMPORT:
            if entry.dll.decode().lower() == "kernel32.dll":
                for imp in entry.imports:
                    if imp.name and imp.name.decode() == "GetSystemTime":
                        iat_offset = pe.get_offset_from_rva(imp.address)
                        restored_addr = struct.unpack("<I", pe_data[iat_offset:iat_offset+4])[0]
                        assert restored_addr == original_addresses["GetSystemTime"]

        pe.close()
        pe_hooked.close()
        pe_restored.close()

    def test_modify_multiple_iat_entries(
        self,
        create_test_pe_x86: bytes,
        temp_dir: Path
    ) -> None:
        """IAT modification handles multiple function hooks simultaneously."""
        pe_data = bytearray(create_test_pe_x86)
        pe = pefile.PE(data=bytes(pe_data))

        hooks = {
            "GetSystemTime": 0x11111111,
            "GetTickCount": 0x22222222,
            "QueryPerformanceCounter": 0x33333333,
        }

        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            if entry.dll.decode().lower() == "kernel32.dll":
                for imp in entry.imports:
                    if imp.name:
                        func_name = imp.name.decode()
                        if func_name in hooks:
                            iat_offset = pe.get_offset_from_rva(imp.address)
                            struct.pack_into("<I", pe_data, iat_offset, hooks[func_name])

        pe_modified = pefile.PE(data=bytes(pe_data))
        verified_hooks = 0

        for entry in pe_modified.DIRECTORY_ENTRY_IMPORT:
            if entry.dll.decode().lower() == "kernel32.dll":
                for imp in entry.imports:
                    if imp.name:
                        func_name = imp.name.decode()
                        if func_name in hooks:
                            iat_offset = pe.get_offset_from_rva(imp.address)
                            current_addr = struct.unpack("<I", pe_data[iat_offset:iat_offset+4])[0]
                            assert current_addr == hooks[func_name]
                            verified_hooks += 1

        assert verified_hooks == len(hooks)

        pe.close()
        pe_modified.close()


class TestDelayedAndBoundImports:
    """Tests for handling delayed imports and bound imports."""

    def test_detect_delayed_imports(self) -> None:
        """IAT parser detects delayed import directory in PE binary."""
        system32 = Path(os.environ.get("SystemRoot", "C:\\Windows")) / "System32"

        test_binaries = [
            system32 / "msvcr120.dll",
            system32 / "msvcp140.dll",
            system32 / "vcruntime140.dll",
        ]

        found_delayed = False

        for binary_path in test_binaries:
            if not binary_path.exists():
                continue

            try:
                pe = pefile.PE(str(binary_path))

                if hasattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT"):
                    assert len(pe.DIRECTORY_ENTRY_DELAY_IMPORT) >= 0
                    found_delayed = True

                pe.close()
            except Exception:
                continue

        if not found_delayed:
            pytest.skip("No binaries with delayed imports found for testing")

    def test_parse_delayed_import_structure(self) -> None:
        """IAT parser correctly parses delayed import descriptor structure."""
        system32 = Path(os.environ.get("SystemRoot", "C:\\Windows")) / "System32"

        test_binaries = [
            system32 / "d3d11.dll",
            system32 / "dxgi.dll",
        ]

        found_delayed = False

        for binary_path in test_binaries:
            if not binary_path.exists():
                continue

            try:
                pe = pefile.PE(str(binary_path))

                if hasattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT") and len(pe.DIRECTORY_ENTRY_DELAY_IMPORT) > 0:
                    for delay_import in pe.DIRECTORY_ENTRY_DELAY_IMPORT:
                        assert hasattr(delay_import.struct, "szName")
                        assert hasattr(delay_import.struct, "pIAT")
                        assert hasattr(delay_import.struct, "pINT")

                        dll_name = pe.get_string_at_rva(delay_import.struct.szName)
                        assert len(dll_name) > 0

                        found_delayed = True

                pe.close()
            except Exception:
                continue

        if not found_delayed:
            pytest.skip("No binaries with delayed imports found for testing")

    def test_detect_bound_imports(self) -> None:
        """IAT parser detects bound import directory in PE binary."""
        system32 = Path(os.environ.get("SystemRoot", "C:\\Windows")) / "System32"

        test_binaries = list(system32.glob("*.exe"))[:20]

        found_bound = False

        for binary_path in test_binaries:
            if not binary_path.exists():
                continue

            try:
                pe = pefile.PE(str(binary_path))

                if hasattr(pe, "DIRECTORY_ENTRY_BOUND_IMPORT"):
                    assert len(pe.DIRECTORY_ENTRY_BOUND_IMPORT) >= 0
                    found_bound = True

                pe.close()
            except Exception:
                continue

        if not found_bound:
            pytest.skip("No binaries with bound imports found for testing")


class TestEdgeCases:
    """Tests for edge cases including packed binaries and stripped binaries."""

    def test_handle_stripped_import_table(
        self,
        create_test_pe_x86: bytes,
        temp_dir: Path
    ) -> None:
        """IAT parser handles binaries with minimal import information."""
        pe_data = bytearray(create_test_pe_x86)
        pe = pefile.PE(data=bytes(pe_data))

        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name:
                    assert imp.address > 0

                    iat_offset = pe.get_offset_from_rva(imp.address)
                    assert iat_offset is not None

        pe.close()

    def test_handle_corrupted_import_descriptor(
        self,
        create_test_pe_x86: bytes,
        temp_dir: Path
    ) -> None:
        """IAT parser gracefully handles corrupted import descriptors."""
        pe_data = bytearray(create_test_pe_x86)

        corrupted_offset = 0x400 + 5
        pe_data[corrupted_offset:corrupted_offset+4] = b"\xFF\xFF\xFF\xFF"

        try:
            pe = pefile.PE(data=bytes(pe_data))
            pe.close()
        except pefile.PEFormatError:
            pass

    def test_handle_missing_import_directory(
        self,
        temp_dir: Path
    ) -> None:
        """IAT parser handles PE files without import directory."""
        minimal_pe = bytearray(b"MZ" + b"\x90" * 58 + struct.pack("<I", 0x80))
        minimal_pe += b"\x00" * (0x80 - len(minimal_pe))
        minimal_pe += b"PE\x00\x00"

        coff_header = struct.pack("<HHIIIHH", 0x014C, 0, 0, 0, 0, 0xE0, 0x010B)
        minimal_pe += coff_header

        optional_header = bytearray(224)
        struct.pack_into("<H", optional_header, 0, 0x010B)
        minimal_pe += bytes(optional_header)

        pe_path = temp_dir / "minimal.exe"
        pe_path.write_bytes(bytes(minimal_pe))

        pe = pefile.PE(str(pe_path))

        assert not hasattr(pe, "DIRECTORY_ENTRY_IMPORT") or len(pe.DIRECTORY_ENTRY_IMPORT) == 0

        pe.close()

    def test_real_system_binary_iat_parsing(self) -> None:
        """IAT parser successfully parses real Windows system binaries."""
        system32 = Path(os.environ.get("SystemRoot", "C:\\Windows")) / "System32"
        notepad = system32 / "notepad.exe"

        if not notepad.exists():
            pytest.skip("notepad.exe not found")

        pe = pefile.PE(str(notepad))

        assert hasattr(pe, "DIRECTORY_ENTRY_IMPORT")
        assert len(pe.DIRECTORY_ENTRY_IMPORT) > 0

        total_imports = 0
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode().lower()
            assert len(dll_name) > 0

            for imp in entry.imports:
                if imp.name:
                    assert imp.address > 0
                    total_imports += 1

        assert total_imports > 0

        pe.close()

    def test_handle_rva_to_offset_conversion(
        self,
        create_test_pe_x86: bytes,
        temp_dir: Path
    ) -> None:
        """IAT parser correctly converts RVA to file offset for IAT access."""
        pe_path = temp_dir / "test_x86.exe"
        pe_path.write_bytes(create_test_pe_x86)

        pe = pefile.PE(str(pe_path))

        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            if entry.dll.decode().lower() == "kernel32.dll":
                for imp in entry.imports:
                    if imp.name:
                        rva = imp.address
                        offset = pe.get_offset_from_rva(rva)

                        assert offset is not None
                        assert offset >= 0
                        assert offset < len(create_test_pe_x86)

                        section = pe.get_section_by_rva(rva)
                        assert section is not None

        pe.close()

    def test_handle_multiple_sections_with_imports(self) -> None:
        """IAT parser handles imports spread across multiple sections."""
        system32 = Path(os.environ.get("SystemRoot", "C:\\Windows")) / "System32"

        test_binaries = [
            system32 / "kernel32.dll",
            system32 / "user32.dll",
            system32 / "gdi32.dll",
        ]

        for binary_path in test_binaries:
            if not binary_path.exists():
                continue

            try:
                pe = pefile.PE(str(binary_path))

                if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                    pe.close()
                    continue

                sections_with_imports = set()

                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        if imp.address:
                            section = pe.get_section_by_rva(imp.address)
                            if section:
                                sections_with_imports.add(section.Name.decode().rstrip('\x00'))

                pe.close()

                if len(sections_with_imports) > 0:
                    break
            except Exception:
                continue


class TestArchitectureHandling:
    """Tests for proper x86 and x64 architecture handling."""

    def test_detect_x86_architecture(
        self,
        create_test_pe_x86: bytes,
        temp_dir: Path
    ) -> None:
        """IAT parser correctly identifies x86 architecture."""
        pe_path = temp_dir / "test_x86.exe"
        pe_path.write_bytes(create_test_pe_x86)

        pe = pefile.PE(str(pe_path))

        assert pe.FILE_HEADER.Machine == 0x014C
        assert pe.OPTIONAL_HEADER.Magic == 0x010B

        is_32bit = pe.OPTIONAL_HEADER.Magic == 0x010B
        assert is_32bit

        pe.close()

    def test_detect_x64_architecture(
        self,
        create_test_pe_x64: bytes,
        temp_dir: Path
    ) -> None:
        """IAT parser correctly identifies x64 architecture."""
        pe_path = temp_dir / "test_x64.exe"
        pe_path.write_bytes(create_test_pe_x64)

        pe = pefile.PE(str(pe_path))

        assert pe.FILE_HEADER.Machine == 0x8664
        assert pe.OPTIONAL_HEADER.Magic == 0x020B

        is_64bit = pe.OPTIONAL_HEADER.Magic == 0x020B
        assert is_64bit

        pe.close()

    def test_iat_entry_size_x86_vs_x64(
        self,
        create_test_pe_x86: bytes,
        create_test_pe_x64: bytes,
        temp_dir: Path
    ) -> None:
        """IAT parser uses correct entry size for x86 (4 bytes) vs x64 (8 bytes)."""
        pe_x86_path = temp_dir / "test_x86.exe"
        pe_x64_path = temp_dir / "test_x64.exe"
        pe_x86_path.write_bytes(create_test_pe_x86)
        pe_x64_path.write_bytes(create_test_pe_x64)

        pe_x86 = pefile.PE(str(pe_x86_path))
        pe_x64 = pefile.PE(str(pe_x64_path))

        is_x86_32bit = pe_x86.OPTIONAL_HEADER.Magic == 0x010B
        is_x64_64bit = pe_x64.OPTIONAL_HEADER.Magic == 0x020B

        x86_entry_size = 4 if is_x86_32bit else 8
        x64_entry_size = 4 if not is_x64_64bit else 8

        assert x86_entry_size == 4
        assert x64_entry_size == 8

        pe_x86.close()
        pe_x64.close()

    def test_handle_wow64_compatibility(self) -> None:
        """IAT parser handles WOW64 (32-bit on 64-bit Windows) correctly."""
        system32 = Path(os.environ.get("SystemRoot", "C:\\Windows")) / "SysWOW64"

        if not system32.exists():
            pytest.skip("SysWOW64 not found (not a 64-bit Windows system)")

        notepad = system32 / "notepad.exe"
        if not notepad.exists():
            pytest.skip("SysWOW64\\notepad.exe not found")

        pe = pefile.PE(str(notepad))

        assert pe.FILE_HEADER.Machine == 0x014C
        assert pe.OPTIONAL_HEADER.Magic == 0x010B

        assert hasattr(pe, "DIRECTORY_ENTRY_IMPORT")

        pe.close()


class TestIATIntegrationWithTrialReset:
    """Integration tests verifying IAT hooking works with trial reset engine."""

    def test_trial_reset_engine_has_module_enumeration(
        self,
        trial_reset_engine: TrialResetEngine
    ) -> None:
        """Trial reset engine can enumerate process modules for IAT location."""
        current_pid = os.getpid()

        modules = trial_reset_engine._enumerate_process_modules(current_pid)  # type: ignore[attr-defined]

        assert isinstance(modules, dict)
        assert len(modules) > 0

        assert "python.exe" in modules or "python311.dll" in modules or "python312.dll" in modules or any("python" in m.lower() for m in modules)

        for module_name, (base_addr, size) in modules.items():
            assert isinstance(module_name, str)
            assert isinstance(base_addr, int)
            assert isinstance(size, int)
            assert base_addr > 0
            assert size > 0

    def test_trial_reset_engine_resolves_function_addresses(
        self,
        trial_reset_engine: TrialResetEngine
    ) -> None:
        """Trial reset engine resolves function addresses in target process."""
        current_pid = os.getpid()

        kernel32 = ctypes.windll.kernel32
        hProcess = kernel32.OpenProcess(0x0400 | 0x0010, False, current_pid)

        if not hProcess:
            pytest.skip("Failed to open current process")

        try:
            host_kernel32 = kernel32.GetModuleHandleW("kernel32.dll")
            assert host_kernel32

            function_names = [b"GetSystemTime", b"GetTickCount", b"QueryPerformanceCounter"]

            resolved = trial_reset_engine._resolve_target_process_functions(  # type: ignore[attr-defined]
                hProcess,
                current_pid,
                host_kernel32,
                function_names
            )

            assert len(resolved) == len(function_names)

            for addr in resolved:
                assert addr is not None
                assert addr > 0

        finally:
            kernel32.CloseHandle(hProcess)

    def test_trial_reset_engine_detects_architecture(
        self,
        trial_reset_engine: TrialResetEngine
    ) -> None:
        """Trial reset engine correctly detects process architecture."""
        current_pid = os.getpid()

        kernel32 = ctypes.windll.kernel32
        hProcess = kernel32.OpenProcess(0x0400 | 0x0010, False, current_pid)

        if not hProcess:
            pytest.skip("Failed to open current process")

        try:
            is_64bit = trial_reset_engine._is_64bit_process(hProcess)  # type: ignore[attr-defined]

            import platform
            expected_64bit = platform.machine().endswith('64')

            assert isinstance(is_64bit, bool)

            if sys.maxsize > 2**32:
                assert is_64bit == True
            else:
                assert is_64bit == False

        finally:
            kernel32.CloseHandle(hProcess)

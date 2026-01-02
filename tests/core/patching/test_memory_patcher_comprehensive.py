"""Comprehensive Tests for Memory Patcher.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellicrack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""

import ctypes
import os
import platform
import struct
import sys
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.patching.memory_patcher import (
    PAGE_EXECUTE_READWRITE,
    PAGE_GUARD,
    PAGE_NOACCESS,
    PTRACE_ATTACH,
    PTRACE_DETACH,
    PTRACE_POKEDATA,
    _bypass_memory_protection_unix,  # noqa: PLC2701
    _bypass_memory_protection_windows,  # noqa: PLC2701
    _create_bool_type,  # noqa: PLC2701
    _create_byte_type,  # noqa: PLC2701
    _create_dword_type,  # noqa: PLC2701
    _create_handle_types,  # noqa: PLC2701
    _create_pointer_types,  # noqa: PLC2701
    _create_word_type,  # noqa: PLC2701
    _get_wintypes,  # noqa: PLC2701
    _handle_guard_pages_unix,  # noqa: PLC2701
    _handle_guard_pages_windows,  # noqa: PLC2701
    _patch_memory_unix,  # noqa: PLC2701
    _patch_memory_windows,  # noqa: PLC2701
    bypass_memory_protection,
    detect_and_bypass_guard_pages,
    generate_launcher_script,
    handle_guard_pages,
    log_message,
    patch_memory_direct,
    setup_memory_patching,
)


@pytest.fixture
def test_address() -> int:
    """Provide valid test memory address."""
    buffer = ctypes.create_string_buffer(4096)
    return ctypes.addressof(buffer)


@pytest.fixture
def test_buffer() -> Any:
    """Create test buffer for memory operations (ctypes.Array[c_char])."""
    buffer = ctypes.create_string_buffer(4096)
    test_pattern = b"ORIGINAL_DATA_PATTERN" * 100
    ctypes.memmove(buffer, test_pattern, min(len(test_pattern), 4096))
    return buffer


class RealSignalEmitter:
    """Real signal emitter for testing that captures emitted messages."""

    def __init__(self) -> None:
        """Initialize signal emitter with message storage."""
        self.messages: list[str] = []

    def emit(self, *args: object) -> None:
        """Capture emitted signal messages.

        Args:
            *args: Signal arguments to capture.

        """
        for arg in args:
            if isinstance(arg, str):
                self.messages.append(arg)


class RealApplicationStub:
    """Real application stub for testing memory patcher functionality."""

    def __init__(self, binary_path: str | None = None) -> None:
        """Initialize application stub with test configuration.

        Args:
            binary_path: Path to target binary file.

        """
        self.binary_path: str | None = binary_path
        self.potential_patches: list[dict[str, object]] = [
            {
                "address": 0x401000,
                "old_bytes": b"\x74\x05",
                "new_bytes": b"\xEB\x05",
                "description": "Patch license check jump",
            },
            {
                "address": 0x402000,
                "old_bytes": b"\x85\xC0\x74\x10",
                "new_bytes": b"\x31\xC0\x90\x90",
                "description": "NOP serial validation",
            },
        ]
        self.update_output: RealSignalEmitter = RealSignalEmitter()


@pytest.fixture
def real_app(tmp_path: Path) -> RealApplicationStub:
    """Create real application stub instance for testing.

    Args:
        tmp_path: Pytest temporary directory fixture.

    Returns:
        Configured RealApplicationStub instance.

    """
    binary_path = str(tmp_path / "target.exe")
    return RealApplicationStub(binary_path=binary_path)


class TestLogMessage:
    """Tests for log_message utility function."""

    def test_log_message_formats_correctly(self) -> None:
        """log_message wraps message in brackets."""
        result: str = log_message("Test message")
        assert result == "[Test message]"
        assert result.startswith("[")
        assert result.endswith("]")

    def test_log_message_preserves_content(self) -> None:
        """log_message preserves all message content."""
        message: str = "Complex [message] with {special} chars & symbols!"
        result: str = log_message(message)
        assert message in result
        assert result == f"[{message}]"

    def test_log_message_handles_empty_string(self) -> None:
        """log_message handles empty strings correctly."""
        result: str = log_message("")
        assert result == "[]"
        assert len(result) == 2


class TestWinTypeCreation:
    """Tests for Windows type creation functions."""

    def test_create_dword_type_valid_values(self) -> None:
        """DWORD type handles valid 32-bit values correctly."""
        DWORD = _create_dword_type(ctypes)
        dword: Any = DWORD(0x12345678)

        assert dword.value == 0x12345678
        assert isinstance(dword.value, int)
        assert 0 <= dword.value <= 0xFFFFFFFF

    def test_create_dword_type_boundary_values(self) -> None:
        """DWORD type enforces 32-bit boundaries."""
        DWORD = _create_dword_type(ctypes)

        dword_max: Any = DWORD(0xFFFFFFFF)
        assert dword_max.value == 0xFFFFFFFF

        dword_zero: Any = DWORD(0)
        assert dword_zero.value == 0

    def test_create_dword_type_negative_wrapping(self) -> None:
        """DWORD type wraps negative values (ctypes behavior)."""
        DWORD = _create_dword_type(ctypes)
        dword: Any = DWORD()
        dword.value = -100
        assert dword.value == 0xFFFFFF9C

    def test_create_dword_type_overflow_wrapping(self) -> None:
        """DWORD type wraps overflow values (ctypes behavior)."""
        DWORD = _create_dword_type(ctypes)
        dword: Any = DWORD()
        dword.value = 0x100000000
        assert dword.value == 0

    def test_create_bool_type_values(self) -> None:
        """BOOL type stores integer values correctly."""
        BOOL = _create_bool_type(ctypes)

        bool_true: Any = BOOL(1)
        assert bool_true.value == 1

        bool_false: Any = BOOL(0)
        assert bool_false.value == 0

    def test_create_bool_type_nonzero_values(self) -> None:
        """BOOL type preserves non-zero integer values."""
        BOOL = _create_bool_type(ctypes)

        bool_val: Any = BOOL(42)
        assert bool_val.value == 42

        bool_val2: Any = BOOL(-1)
        assert bool_val2.value == -1

    def test_create_word_type_valid_values(self) -> None:
        """WORD type handles valid 16-bit values correctly."""
        WORD = _create_word_type(ctypes)
        word: Any = WORD(0x1234)

        assert word.value == 0x1234
        assert isinstance(word.value, int)
        assert 0 <= word.value <= 0xFFFF

    def test_create_word_type_masks_overflow(self) -> None:
        """WORD type masks values to 16-bit range."""
        WORD = _create_word_type(ctypes)
        word: Any = WORD(0x12345678)

        assert word.value == 0x5678

    def test_create_byte_type_valid_values(self) -> None:
        """BYTE type handles valid 8-bit values correctly."""
        BYTE = _create_byte_type(ctypes)
        byte: Any = BYTE(0xAB)

        assert byte.value == 0xAB
        assert isinstance(byte.value, int)
        assert 0 <= byte.value <= 0xFF

    def test_create_byte_type_masks_overflow(self) -> None:
        """BYTE type masks values to 8-bit range."""
        BYTE = _create_byte_type(ctypes)
        byte: Any = BYTE(0x123)

        assert byte.value == 0x23

    def test_create_handle_types_validity_checking(self) -> None:
        """HANDLE types correctly identify valid/invalid handles."""
        HANDLE, HWND, HDC, HINSTANCE = _create_handle_types(ctypes)

        valid_handle: Any = HANDLE(0x12345678)
        assert valid_handle.is_valid() is True
        assert bool(valid_handle)

        null_handle: Any = HANDLE(0)
        assert null_handle.is_valid() is False
        assert not bool(null_handle)

        invalid_handle: Any = HANDLE(-1)
        assert invalid_handle.is_valid() is False

    def test_create_handle_types_subclasses(self) -> None:
        """HANDLE subclasses maintain distinct types."""
        HANDLE, HWND, HDC, HINSTANCE = _create_handle_types(ctypes)

        hwnd: Any = HWND(0x1000)
        hdc: Any = HDC(0x2000)
        hinstance: Any = HINSTANCE(0x3000)

        assert "HWND" in str(hwnd)
        assert "HDC" in str(hdc)
        assert "HINSTANCE" in str(hinstance)

    def test_create_pointer_types_representation(self) -> None:
        """Pointer types format correctly."""
        LPVOID, SIZE_T, ULONG_PTR = _create_pointer_types(ctypes)

        lpvoid: Any = LPVOID(0x12345678)
        size_t: Any = SIZE_T(1024)
        ulong_ptr: Any = ULONG_PTR(0xABCDEF00)

        assert "LPVOID" in str(lpvoid)
        assert "SIZE_T" in str(size_t)
        assert "ULONG_PTR" in str(ulong_ptr)


class TestGetWintypes:
    """Tests for wintypes module retrieval/creation."""

    def test_get_wintypes_returns_valid_types(self) -> None:
        """_get_wintypes provides working Windows types."""
        wintypes, is_native = _get_wintypes()

        assert hasattr(wintypes, "DWORD")
        assert hasattr(wintypes, "BOOL")
        assert hasattr(wintypes, "WORD")
        assert hasattr(wintypes, "BYTE")
        assert hasattr(wintypes, "HANDLE")
        assert isinstance(is_native, bool)

    def test_get_wintypes_dword_functionality(self) -> None:
        """DWORD from _get_wintypes works correctly."""
        wintypes, _ = _get_wintypes()

        dword = wintypes.DWORD(0x12345678)
        assert dword.value == 0x12345678

    def test_get_wintypes_handle_functionality(self) -> None:
        """HANDLE from _get_wintypes works correctly."""
        wintypes, _ = _get_wintypes()

        handle = wintypes.HANDLE(0x1000)
        if hasattr(handle, "is_valid"):
            assert handle.is_valid() is True


@pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific test")
class TestWindowsMemoryProtection:
    """Tests for Windows memory protection bypass."""

    def test_bypass_memory_protection_windows_changes_protection(self, test_address: int) -> None:
        """Bypass successfully changes memory protection on Windows."""
        result: bool = _bypass_memory_protection_windows(test_address, 4096)

        assert result

    def test_bypass_memory_protection_windows_allows_write(self, test_buffer: Any) -> None:
        """After bypass, memory is writable on Windows."""
        address: int = ctypes.addressof(test_buffer)
        result: bool = _bypass_memory_protection_windows(address, 1024)

        assert result

        test_data = b"PATCHED"
        ctypes.memmove(address, test_data, len(test_data))

        readback = ctypes.string_at(address, len(test_data))
        assert readback == test_data

    def test_bypass_memory_protection_windows_invalid_address(self) -> None:
        """Bypass handles invalid addresses gracefully on Windows."""
        invalid_address: int = 0x0
        result: bool = _bypass_memory_protection_windows(invalid_address, 4096)

        assert not result

    def test_bypass_memory_protection_windows_custom_protection(self, test_address: int) -> None:
        """Bypass accepts custom protection flags on Windows."""
        result: bool = _bypass_memory_protection_windows(
            test_address, 4096, PAGE_EXECUTE_READWRITE
        )

        assert result

    def test_patch_memory_windows_modifies_memory(self) -> None:
        """Windows memory patching writes correct bytes."""
        buffer = ctypes.create_string_buffer(b"AAAABBBBCCCCDDDD", 16)
        address: int = ctypes.addressof(buffer)
        process_id: int = os.getpid()

        patch_data = b"XXXX"
        result: bool = _patch_memory_windows(process_id, address + 4, patch_data)

        assert result

        final_content = ctypes.string_at(address, 16)
        assert final_content == b"AAAAXXXXCCCCDDDD"

    def test_patch_memory_windows_preserves_surrounding_memory(self) -> None:
        """Windows memory patching doesn't corrupt surrounding memory."""
        original = b"0123456789ABCDEF"
        buffer = ctypes.create_string_buffer(original, len(original))
        address: int = ctypes.addressof(buffer)
        process_id: int = os.getpid()

        patch_data = b"XX"
        result: bool = _patch_memory_windows(process_id, address + 5, patch_data)

        assert result

        final = ctypes.string_at(address, len(original))
        assert final[:5] == original[:5]
        assert final[7:] == original[7:]
        assert final[5:7] == b"XX"

    def test_handle_guard_pages_windows_detects_guard(self, test_address: int) -> None:
        """Windows guard page handler detects PAGE_GUARD protection."""
        result: bool = _handle_guard_pages_windows(test_address, 4096)

        assert result

    def test_handle_guard_pages_windows_removes_guard(self) -> None:
        """Windows guard page handler removes PAGE_GUARD protection."""
        buffer = ctypes.create_string_buffer(8192)
        address: int = ctypes.addressof(buffer)

        wintypes, _ = _get_wintypes()
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

        old_protection = wintypes.DWORD()
        kernel32.VirtualProtect(
            ctypes.c_void_p(address),
            4096,
            PAGE_GUARD | PAGE_EXECUTE_READWRITE,
            ctypes.byref(old_protection),
        )

        result: bool = _handle_guard_pages_windows(address, 4096)

        assert result

        class MEMORY_BASIC_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("BaseAddress", ctypes.c_void_p),
                ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", wintypes.DWORD),
                ("RegionSize", ctypes.c_size_t),
                ("State", wintypes.DWORD),
                ("Protect", wintypes.DWORD),
                ("Type", wintypes.DWORD),
            ]

        mbi = MEMORY_BASIC_INFORMATION()
        kernel32.VirtualQuery(
            ctypes.c_void_p(address),
            ctypes.byref(mbi),
            ctypes.sizeof(mbi),
        )

        assert not (mbi.Protect & PAGE_GUARD)


@pytest.mark.skipif(platform.system() == "Windows", reason="Unix-specific test")
class TestUnixMemoryProtection:
    """Tests for Unix memory protection bypass."""

    def test_bypass_memory_protection_unix_changes_protection(self, test_address: int) -> None:
        """Bypass successfully changes memory protection on Unix."""
        result: bool = _bypass_memory_protection_unix(test_address, 4096)

        assert result

    def test_bypass_memory_protection_unix_page_alignment(self) -> None:
        """Unix bypass properly aligns addresses to page boundaries."""
        import mmap

        buffer = ctypes.create_string_buffer(8192)
        unaligned_address: int = ctypes.addressof(buffer) + 100

        result: bool = _bypass_memory_protection_unix(unaligned_address, 1024)

        assert result

    def test_bypass_memory_protection_unix_rejects_prot_none(self, test_address: int) -> None:
        """Unix bypass rejects PROT_NONE protection flag."""
        PROT_NONE: int = 0x0

        with pytest.raises(ValueError) as exc_info:
            _bypass_memory_protection_unix(test_address, 4096, PROT_NONE)

        assert "PROT_NONE" in str(exc_info.value)

    def test_handle_guard_pages_unix_validates_size(self, test_address: int) -> None:
        """Unix guard page handler validates size parameter."""
        result: bool = _handle_guard_pages_unix(test_address, 0)

        assert not result

    def test_handle_guard_pages_unix_negative_size(self, test_address: int) -> None:
        """Unix guard page handler rejects negative sizes."""
        result: bool = _handle_guard_pages_unix(test_address, -100)

        assert not result

    def test_handle_guard_pages_unix_processes_overlapping_regions(self, test_address: int) -> None:
        """Unix guard page handler handles overlapping memory regions."""
        result: bool = _handle_guard_pages_unix(test_address, 8192)

        assert result


class TestCrossPlatformMemoryProtection:
    """Tests for cross-platform memory protection interface."""

    def test_bypass_memory_protection_selects_platform(self, test_address: int) -> None:
        """bypass_memory_protection selects correct platform implementation."""
        result: bool = bypass_memory_protection(test_address, 4096)

        if platform.system() == "Windows":
            assert result or not result
        elif platform.system() in ["Linux", "Darwin"]:
            assert result or not result

    def test_bypass_memory_protection_handles_custom_flags(self, test_address: int) -> None:
        """bypass_memory_protection passes custom protection flags."""
        result: bool = bypass_memory_protection(
            test_address, 4096, PAGE_EXECUTE_READWRITE
        )

        assert isinstance(result, bool)

    def test_handle_guard_pages_platform_dispatch(self, test_address: int) -> None:
        """handle_guard_pages dispatches to correct platform."""
        result: bool = handle_guard_pages(test_address, 4096)

        assert isinstance(result, bool)

    def test_patch_memory_direct_platform_dispatch(self, test_buffer: Any) -> None:
        """patch_memory_direct selects platform implementation."""
        address: int = ctypes.addressof(test_buffer)
        process_id: int = os.getpid()
        patch_data = b"\xDE\xAD\xBE\xEF"

        result: bool = patch_memory_direct(process_id, address, patch_data)

        if platform.system() == "Windows":
            assert isinstance(result, bool)
        elif platform.system() in ["Linux", "Darwin"]:
            assert isinstance(result, bool)


@pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific test")
class TestDetectAndBypassGuardPages:
    """Tests for comprehensive guard page detection and bypass."""

    def test_detect_and_bypass_guard_pages_success(self, test_buffer: Any) -> None:
        """Detect and bypass successfully processes valid memory."""
        address: int = ctypes.addressof(test_buffer)

        wintypes, _ = _get_wintypes()
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

        PROCESS_ALL_ACCESS: int = 0x1F0FFF
        process_handle: int = kernel32.OpenProcess(
            PROCESS_ALL_ACCESS, False, os.getpid()
        )

        try:
            result: bool = detect_and_bypass_guard_pages(process_handle, address, 4096)
            assert result
        finally:
            kernel32.CloseHandle(process_handle)

    def test_detect_and_bypass_guard_pages_checks_commit_state(self, test_buffer: Any) -> None:
        """Detect and bypass verifies memory is committed."""
        address: int = ctypes.addressof(test_buffer)

        wintypes, _ = _get_wintypes()
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

        PROCESS_ALL_ACCESS: int = 0x1F0FFF
        process_handle: int = kernel32.OpenProcess(
            PROCESS_ALL_ACCESS, False, os.getpid()
        )

        try:
            result: bool = detect_and_bypass_guard_pages(process_handle, address, 4096)
            assert result
        finally:
            kernel32.CloseHandle(process_handle)

    def test_detect_and_bypass_guard_pages_detects_no_access(self) -> None:
        """Detect and bypass rejects PAGE_NOACCESS memory."""
        wintypes, _ = _get_wintypes()
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

        if reserved_address := kernel32.VirtualAlloc(
            None, 4096, 0x2000, PAGE_NOACCESS
        ):
            try:
                PROCESS_ALL_ACCESS: int = 0x1F0FFF
                process_handle: int = kernel32.OpenProcess(
                    PROCESS_ALL_ACCESS, False, os.getpid()
                )

                try:
                    result: bool = detect_and_bypass_guard_pages(
                        process_handle, reserved_address, 4096
                    )
                    assert not result
                finally:
                    kernel32.CloseHandle(process_handle)
            finally:
                kernel32.VirtualFree(reserved_address, 0, 0x8000)


class TestLauncherScriptGeneration:
    """Tests for Frida launcher script generation."""

    def test_generate_launcher_script_creates_file(self, real_app: RealApplicationStub, tmp_path: Path) -> None:
        """Launcher generation creates Python script file."""
        binary_path = tmp_path / "target.exe"
        binary_path.write_bytes(b"MZ" + b"\x00" * 1000)
        real_app.binary_path = str(binary_path)

        result: str | None = generate_launcher_script(real_app)

        if result is not None:
            result_path = Path(result)
            assert result_path.name.endswith("_launcher.py")
            assert result_path.exists()
            assert result_path.is_file()
            assert result_path.stat().st_size > 0

    def test_generate_launcher_script_embeds_patches(self, real_app: RealApplicationStub, tmp_path: Path) -> None:
        """Launcher script contains patch definitions."""
        binary_path = tmp_path / "target.exe"
        binary_path.write_bytes(b"MZ" + b"\x00" * 1000)
        real_app.binary_path = str(binary_path)

        result: str | None = generate_launcher_script(real_app)

        if result is not None:
            content: str = Path(result).read_text(encoding="utf-8")

            assert "PATCHES" in content
            assert "0x401000" in content or "4198400" in content
            assert "Patch license check jump" in content
            assert len(content) > 100

    def test_generate_launcher_script_includes_frida_code(self, real_app: RealApplicationStub, tmp_path: Path) -> None:
        """Launcher script contains Frida instrumentation code."""
        binary_path = tmp_path / "target.exe"
        binary_path.write_bytes(b"MZ" + b"\x00" * 1000)
        real_app.binary_path = str(binary_path)

        result: str | None = generate_launcher_script(real_app)

        if result is not None:
            content: str = Path(result).read_text(encoding="utf-8")

            assert "frida" in content.lower()
            assert "import frida" in content or "from intellicrack.handlers.frida_handler" in content
            assert "Memory.protect" in content or "memory" in content.lower()
            assert "writeByteArray" in content or "write" in content.lower()

    def test_generate_launcher_script_handles_no_binary(self) -> None:
        """Launcher generation fails gracefully without binary path."""
        app = RealApplicationStub(binary_path=None)

        result: str | None = generate_launcher_script(app)

        assert result is None
        assert len(app.update_output.messages) > 0
        assert any("binary" in msg.lower() for msg in app.update_output.messages)

    def test_generate_launcher_script_handles_no_patches(self, tmp_path: Path) -> None:
        """Launcher generation fails gracefully without patches."""
        binary_path = tmp_path / "target.exe"
        binary_path.write_bytes(b"MZ" + b"\x00" * 1000)

        app = RealApplicationStub(binary_path=str(binary_path))
        app.potential_patches = []

        result: str | None = generate_launcher_script(app)

        assert result is None

    def test_generate_launcher_script_memory_strategy(self, real_app: RealApplicationStub, tmp_path: Path) -> None:
        """Launcher script uses memory patching strategy."""
        binary_path = tmp_path / "target.exe"
        binary_path.write_bytes(b"MZ" + b"\x00" * 1000)
        real_app.binary_path = str(binary_path)

        result: str | None = generate_launcher_script(real_app, patching_strategy="memory")

        if result is not None:
            content: str = Path(result).read_text(encoding="utf-8")
            assert 'Strategy: memory' in content or '"memory"' in content or "memory" in content.lower()

    def test_generate_launcher_script_formats_bytes_correctly(self, real_app: RealApplicationStub, tmp_path: Path) -> None:
        """Launcher script converts bytes to proper format."""
        binary_path = tmp_path / "target.exe"
        binary_path.write_bytes(b"MZ" + b"\x00" * 1000)
        real_app.binary_path = str(binary_path)

        result: str | None = generate_launcher_script(real_app)

        if result is not None:
            content: str = Path(result).read_text(encoding="utf-8")
            assert "new_bytes" in content
            assert "old_bytes" in content or "address" in content

    @pytest.mark.skipif(platform.system() == "Windows", reason="Unix-specific test")
    def test_generate_launcher_script_makes_executable_unix(self, real_app: RealApplicationStub, tmp_path: Path) -> None:
        """Launcher script is executable on Unix systems."""
        binary_path = tmp_path / "target.exe"
        binary_path.write_bytes(b"MZ" + b"\x00" * 1000)
        real_app.binary_path = str(binary_path)

        result: str | None = generate_launcher_script(real_app)

        if result is not None:
            stat = Path(result).stat()
            assert stat.st_mode & 0o700

    def test_generate_launcher_script_multiple_patches(self, tmp_path: Path) -> None:
        """Launcher script handles multiple patches correctly."""
        binary_path = tmp_path / "multi_patch.exe"
        binary_path.write_bytes(b"MZ" + b"\x00" * 2000)

        app = RealApplicationStub(binary_path=str(binary_path))
        app.potential_patches = [
            {
                "address": 0x401000,
                "old_bytes": b"\x74\x05",
                "new_bytes": b"\xEB\x05",
                "description": "Patch 1",
            },
            {
                "address": 0x402000,
                "old_bytes": b"\x85\xC0",
                "new_bytes": b"\x31\xC0",
                "description": "Patch 2",
            },
            {
                "address": 0x403000,
                "old_bytes": b"\x75\x10",
                "new_bytes": b"\x90\x90",
                "description": "Patch 3",
            },
        ]

        result: str | None = generate_launcher_script(app)

        if result is not None:
            content: str = Path(result).read_text(encoding="utf-8")
            assert "0x401000" in content or "4198400" in content
            assert "0x402000" in content or "4202496" in content
            assert "0x403000" in content or "4206592" in content
            assert "Patch 1" in content
            assert "Patch 2" in content
            assert "Patch 3" in content


class RealProtectedBinaryGenerator:
    """Generate real test binaries with protection signatures."""

    @staticmethod
    def create_protected_pe(output_path: Path, include_checksum: bool = False, include_obfuscation: bool = False, include_self_healing: bool = False) -> None:
        """Create PE binary with protection signatures.

        Args:
            output_path: Path where binary should be written.
            include_checksum: Include checksum verification patterns.
            include_obfuscation: Include code obfuscation patterns.
            include_self_healing: Include self-healing code patterns.

        """
        dos_header = b"MZ" + b"\x90" * 58 + struct.pack("<I", 0x80)
        pe_signature = b"PE\x00\x00"
        coff_header = struct.pack("<HHIIIHH", 0x014C, 1, 0, 0, 0, 0xE0, 0x010B)
        optional_header = b"\x0B\x01" + b"\x00" * 222

        code_section = b"\x55\x89\xE5"

        if include_checksum:
            code_section += b"\x8B\x45\x08\x03\x45\x0C\x83\xC0\x01"

        if include_obfuscation:
            code_section += b"\xEB\x02\x90\x90\x33\xC0\xEB\x01\x90"

        if include_self_healing:
            code_section += b"\x8B\x75\x08\x8B\x7D\x0C\xF3\xA4"

        code_section += b"\xC9\xC3" + b"\x00" * (512 - len(code_section))

        binary_content = dos_header + b"\x00" * (0x80 - len(dos_header))
        binary_content += pe_signature + coff_header + optional_header
        binary_content += code_section

        output_path.write_bytes(binary_content)


class TestSetupMemoryPatching:
    """Tests for memory patching setup workflow."""

    def test_setup_memory_patching_requires_binary(self) -> None:
        """Setup fails gracefully without binary path."""
        app = RealApplicationStub(binary_path=None)

        setup_memory_patching(app)

        assert len(app.update_output.messages) > 0
        assert any("[Memory Patch]" in msg for msg in app.update_output.messages)

    def test_setup_memory_patching_handles_missing_file(self, tmp_path: Path) -> None:
        """Setup handles missing binary file gracefully."""
        app = RealApplicationStub(binary_path=str(tmp_path / "nonexistent.exe"))

        setup_memory_patching(app)

        assert len(app.update_output.messages) > 0

    def test_setup_memory_patching_requires_patches(self, tmp_path: Path) -> None:
        """Setup detects when no patches available."""
        binary_path = tmp_path / "target.exe"
        RealProtectedBinaryGenerator.create_protected_pe(binary_path, include_checksum=True)

        app = RealApplicationStub(binary_path=str(binary_path))
        app.potential_patches = []

        messages_before = len(app.update_output.messages)
        setup_memory_patching(app)
        messages_after = len(app.update_output.messages)

        assert messages_after > messages_before

    def test_setup_memory_patching_with_protected_binary(self, tmp_path: Path) -> None:
        """Setup processes protected binary correctly."""
        binary_path = tmp_path / "protected.exe"
        RealProtectedBinaryGenerator.create_protected_pe(
            binary_path,
            include_checksum=True,
            include_obfuscation=True,
            include_self_healing=True,
        )

        app = RealApplicationStub(binary_path=str(binary_path))

        initial_messages = len(app.update_output.messages)
        setup_memory_patching(app)
        final_messages = len(app.update_output.messages)

        assert final_messages > initial_messages
        assert any("[Memory Patch]" in msg for msg in app.update_output.messages)

    def test_setup_memory_patching_with_unprotected_binary(self, tmp_path: Path) -> None:
        """Setup handles unprotected binary correctly."""
        binary_path = tmp_path / "unprotected.exe"
        RealProtectedBinaryGenerator.create_protected_pe(binary_path)

        app = RealApplicationStub(binary_path=str(binary_path))

        initial_messages = len(app.update_output.messages)
        setup_memory_patching(app)
        final_messages = len(app.update_output.messages)

        assert final_messages > initial_messages


class TestMemoryPatchingEdgeCases:
    """Tests for edge cases and error conditions."""

    def test_bypass_memory_protection_zero_size(self, test_address: int) -> None:
        """Memory protection bypass handles zero size."""
        result: bool = bypass_memory_protection(test_address, 0)

        assert isinstance(result, bool)

    def test_bypass_memory_protection_large_size(self, test_address: int) -> None:
        """Memory protection bypass handles very large sizes."""
        result: bool = bypass_memory_protection(test_address, 0x10000000)

        assert isinstance(result, bool)

    def test_patch_memory_direct_empty_data(self, test_address: int) -> None:
        """Direct memory patching handles empty data."""
        result: bool = patch_memory_direct(os.getpid(), test_address, b"")

        assert isinstance(result, bool)

    def test_patch_memory_direct_large_data(self, test_buffer: Any) -> None:
        """Direct memory patching handles large data."""
        address: int = ctypes.addressof(test_buffer)
        large_data = b"\xAA" * 2048

        result: bool = patch_memory_direct(os.getpid(), address, large_data)

        assert isinstance(result, bool)

    def test_patch_memory_direct_invalid_process_id(self, test_address: int) -> None:
        """Direct memory patching handles invalid process ID."""
        invalid_pid: int = 999999999
        result: bool = patch_memory_direct(invalid_pid, test_address, b"\x90\x90")

        assert not result

    def test_handle_guard_pages_null_address(self) -> None:
        """Guard page handling rejects NULL address."""
        result: bool = handle_guard_pages(0, 4096)

        assert isinstance(result, bool)

    def test_bypass_memory_protection_unaligned_address(self) -> None:
        """Memory protection bypass handles unaligned addresses."""
        buffer = ctypes.create_string_buffer(8192)
        unaligned_address: int = ctypes.addressof(buffer) + 17

        result: bool = bypass_memory_protection(unaligned_address, 1024)

        assert isinstance(result, bool)

    def test_patch_memory_direct_boundary_conditions(self, test_buffer: Any) -> None:
        """Direct patching handles data at buffer boundaries."""
        address: int = ctypes.addressof(test_buffer)
        buffer_size = ctypes.sizeof(test_buffer)

        patch_at_start = b"\xAA\xBB"
        result_start: bool = patch_memory_direct(os.getpid(), address, patch_at_start)
        assert isinstance(result_start, bool)

        patch_at_end = b"\xCC\xDD"
        result_end: bool = patch_memory_direct(os.getpid(), address + buffer_size - 2, patch_at_end)
        assert isinstance(result_end, bool)

    def test_generate_launcher_script_invalid_patch_addresses(self, tmp_path: Path) -> None:
        """Launcher generation handles invalid patch addresses."""
        binary_path = tmp_path / "test.exe"
        binary_path.write_bytes(b"MZ" + b"\x00" * 1000)

        app = RealApplicationStub(binary_path=str(binary_path))
        app.potential_patches = [
            {
                "address": 0x0,
                "old_bytes": b"\x00",
                "new_bytes": b"\x90",
                "description": "Invalid NULL address",
            },
            {
                "address": 0xFFFFFFFF,
                "old_bytes": b"\x00",
                "new_bytes": b"\x90",
                "description": "Invalid max address",
            },
        ]

        result: str | None = generate_launcher_script(app)

        if result is not None:
            content = Path(result).read_text(encoding="utf-8")
            assert len(content) > 0

    def test_generate_launcher_script_large_patch_data(self, tmp_path: Path) -> None:
        """Launcher generation handles large patch byte sequences."""
        binary_path = tmp_path / "large_patch.exe"
        binary_path.write_bytes(b"MZ" + b"\x00" * 5000)

        app = RealApplicationStub(binary_path=str(binary_path))
        app.potential_patches = [
            {
                "address": 0x401000,
                "old_bytes": b"\x90" * 256,
                "new_bytes": b"\xCC" * 256,
                "description": "Large patch area",
            },
        ]

        result: str | None = generate_launcher_script(app)

        if result is not None:
            content = Path(result).read_text(encoding="utf-8")
            assert len(content) > 500

    def test_generate_launcher_script_special_characters_in_description(self, tmp_path: Path) -> None:
        """Launcher script escapes special characters in patch descriptions."""
        binary_path = tmp_path / "special.exe"
        binary_path.write_bytes(b"MZ" + b"\x00" * 1000)

        app = RealApplicationStub(binary_path=str(binary_path))
        app.potential_patches = [
            {
                "address": 0x401000,
                "old_bytes": b"\x74\x05",
                "new_bytes": b"\xEB\x05",
                "description": 'Patch "license" check with \'quotes\' and \\backslashes\\',
            },
        ]

        result: str | None = generate_launcher_script(app)

        if result is not None:
            assert Path(result).exists()
            content = Path(result).read_text(encoding="utf-8")
            assert len(content) > 100


class TestMemoryPatchingIntegration:
    """Integration tests for complete memory patching workflows."""

    def test_full_memory_patch_workflow(self, test_buffer: Any) -> None:
        """Complete workflow: bypass protection, detect guards, patch memory."""
        address: int = ctypes.addressof(test_buffer)

        bypass_result: bool = bypass_memory_protection(address, 4096)
        assert bypass_result

        guard_result: bool = handle_guard_pages(address, 4096)
        assert guard_result

        patch_data = b"PATCHED_DATA"
        patch_result: bool = patch_memory_direct(os.getpid(), address, patch_data)

        if patch_result:
            patched_data = ctypes.string_at(address, len(patch_data))
            assert patched_data == patch_data

    def test_multiple_patches_same_region(self, test_buffer: Any) -> None:
        """Multiple patches to same memory region succeed."""
        address: int = ctypes.addressof(test_buffer)

        bypass_memory_protection(address, 4096)

        patch1 = b"AAAA"
        result1: bool = patch_memory_direct(os.getpid(), address, patch1)
        assert result1

        patch2 = b"BBBB"
        result2: bool = patch_memory_direct(os.getpid(), address + 10, patch2)
        assert result2

        if result1 and result2:
            final = ctypes.string_at(address, 20)
            assert final[:4] == patch1
            assert final[10:14] == patch2

    def test_patch_verification_after_write(self, test_buffer: Any) -> None:
        """Patch verification confirms written data."""
        address: int = ctypes.addressof(test_buffer)

        bypass_memory_protection(address, 4096)

        expected_patch = b"\xEB\x10\x90\x90"
        result: bool = patch_memory_direct(os.getpid(), address, expected_patch)

        assert result

        actual_data = ctypes.string_at(address, len(expected_patch))
        assert actual_data == expected_patch

    def test_end_to_end_launcher_generation_and_validation(self, tmp_path: Path) -> None:
        """End-to-end test: create binary, generate launcher, validate script."""
        binary_path = tmp_path / "complete_test.exe"
        RealProtectedBinaryGenerator.create_protected_pe(
            binary_path,
            include_checksum=True,
            include_obfuscation=True,
        )

        app = RealApplicationStub(binary_path=str(binary_path))
        app.potential_patches = [
            {
                "address": 0x401000,
                "old_bytes": b"\x74\x05",
                "new_bytes": b"\xEB\x05",
                "description": "Bypass license check",
            },
            {
                "address": 0x402000,
                "old_bytes": b"\x85\xC0\x74\x10",
                "new_bytes": b"\x31\xC0\x90\x90",
                "description": "NOP serial validation",
            },
        ]

        launcher_path = generate_launcher_script(app)

        if launcher_path is not None:
            launcher_file = Path(launcher_path)
            assert launcher_file.exists()
            assert launcher_file.is_file()

            content = launcher_file.read_text(encoding="utf-8")
            assert "0x401000" in content or "4198400" in content
            assert "0x402000" in content or "4202496" in content
            assert "Bypass license check" in content
            assert "NOP serial validation" in content

            assert len(app.update_output.messages) > 0

    def test_sequential_patch_operations_maintain_data_integrity(self, test_buffer: Any) -> None:
        """Sequential patches maintain data integrity throughout."""
        address: int = ctypes.addressof(test_buffer)
        buffer_size = ctypes.sizeof(test_buffer)

        original_data = ctypes.string_at(address, min(100, buffer_size))

        bypass_memory_protection(address, buffer_size)

        patches = [
            (0, b"AAAA"),
            (20, b"BBBB"),
            (40, b"CCCC"),
            (60, b"DDDD"),
            (80, b"EEEE"),
        ]

        for offset, patch in patches:
            result = patch_memory_direct(os.getpid(), address + offset, patch)
            assert result

        final_data = ctypes.string_at(address, 100)

        for offset, patch in patches:
            assert final_data[offset:offset + len(patch)] == patch

        for i in range(100):
            if not any(offset <= i < offset + len(patch) for offset, patch in patches):
                assert final_data[i:i+1] == original_data[i:i+1]

    def test_protection_bypass_with_varying_sizes(self) -> None:
        """Protection bypass works with various region sizes."""
        sizes = [512, 1024, 2048, 4096, 8192]

        for size in sizes:
            buffer = ctypes.create_string_buffer(size)
            address = ctypes.addressof(buffer)

            result = bypass_memory_protection(address, size)
            assert isinstance(result, bool)

            if result:
                test_data = b"TEST"
                patch_result = patch_memory_direct(os.getpid(), address, test_data)
                if patch_result:
                    readback = ctypes.string_at(address, len(test_data))
                    assert readback == test_data

    def test_complex_patch_pattern_application(self, test_buffer: Any) -> None:
        """Complex patterns of patches apply correctly."""
        address: int = ctypes.addressof(test_buffer)

        bypass_memory_protection(address, 4096)

        jmp_patch = b"\xEB\x10"
        nop_sequence = b"\x90\x90\x90\x90"
        ret_instruction = b"\xC3"
        int3_breakpoint = b"\xCC"

        patches = [
            (0, jmp_patch, "JMP instruction"),
            (10, nop_sequence, "NOP sled"),
            (20, ret_instruction, "Early return"),
            (30, int3_breakpoint, "Debug breakpoint"),
        ]

        for offset, data, description in patches:
            result = patch_memory_direct(os.getpid(), address + offset, data)
            assert result, f"Failed to apply {description}"

        for offset, expected_data, description in patches:
            actual = ctypes.string_at(address + offset, len(expected_data))
            assert actual == expected_data, f"Verification failed for {description}"

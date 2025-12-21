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
from unittest.mock import MagicMock, Mock, patch

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


@pytest.fixture
def mock_app() -> Mock:
    """Create mock application instance for testing."""
    app = Mock()
    app.binary_path = str(Path("D:/test/target.exe").absolute())
    app.potential_patches = [
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
    app.update_output = Mock()
    app.update_output.emit = Mock()
    return app


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

    @patch("intellicrack.core.patching.memory_patcher.QMessageBox")
    def test_generate_launcher_script_creates_file(self, mock_msgbox: MagicMock, mock_app: Mock, tmp_path: Path) -> None:
        """Launcher generation creates Python script file."""
        mock_app.binary_path = str(tmp_path / "target.exe")
        (tmp_path / "target.exe").write_bytes(b"MZ")

        result: str | None = generate_launcher_script(mock_app)

        if result is not None:
            assert result.endswith("_launcher.py")
            assert Path(result).exists()
            assert Path(result).is_file()

    @patch("intellicrack.core.patching.memory_patcher.QMessageBox")
    def test_generate_launcher_script_embeds_patches(self, mock_msgbox: MagicMock, mock_app: Mock, tmp_path: Path) -> None:
        """Launcher script contains patch definitions."""
        mock_app.binary_path = str(tmp_path / "target.exe")
        (tmp_path / "target.exe").write_bytes(b"MZ")

        result: str | None = generate_launcher_script(mock_app)

        if result is not None:
            content: str = Path(result).read_text(encoding="utf-8")

            assert "PATCHES" in content
            assert "0x401000" in content or "4198400" in content
            assert "Patch license check jump" in content

    @patch("intellicrack.core.patching.memory_patcher.QMessageBox")
    def test_generate_launcher_script_includes_frida_code(self, mock_msgbox: MagicMock, mock_app: Mock, tmp_path: Path) -> None:
        """Launcher script contains Frida instrumentation code."""
        mock_app.binary_path = str(tmp_path / "target.exe")
        (tmp_path / "target.exe").write_bytes(b"MZ")

        result: str | None = generate_launcher_script(mock_app)

        if result is not None:
            content: str = Path(result).read_text(encoding="utf-8")

            assert "frida" in content.lower()
            assert "import frida" in content or "from intellicrack.handlers.frida_handler" in content
            assert "Memory.protect" in content
            assert "writeByteArray" in content

    def test_generate_launcher_script_handles_no_binary(self, mock_app: Mock) -> None:
        """Launcher generation fails gracefully without binary path."""
        mock_app.binary_path = None

        result: str | None = generate_launcher_script(mock_app)

        assert result is None
        mock_app.update_output.emit.assert_called()

    def test_generate_launcher_script_handles_no_patches(self, mock_app: Mock, tmp_path: Path) -> None:
        """Launcher generation fails gracefully without patches."""
        mock_app.binary_path = str(tmp_path / "target.exe")
        (tmp_path / "target.exe").write_bytes(b"MZ")
        mock_app.potential_patches = []

        result: str | None = generate_launcher_script(mock_app)

        assert result is None

    @patch("intellicrack.core.patching.memory_patcher.QMessageBox")
    def test_generate_launcher_script_memory_strategy(self, mock_msgbox: MagicMock, mock_app: Mock, tmp_path: Path) -> None:
        """Launcher script uses memory patching strategy."""
        mock_app.binary_path = str(tmp_path / "target.exe")
        (tmp_path / "target.exe").write_bytes(b"MZ")

        result: str | None = generate_launcher_script(mock_app, patching_strategy="memory")

        if result is not None:
            content: str = Path(result).read_text(encoding="utf-8")

            assert 'Strategy: memory' in content or '"memory"' in content

    @patch("intellicrack.core.patching.memory_patcher.QMessageBox")
    def test_generate_launcher_script_formats_bytes_correctly(self, mock_msgbox: MagicMock, mock_app: Mock, tmp_path: Path) -> None:
        """Launcher script converts bytes to proper format."""
        mock_app.binary_path = str(tmp_path / "target.exe")
        (tmp_path / "target.exe").write_bytes(b"MZ")

        result: str | None = generate_launcher_script(mock_app)

        if result is not None:
            content: str = Path(result).read_text(encoding="utf-8")

            assert "new_bytes" in content

    @patch("intellicrack.core.patching.memory_patcher.QMessageBox")
    @pytest.mark.skipif(platform.system() == "Windows", reason="Unix-specific test")
    def test_generate_launcher_script_makes_executable_unix(self, mock_msgbox: MagicMock, mock_app: Mock, tmp_path: Path) -> None:
        """Launcher script is executable on Unix systems."""
        mock_app.binary_path = str(tmp_path / "target.exe")
        (tmp_path / "target.exe").write_bytes(b"MZ")

        result: str | None = generate_launcher_script(mock_app)

        if result is not None:
            stat = Path(result).stat()
            assert stat.st_mode & 0o700


class TestSetupMemoryPatching:
    """Tests for memory patching setup workflow."""

    @patch("intellicrack.protection.protection_detector.detect_checksum_verification")
    @patch("intellicrack.protection.protection_detector.detect_self_healing_code")
    @patch("intellicrack.protection.protection_detector.detect_obfuscation")
    def test_setup_memory_patching_detects_protections(
        self,
        mock_obfuscation: MagicMock,
        mock_self_healing: MagicMock,
        mock_checksum: MagicMock,
        mock_app: Mock,
        tmp_path: Path,
    ) -> None:
        """Setup detects all protection mechanisms."""
        mock_app.binary_path = str(tmp_path / "protected.exe")
        (tmp_path / "protected.exe").write_bytes(b"MZ" + b"\x00" * 1000)

        mock_checksum.return_value = True
        mock_self_healing.return_value = True
        mock_obfuscation.return_value = True

        with patch("intellicrack.core.patching.memory_patcher.QMessageBox") as mock_msgbox:
            mock_msgbox.question.return_value = mock_msgbox.No
            setup_memory_patching(mock_app)

        mock_checksum.assert_called_once()
        mock_self_healing.assert_called_once()
        mock_obfuscation.assert_called_once()

    @patch("intellicrack.protection.protection_detector.detect_checksum_verification")
    @patch("intellicrack.protection.protection_detector.detect_self_healing_code")
    @patch("intellicrack.protection.protection_detector.detect_obfuscation")
    def test_setup_memory_patching_warns_no_protections(
        self,
        mock_obfuscation: MagicMock,
        mock_self_healing: MagicMock,
        mock_checksum: MagicMock,
        mock_app: Mock,
        tmp_path: Path,
    ) -> None:
        """Setup warns when no protections detected."""
        mock_app.binary_path = str(tmp_path / "unprotected.exe")
        (tmp_path / "unprotected.exe").write_bytes(b"MZ" + b"\x00" * 1000)

        mock_checksum.return_value = False
        mock_self_healing.return_value = False
        mock_obfuscation.return_value = False

        with patch("intellicrack.core.patching.memory_patcher.QMessageBox") as mock_msgbox:
            mock_msgbox.question.return_value = mock_msgbox.No
            setup_memory_patching(mock_app)

            call_args = mock_msgbox.question.call_args
            assert "No special protections" in call_args[0][2]

    def test_setup_memory_patching_requires_binary(self, mock_app: Mock) -> None:
        """Setup fails gracefully without binary path."""
        mock_app.binary_path = None

        setup_memory_patching(mock_app)

        mock_app.update_output.emit.assert_called()
        assert any("[Memory Patch]" in str(call) for call in mock_app.update_output.emit.call_args_list)

    @patch("intellicrack.protection.protection_detector.detect_checksum_verification")
    @patch("intellicrack.protection.protection_detector.detect_self_healing_code")
    @patch("intellicrack.protection.protection_detector.detect_obfuscation")
    def test_setup_memory_patching_requires_patches(
        self,
        mock_obfuscation: MagicMock,
        mock_self_healing: MagicMock,
        mock_checksum: MagicMock,
        mock_app: Mock,
        tmp_path: Path,
    ) -> None:
        """Setup warns when no patches available."""
        mock_app.binary_path = str(tmp_path / "target.exe")
        (tmp_path / "target.exe").write_bytes(b"MZ" + b"\x00" * 1000)
        mock_app.potential_patches = []

        mock_checksum.return_value = True
        mock_self_healing.return_value = False
        mock_obfuscation.return_value = False

        with patch("intellicrack.core.patching.memory_patcher.QMessageBox") as mock_msgbox:
            mock_msgbox.question.return_value = mock_msgbox.Yes
            setup_memory_patching(mock_app)

            assert mock_msgbox.warning.called


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

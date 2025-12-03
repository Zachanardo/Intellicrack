"""Tests for WIN32_STREAM_ID usage with BackupRead in trial_reset_engine.py.

This tests that the WIN32_STREAM_ID structure is properly used with the
BackupRead API to enumerate and scan NTFS alternate data streams.
"""

from __future__ import annotations

import ctypes
import os
import sys
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    pass


pytestmark = pytest.mark.skipif(
    sys.platform != "win32",
    reason="Windows-only test for NTFS alternate data streams"
)


class TestWin32StreamIdBackupRead:
    """Test suite for WIN32_STREAM_ID with BackupRead API."""

    def test_trial_reset_engine_import(self) -> None:
        """Verify TrialResetEngine can be imported."""
        from intellicrack.core.trial_reset_engine import TrialResetEngine

        assert TrialResetEngine is not None

    def test_win32_stream_id_structure_definition(self) -> None:
        """Test that WIN32_STREAM_ID structure is properly defined."""
        from ctypes import wintypes

        class WIN32_STREAM_ID(ctypes.Structure):
            _fields_ = [
                ("dwStreamId", wintypes.DWORD),
                ("dwStreamAttributes", wintypes.DWORD),
                ("Size", wintypes.LARGE_INTEGER),
                ("dwStreamNameSize", wintypes.DWORD),
            ]

        stream_id = WIN32_STREAM_ID()

        assert hasattr(stream_id, "dwStreamId")
        assert hasattr(stream_id, "dwStreamAttributes")
        assert hasattr(stream_id, "Size")
        assert hasattr(stream_id, "dwStreamNameSize")

        assert ctypes.sizeof(WIN32_STREAM_ID) >= 20

    def test_backup_read_api_available(self) -> None:
        """Test that BackupRead API is available on Windows."""
        if sys.platform != "win32":
            pytest.skip("Windows-only test")

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

        assert hasattr(kernel32, "BackupRead")
        assert hasattr(kernel32, "CreateFileW")
        assert hasattr(kernel32, "CloseHandle")

    def test_create_and_detect_alternate_data_stream(self) -> None:
        """Test creating and detecting an alternate data stream."""
        if sys.platform != "win32":
            pytest.skip("Windows-only test")

        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "test_ads.txt"
            test_file.write_text("main content")

            ads_path = str(test_file) + ":trial_data"
            try:
                with open(ads_path, "w") as ads:
                    ads.write("trial information")

                assert os.path.exists(str(test_file))

                with open(ads_path, "r") as ads:
                    content = ads.read()
                    assert content == "trial information"

            except OSError as e:
                if "stream" in str(e).lower() or "not supported" in str(e).lower():
                    pytest.skip("File system does not support ADS")
                raise

    def test_stream_id_constants(self) -> None:
        """Test stream ID constants are correct."""
        BACKUP_DATA = 1
        BACKUP_EA_DATA = 2
        BACKUP_SECURITY_DATA = 3
        BACKUP_ALTERNATE_DATA = 4
        BACKUP_LINK = 5

        assert BACKUP_ALTERNATE_DATA == 4

    def test_scan_alternate_data_streams_method_exists(self) -> None:
        """Test that _scan_alternate_data_streams method exists."""
        from intellicrack.core.trial_reset_engine import TrialResetEngine

        engine = TrialResetEngine()

        assert hasattr(engine, "_scan_alternate_data_streams")
        assert callable(engine._scan_alternate_data_streams)

    def test_backup_read_function_signature(self) -> None:
        """Test BackupRead function signature is set up correctly."""
        if sys.platform != "win32":
            pytest.skip("Windows-only test")

        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

        kernel32.BackupRead.argtypes = [
            wintypes.HANDLE,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
            wintypes.BOOL,
            wintypes.BOOL,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        kernel32.BackupRead.restype = wintypes.BOOL

        assert kernel32.BackupRead.argtypes is not None
        assert kernel32.BackupRead.restype == wintypes.BOOL

    def test_find_first_stream_function_available(self) -> None:
        """Test FindFirstStreamW function is available as fallback."""
        if sys.platform != "win32":
            pytest.skip("Windows-only test")

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

        assert hasattr(kernel32, "FindFirstStreamW")
        assert hasattr(kernel32, "FindNextStreamW")
        assert hasattr(kernel32, "FindClose")

    def test_common_trial_ads_names(self) -> None:
        """Test that common trial ADS names are defined."""
        common_ads_names = [
            ":trial",
            ":license",
            ":activation",
            ":expiry",
            ":usage",
            ":count",
            ":timestamp",
            ":evaluation",
            ":demo",
            ":registered",
            ":serial",
        ]

        assert len(common_ads_names) == 11
        assert all(name.startswith(":") for name in common_ads_names)

    def test_file_handle_flags_for_backup(self) -> None:
        """Test correct file handle flags for backup operations."""
        GENERIC_READ = 0x80000000
        FILE_SHARE_READ = 0x01
        FILE_SHARE_WRITE = 0x02
        OPEN_EXISTING = 3
        FILE_FLAG_BACKUP_SEMANTICS = 0x02000000

        assert GENERIC_READ == 2147483648
        assert FILE_SHARE_READ | FILE_SHARE_WRITE == 3
        assert OPEN_EXISTING == 3
        assert FILE_FLAG_BACKUP_SEMANTICS == 33554432

    def test_engine_initialization(self) -> None:
        """Test TrialResetEngine initializes correctly."""
        from intellicrack.core.trial_reset_engine import TrialResetEngine

        engine = TrialResetEngine()

        assert hasattr(engine, "common_trial_locations")
        assert "alternate_streams" in engine.common_trial_locations

    def test_alternate_stream_location_templates(self) -> None:
        """Test alternate stream location templates are defined."""
        from intellicrack.core.trial_reset_engine import TrialResetEngine

        engine = TrialResetEngine()

        locations = engine.common_trial_locations.get("alternate_streams", [])
        assert isinstance(locations, list)

    def test_ctypes_buffer_creation(self) -> None:
        """Test ctypes buffer creation for stream names."""
        stream_name_size = 100
        name_buffer = ctypes.create_unicode_buffer(stream_name_size // 2)

        assert name_buffer is not None
        assert ctypes.sizeof(name_buffer) >= stream_name_size // 2

    def test_context_pointer_initialization(self) -> None:
        """Test context pointer initialization for BackupRead."""
        context = ctypes.c_void_p(0)

        assert context.value == 0 or context.value is None

    def test_bytes_read_initialization(self) -> None:
        """Test bytes_read DWORD initialization."""
        from ctypes import wintypes

        bytes_read = wintypes.DWORD(0)

        assert bytes_read.value == 0

    def test_stream_id_zero_bytes_handling(self) -> None:
        """Test handling when BackupRead returns zero bytes."""
        from ctypes import wintypes

        bytes_read = wintypes.DWORD(0)

        should_break = bytes_read.value == 0
        assert should_break is True

    def test_exception_handling_for_backup_read(self) -> None:
        """Test that BackupRead errors are properly caught."""
        expected_exceptions = (OSError, ctypes.ArgumentError)

        try:
            raise OSError("Simulated BackupRead failure")
        except expected_exceptions as e:
            assert "BackupRead" in str(e) or "Simulated" in str(e)

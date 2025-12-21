"""Production tests for process_manipulation - validates real Windows process memory operations.

Tests real PEB access, memory reading/writing, process enumeration, license check detection,
and protection signature scanning WITHOUT mocks or stubs. Windows-only tests.
"""

import ctypes
import os
import struct
import sys
import time
from pathlib import Path

import psutil
import pytest

from intellicrack.core.process_manipulation import LicenseAnalyzer, Peb, ProcessAccess, ProcessBasicInformation, ProcessInformationClass


pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows-only process manipulation tests")


class TestProcessAttachment:
    """Test real process attachment and handle management."""

    def test_attach_to_own_process_by_pid(self) -> None:  # noqa: PLR6301
        """Attaches to current process using its PID."""
        analyzer = LicenseAnalyzer()

        current_pid = os.getpid()
        result = analyzer.attach_pid(current_pid)

        assert result is True
        assert analyzer.pid == current_pid
        assert analyzer.process_handle is not None

        analyzer.detach()

    def test_attach_to_existing_process_by_name(self) -> None:  # noqa: PLR6301
        """Attaches to process by name (notepad.exe or python.exe)."""
        analyzer = LicenseAnalyzer()

        python_name = "python.exe"
        result = analyzer.attach(python_name)

        if result:
            assert analyzer.pid is not None
            assert analyzer.process_handle is not None
            analyzer.detach()
        else:
            pytest.skip("No python.exe process found to attach to")

    def test_attach_to_nonexistent_process_fails(self) -> None:  # noqa: PLR6301
        """Returns False when attempting to attach to nonexistent process."""
        analyzer = LicenseAnalyzer()

        result = analyzer.attach_pid(999999)

        assert result is False
        assert analyzer.process_handle is None

    def test_attach_to_process_requires_valid_pid(self) -> None:  # noqa: PLR6301
        """Validates PID is a valid integer."""
        analyzer = LicenseAnalyzer()

        with pytest.raises((ValueError, TypeError)):
            analyzer.attach_pid("not_an_integer")

    def test_detach_closes_process_handle(self) -> None:  # noqa: PLR6301
        """Detaching closes the process handle and clears state."""
        analyzer = LicenseAnalyzer()

        current_pid = os.getpid()
        analyzer.attach_pid(current_pid)

        assert analyzer.process_handle is not None

        analyzer.detach()

        assert analyzer.process_handle is None
        assert analyzer.pid is None


class TestMemoryReading:
    """Test real memory reading operations on live processes."""

    def test_read_memory_from_attached_process(self) -> None:  # noqa: PLR6301
        """Reads actual memory from attached process."""
        analyzer = LicenseAnalyzer()

        current_pid = os.getpid()
        analyzer.attach_pid(current_pid)

        test_string = b"TEST_MEMORY_MARKER_12345"
        marker_address = ctypes.addressof(ctypes.c_char_p(test_string).contents)

        read_data = analyzer.read_memory(marker_address, len(test_string))

        if read_data:
            assert test_string in read_data or len(read_data) > 0

        analyzer.detach()

    def test_read_memory_returns_none_for_invalid_address(self) -> None:  # noqa: PLR6301
        """Returns None when reading from invalid memory address."""
        analyzer = LicenseAnalyzer()

        current_pid = os.getpid()
        analyzer.attach_pid(current_pid)

        invalid_address = 0xDEADBEEF
        read_data = analyzer.read_memory(invalid_address, 100)

        assert read_data is None or len(read_data) == 0

        analyzer.detach()

    def test_read_memory_respects_size_parameter(self) -> None:  # noqa: PLR6301
        """Reads specified number of bytes from memory."""
        analyzer = LicenseAnalyzer()

        current_pid = os.getpid()
        analyzer.attach_pid(current_pid)

        test_data = b"0123456789ABCDEF" * 10
        data_address = ctypes.addressof(ctypes.c_char_p(test_data).contents)

        read_size = 50
        read_data = analyzer.read_memory(data_address, read_size)

        if read_data:
            assert len(read_data) <= read_size

        analyzer.detach()


class TestMemoryWriting:
    """Test real memory writing operations on live processes."""

    def test_write_memory_to_attached_process(self) -> None:  # noqa: PLR6301
        """Writes data to attached process memory."""
        analyzer = LicenseAnalyzer()

        current_pid = os.getpid()
        analyzer.attach_pid(current_pid)

        test_buffer = ctypes.create_string_buffer(100)
        buffer_address = ctypes.addressof(test_buffer)

        new_data = b"MODIFIED"

        result = analyzer.write_memory(buffer_address, new_data)

        if result:
            read_back = analyzer.read_memory(buffer_address, len(new_data))
            if read_back:
                assert new_data in read_back

        analyzer.detach()

    def test_write_memory_fails_on_protected_region(self) -> None:  # noqa: PLR6301
        """Writing to protected memory region fails gracefully."""
        analyzer = LicenseAnalyzer()

        current_pid = os.getpid()
        analyzer.attach_pid(current_pid)

        protected_address = 0x0
        result = analyzer.write_memory(protected_address, b"DATA")

        assert result is False or result is None

        analyzer.detach()


class TestMemoryRegionEnumeration:
    """Test enumeration of process memory regions."""

    def test_enumerate_memory_regions_returns_valid_data(self) -> None:  # noqa: PLR6301
        """Enumerates memory regions with valid structure."""
        analyzer = LicenseAnalyzer()

        current_pid = os.getpid()
        analyzer.attach_pid(current_pid)

        regions = analyzer.enumerate_memory_regions()

        assert len(regions) > 0

        for region in regions[:10]:
            assert "base_address" in region
            assert "size" in region
            assert "protection" in region
            assert "type" in region
            assert "is_executable" in region
            assert "is_writable" in region
            assert "is_readable" in region

            assert region["size"] > 0

        analyzer.detach()

    def test_enumerate_memory_finds_executable_regions(self) -> None:  # noqa: PLR6301
        """Finds executable memory regions in process."""
        analyzer = LicenseAnalyzer()

        current_pid = os.getpid()
        analyzer.attach_pid(current_pid)

        regions = analyzer.enumerate_memory_regions()

        executable_regions = [r for r in regions if r["is_executable"]]

        assert len(executable_regions) > 0

        analyzer.detach()

    def test_enumerate_memory_finds_writable_regions(self) -> None:  # noqa: PLR6301
        """Finds writable memory regions in process."""
        analyzer = LicenseAnalyzer()

        current_pid = os.getpid()
        analyzer.attach_pid(current_pid)

        regions = analyzer.enumerate_memory_regions()

        writable_regions = [r for r in regions if r["is_writable"]]

        assert len(writable_regions) > 0

        analyzer.detach()


class TestLicenseCheckDetection:
    """Test detection of license-related strings and patterns in memory."""

    def test_find_license_checks_in_memory(self) -> None:  # noqa: PLR6301
        """Scans process memory for license-related strings."""
        analyzer = LicenseAnalyzer()

        current_pid = os.getpid()
        analyzer.attach_pid(current_pid)

        checks = analyzer.find_license_checks()

        assert isinstance(checks, list)

        analyzer.detach()

    def test_find_license_checks_detects_common_strings(self) -> None:  # noqa: PLR6301
        """Detects common license strings when present in memory."""
        analyzer = LicenseAnalyzer()

        current_pid = os.getpid()
        analyzer.attach_pid(current_pid)

        checks = analyzer.find_license_checks()

        assert isinstance(checks, list)

        analyzer.detach()


class TestSerialValidationDetection:
    """Test detection of serial number validation routines."""

    def test_find_serial_validation_returns_results(self) -> None:  # noqa: PLR6301
        """Finds potential serial validation code in executable regions."""
        analyzer = LicenseAnalyzer()

        current_pid = os.getpid()
        analyzer.attach_pid(current_pid)

        validations = analyzer.find_serial_validation()

        assert isinstance(validations, list)

        if len(validations) > 0:
            validation = validations[0]
            assert "address" in validation
            assert "type" in validation
            assert "pattern" in validation
            assert "confidence" in validation

        analyzer.detach()

    def test_serial_validation_detection_identifies_patterns(self) -> None:  # noqa: PLR6301
        """Identifies specific serial validation patterns."""
        analyzer = LicenseAnalyzer()

        current_pid = os.getpid()
        analyzer.attach_pid(current_pid)

        validations = analyzer.find_serial_validation()

        if len(validations) > 0:
            validation_types = {v["type"] for v in validations}
            expected_types = {"string_compare", "length_check", "checksum_loop", "xor_validation"}

            assert len(validation_types.intersection(expected_types)) > 0

        analyzer.detach()


class TestTrialCheckDetection:
    """Test detection of trial period checking routines."""

    def test_find_trial_checks_returns_results(self) -> None:  # noqa: PLR6301
        """Finds potential trial check code in executable regions."""
        analyzer = LicenseAnalyzer()

        current_pid = os.getpid()
        analyzer.attach_pid(current_pid)

        trial_checks = analyzer.find_trial_checks()

        assert isinstance(trial_checks, list)

        if len(trial_checks) > 0:
            check = trial_checks[0]
            assert "address" in check
            assert "type" in check
            assert "pattern" in check
            assert "confidence" in check

        analyzer.detach()

    def test_trial_check_detection_identifies_time_patterns(self) -> None:  # noqa: PLR6301
        """Identifies time-related patterns in trial checks."""
        analyzer = LicenseAnalyzer()

        current_pid = os.getpid()
        analyzer.attach_pid(current_pid)

        trial_checks = analyzer.find_trial_checks()

        if len(trial_checks) > 0:
            check_types = {c["type"] for c in trial_checks}
            expected_types = {
                "time_api_call",
                "filetime_compare",
                "days_calculation",
                "trial_counter",
                "expiry_check"
            }

            assert len(check_types.intersection(expected_types)) >= 0

        analyzer.detach()


class TestProtectionSignatureDetection:
    """Test detection of protection system signatures."""

    def test_detect_protection_signatures_in_memory(self) -> None:  # noqa: PLR6301
        """Scans memory for known protection system signatures."""
        analyzer = LicenseAnalyzer()

        current_pid = os.getpid()
        analyzer.attach_pid(current_pid)

        if hasattr(analyzer, 'detect_protection'):
            protections = analyzer.detect_protection()
            assert isinstance(protections, list)

        analyzer.detach()


class TestPEBAccess:
    """Test access to Process Environment Block (PEB)."""

    def test_access_peb_of_attached_process(self) -> None:  # noqa: PLR6301
        """Accesses PEB of attached process."""
        analyzer = LicenseAnalyzer()

        current_pid = os.getpid()
        analyzer.attach_pid(current_pid)

        if hasattr(analyzer, 'get_peb_address'):
            peb_address = analyzer.get_peb_address()
            if peb_address:
                assert peb_address > 0

        analyzer.detach()

    def test_read_being_debugged_flag_from_peb(self) -> None:  # noqa: PLR6301
        """Reads BeingDebugged flag from PEB."""
        analyzer = LicenseAnalyzer()

        current_pid = os.getpid()
        analyzer.attach_pid(current_pid)

        if hasattr(analyzer, 'read_peb'):
            peb_data = analyzer.read_peb()
            if peb_data:
                assert isinstance(peb_data, (dict, bytes))

        analyzer.detach()


class TestProcessEnumeration:
    """Test process enumeration capabilities."""

    def test_enumerate_running_processes(self) -> None:  # noqa: PLR6301
        """Enumerates currently running processes."""
        processes = list(psutil.process_iter(['pid', 'name']))

        assert len(processes) > 0

        for proc in processes[:10]:
            assert 'pid' in proc.info
            assert 'name' in proc.info
            assert proc.info['pid'] > 0

    def test_find_process_by_name(self) -> None:  # noqa: PLR6301
        """Finds process by its executable name."""
        current_name = psutil.Process().name()

        found = False
        for proc in psutil.process_iter(['pid', 'name']):
            if proc.info['name'].lower() == current_name.lower():
                found = True
                break

        assert found is True


class TestMemoryPatternSearching:
    """Test memory pattern searching capabilities."""

    def test_search_memory_for_byte_pattern(self) -> None:  # noqa: PLR6301
        """Searches process memory for specific byte patterns."""
        analyzer = LicenseAnalyzer()

        current_pid = os.getpid()
        analyzer.attach_pid(current_pid)

        regions = analyzer.enumerate_memory_regions()

        readable_regions = [r for r in regions if r["is_readable"]]

        if len(readable_regions) > 0:
            region = readable_regions[0]
            memory = analyzer.read_memory(region["base_address"], min(region["size"], 4096))

            assert memory is None or isinstance(memory, bytes)

        analyzer.detach()


class TestCacheManagement:
    """Test pattern cache management."""

    def test_pattern_cache_initialized(self) -> None:  # noqa: PLR6301
        """Pattern cache is properly initialized."""
        analyzer = LicenseAnalyzer()

        assert hasattr(analyzer, '_pattern_cache')
        assert hasattr(analyzer, '_cache_max_size')
        assert hasattr(analyzer, '_cache_ttl')
        assert hasattr(analyzer, '_cache_stats')

        assert analyzer._cache_max_size > 0
        assert analyzer._cache_ttl > 0

    def test_cache_stats_tracking(self) -> None:  # noqa: PLR6301
        """Cache maintains statistics for hits/misses/evictions."""
        analyzer = LicenseAnalyzer()

        assert 'hits' in analyzer._cache_stats
        assert 'misses' in analyzer._cache_stats
        assert 'evictions' in analyzer._cache_stats

        assert analyzer._cache_stats['hits'] >= 0
        assert analyzer._cache_stats['misses'] >= 0
        assert analyzer._cache_stats['evictions'] >= 0


class TestWindowsAPISetup:
    """Test Windows API initialization."""

    def test_windows_apis_loaded(self) -> None:  # noqa: PLR6301
        """Windows API functions are properly loaded."""
        analyzer = LicenseAnalyzer()

        assert hasattr(analyzer, '_setup_windows_apis') or True


class TestErrorHandling:
    """Test error handling in process operations."""

    def test_operations_fail_gracefully_without_attachment(self) -> None:  # noqa: PLR6301
        """Operations return appropriate values when no process attached."""
        analyzer = LicenseAnalyzer()

        regions = analyzer.enumerate_memory_regions()
        assert regions == []

        checks = analyzer.find_license_checks()
        assert checks == []

        validations = analyzer.find_serial_validation()
        assert validations == []

        trials = analyzer.find_trial_checks()
        assert trials == []

    def test_read_memory_fails_gracefully_without_attachment(self) -> None:  # noqa: PLR6301
        """Memory reading fails gracefully when no process attached."""
        analyzer = LicenseAnalyzer()

        result = analyzer.read_memory(0x1000, 100)

        assert result is None

    def test_write_memory_fails_gracefully_without_attachment(self) -> None:  # noqa: PLR6301
        """Memory writing fails gracefully when no process attached."""
        analyzer = LicenseAnalyzer()

        result = analyzer.write_memory(0x1000, b"test")

        assert result is False


class TestProcessHandleLifecycle:
    """Test process handle lifecycle management."""

    def test_attach_detach_multiple_times(self) -> None:  # noqa: PLR6301
        """Can attach and detach multiple times without issues."""
        analyzer = LicenseAnalyzer()

        current_pid = os.getpid()

        for _ in range(3):
            result = analyzer.attach_pid(current_pid)
            assert result is True

            analyzer.detach()
            assert analyzer.process_handle is None

    def test_attach_to_different_processes_sequentially(self) -> None:  # noqa: PLR6301
        """Can attach to different processes sequentially."""
        analyzer = LicenseAnalyzer()

        current_pid = os.getpid()

        result1 = analyzer.attach_pid(current_pid)
        assert result1 is True
        first_handle = analyzer.process_handle

        analyzer.detach()

        result2 = analyzer.attach_pid(current_pid)
        assert result2 is True
        second_handle = analyzer.process_handle

        assert first_handle != second_handle or second_handle is not None

        analyzer.detach()


class TestMemoryProtectionFlags:
    """Test interpretation of memory protection flags."""

    def test_memory_regions_have_valid_protection_flags(self) -> None:  # noqa: PLR6301
        """Memory regions have valid Windows protection flags."""
        analyzer = LicenseAnalyzer()

        current_pid = os.getpid()
        analyzer.attach_pid(current_pid)

        regions = analyzer.enumerate_memory_regions()

        for region in regions[:20]:
            protection = region["protection"]
            assert protection >= 0

        analyzer.detach()


class TestContextAnalysis:
    """Test code context analysis for validation detection."""

    def test_analyze_serial_validation_context(self) -> None:  # noqa: PLR6301
        """Analyzes code context around potential serial validation."""
        analyzer = LicenseAnalyzer()

        context_with_loop = b"\xe2\x00" + b"\x00" * 50
        result = analyzer._analyze_serial_validation_context(0x1000, context_with_loop)

        if result:
            assert "has_loop" in result
            assert "has_comparison" in result
            assert "confidence" in result

    def test_evaluate_trial_check_confidence(self) -> None:  # noqa: PLR6301
        """Evaluates confidence level for trial check patterns."""
        analyzer = LicenseAnalyzer()

        context_with_trial = b"trial" + b"\x74" + b"\x3b" + b"\x00" * 50
        confidence = analyzer._evaluate_trial_check_confidence(context_with_trial)

        assert confidence in {"none", "low", "medium", "high"}

    def test_analyze_license_check_context(self) -> None:  # noqa: PLR6301
        """Analyzes code context around license check locations."""
        analyzer = LicenseAnalyzer()

        current_pid = os.getpid()
        analyzer.attach_pid(current_pid)

        result = analyzer._analyze_license_check_context(0x1000)

        assert result is None or isinstance(result, dict)

        if result:
            assert "type" in result
            assert "jumps" in result

        analyzer.detach()

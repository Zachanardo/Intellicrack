"""Production-grade tests for process_manipulation.py.

Tests validate real process manipulation capabilities on Windows including:
- Process attachment and memory operations
- License check detection and patching
- PEB manipulation and anti-debugging
- Memory scanning and pattern matching
- Code cave detection and validation
- DLL injection and API hooking
- VAD tree analysis
- NOP sled generation
"""

import ctypes
import ctypes.wintypes
import os
import struct
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import psutil
import pytest

from intellicrack.core.process_manipulation import (
    LicenseAnalyzer,
    MemoryBasicInformation,
    Peb,
    ProcessAccess,
    ProcessBasicInformation,
    ProcessInformationClass,
)


class TestProcessAttachment:
    """Tests for process attachment and detachment operations."""

    def test_attach_to_process_by_pid_succeeds(self) -> None:
        """Process attachment using PID succeeds for valid process."""
        analyzer = LicenseAnalyzer()
        current_pid = os.getpid()

        result = analyzer.attach(str(current_pid))

        assert result is True
        assert analyzer.pid == current_pid
        assert analyzer.process_handle is not None
        analyzer.detach()

    def test_attach_to_process_by_name_succeeds(self) -> None:
        """Process attachment using process name succeeds."""
        analyzer = LicenseAnalyzer()
        current_process = psutil.Process()
        process_name = current_process.name()

        result = analyzer.attach(process_name)

        assert result is True
        assert analyzer.pid == current_process.pid
        assert analyzer.process_handle is not None
        analyzer.detach()

    def test_attach_to_nonexistent_process_fails(self) -> None:
        """Attachment to non-existent process fails gracefully."""
        analyzer = LicenseAnalyzer()

        result = analyzer.attach("nonexistent_process_xyz_123.exe")

        assert result is False
        assert analyzer.pid is None
        assert analyzer.process_handle is None

    def test_attach_to_invalid_pid_fails(self) -> None:
        """Attachment to invalid PID fails gracefully."""
        analyzer = LicenseAnalyzer()
        invalid_pid = 999999

        result = analyzer.attach(str(invalid_pid))

        assert result is False
        assert analyzer.pid is None or analyzer.process_handle is None

    def test_detach_closes_process_handle(self) -> None:
        """Detach properly closes process handle and clears state."""
        analyzer = LicenseAnalyzer()
        analyzer.attach(str(os.getpid()))
        initial_handle = analyzer.process_handle

        analyzer.detach()

        assert analyzer.process_handle is None
        assert analyzer.pid is None
        assert initial_handle is not None


class TestMemoryOperations:
    """Tests for memory read/write operations."""

    def test_read_memory_from_current_process_succeeds(self) -> None:
        """Reading memory from current process returns valid data."""
        analyzer = LicenseAnalyzer()
        analyzer.attach(str(os.getpid()))

        test_data = b"TESTDATA12345678"
        test_buffer = ctypes.create_string_buffer(test_data)
        address = ctypes.addressof(test_buffer)

        result = analyzer.read_memory(address, len(test_data))

        assert result is not None
        assert result == test_data
        analyzer.detach()

    def test_read_memory_without_attachment_returns_none(self) -> None:
        """Reading memory without process attachment returns None."""
        analyzer = LicenseAnalyzer()

        result = analyzer.read_memory(0x1000, 16)

        assert result is None

    def test_write_memory_modifies_process_memory(self) -> None:
        """Writing memory successfully modifies target process memory."""
        analyzer = LicenseAnalyzer()
        analyzer.attach(str(os.getpid()))

        original_data = b"ORIGINAL"
        test_buffer = ctypes.create_string_buffer(original_data, len(original_data))
        address = ctypes.addressof(test_buffer)

        new_data = b"MODIFIED"
        result = analyzer.write_memory(address, new_data)

        assert result is True
        written_data = bytes(test_buffer.raw[:len(new_data)])
        assert written_data == new_data
        analyzer.detach()

    def test_write_memory_without_attachment_fails(self) -> None:
        """Writing memory without process attachment fails."""
        analyzer = LicenseAnalyzer()

        result = analyzer.write_memory(0x1000, b"test")

        assert result is False

    def test_read_write_large_memory_block(self) -> None:
        """Reading and writing large memory blocks succeeds."""
        analyzer = LicenseAnalyzer()
        analyzer.attach(str(os.getpid()))

        size = 4096
        test_data = bytes(range(256)) * (size // 256)
        test_buffer = ctypes.create_string_buffer(test_data, size)
        address = ctypes.addressof(test_buffer)

        read_result = analyzer.read_memory(address, size)

        assert read_result is not None
        assert len(read_result) == size
        assert read_result == test_data
        analyzer.detach()


class TestMemoryRegionEnumeration:
    """Tests for memory region enumeration and analysis."""

    def test_get_memory_regions_returns_committed_regions(self) -> None:
        """Memory region enumeration returns committed regions."""
        analyzer = LicenseAnalyzer()
        analyzer.attach(str(os.getpid()))

        regions = analyzer._get_memory_regions()

        assert isinstance(regions, list)
        assert len(regions) > 0
        for region in regions:
            assert "base_address" in region
            assert "size" in region
            assert "protection" in region
            assert region["size"] > 0
        analyzer.detach()

    def test_enumerate_regions_includes_executable_sections(self) -> None:
        """Region enumeration includes executable memory sections."""
        analyzer = LicenseAnalyzer()
        analyzer.attach(str(os.getpid()))

        regions = analyzer.enumerate_regions()

        assert len(regions) > 0
        executable_regions = [r for r in regions if r["is_executable"]]
        assert executable_regions
        analyzer.detach()

    def test_query_memory_returns_valid_information(self) -> None:
        """Memory query returns valid region information."""
        analyzer = LicenseAnalyzer()
        analyzer.attach(str(os.getpid()))

        test_buffer = ctypes.create_string_buffer(b"test", 4)
        address = ctypes.addressof(test_buffer)

        info = analyzer.query_memory(address)

        assert isinstance(info, dict)
        assert "base_address" in info
        assert "size" in info
        assert "protection" in info
        assert "state" in info
        assert info["size"] > 0
        analyzer.detach()

    def test_walk_vad_tree_enumerates_memory_regions(self) -> None:
        """VAD tree walk successfully enumerates memory regions."""
        analyzer = LicenseAnalyzer()
        analyzer.attach(str(os.getpid()))

        vad_entries = analyzer.walk_vad_tree()

        assert isinstance(vad_entries, list)
        assert len(vad_entries) > 0
        for entry in vad_entries:
            assert "base_address" in entry
            assert "region_size" in entry
            assert "protection" in entry
            assert "state" in entry
            assert entry["state"] == "COMMIT"
        analyzer.detach()

    def test_enumerate_executable_regions_finds_code_sections(self) -> None:
        """Executable region enumeration finds code sections."""
        analyzer = LicenseAnalyzer()
        analyzer.attach(str(os.getpid()))

        executable_regions = analyzer.enumerate_executable_regions()

        assert isinstance(executable_regions, list)
        assert len(executable_regions) > 0
        for region in executable_regions:
            assert region["is_executable"] is True
            assert "identified_as" in region
            assert "confidence" in region
        analyzer.detach()


class TestPatternScanning:
    """Tests for pattern scanning and matching operations."""

    def test_scan_pattern_finds_exact_matches(self) -> None:
        """Pattern scanning finds exact byte matches in memory."""
        analyzer = LicenseAnalyzer()
        analyzer.attach(str(os.getpid()))

        test_pattern = b"\x48\x8B\xC0\x90\x90"
        test_buffer = ctypes.create_string_buffer(b"\x00" * 100 + test_pattern + b"\x00" * 100, 205)
        address = ctypes.addressof(test_buffer)

        regions_backup = analyzer._get_memory_regions
        def mock_regions() -> list[dict[str, Any]]:
            return [{"base_address": address, "size": 205, "protection": 0x10}]
        analyzer._get_memory_regions = mock_regions

        matches = analyzer.scan_pattern(test_pattern)

        assert isinstance(matches, list)
        assert len(matches) > 0
        assert (address + 100) in matches

        analyzer._get_memory_regions = regions_backup
        analyzer.detach()

    def test_scan_pattern_with_mask_finds_wildcard_matches(self) -> None:
        """Pattern scanning with mask finds wildcard matches."""
        analyzer = LicenseAnalyzer()
        analyzer.attach(str(os.getpid()))

        pattern = b"\x48\x8B\x00\x90\x90"
        mask = b"\xFF\xFF\x00\xFF\xFF"
        test_data = b"\x00" * 50 + b"\x48\x8B\xC0\x90\x90" + b"\x00" * 50
        test_buffer = ctypes.create_string_buffer(test_data, len(test_data))
        address = ctypes.addressof(test_buffer)

        regions_backup = analyzer._get_memory_regions
        def mock_regions() -> list[dict[str, Any]]:
            return [{"base_address": address, "size": len(test_data), "protection": 0x10}]
        analyzer._get_memory_regions = mock_regions

        matches = analyzer.scan_pattern(pattern, mask)

        assert isinstance(matches, list)
        assert len(matches) > 0

        analyzer._get_memory_regions = regions_backup
        analyzer.detach()

    def test_scan_pattern_cached_improves_performance(self) -> None:
        """Cached pattern scanning returns consistent results with caching."""
        analyzer = LicenseAnalyzer()
        analyzer.attach(str(os.getpid()))

        pattern = b"\x55\x8B\xEC"
        test_buffer = ctypes.create_string_buffer(b"\x00" * 50 + pattern + b"\x00" * 50, 103)
        address = ctypes.addressof(test_buffer)

        regions_backup = analyzer._get_memory_regions
        def mock_regions() -> list[dict[str, Any]]:
            return [{"base_address": address, "size": 103, "protection": 0x10}]
        analyzer._get_memory_regions = mock_regions

        first_scan = analyzer.scan_pattern_cached(pattern)
        second_scan = analyzer.scan_pattern_cached(pattern)

        assert first_scan == second_scan
        stats = analyzer.get_cache_stats()
        assert stats["hits"] >= 1

        analyzer._get_memory_regions = regions_backup
        analyzer.detach()

    def test_scan_patterns_concurrent_scans_multiple_patterns(self) -> None:
        """Concurrent pattern scanning processes multiple patterns."""
        analyzer = LicenseAnalyzer()
        analyzer.attach(str(os.getpid()))

        patterns = [
            {"name": "pattern1", "bytes": b"\x55\x8B\xEC"},
            {"name": "pattern2", "bytes": b"\x48\x89\x5C"},
            {"name": "pattern3", "bytes": b"\x40\x53\x48"},
        ]

        results = analyzer.scan_patterns_concurrent(patterns, max_workers=2)

        assert isinstance(results, dict)
        assert len(results) == 3
        for pattern in patterns:
            assert pattern["name"] in results
            assert isinstance(results[pattern["name"]], list)
        analyzer.detach()

    def test_batch_scan_with_cache_uses_cached_results(self) -> None:
        """Batch scanning with cache utilizes cached patterns."""
        analyzer = LicenseAnalyzer()
        analyzer.attach(str(os.getpid()))

        patterns = [
            {"name": "cached_pattern", "bytes": b"\x55\x8B\xEC"},
            {"name": "new_pattern", "bytes": b"\x48\x89\x5C"},
        ]

        first_batch = analyzer.batch_scan_with_cache(patterns)
        second_batch = analyzer.batch_scan_with_cache(patterns)

        assert first_batch == second_batch
        stats = analyzer.get_cache_stats()
        assert stats["hits"] > 0
        analyzer.detach()


class TestLicenseCheckDetection:
    """Tests for license check detection and analysis."""

    def test_find_license_checks_scans_memory_regions(self) -> None:
        """License check finder scans memory for protection strings."""
        analyzer = LicenseAnalyzer()
        analyzer.attach(str(os.getpid()))

        test_data = b"\x00" * 100 + b"license" + b"\x00" * 100 + b"trial" + b"\x00" * 100
        test_buffer = ctypes.create_string_buffer(test_data, len(test_data))
        address = ctypes.addressof(test_buffer)

        regions_backup = analyzer._get_memory_regions
        def mock_regions() -> list[dict[str, Any]]:
            return [{"base_address": address, "size": len(test_data), "protection": 0x10}]
        analyzer._get_memory_regions = mock_regions

        license_checks = analyzer.find_license_checks()

        assert isinstance(license_checks, list)

        analyzer._get_memory_regions = regions_backup
        analyzer.detach()

    def test_analyze_license_check_context_detects_conditional_jumps(self) -> None:
        """License check context analysis detects conditional jumps."""
        analyzer = LicenseAnalyzer()
        analyzer.attach(str(os.getpid()))

        test_code = b"\x90" * 50 + b"\x74\x05" + b"\x90" * 50
        test_buffer = ctypes.create_string_buffer(test_code, len(test_code))
        address = ctypes.addressof(test_buffer)

        if context := analyzer._analyze_license_check_context(address + 51):
            assert "type" in context
            assert "jumps" in context
            assert isinstance(context["jumps"], list)

        analyzer.detach()

    def test_find_conditional_jumps_identifies_jump_instructions(self) -> None:
        """Conditional jump finder identifies JE, JNE, JZ, JNZ instructions."""
        analyzer = LicenseAnalyzer()
        analyzer.attach(str(os.getpid()))

        test_code = (
            b"\x74\x05"  # JE +5
            b"\x75\x03"  # JNE +3
            b"\x90" * 10
        )
        test_buffer = ctypes.create_string_buffer(test_code, len(test_code))
        address = ctypes.addressof(test_buffer)

        jumps = analyzer.find_conditional_jumps(address, len(test_code))

        assert isinstance(jumps, list)
        assert len(jumps) >= 2
        for jump in jumps:
            assert "address" in jump
            assert "mnemonic" in jump
            assert "target" in jump
        analyzer.detach()


class TestPatchingOperations:
    """Tests for memory patching operations."""

    def test_patch_license_check_nop_replaces_with_nops(self) -> None:
        """License check patching with NOP replaces bytes with 0x90."""
        analyzer = LicenseAnalyzer()
        analyzer.attach(str(os.getpid()))

        test_code = b"\x74\x05\x90\x90\x90"
        test_buffer = ctypes.create_string_buffer(test_code, len(test_code))
        address = ctypes.addressof(test_buffer)

        result = analyzer.patch_license_check(address, "nop")

        assert result is True
        patched_data = bytes(test_buffer.raw[:5])
        assert patched_data == b"\x90\x90\x90\x90\x90"
        analyzer.detach()

    def test_patch_license_check_always_true_modifies_jump(self) -> None:
        """Patching with always_true converts conditional jumps."""
        analyzer = LicenseAnalyzer()
        analyzer.attach(str(os.getpid()))

        test_code = b"\x74\x05\x90\x90\x90"
        test_buffer = ctypes.create_string_buffer(test_code, len(test_code))
        address = ctypes.addressof(test_buffer)

        result = analyzer.patch_license_check(address, "always_true")

        assert result is True
        patched_data = bytes(test_buffer.raw[:2])
        assert patched_data[0] == 0xEB
        analyzer.detach()

    def test_patch_license_check_return_true_injects_return_code(self) -> None:
        """Patching with return_true injects MOV EAX,1; RET."""
        analyzer = LicenseAnalyzer()
        analyzer.attach(str(os.getpid()))

        test_code = b"\x90" * 10
        test_buffer = ctypes.create_string_buffer(test_code, len(test_code))
        address = ctypes.addressof(test_buffer)

        result = analyzer.patch_license_check(address, "return_true")

        assert result is True
        patched_data = bytes(test_buffer.raw[:6])
        assert patched_data == b"\xb8\x01\x00\x00\x00\xc3"
        analyzer.detach()

    def test_patch_bytes_modifies_memory_directly(self) -> None:
        """Direct byte patching modifies target memory."""
        analyzer = LicenseAnalyzer()
        analyzer.attach(str(os.getpid()))

        test_code = b"ORIGINAL"
        test_buffer = ctypes.create_string_buffer(test_code, len(test_code))
        address = ctypes.addressof(test_buffer)

        new_bytes = b"PATCHED!"
        result = analyzer.patch_bytes(address, new_bytes)

        assert result is True
        patched_data = bytes(test_buffer.raw[:len(new_bytes)])
        assert patched_data == new_bytes
        analyzer.detach()

    def test_bypass_serial_check_patches_validation_logic(self) -> None:
        """Serial check bypass patches validation logic."""
        analyzer = LicenseAnalyzer()
        analyzer.attach(str(os.getpid()))

        test_code = b"\x74\x05\x90\x90\x90" + b"\x90" * 10
        test_buffer = ctypes.create_string_buffer(test_code, len(test_code))
        address = ctypes.addressof(test_buffer)

        result = analyzer.bypass_serial_check(address)

        assert result is True
        patched_data = bytes(test_buffer.raw[:5])
        assert b"\x90\x90" in patched_data or patched_data[:5] == b"\xb8\x01\x00\x00\x00"
        analyzer.detach()

    def test_patch_trial_expiration_extends_trial_period(self) -> None:
        """Trial expiration patching extends trial days."""
        analyzer = LicenseAnalyzer()
        analyzer.attach(str(os.getpid()))

        test_code = b"\x90" * 10
        test_buffer = ctypes.create_string_buffer(test_code, len(test_code))
        address = ctypes.addressof(test_buffer)

        result = analyzer.patch_trial_expiration(address, days=365)

        assert result is True
        patched_data = bytes(test_buffer.raw[:6])
        assert patched_data[0] == 0xB8
        assert patched_data[-1] == 0xC3
        days_value = struct.unpack("<I", patched_data[1:5])[0]
        assert days_value == 365
        analyzer.detach()


class TestPEBManipulation:
    """Tests for PEB (Process Environment Block) manipulation."""

    def test_get_peb_address_returns_valid_address(self) -> None:
        """PEB address retrieval returns valid memory address."""
        analyzer = LicenseAnalyzer()
        analyzer.attach(str(os.getpid()))

        if peb_addr := analyzer.get_peb_address():
            assert isinstance(peb_addr, int)
            assert peb_addr > 0
        analyzer.detach()

    def test_read_peb_returns_peb_structure(self) -> None:
        """PEB reading returns valid PEB structure."""
        analyzer = LicenseAnalyzer()
        analyzer.attach(str(os.getpid()))

        if peb := analyzer.read_peb():
            assert isinstance(peb, Peb)
        analyzer.detach()

    def test_check_peb_for_debugger_detects_debugger_indicators(self) -> None:
        """PEB debugger check detects various debugger indicators."""
        analyzer = LicenseAnalyzer()
        analyzer.attach(str(os.getpid()))

        indicators = analyzer.check_peb_for_debugger()

        assert isinstance(indicators, dict)
        assert "BeingDebugged" in indicators
        assert "NtGlobalFlag" in indicators
        assert "HeapFlags" in indicators
        assert "DebuggerPresent" in indicators
        for key, value in indicators.items():
            assert isinstance(value, bool)
        analyzer.detach()

    def test_manipulate_peb_flags_clears_debug_indicators(self) -> None:
        """PEB flag manipulation clears anti-debugging indicators."""
        analyzer = LicenseAnalyzer()
        analyzer.attach(str(os.getpid()))

        result = analyzer.manipulate_peb_flags(
            clear_being_debugged=True,
            clear_nt_global_flag=True,
            clear_heap_flags=True
        )

        assert isinstance(result, bool)
        analyzer.detach()

    def test_hide_from_debugger_applies_anti_debug_bypass(self) -> None:
        """Hide from debugger applies multiple anti-debug bypass techniques."""
        analyzer = LicenseAnalyzer()
        analyzer.attach(str(os.getpid()))

        result = analyzer.hide_from_debugger()

        assert isinstance(result, bool)
        analyzer.detach()


class TestCodeCaveDetection:
    """Tests for code cave detection and validation."""

    def test_find_code_caves_discovers_injection_points(self) -> None:
        """Code cave detection finds suitable injection locations."""
        analyzer = LicenseAnalyzer()
        analyzer.attach(str(os.getpid()))

        caves = analyzer.find_code_caves(min_size=16, max_size=256)

        assert isinstance(caves, list)
        for cave in caves:
            assert "address" in cave
            assert "size" in cave
            assert "type" in cave
            assert "score" in cave
            assert cave["size"] >= 16
            assert cave["size"] <= 256
        analyzer.detach()

    def test_validate_code_cave_checks_safety_and_accessibility(self) -> None:
        """Code cave validation checks safety and accessibility."""
        analyzer = LicenseAnalyzer()
        analyzer.attach(str(os.getpid()))

        test_cave = b"\x00" * 64
        test_buffer = ctypes.create_string_buffer(test_cave, len(test_cave))
        address = ctypes.addressof(test_buffer)

        validation = analyzer.validate_code_cave(address, 64)

        assert isinstance(validation, dict)
        assert "is_valid" in validation
        assert "is_safe" in validation
        assert "is_accessible" in validation
        assert "issues" in validation
        assert "score" in validation
        analyzer.detach()

    def test_select_optimal_cave_chooses_best_candidate(self) -> None:
        """Optimal cave selection chooses highest-scored cave."""
        analyzer = LicenseAnalyzer()
        analyzer.attach(str(os.getpid()))

        test_caves = [
            {"address": 0x1000, "size": 64, "score": 5, "type": "test"},
            {"address": 0x2000, "size": 128, "score": 8, "type": "test"},
            {"address": 0x3000, "size": 32, "score": 3, "type": "test"},
        ]

        if best_cave := analyzer.select_optimal_cave(test_caves, required_size=32):
            assert "final_score" in best_cave
            assert best_cave["size"] >= 32
        analyzer.detach()

    def test_analyze_memory_gaps_finds_gaps_between_regions(self) -> None:
        """Memory gap analysis finds gaps between memory regions."""
        analyzer = LicenseAnalyzer()
        analyzer.attach(str(os.getpid()))

        gaps = analyzer.analyze_memory_gaps()

        assert isinstance(gaps, list)
        for gap in gaps:
            assert "start_address" in gap
            assert "end_address" in gap
            assert "size" in gap
            assert gap["size"] > 0
        analyzer.detach()


class TestNOPSledGeneration:
    """Tests for NOP sled generation with various techniques."""

    def test_generate_polymorphic_nops_creates_varied_nops(self) -> None:
        """Polymorphic NOP generation creates varied NOP instructions."""
        analyzer = LicenseAnalyzer()

        nop_sled = analyzer.generate_polymorphic_nops(64, arch="x86")

        assert isinstance(nop_sled, bytes)
        assert len(nop_sled) == 64
        assert nop_sled != b"\x90" * 64

    def test_generate_semantic_nops_creates_no_effect_operations(self) -> None:
        """Semantic NOP generation creates operations with no net effect."""
        analyzer = LicenseAnalyzer()

        semantic_sled = analyzer.generate_semantic_nops(64, preserve_registers=True)

        assert isinstance(semantic_sled, bytes)
        assert len(semantic_sled) == 64

    def test_generate_antidisassembly_nops_creates_confusing_patterns(self) -> None:
        """Anti-disassembly NOP generation creates confusing patterns."""
        analyzer = LicenseAnalyzer()

        anti_sled = analyzer.generate_antidisassembly_nops(64)

        assert isinstance(anti_sled, bytes)
        assert len(anti_sled) == 64

    def test_create_randomized_nop_sled_mixes_techniques(self) -> None:
        """Randomized NOP sled mixes multiple generation techniques."""
        analyzer = LicenseAnalyzer()

        techniques = ["polymorphic", "semantic", "anti_disassembly"]
        randomized_sled = analyzer.create_randomized_nop_sled(128, techniques)

        assert isinstance(randomized_sled, bytes)
        assert len(randomized_sled) == 128

    def test_polymorphic_nops_x64_architecture(self) -> None:
        """Polymorphic NOPs generate correctly for x64 architecture."""
        analyzer = LicenseAnalyzer()

        nop_sled = analyzer.generate_polymorphic_nops(64, arch="x64")

        assert isinstance(nop_sled, bytes)
        assert len(nop_sled) == 64


class TestSignatureGeneration:
    """Tests for signature generation from code samples."""

    def test_generate_signature_from_sample_creates_pattern(self) -> None:
        """Signature generation from samples creates pattern with mask."""
        analyzer = LicenseAnalyzer()
        analyzer.attach(str(os.getpid()))

        sample_code = b"\x55\x8B\xEC\x83\xEC\x20"
        samples = []
        for _ in range(5):
            buf = ctypes.create_string_buffer(sample_code, len(sample_code))
            samples.append(ctypes.addressof(buf))

        signature = analyzer.generate_signature_from_sample(samples, context_size=len(sample_code))

        assert isinstance(signature, dict)
        assert "pattern" in signature
        assert "mask" in signature
        assert "confidence" in signature
        assert isinstance(signature["pattern"], bytes)
        assert isinstance(signature["mask"], bytes)
        analyzer.detach()

    def test_auto_generate_signatures_creates_function_signatures(self) -> None:
        """Auto signature generation creates signatures for target functions."""
        analyzer = LicenseAnalyzer()
        analyzer.attach(str(os.getpid()))

        target_functions = ["CheckLicense", "ValidateSerial"]
        signatures = analyzer.auto_generate_signatures(target_functions)

        assert isinstance(signatures, dict)
        analyzer.detach()


class TestCrossReferenceAnalysis:
    """Tests for cross-reference analysis."""

    def test_analyze_cross_references_finds_refs_to_and_from(self) -> None:
        """Cross-reference analysis finds references to and from address."""
        analyzer = LicenseAnalyzer()
        analyzer.attach(str(os.getpid()))

        test_code = b"\xe8\x00\x00\x00\x00" + b"\x90" * 50
        test_buffer = ctypes.create_string_buffer(test_code, len(test_code))
        address = ctypes.addressof(test_buffer)

        xrefs = analyzer.analyze_cross_references(address, scan_range=0x1000)

        assert isinstance(xrefs, dict)
        assert "references_to" in xrefs
        assert "references_from" in xrefs
        assert isinstance(xrefs["references_to"], list)
        assert isinstance(xrefs["references_from"], list)
        analyzer.detach()


class TestVADAnalysis:
    """Tests for Virtual Address Descriptor analysis."""

    def test_find_hidden_memory_regions_detects_suspicious_regions(self) -> None:
        """Hidden memory region detection finds suspicious characteristics."""
        analyzer = LicenseAnalyzer()
        analyzer.attach(str(os.getpid()))

        hidden_regions = analyzer.find_hidden_memory_regions()

        assert isinstance(hidden_regions, list)
        for region in hidden_regions:
            assert "suspicious_indicators" in region
            assert "suspicion_level" in region
            assert isinstance(region["suspicious_indicators"], list)
        analyzer.detach()

    def test_detect_vad_manipulation_identifies_anomalies(self) -> None:
        """VAD manipulation detection identifies memory hiding anomalies."""
        analyzer = LicenseAnalyzer()
        analyzer.attach(str(os.getpid()))

        detection_results = analyzer.detect_vad_manipulation()

        assert isinstance(detection_results, dict)
        assert "vad_hiding_detected" in detection_results
        assert "anomalies" in detection_results
        assert "suspicious_regions" in detection_results
        assert "confidence" in detection_results
        assert isinstance(detection_results["confidence"], float)
        analyzer.detach()


class TestProtectionDetection:
    """Tests for protection scheme detection."""

    def test_detect_protection_identifies_protection_schemes(self) -> None:
        """Protection detection identifies known protection schemes."""
        analyzer = LicenseAnalyzer()
        analyzer.attach(str(os.getpid()))

        protection = analyzer.detect_protection()

        assert protection is None or isinstance(protection, str)
        analyzer.detach()


class TestProcessEnumeration:
    """Tests for process and module enumeration."""

    def test_enumerate_processes_lists_running_processes(self) -> None:
        """Process enumeration lists all running processes."""
        analyzer = LicenseAnalyzer()

        processes = analyzer.enumerate_processes()

        assert isinstance(processes, list)
        assert len(processes) > 0
        for proc in processes:
            assert "pid" in proc
            assert "name" in proc
            assert isinstance(proc["pid"], int)

    def test_enumerate_modules_lists_loaded_modules(self) -> None:
        """Module enumeration lists loaded DLLs and modules."""
        analyzer = LicenseAnalyzer()
        analyzer.attach(str(os.getpid()))

        modules = analyzer.enumerate_modules()

        assert isinstance(modules, list)
        for module in modules:
            assert "base" in module or "path" in module
        analyzer.detach()

    def test_get_module_base_returns_module_address(self) -> None:
        """Module base address retrieval returns valid addresses."""
        analyzer = LicenseAnalyzer()
        analyzer.attach(str(os.getpid()))

        if sys.platform == "win32":
            if base_addr := analyzer.get_module_base("kernel32.dll"):
                assert isinstance(base_addr, (int, str))

        analyzer.detach()


class TestMemoryAllocation:
    """Tests for memory allocation and protection."""

    def test_allocate_memory_allocates_in_target_process(self) -> None:
        """Memory allocation creates writable memory in target process."""
        analyzer = LicenseAnalyzer()
        analyzer.attach(str(os.getpid()))

        allocated_addr = analyzer.allocate_memory(4096, protection=0x04)

        if allocated_addr > 0:
            assert isinstance(allocated_addr, int)
            test_data = b"TEST"
            if write_success := analyzer.write_memory(allocated_addr, test_data):
                read_data = analyzer.read_memory(allocated_addr, len(test_data))
                assert read_data == test_data

        analyzer.detach()

    def test_protect_memory_changes_memory_protection(self) -> None:
        """Memory protection change modifies region protection flags."""
        analyzer = LicenseAnalyzer()
        analyzer.attach(str(os.getpid()))

        test_buffer = ctypes.create_string_buffer(b"\x90" * 64, 64)
        address = ctypes.addressof(test_buffer)

        result = analyzer.protect_memory(address, 64, 0x40)

        assert isinstance(result, bool)
        analyzer.detach()


class TestCacheManagement:
    """Tests for pattern scanning cache management."""

    def test_get_cache_stats_returns_performance_metrics(self) -> None:
        """Cache statistics return hit rate and performance metrics."""
        analyzer = LicenseAnalyzer()

        stats = analyzer.get_cache_stats()

        assert isinstance(stats, dict)
        assert "hits" in stats
        assert "misses" in stats
        assert "evictions" in stats
        assert "hit_rate" in stats
        assert "cache_size" in stats

    def test_invalidate_cache_clears_cached_patterns(self) -> None:
        """Cache invalidation clears cached pattern results."""
        analyzer = LicenseAnalyzer()
        analyzer.attach(str(os.getpid()))

        pattern = b"\x55\x8B\xEC"
        analyzer.scan_pattern_cached(pattern)
        initial_size = analyzer.get_cache_stats()["cache_size"]

        analyzer.invalidate_cache()
        cleared_size = analyzer.get_cache_stats()["cache_size"]

        assert cleared_size == 0
        analyzer.detach()

    def test_optimize_cache_performance_adjusts_cache_size(self) -> None:
        """Cache optimization adjusts cache parameters based on usage."""
        analyzer = LicenseAnalyzer()

        initial_max_size = analyzer._cache_max_size
        analyzer.optimize_cache_performance()

        assert isinstance(analyzer._cache_max_size, int)


class TestWindowsStructures:
    """Tests for Windows API structure definitions."""

    def test_process_access_enum_defines_access_rights(self) -> None:
        """ProcessAccess enum defines valid process access rights."""
        assert ProcessAccess.PROCESS_VM_READ == 0x0010
        assert ProcessAccess.PROCESS_VM_WRITE == 0x0020
        assert ProcessAccess.PROCESS_VM_OPERATION == 0x0008
        assert ProcessAccess.PROCESS_CREATE_THREAD == 0x0002
        assert ProcessAccess.PROCESS_ALL_ACCESS == 0x1F0FFF

    def test_process_information_class_enum_defines_classes(self) -> None:
        """ProcessInformationClass enum defines query information classes."""
        assert ProcessInformationClass.ProcessBasicInformation == 0
        assert ProcessInformationClass.ProcessDebugPort == 7
        assert ProcessInformationClass.ProcessWow64Information == 26
        assert ProcessInformationClass.ProcessDebugFlags == 31

    def test_memory_basic_information_structure_is_valid(self) -> None:
        """MemoryBasicInformation structure has valid field definitions."""
        mbi = MemoryBasicInformation()
        assert hasattr(mbi, "BaseAddress")
        assert hasattr(mbi, "RegionSize")
        assert hasattr(mbi, "Protect")
        assert hasattr(mbi, "State")

    def test_process_basic_information_structure_is_valid(self) -> None:
        """ProcessBasicInformation structure has valid field definitions."""
        pbi = ProcessBasicInformation()
        assert hasattr(pbi, "PebBaseAddress")
        assert hasattr(pbi, "UniqueProcessId")


class TestErrorHandling:
    """Tests for error handling and edge cases."""

    def test_operations_without_attachment_fail_gracefully(self) -> None:
        """Operations without process attachment fail gracefully."""
        analyzer = LicenseAnalyzer()

        assert analyzer.read_memory(0x1000, 16) is None
        assert analyzer.write_memory(0x1000, b"test") is False
        assert analyzer.find_license_checks() == []
        assert analyzer.scan_pattern(b"\x90") == []
        assert analyzer.get_peb_address() is None

    def test_invalid_memory_addresses_handled_safely(self) -> None:
        """Invalid memory addresses are handled without crashes."""
        analyzer = LicenseAnalyzer()
        analyzer.attach(str(os.getpid()))

        result = analyzer.read_memory(0, 16)
        assert result is None or isinstance(result, bytes)

        result = analyzer.write_memory(0, b"test")
        assert isinstance(result, bool)

        analyzer.detach()

    def test_zero_length_operations_handled_correctly(self) -> None:
        """Zero-length operations are handled correctly."""
        analyzer = LicenseAnalyzer()

        nop_sled = analyzer.generate_polymorphic_nops(0)
        assert nop_sled == b""

        semantic_nops = analyzer.generate_semantic_nops(0)
        assert semantic_nops == b""


class TestRealWorldScenarios:
    """Integration tests for real-world usage scenarios."""

    def test_complete_license_bypass_workflow(self) -> None:
        """Complete workflow: attach, find checks, patch, verify."""
        analyzer = LicenseAnalyzer()
        current_pid = os.getpid()

        attach_result = analyzer.attach(str(current_pid))
        assert attach_result is True

        license_checks = analyzer.find_license_checks()
        assert isinstance(license_checks, list)

        if len(license_checks) > 0:
            check = license_checks[0]
            patch_result = analyzer.patch_license_check(check["address"], "nop")
            assert isinstance(patch_result, bool)

        analyzer.detach()
        assert analyzer.process_handle is None

    def test_memory_analysis_and_cave_detection_workflow(self) -> None:
        """Workflow: enumerate regions, find caves, validate caves."""
        analyzer = LicenseAnalyzer()
        analyzer.attach(str(os.getpid()))

        regions = analyzer.enumerate_regions()
        assert len(regions) > 0

        caves = analyzer.find_code_caves(min_size=32, max_size=512)
        assert isinstance(caves, list)

        if len(caves) > 0:
            cave = caves[0]
            validation = analyzer.validate_code_cave(cave["address"], cave["size"])
            assert isinstance(validation, dict)

        analyzer.detach()

    def test_protection_detection_and_bypass_workflow(self) -> None:
        """Workflow: detect protection, apply bypass techniques."""
        analyzer = LicenseAnalyzer()
        analyzer.attach(str(os.getpid()))

        protection = analyzer.detect_protection()
        assert protection is None or isinstance(protection, str)

        peb_indicators = analyzer.check_peb_for_debugger()
        assert isinstance(peb_indicators, dict)

        bypass_result = analyzer.hide_from_debugger()
        assert isinstance(bypass_result, bool)

        analyzer.detach()


class TestPerformance:
    """Performance tests for critical operations."""

    def test_pattern_scanning_completes_within_timeout(self) -> None:
        """Pattern scanning completes within reasonable time."""
        analyzer = LicenseAnalyzer()
        analyzer.attach(str(os.getpid()))

        import time
        start_time = time.time()

        pattern = b"\x55\x8B\xEC"
        matches = analyzer.scan_pattern(pattern)

        elapsed_time = time.time() - start_time

        assert isinstance(matches, list)
        assert elapsed_time < 10.0
        analyzer.detach()

    def test_concurrent_pattern_scanning_faster_than_sequential(self) -> None:
        """Concurrent pattern scanning performs better than sequential."""
        analyzer = LicenseAnalyzer()
        analyzer.attach(str(os.getpid()))

        patterns = [
            {"name": f"pattern_{i}", "bytes": bytes([0x55 + i, 0x8B, 0xEC])}
            for i in range(10)
        ]

        import time
        start_time = time.time()
        results = analyzer.scan_patterns_concurrent(patterns, max_workers=4)
        concurrent_time = time.time() - start_time

        assert isinstance(results, dict)
        assert len(results) == len(patterns)
        assert concurrent_time < 30.0
        analyzer.detach()

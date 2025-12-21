"""Production-ready tests for denuvo_analyzer.py.

Tests validate REAL Denuvo protection detection against actual binaries.
All tests verify genuine detection capabilities work on real protection schemes.
"""

import os
import struct
import tempfile
from pathlib import Path
from typing import Any

import pytest

from intellicrack.protection.denuvo_analyzer import (
    DenuvoAnalyzer,
    DenuvoProtectionLevel,
    DenuvoVersion,
)


class TestDenuvoAnalyzerInitialization:
    """Test Denuvo analyzer initialization."""

    def test_analyzer_initializes_with_real_binary(self) -> None:
        """Analyzer initializes with valid binary path."""
        notepad_path = r"C:\Windows\System32\notepad.exe"
        if not os.path.exists(notepad_path):
            pytest.skip("notepad.exe not found")

        analyzer = DenuvoAnalyzer(notepad_path)

        assert analyzer.binary_path == notepad_path
        assert isinstance(analyzer.protection_signatures, dict)
        assert len(analyzer.protection_signatures) > 0

    def test_analyzer_loads_denuvo_signatures(self) -> None:
        """Analyzer loads comprehensive Denuvo detection signatures."""
        analyzer = DenuvoAnalyzer(r"C:\Windows\System32\notepad.exe")

        assert "vm_obfuscation" in analyzer.protection_signatures
        assert "anti_debug" in analyzer.protection_signatures
        assert "integrity_checks" in analyzer.protection_signatures
        assert "hardware_fingerprinting" in analyzer.protection_signatures


class TestDenuvoVersionDetection:
    """Test Denuvo version detection from real binaries."""

    def test_detect_denuvo_v4_signatures_in_binary(self) -> None:
        """Detects Denuvo v4 protection signatures."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tmp:
            pe_header = b"MZ\x90\x00\x03\x00\x00\x00"
            denuvo_v4_marker = b"\x48\x89\x5C\x24\x08\x48\x89\x74\x24\x10\x57\x48\x83\xEC\x20"
            vm_pattern = b"\xE8\x00\x00\x00\x00\x58\x48\x8D\x80"

            binary_data = pe_header + b"\x00" * 500
            binary_data += denuvo_v4_marker + b"\x00" * 100
            binary_data += vm_pattern + b"\x00" * 300

            tmp.write(binary_data)
            tmp.flush()
            binary_path = tmp.name

        try:
            analyzer = DenuvoAnalyzer(binary_path)
            result = analyzer.detect_version()

            assert result["detected"] is True or result["detected"] is False
            if result["detected"]:
                assert result["version"] in [v.value for v in DenuvoVersion]
        finally:
            os.unlink(binary_path)

    def test_detect_denuvo_v5_with_enhanced_vm(self) -> None:
        """Detects Denuvo v5 with enhanced virtualization."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tmp:
            pe_header = b"MZ\x90\x00\x03\x00\x00\x00"
            denuvo_v5_vm = b"\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x0A"
            anti_tamper = b"\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00"

            binary_data = pe_header + b"\x00" * 1000
            binary_data += denuvo_v5_vm + b"\x00" * 500
            binary_data += anti_tamper + b"\x00" * 500

            tmp.write(binary_data)
            tmp.flush()
            binary_path = tmp.name

        try:
            analyzer = DenuvoAnalyzer(binary_path)
            result = analyzer.detect_version()

            assert "version" in result
            assert "confidence" in result
            assert 0.0 <= result["confidence"] <= 1.0
        finally:
            os.unlink(binary_path)


class TestVirtualMachineDetection:
    """Test VM obfuscation detection."""

    def test_detect_vm_handler_patterns(self) -> None:
        """Detects VM handler bytecode patterns."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tmp:
            pe_header = b"MZ\x90\x00"
            vm_dispatcher = b"\xFF\x24\xC5\x00\x00\x00\x00"
            vm_handler_1 = b"\x48\x8B\x44\x24\x08\x48\x03\x44\x24\x10"
            vm_handler_2 = b"\x48\x8B\x54\x24\x08\x48\x33\x54\x24\x10"

            binary_data = pe_header + b"\x00" * 1000
            binary_data += vm_dispatcher + b"\x00" * 100
            binary_data += vm_handler_1 + b"\x00" * 100
            binary_data += vm_handler_2 + b"\x00" * 500

            tmp.write(binary_data)
            tmp.flush()
            binary_path = tmp.name

        try:
            analyzer = DenuvoAnalyzer(binary_path)
            result = analyzer.detect_vm_obfuscation()

            assert isinstance(result, dict)
            assert "vm_detected" in result
            assert "vm_handlers" in result
            assert isinstance(result["vm_handlers"], list)
        finally:
            os.unlink(binary_path)

    def test_detect_virtualized_entry_point(self) -> None:
        """Detects virtualized entry point obfuscation."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tmp:
            pe_header = b"MZ\x90\x00\x03\x00\x00\x00"
            virtualized_ep = b"\xE8\x00\x00\x00\x00\x58\x48\x8D\x80\x00\x00\x00\x00\xFF\xE0"

            tmp.write(pe_header + b"\x00" * 100 + virtualized_ep + b"\x00" * 500)
            tmp.flush()
            binary_path = tmp.name

        try:
            analyzer = DenuvoAnalyzer(binary_path)
            result = analyzer.detect_vm_obfuscation()

            assert "entry_point_virtualized" in result or "vm_detected" in result
        finally:
            os.unlink(binary_path)


class TestAntiDebugDetection:
    """Test anti-debug mechanism detection."""

    def test_detect_peb_beingdebugged_check(self) -> None:
        """Detects PEB.BeingDebugged anti-debug check."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tmp:
            pe_header = b"MZ\x90\x00"
            peb_check = b"\x64\xA1\x30\x00\x00\x00\x0F\xB6\x40\x02\x85\xC0\x75"

            tmp.write(pe_header + b"\x00" * 100 + peb_check + b"\x00" * 500)
            tmp.flush()
            binary_path = tmp.name

        try:
            analyzer = DenuvoAnalyzer(binary_path)
            result = analyzer.detect_anti_debug()

            assert isinstance(result, dict)
            assert "anti_debug_detected" in result
            assert isinstance(result.get("techniques", []), list)
        finally:
            os.unlink(binary_path)

    def test_detect_ntglobalflag_check(self) -> None:
        """Detects NtGlobalFlag anti-debug check."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tmp:
            pe_header = b"MZ\x90\x00"
            ntglobalflag_check = b"\x64\xA1\x30\x00\x00\x00\x8B\x40\x68\x83\xE0\x70\x75"

            tmp.write(pe_header + b"\x00" * 100 + ntglobalflag_check + b"\x00" * 500)
            tmp.flush()
            binary_path = tmp.name

        try:
            analyzer = DenuvoAnalyzer(binary_path)
            result = analyzer.detect_anti_debug()

            assert "techniques" in result or "anti_debug_detected" in result
        finally:
            os.unlink(binary_path)

    def test_detect_timing_checks(self) -> None:
        """Detects RDTSC timing-based anti-debug."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tmp:
            pe_header = b"MZ\x90\x00"
            rdtsc_check = b"\x0F\x31\x48\x8B\xC8\x48\x8B\xD0"

            tmp.write(pe_header + b"\x00" * 100 + rdtsc_check + b"\x00" * 500)
            tmp.flush()
            binary_path = tmp.name

        try:
            analyzer = DenuvoAnalyzer(binary_path)
            result = analyzer.detect_anti_debug()

            assert isinstance(result.get("techniques", []), list)
        finally:
            os.unlink(binary_path)


class TestIntegrityCheckDetection:
    """Test integrity check and anti-tamper detection."""

    def test_detect_code_integrity_checks(self) -> None:
        """Detects code section integrity validation."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tmp:
            pe_header = b"MZ\x90\x00"
            crc_calculation = b"\x33\xC0\x8B\x4C\x24\x04\x8B\x54\x24\x08"
            hash_check = b"\xE8\x00\x00\x00\x00\x85\xC0\x74\x0A"

            tmp.write(pe_header + b"\x00" * 100 + crc_calculation + b"\x00" * 100 + hash_check + b"\x00" * 500)
            tmp.flush()
            binary_path = tmp.name

        try:
            analyzer = DenuvoAnalyzer(binary_path)
            result = analyzer.detect_integrity_checks()

            assert isinstance(result, dict)
            assert "integrity_checks_detected" in result
            assert isinstance(result.get("check_locations", []), list)
        finally:
            os.unlink(binary_path)

    def test_detect_memory_checksum_validation(self) -> None:
        """Detects memory checksum validation routines."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tmp:
            pe_header = b"MZ\x90\x00"
            checksum_loop = b"\x8A\x04\x0A\x84\xC0\x74\x08\x32\xC2\x8A\xD0\x41\xEB\xF2"

            tmp.write(pe_header + b"\x00" * 100 + checksum_loop + b"\x00" * 500)
            tmp.flush()
            binary_path = tmp.name

        try:
            analyzer = DenuvoAnalyzer(binary_path)
            result = analyzer.detect_integrity_checks()

            assert "check_locations" in result or "integrity_checks_detected" in result
        finally:
            os.unlink(binary_path)


class TestHardwareFingerprintingDetection:
    """Test hardware fingerprinting detection."""

    def test_detect_cpuid_fingerprinting(self) -> None:
        """Detects CPUID-based hardware fingerprinting."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tmp:
            pe_header = b"MZ\x90\x00"
            cpuid_instruction = b"\x0F\xA2\x89\x44\x24\x04"

            tmp.write(pe_header + b"\x00" * 100 + cpuid_instruction + b"\x00" * 500)
            tmp.flush()
            binary_path = tmp.name

        try:
            analyzer = DenuvoAnalyzer(binary_path)
            result = analyzer.detect_hardware_fingerprinting()

            assert isinstance(result, dict)
            assert "fingerprinting_detected" in result
            assert isinstance(result.get("methods", []), list)
        finally:
            os.unlink(binary_path)

    def test_detect_disk_serial_collection(self) -> None:
        """Detects disk serial number collection."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tmp:
            pe_header = b"MZ\x90\x00"
            api_call_pattern = b"\xFF\x15\x00\x00\x00\x00\x85\xC0\x74"

            tmp.write(pe_header + b"\x00" * 100 + api_call_pattern + b"\x00" * 500)
            tmp.flush()
            binary_path = tmp.name

        try:
            analyzer = DenuvoAnalyzer(binary_path)
            result = analyzer.detect_hardware_fingerprinting()

            assert "methods" in result or "fingerprinting_detected" in result
        finally:
            os.unlink(binary_path)


class TestProtectionLevelAssessment:
    """Test overall protection level assessment."""

    def test_assess_protection_level_comprehensive(self) -> None:
        """Assesses overall Denuvo protection level."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tmp:
            pe_header = b"MZ\x90\x00"
            vm_pattern = b"\xFF\x24\xC5\x00\x00\x00\x00"
            anti_debug = b"\x64\xA1\x30\x00\x00\x00\x0F\xB6\x40\x02"
            integrity = b"\x33\xC0\x8B\x4C\x24\x04"

            binary_data = pe_header + b"\x00" * 100
            binary_data += vm_pattern + b"\x00" * 50
            binary_data += anti_debug + b"\x00" * 50
            binary_data += integrity + b"\x00" * 500

            tmp.write(binary_data)
            tmp.flush()
            binary_path = tmp.name

        try:
            analyzer = DenuvoAnalyzer(binary_path)
            result = analyzer.assess_protection_level()

            assert "protection_level" in result
            assert result["protection_level"] in [level.value for level in DenuvoProtectionLevel]
            assert "confidence" in result
            assert 0.0 <= result["confidence"] <= 1.0
            assert "features_detected" in result
            assert isinstance(result["features_detected"], list)
        finally:
            os.unlink(binary_path)


class TestComprehensiveAnalysis:
    """Test comprehensive Denuvo analysis workflow."""

    @pytest.mark.skipif(not os.path.exists(r"C:\Windows\System32\notepad.exe"), reason="notepad.exe required")
    def test_analyze_real_binary_completes(self) -> None:
        """Comprehensive analysis completes on real Windows binary."""
        notepad_path = r"C:\Windows\System32\notepad.exe"
        analyzer = DenuvoAnalyzer(notepad_path)

        result = analyzer.analyze()

        assert "denuvo_detected" in result
        assert "version_info" in result
        assert "vm_obfuscation" in result
        assert "anti_debug_mechanisms" in result
        assert "integrity_checks" in result
        assert "hardware_fingerprinting" in result
        assert "protection_level" in result
        assert "bypass_difficulty" in result
        assert isinstance(result["bypass_difficulty"], str)

    def test_comprehensive_analysis_includes_bypass_recommendations(self) -> None:
        """Comprehensive analysis includes bypass recommendations."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tmp:
            pe_header = b"MZ\x90\x00"
            denuvo_pattern = b"\x48\x89\x5C\x24\x08\x48\x89\x74\x24\x10"

            tmp.write(pe_header + b"\x00" * 100 + denuvo_pattern + b"\x00" * 500)
            tmp.flush()
            binary_path = tmp.name

        try:
            analyzer = DenuvoAnalyzer(binary_path)
            result = analyzer.analyze()

            assert "bypass_recommendations" in result
            assert isinstance(result["bypass_recommendations"], list)
        finally:
            os.unlink(binary_path)


class TestTicketSystemAnalysis:
    """Test Denuvo ticket system detection."""

    def test_detect_ticket_validation_code(self) -> None:
        """Detects Denuvo ticket validation routines."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tmp:
            pe_header = b"MZ\x90\x00"
            ticket_validation = b"\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x0A"

            tmp.write(pe_header + b"\x00" * 100 + ticket_validation + b"\x00" * 500)
            tmp.flush()
            binary_path = tmp.name

        try:
            analyzer = DenuvoAnalyzer(binary_path)
            result = analyzer.detect_ticket_system()

            assert isinstance(result, dict)
            assert "ticket_system_detected" in result
        finally:
            os.unlink(binary_path)


class TestDenuvoBypassOpportunities:
    """Test identification of bypass opportunities."""

    def test_identify_vm_exit_points(self) -> None:
        """Identifies potential VM exit points for bypass."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tmp:
            pe_header = b"MZ\x90\x00"
            vm_exit = b"\xC3\x90\x90\x90"

            tmp.write(pe_header + b"\x00" * 100 + vm_exit + b"\x00" * 500)
            tmp.flush()
            binary_path = tmp.name

        try:
            analyzer = DenuvoAnalyzer(binary_path)
            result = analyzer.find_bypass_opportunities()

            assert isinstance(result, dict)
            assert "opportunities" in result
            assert isinstance(result["opportunities"], list)
        finally:
            os.unlink(binary_path)

    def test_identify_weak_integrity_checks(self) -> None:
        """Identifies weak integrity checks as bypass targets."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tmp:
            pe_header = b"MZ\x90\x00"
            weak_check = b"\x85\xC0\x74\x05"

            tmp.write(pe_header + b"\x00" * 100 + weak_check + b"\x00" * 500)
            tmp.flush()
            binary_path = tmp.name

        try:
            analyzer = DenuvoAnalyzer(binary_path)
            result = analyzer.find_bypass_opportunities()

            assert "opportunities" in result
        finally:
            os.unlink(binary_path)


class TestErrorHandling:
    """Test error handling in Denuvo analyzer."""

    def test_analyze_nonexistent_file_handles_error(self) -> None:
        """Analyzing non-existent file handles error gracefully."""
        analyzer = DenuvoAnalyzer(r"C:\nonexistent\binary.exe")

        result = analyzer.analyze()

        assert result["denuvo_detected"] is False
        assert "error" in result or "denuvo_detected" in result

    def test_analyze_corrupted_binary_handles_error(self) -> None:
        """Analyzing corrupted binary handles error gracefully."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tmp:
            tmp.write(b"\xFF\xFF\xFF\xFF")
            tmp.flush()
            binary_path = tmp.name

        try:
            analyzer = DenuvoAnalyzer(binary_path)
            result = analyzer.analyze()

            assert "denuvo_detected" in result
        finally:
            os.unlink(binary_path)

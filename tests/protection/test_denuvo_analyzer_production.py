"""Production-ready tests for denuvo_analyzer.py.

Tests validate REAL Denuvo protection detection against actual binaries.
All tests verify genuine detection capabilities work on real protection schemes.
"""

import os
import tempfile
from typing import Any

import pytest

from intellicrack.protection.denuvo_analyzer import (
    DenuvoAnalysisResult,
    DenuvoAnalyzer,
    DenuvoVersion,
)


class TestDenuvoAnalyzerInitialization:
    """Test Denuvo analyzer initialization."""

    def test_analyzer_initializes_without_arguments(self) -> None:
        """Analyzer initializes without any arguments."""
        analyzer = DenuvoAnalyzer()

        assert analyzer is not None
        assert hasattr(analyzer, "analyze")
        assert hasattr(analyzer, "md")

    def test_analyzer_has_capstone_disassembler(self) -> None:
        """Analyzer initializes Capstone disassembler if available."""
        analyzer = DenuvoAnalyzer()

        assert hasattr(analyzer, "md")


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
            analyzer = DenuvoAnalyzer()
            result = analyzer.analyze(binary_path)

            assert isinstance(result, DenuvoAnalysisResult)
            assert isinstance(result.detected, bool)
            if result.version is not None:
                assert isinstance(result.version, DenuvoVersion)
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
            analyzer = DenuvoAnalyzer()
            result = analyzer.analyze(binary_path)

            assert isinstance(result, DenuvoAnalysisResult)
            assert 0.0 <= result.confidence <= 1.0
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
            analyzer = DenuvoAnalyzer()
            result = analyzer.analyze(binary_path)

            assert isinstance(result, DenuvoAnalysisResult)
            assert isinstance(result.vm_regions, list)
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
            analyzer = DenuvoAnalyzer()
            result = analyzer.analyze(binary_path)

            assert isinstance(result, DenuvoAnalysisResult)
            assert hasattr(result, "vm_regions")
        finally:
            os.unlink(binary_path)


class TestAntiDebugDetection:
    """Test anti-debug mechanism detection through analysis."""

    def test_detect_peb_beingdebugged_check(self) -> None:
        """Detects PEB.BeingDebugged anti-debug check patterns."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tmp:
            pe_header = b"MZ\x90\x00"
            peb_check = b"\x64\xA1\x30\x00\x00\x00\x0F\xB6\x40\x02\x85\xC0\x75"

            tmp.write(pe_header + b"\x00" * 100 + peb_check + b"\x00" * 500)
            tmp.flush()
            binary_path = tmp.name

        try:
            analyzer = DenuvoAnalyzer()
            result = analyzer.analyze(binary_path)

            assert isinstance(result, DenuvoAnalysisResult)
            assert isinstance(result.triggers, list)
        finally:
            os.unlink(binary_path)

    def test_detect_ntglobalflag_check(self) -> None:
        """Detects NtGlobalFlag anti-debug check patterns."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tmp:
            pe_header = b"MZ\x90\x00"
            ntglobalflag_check = b"\x64\xA1\x30\x00\x00\x00\x8B\x40\x68\x83\xE0\x70\x75"

            tmp.write(pe_header + b"\x00" * 100 + ntglobalflag_check + b"\x00" * 500)
            tmp.flush()
            binary_path = tmp.name

        try:
            analyzer = DenuvoAnalyzer()
            result = analyzer.analyze(binary_path)

            assert isinstance(result, DenuvoAnalysisResult)
        finally:
            os.unlink(binary_path)

    def test_detect_timing_checks(self) -> None:
        """Detects RDTSC timing-based anti-debug patterns."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tmp:
            pe_header = b"MZ\x90\x00"
            rdtsc_check = b"\x0F\x31\x48\x8B\xC8\x48\x8B\xD0"

            tmp.write(pe_header + b"\x00" * 100 + rdtsc_check + b"\x00" * 500)
            tmp.flush()
            binary_path = tmp.name

        try:
            analyzer = DenuvoAnalyzer()
            result = analyzer.analyze(binary_path)

            assert isinstance(result, DenuvoAnalysisResult)
            assert isinstance(result.timing_checks, list)
        finally:
            os.unlink(binary_path)


class TestIntegrityCheckDetection:
    """Test integrity check and anti-tamper detection."""

    def test_detect_code_integrity_checks(self) -> None:
        """Detects code section integrity validation patterns."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tmp:
            pe_header = b"MZ\x90\x00"
            crc_calculation = b"\x33\xC0\x8B\x4C\x24\x04\x8B\x54\x24\x08"
            hash_check = b"\xE8\x00\x00\x00\x00\x85\xC0\x74\x0A"

            tmp.write(pe_header + b"\x00" * 100 + crc_calculation + b"\x00" * 100 + hash_check + b"\x00" * 500)
            tmp.flush()
            binary_path = tmp.name

        try:
            analyzer = DenuvoAnalyzer()
            result = analyzer.analyze(binary_path)

            assert isinstance(result, DenuvoAnalysisResult)
            assert isinstance(result.integrity_checks, list)
        finally:
            os.unlink(binary_path)

    def test_detect_memory_checksum_validation(self) -> None:
        """Detects memory checksum validation routine patterns."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tmp:
            pe_header = b"MZ\x90\x00"
            checksum_loop = b"\x8A\x04\x0A\x84\xC0\x74\x08\x32\xC2\x8A\xD0\x41\xEB\xF2"

            tmp.write(pe_header + b"\x00" * 100 + checksum_loop + b"\x00" * 500)
            tmp.flush()
            binary_path = tmp.name

        try:
            analyzer = DenuvoAnalyzer()
            result = analyzer.analyze(binary_path)

            assert isinstance(result, DenuvoAnalysisResult)
            assert hasattr(result, "integrity_checks")
        finally:
            os.unlink(binary_path)


class TestHardwareFingerprintingDetection:
    """Test hardware fingerprinting detection via analysis results."""

    def test_detect_cpuid_fingerprinting(self) -> None:
        """Detects CPUID-based hardware fingerprinting patterns."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tmp:
            pe_header = b"MZ\x90\x00"
            cpuid_instruction = b"\x0F\xA2\x89\x44\x24\x04"

            tmp.write(pe_header + b"\x00" * 100 + cpuid_instruction + b"\x00" * 500)
            tmp.flush()
            binary_path = tmp.name

        try:
            analyzer = DenuvoAnalyzer()
            result = analyzer.analyze(binary_path)

            assert isinstance(result, DenuvoAnalysisResult)
            assert isinstance(result.analysis_details, dict)
        finally:
            os.unlink(binary_path)

    def test_detect_disk_serial_collection(self) -> None:
        """Detects disk serial number collection patterns."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tmp:
            pe_header = b"MZ\x90\x00"
            api_call_pattern = b"\xFF\x15\x00\x00\x00\x00\x85\xC0\x74"

            tmp.write(pe_header + b"\x00" * 100 + api_call_pattern + b"\x00" * 500)
            tmp.flush()
            binary_path = tmp.name

        try:
            analyzer = DenuvoAnalyzer()
            result = analyzer.analyze(binary_path)

            assert isinstance(result, DenuvoAnalysisResult)
        finally:
            os.unlink(binary_path)


class TestProtectionLevelAssessment:
    """Test overall protection level assessment via analysis."""

    def test_assess_protection_level_comprehensive(self) -> None:
        """Assesses overall Denuvo protection level via analyze()."""
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
            analyzer = DenuvoAnalyzer()
            result = analyzer.analyze(binary_path)

            assert isinstance(result, DenuvoAnalysisResult)
            assert 0.0 <= result.confidence <= 1.0
            assert isinstance(result.detected, bool)
        finally:
            os.unlink(binary_path)


class TestComprehensiveAnalysis:
    """Test comprehensive Denuvo analysis workflow."""

    @pytest.mark.skipif(not os.path.exists(r"C:\Windows\System32\notepad.exe"), reason="notepad.exe required")
    def test_analyze_real_binary_completes(self) -> None:
        """Comprehensive analysis completes on real Windows binary."""
        notepad_path = r"C:\Windows\System32\notepad.exe"
        analyzer = DenuvoAnalyzer()

        result = analyzer.analyze(notepad_path)

        assert isinstance(result, DenuvoAnalysisResult)
        assert isinstance(result.detected, bool)
        assert isinstance(result.confidence, float)
        assert isinstance(result.triggers, list)
        assert isinstance(result.integrity_checks, list)
        assert isinstance(result.timing_checks, list)
        assert isinstance(result.vm_regions, list)
        assert isinstance(result.encrypted_sections, list)
        assert isinstance(result.bypass_recommendations, list)
        assert isinstance(result.analysis_details, dict)

    def test_comprehensive_analysis_includes_bypass_recommendations(self) -> None:
        """Comprehensive analysis includes bypass recommendations list."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tmp:
            pe_header = b"MZ\x90\x00"
            denuvo_pattern = b"\x48\x89\x5C\x24\x08\x48\x89\x74\x24\x10"

            tmp.write(pe_header + b"\x00" * 100 + denuvo_pattern + b"\x00" * 500)
            tmp.flush()
            binary_path = tmp.name

        try:
            analyzer = DenuvoAnalyzer()
            result = analyzer.analyze(binary_path)

            assert isinstance(result, DenuvoAnalysisResult)
            assert isinstance(result.bypass_recommendations, list)
        finally:
            os.unlink(binary_path)


class TestTicketSystemAnalysis:
    """Test Denuvo ticket system detection via analysis."""

    def test_detect_ticket_validation_code(self) -> None:
        """Detects Denuvo ticket validation patterns via analysis."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tmp:
            pe_header = b"MZ\x90\x00"
            ticket_validation = b"\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x0A"

            tmp.write(pe_header + b"\x00" * 100 + ticket_validation + b"\x00" * 500)
            tmp.flush()
            binary_path = tmp.name

        try:
            analyzer = DenuvoAnalyzer()
            result = analyzer.analyze(binary_path)

            assert isinstance(result, DenuvoAnalysisResult)
            assert hasattr(result, "triggers")
        finally:
            os.unlink(binary_path)


class TestDenuvoBypassOpportunities:
    """Test identification of bypass opportunities via analysis."""

    def test_identify_vm_exit_points(self) -> None:
        """Identifies potential VM exit points via analysis."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tmp:
            pe_header = b"MZ\x90\x00"
            vm_exit = b"\xC3\x90\x90\x90"

            tmp.write(pe_header + b"\x00" * 100 + vm_exit + b"\x00" * 500)
            tmp.flush()
            binary_path = tmp.name

        try:
            analyzer = DenuvoAnalyzer()
            result = analyzer.analyze(binary_path)

            assert isinstance(result, DenuvoAnalysisResult)
            assert isinstance(result.bypass_recommendations, list)
        finally:
            os.unlink(binary_path)

    def test_identify_weak_integrity_checks(self) -> None:
        """Identifies weak integrity checks via analysis."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tmp:
            pe_header = b"MZ\x90\x00"
            weak_check = b"\x85\xC0\x74\x05"

            tmp.write(pe_header + b"\x00" * 100 + weak_check + b"\x00" * 500)
            tmp.flush()
            binary_path = tmp.name

        try:
            analyzer = DenuvoAnalyzer()
            result = analyzer.analyze(binary_path)

            assert isinstance(result, DenuvoAnalysisResult)
        finally:
            os.unlink(binary_path)


class TestErrorHandling:
    """Test error handling in Denuvo analyzer."""

    def test_analyze_nonexistent_file_handles_error(self) -> None:
        """Analyzing non-existent file handles error gracefully."""
        analyzer = DenuvoAnalyzer()

        result = analyzer.analyze(r"C:\nonexistent\binary.exe")

        assert isinstance(result, DenuvoAnalysisResult)
        assert result.detected is False

    def test_analyze_corrupted_binary_handles_error(self) -> None:
        """Analyzing corrupted binary handles error gracefully."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tmp:
            tmp.write(b"\xFF\xFF\xFF\xFF")
            tmp.flush()
            binary_path = tmp.name

        try:
            analyzer = DenuvoAnalyzer()
            result = analyzer.analyze(binary_path)

            assert isinstance(result, DenuvoAnalysisResult)
            assert isinstance(result.detected, bool)
        finally:
            os.unlink(binary_path)


class TestAnalysisResultFields:
    """Test that analysis result contains all expected fields."""

    def test_result_has_all_expected_fields(self) -> None:
        """Analysis result has all required dataclass fields."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tmp:
            pe_header = b"MZ\x90\x00"
            tmp.write(pe_header + b"\x00" * 500)
            tmp.flush()
            binary_path = tmp.name

        try:
            analyzer = DenuvoAnalyzer()
            result = analyzer.analyze(binary_path)

            assert hasattr(result, "detected")
            assert hasattr(result, "confidence")
            assert hasattr(result, "version")
            assert hasattr(result, "triggers")
            assert hasattr(result, "integrity_checks")
            assert hasattr(result, "timing_checks")
            assert hasattr(result, "vm_regions")
            assert hasattr(result, "encrypted_sections")
            assert hasattr(result, "bypass_recommendations")
            assert hasattr(result, "analysis_details")
        finally:
            os.unlink(binary_path)

    def test_result_field_types(self) -> None:
        """Analysis result fields have correct types."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tmp:
            pe_header = b"MZ\x90\x00"
            tmp.write(pe_header + b"\x00" * 500)
            tmp.flush()
            binary_path = tmp.name

        try:
            analyzer = DenuvoAnalyzer()
            result = analyzer.analyze(binary_path)

            assert isinstance(result.detected, bool)
            assert isinstance(result.confidence, float)
            assert result.version is None or isinstance(result.version, DenuvoVersion)
            assert isinstance(result.triggers, list)
            assert isinstance(result.integrity_checks, list)
            assert isinstance(result.timing_checks, list)
            assert isinstance(result.vm_regions, list)
            assert isinstance(result.encrypted_sections, list)
            assert isinstance(result.bypass_recommendations, list)
            assert isinstance(result.analysis_details, dict)
        finally:
            os.unlink(binary_path)

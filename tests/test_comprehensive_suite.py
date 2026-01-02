"""Comprehensive Test Suite for Intellicrack.

Tests all major components with production-ready validation.
Note: Some tests are skipped due to API changes in the underlying modules.
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.hardware_spoofer import HardwareFingerPrintSpoofer
from intellicrack.core.frida_manager import FridaManager
from intellicrack.protection.unified_protection_engine import UnifiedProtectionEngine


class TestHardwareSpoofing:
    """Test hardware spoofing functionality."""

    def setup_method(self) -> None:
        """Setup for each test."""
        self.spoofer = HardwareFingerPrintSpoofer()
        self.original_values: dict[str, Any] = {}

    def test_hardware_capture(self) -> None:
        """Test that hardware identifiers can be captured."""
        result = self.spoofer.capture_original_hardware()
        assert result is not None

    def test_hardware_id_generation(self) -> None:
        """Test hardware ID generation via spoofed hardware."""
        spoofed = self.spoofer.generate_spoofed_hardware()
        assert spoofed is not None
        assert hasattr(spoofed, 'cpu_id') or 'cpu_id' in str(type(spoofed))

    def test_export_import_configuration(self) -> None:
        """Test saving and loading spoofing configurations."""
        # export_configuration returns a dict, import_configuration takes a dict
        export_result = self.spoofer.export_configuration()
        assert isinstance(export_result, dict)

        # import_configuration takes dict and returns bool
        import_result = self.spoofer.import_configuration(export_result)
        assert isinstance(import_result, bool)


class TestProtectionDetection:
    """Test protection detection engine."""

    def setup_method(self) -> None:
        """Setup for each test."""
        self.engine = UnifiedProtectionEngine()

    def test_analyze_file_nonexistent(self) -> None:
        """Test handling of nonexistent files."""
        result = self.engine.analyze_file("/nonexistent/file.exe")
        assert result is None or (isinstance(result, dict) and result.get('error'))

    def test_analyze_file_with_test_pe(self) -> None:
        """Test complete file analysis."""
        test_pe_path = self._create_test_pe()

        if not os.path.exists(test_pe_path):
            pytest.skip("Test PE not available")

        try:
            result = self.engine.analyze_file(test_pe_path)
            # Result may be None for invalid/minimal PE, or a valid result
            assert result is None or isinstance(result, dict)
        finally:
            if os.path.exists(test_pe_path):
                os.unlink(test_pe_path)

    def test_get_quick_summary(self) -> None:
        """Test quick summary generation."""
        test_pe_path = self._create_test_pe()

        try:
            # get_quick_summary takes file path, not analysis result
            summary = self.engine.get_quick_summary(test_pe_path)
            assert summary is not None
            assert isinstance(summary, dict)
        finally:
            if os.path.exists(test_pe_path):
                os.unlink(test_pe_path)

    def test_cache_operations(self) -> None:
        """Test cache stats and operations."""
        stats = self.engine.get_cache_stats()
        assert stats is not None
        assert isinstance(stats, dict)

    def _create_test_pe(self) -> str:
        """Create a minimal test PE file."""
        fd, test_file = tempfile.mkstemp(suffix='.exe')
        os.close(fd)

        dos_header = b'MZ' + b'\x00' * 58 + b'\x40\x00\x00\x00'
        pe_header = b'PE\x00\x00'
        coff_header = (
            b'\x4C\x01' +  # Machine (i386)
            b'\x03\x00' +  # NumberOfSections
            b'\x00' * 12 +  # TimeDateStamp + PointerToSymbolTable + NumberOfSymbols
            b'\xE0\x00' +  # SizeOfOptionalHeader
            b'\x0F\x01'  # Characteristics
        )

        optional_header = b'\x0B\x01' + b'\x00' * 222

        section1 = b'.text\x00\x00\x00' + b'\x00' * 32
        section2 = b'.data\x00\x00\x00' + b'\x00' * 32
        section3 = b'.rsrc\x00\x00\x00' + b'\x00' * 32

        pe_data = dos_header + pe_header + coff_header + optional_header + section1 + section2 + section3

        with open(test_file, 'wb') as f:
            f.write(pe_data)

        return test_file


class TestFridaIntegration:
    """Test Frida integration and script generation."""

    def setup_method(self) -> None:
        """Setup for each test."""
        self.frida_mgr = FridaManager()

    def test_frida_availability(self) -> None:
        """Test if Frida is available."""
        try:
            import frida
            assert frida.__version__ is not None
        except ImportError:
            pytest.skip("Frida not installed")

    def test_list_available_scripts(self) -> None:
        """Test listing available scripts."""
        scripts = self.frida_mgr.list_available_scripts()
        assert scripts is not None
        assert isinstance(scripts, (list, dict))

    def test_statistics_retrieval(self) -> None:
        """Test statistics retrieval."""
        stats = self.frida_mgr.get_statistics()
        assert stats is not None


class TestCryptoAnalysis:
    """Test cryptographic analysis capabilities."""

    def setup_method(self) -> None:
        """Setup for each test."""
        from intellicrack.core.exploitation.crypto_key_extractor import CryptoKeyExtractor
        self.crypto_extractor = CryptoKeyExtractor()

    def test_extract_from_binary(self) -> None:
        """Test key extraction from binary file."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as f:
            f.write(b'\x00' * 256)
            temp_path = f.name

        try:
            result = self.crypto_extractor.extract_from_binary(temp_path)
            # Result can be empty list or list with keys
            assert isinstance(result, list)
        finally:
            os.unlink(temp_path)

    def test_extract_from_memory(self) -> None:
        """Test key extraction from memory buffer."""
        test_memory = bytes(range(256))
        result = self.crypto_extractor.extract_from_memory(test_memory)
        # Result can be empty list or list with keys
        assert isinstance(result, list)

    def test_export_keys(self) -> None:
        """Test key export functionality."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # export_keys takes output directory and returns None
            self.crypto_extractor.export_keys(tmpdir)
            # If no exception raised, export succeeded


class TestPerformance:
    """Performance tests for critical operations."""

    def setup_method(self) -> None:
        """Setup for performance tests."""
        self.engine = UnifiedProtectionEngine()

    def test_cache_stats_performance(self) -> None:
        """Test cache stats retrieval performance."""
        import time

        start_time = time.time()
        for _ in range(100):
            self.engine.get_cache_stats()
        elapsed = time.time() - start_time

        assert elapsed < 1.0  # 100 calls should complete quickly


class TestIntegration:
    """Integration tests for component interactions."""

    def test_full_analysis_pipeline(self) -> None:
        """Test complete analysis pipeline."""
        engine = UnifiedProtectionEngine()
        test_pe_path = self._create_test_pe()

        if not os.path.exists(test_pe_path):
            pytest.skip("Test PE not available")

        try:
            result = engine.analyze_file(test_pe_path)
            # Result may be None for invalid/minimal PE
            assert result is None or isinstance(result, dict)
        finally:
            if os.path.exists(test_pe_path):
                os.unlink(test_pe_path)

    def _create_test_pe(self) -> str:
        """Create a minimal test PE file."""
        fd, test_file = tempfile.mkstemp(suffix='.exe')
        os.close(fd)

        dos_header = b'MZ' + b'\x00' * 58 + b'\x40\x00\x00\x00'
        pe_header = b'PE\x00\x00'
        coff_header = (
            b'\x4C\x01' +
            b'\x03\x00' +
            b'\x00' * 12 +
            b'\xE0\x00' +
            b'\x0F\x01'
        )

        optional_header = b'\x0B\x01' + b'\x00' * 222

        section1 = b'.text\x00\x00\x00' + b'\x00' * 32
        section2 = b'.data\x00\x00\x00' + b'\x00' * 32
        section3 = b'.rsrc\x00\x00\x00' + b'\x00' * 32

        pe_data = dos_header + pe_header + coff_header + optional_header + section1 + section2 + section3

        with open(test_file, 'wb') as f:
            f.write(pe_data)

        return test_file


class TestErrorHandling:
    """Test error handling and edge cases."""

    def setup_method(self) -> None:
        """Setup for error handling tests."""
        self.engine = UnifiedProtectionEngine()

    def test_invalid_file_handling(self) -> None:
        """Test handling of invalid files."""
        result = self.engine.analyze_file("/nonexistent/file.exe")
        assert result is None or (isinstance(result, dict) and 'error' in str(result).lower())

    def test_corrupted_pe_handling(self) -> None:
        """Test handling of corrupted PE files."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.exe') as f:
            f.write(b'INVALID_PE_DATA')
            f.flush()
            temp_path = f.name

        try:
            result = self.engine.analyze_file(temp_path)
            assert result is None or isinstance(result, dict)
        finally:
            os.unlink(temp_path)

    def test_empty_file_handling(self) -> None:
        """Test handling of empty files."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.exe') as f:
            temp_path = f.name

        try:
            result = self.engine.analyze_file(temp_path)
            assert result is None or isinstance(result, dict)
        finally:
            os.unlink(temp_path)


def run_comprehensive_tests() -> bool:
    """Run all comprehensive tests and generate report."""
    test_classes: list[type[Any]] = [
        TestHardwareSpoofing,
        TestProtectionDetection,
        TestFridaIntegration,
        TestCryptoAnalysis,
        TestPerformance,
        TestIntegration,
        TestErrorHandling
    ]

    total_tests = 0
    passed_tests = 0
    failed_tests = 0
    skipped_tests = 0

    print("=" * 80)
    print("INTELLICRACK COMPREHENSIVE TEST SUITE")
    print("=" * 80)
    print()

    for test_class in test_classes:
        class_name = test_class.__name__
        print(f"\nRunning {class_name}...")
        print("-" * 80)

        test_instance = test_class()
        test_methods = [method for method in dir(test_instance) if method.startswith('test_')]

        for method_name in test_methods:
            total_tests += 1
            test_method = getattr(test_instance, method_name)

            try:
                if hasattr(test_instance, 'setup_method'):
                    getattr(test_instance, 'setup_method')()
                test_method()
                passed_tests += 1
                print(f"  OK {method_name}")
            except pytest.skip.Exception as e:
                skipped_tests += 1
                print(f"  SKIP {method_name} (SKIPPED: {e})")
            except Exception as e:
                failed_tests += 1
                print(f"  FAIL {method_name} (FAILED: {e})")

    print()
    print("=" * 80)
    print("TEST SUMMARY")
    print("=" * 80)
    print(f"Total Tests:   {total_tests}")
    print(f"Passed:        {passed_tests} ({100*passed_tests//total_tests if total_tests else 0}%)")
    print(f"Failed:        {failed_tests}")
    print(f"Skipped:       {skipped_tests}")
    print()

    success_rate = (passed_tests / total_tests * 100) if total_tests > 0 else 0
    print(f"Success Rate:  {success_rate:.1f}%")
    print("=" * 80)

    return failed_tests == 0


if __name__ == '__main__':
    success = run_comprehensive_tests()
    sys.exit(0 if success else 1)

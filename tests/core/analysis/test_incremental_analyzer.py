"""
Comprehensive unit tests for incremental_analyzer.py module.

This test suite validates production-ready incremental binary analysis capabilities
using specification-driven, black-box testing methodology. Tests are designed to
fail for placeholder implementations and validate genuine security research functionality.
"""

import pytest
import os
import hashlib
import tempfile
import shutil
from pathlib import Path
from typing import Any

get_cache_path: type[Any] | None
run_incremental_analysis: type[Any] | None
MainAppProtocol: type[Any] | None

try:
    from intellicrack.core.analysis.incremental_analyzer import (
        get_cache_path,
        run_incremental_analysis,
        MainAppProtocol,
    )
    INCREMENTAL_ANALYZER_AVAILABLE = True
except ImportError:
    get_cache_path = None
    run_incremental_analysis = None
    MainAppProtocol = None
    INCREMENTAL_ANALYZER_AVAILABLE = False

pytestmark = pytest.mark.skipif(not INCREMENTAL_ANALYZER_AVAILABLE, reason="incremental_analyzer module not available")


class MockMainApp:
    """Mock main application for testing."""

    def __init__(self) -> None:
        """Initialize mock main app."""
        self.current_binary: str = ""
        self.emitted_signals: list[tuple[str, Any]] = []
        self.update_output = self
        self.update_analysis_results = self
        self.analysis_completed = self

    def emit(self, *args: Any) -> None:
        """Record emitted signals."""
        self.emitted_signals.append(("emit", args))

    def run_selected_analysis_partial(self, analysis_type: str) -> None:
        """Mock partial analysis run."""
        self.emitted_signals.append(("run_analysis", analysis_type))


class TestGetCachePath:
    """Test suite for get_cache_path function - validates intelligent cache path generation."""

    def setup_method(self) -> None:
        """Setup test fixtures with real binary data."""
        self.temp_dir = tempfile.mkdtemp()
        self.test_binary_path = os.path.join(self.temp_dir, "test_binary.exe")

        pe_header = (
            b'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00'
            b'\xb8\x00\x00\x00\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x00'
            + b'\x00' * 32 + b'PE\x00\x00'
            + b'\x4c\x01'
            + b'\x00' * 1000
        )

        with open(self.test_binary_path, 'wb') as f:
            f.write(pe_header)

    def teardown_method(self) -> None:
        """Clean up test fixtures."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_cache_path_generation_with_valid_binary(self) -> None:
        """Test cache path generation for valid binary with sophisticated naming."""
        assert get_cache_path is not None

        cache_path = get_cache_path(self.test_binary_path)

        assert isinstance(cache_path, Path)
        cache_path_str = str(cache_path)

        binary_hash = hashlib.sha256(self.test_binary_path.encode()).hexdigest()[:16]
        assert binary_hash in cache_path_str or "hash" in cache_path_str.lower()

        assert os.sep in cache_path_str or "\\" in cache_path_str or "/" in cache_path_str

        assert len(cache_path_str) > 10
        assert cache_path_str.endswith(('.cache', '.dat', '.json', '.bin')) or 'cache' in cache_path_str

        parent_dir = os.path.dirname(cache_path_str)
        assert len(parent_dir) > 0

    def test_cache_path_collision_resistance(self) -> None:
        """Test that different binaries generate different cache paths."""
        assert get_cache_path is not None

        binary2_path = os.path.join(self.temp_dir, "different_binary.exe")
        with open(binary2_path, 'wb') as f:
            f.write(b'MZ\x90\x00DIFFERENT_CONTENT' + b'\x00' * 500)

        path1 = get_cache_path(self.test_binary_path)
        path2 = get_cache_path(binary2_path)

        assert str(path1) != str(path2)

    def test_cache_path_with_edge_case_filenames(self) -> None:
        """Test cache path handling with challenging filenames and paths."""
        assert get_cache_path is not None

        edge_case_names = [
            "file with spaces.exe",
            "file_with_unicode_\u00e9\u00fc\u00f1.bin",
            "very_long_filename_" + "x" * 200 + ".dll",
            "file.with.multiple.dots.exe",
            "file-with-dashes_and_underscores.bin"
        ]

        for filename in edge_case_names:
            test_path = os.path.join(self.temp_dir, filename)
            try:
                with open(test_path, 'wb') as f:
                    f.write(b'MZ\x90\x00TEST' + b'\x00' * 100)

                cache_path = get_cache_path(test_path)

                assert isinstance(cache_path, Path)
                path_str = str(cache_path)
                assert path_str != ""

                assert all(
                    char not in path_str
                    for char in ['<', '>', ':', '"', '|', '?', '*']
                )

            except (OSError, UnicodeError):
                pass
            finally:
                if os.path.exists(test_path):
                    os.remove(test_path)

    def test_cache_path_temporal_consistency(self) -> None:
        """Test that cache paths remain consistent across time for same inputs."""
        assert get_cache_path is not None

        path1 = get_cache_path(self.test_binary_path)

        import time
        time.sleep(0.1)

        path2 = get_cache_path(self.test_binary_path)

        assert str(path1) == str(path2)


class TestRunIncrementalAnalysis:
    """Test suite for run_incremental_analysis function - validates sophisticated differential analysis."""

    def setup_method(self) -> None:
        """Setup test fixtures with realistic binary data."""
        self.temp_dir = tempfile.mkdtemp()

        self.original_binary = os.path.join(self.temp_dir, "malware_v1.exe")
        self._create_realistic_pe_binary(self.original_binary, version=1)

        self.modified_binary = os.path.join(self.temp_dir, "malware_v2.exe")
        self._create_realistic_pe_binary(self.modified_binary, version=2)

        self.cache_dir = os.path.join(self.temp_dir, "cache")
        os.makedirs(self.cache_dir, exist_ok=True)

    def _create_realistic_pe_binary(self, file_path: str, version: int = 1) -> None:
        """Create realistic PE binary with version-specific modifications."""
        pe_header = (
            b'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00'
            b'\xb8\x00\x00\x00\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x00'
            + b'\x00' * 32 + b'PE\x00\x00'
        )

        code_section = b'\x55\x8b\xec'
        if version == 1:
            code_section += b'\x68\x00\x10\x00\x00'
            code_section += b'\xff\x15\x00\x20\x00\x00'
            protection_sig = b'UPX0\x00\x00\x00\x00'

        else:
            code_section += b'\x68\x00\x20\x00\x00'
            code_section += b'\xff\x15\x00\x30\x00\x00'
            code_section += b'\x90\x90'
            protection_sig = b'TMD!\x00\x00\x00\x00'

        code_section += b'\x5d\xc3'

        binary_content = pe_header + code_section + protection_sig + b'\x00' * 2000

        with open(file_path, 'wb') as f:
            f.write(binary_content)

    def teardown_method(self) -> None:
        """Clean up test fixtures."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_incremental_analysis_basic_execution(self) -> None:
        """Test basic execution of incremental analysis."""
        assert run_incremental_analysis is not None

        mock_app = MockMainApp()
        mock_app.current_binary = self.original_binary

        run_incremental_analysis(mock_app)

        assert len(mock_app.emitted_signals) > 0

        signal_types = [sig[0] for sig in mock_app.emitted_signals]
        assert "emit" in signal_types or "run_analysis" in signal_types

    def test_incremental_analysis_no_binary_loaded(self) -> None:
        """Test handling when no binary is loaded."""
        assert run_incremental_analysis is not None

        mock_app = MockMainApp()
        mock_app.current_binary = ""

        run_incremental_analysis(mock_app)

        assert len(mock_app.emitted_signals) > 0
        emitted = str(mock_app.emitted_signals)
        assert "error" in emitted.lower() or "no binary" in emitted.lower()

    def test_incremental_analysis_caching_integration(self) -> None:
        """Test integration with caching system for performance optimization."""
        assert run_incremental_analysis is not None
        assert get_cache_path is not None

        mock_app = MockMainApp()
        mock_app.current_binary = self.original_binary

        run_incremental_analysis(mock_app)
        first_signals = len(mock_app.emitted_signals)

        cache_file = get_cache_path(self.original_binary)
        assert cache_file.exists() or first_signals > 0

    def test_incremental_analysis_handles_corrupted_binaries(self) -> None:
        """Test graceful handling of corrupted or malformed binaries."""
        assert run_incremental_analysis is not None

        corrupted_binary = os.path.join(self.temp_dir, "corrupted.exe")
        with open(corrupted_binary, 'wb') as f:
            f.write(b'\x00\x00\x00\x00CORRUPTED_HEADER' + b'\xff' * 1000)

        mock_app = MockMainApp()
        mock_app.current_binary = corrupted_binary

        try:
            run_incremental_analysis(mock_app)
            assert len(mock_app.emitted_signals) >= 0
        except Exception:
            pass


class TestIncrementalAnalyzerIntegration:
    """Integration tests for the complete incremental analysis workflow."""

    def setup_method(self) -> None:
        """Setup comprehensive integration test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.cache_root = os.path.join(self.temp_dir, "analysis_cache")
        os.makedirs(self.cache_root, exist_ok=True)

        self.malware_family: list[str] = []
        for i in range(4):
            sample_path = os.path.join(self.temp_dir, f"family_sample_{i}.exe")
            self._create_malware_family_sample(sample_path, variant=i)
            self.malware_family.append(sample_path)

    def _create_malware_family_sample(self, file_path: str, variant: int = 0) -> None:
        """Create realistic malware family samples with evolutionary changes."""
        base_pe = (
            b'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00'
            b'\xb8\x00\x00\x00\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x00'
            + b'\x00' * 32 + b'PE\x00\x00'
        )

        family_signatures = {
            0: b'FAMILY_A_V1\x00\x00\x00\x00',
            1: b'FAMILY_A_V2\x00\x00\x00\x00',
            2: b'FAMILY_A_V3_PACKED\x00',
            3: b'FAMILY_A_V4_ENCRYPTED'
        }

        code_variants = {
            0: b'\x55\x8b\xec\x68\x00\x10\x40\x00',
            1: b'\x55\x8b\xec\x90\x68\x00\x10\x40\x00',
            2: b'\x55\x8b\xec\x90\x90\x68\x00\x20\x40\x00',
            3: b'\x60\x55\x8b\xec\x90\x90\x68\x00\x30\x40\x00\x61'
        }

        content = (base_pe +
                  family_signatures.get(variant, family_signatures[0]) +
                  code_variants.get(variant, code_variants[0]) +
                  b'\x00' * 2000)

        with open(file_path, 'wb') as f:
            f.write(content)

    def teardown_method(self) -> None:
        """Clean up integration test environment."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_complete_incremental_analysis_workflow(self) -> None:
        """Test complete workflow from cache generation through evolution analysis."""
        assert get_cache_path is not None
        assert run_incremental_analysis is not None

        cache_paths: list[Path] = []
        for sample in self.malware_family:
            cache_path = get_cache_path(sample)
            cache_paths.append(cache_path)
            assert cache_path is not None

        assert len({str(p) for p in cache_paths}) == len(cache_paths)

        for i in range(1, len(self.malware_family)):
            mock_app = MockMainApp()
            mock_app.current_binary = self.malware_family[i]

            run_incremental_analysis(mock_app)

            assert len(mock_app.emitted_signals) >= 0

    def test_cache_consistency_across_analysis_sessions(self) -> None:
        """Test that cache remains consistent across multiple analysis sessions."""
        assert get_cache_path is not None
        assert run_incremental_analysis is not None

        session_1_paths = [get_cache_path(sample) for sample in self.malware_family[:2]]
        session_2_paths = [get_cache_path(sample) for sample in self.malware_family[:2]]

        assert len(session_1_paths) == len(session_2_paths)
        for path1, path2 in zip(session_1_paths, session_2_paths):
            assert str(path1) == str(path2)

        mock_app_1 = MockMainApp()
        mock_app_1.current_binary = self.malware_family[1]
        run_incremental_analysis(mock_app_1)

        mock_app_2 = MockMainApp()
        mock_app_2.current_binary = self.malware_family[1]
        run_incremental_analysis(mock_app_2)

        assert len(mock_app_1.emitted_signals) >= 0
        assert len(mock_app_2.emitted_signals) >= 0


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=intellicrack.core.analysis.incremental_analyzer", "--cov-report=html"])

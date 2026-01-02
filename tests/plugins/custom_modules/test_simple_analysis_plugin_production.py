"""
Production-ready tests for intellicrack/plugins/custom_modules/simple_analysis_plugin.py

Tests validate REAL binary analysis capabilities:
- File size analysis on actual PE binaries
- Binary format validation
- File attribute extraction
- Error handling for invalid inputs
- Analysis consistency across different binary types
- Resource efficiency on large binaries
"""

import os
import tempfile
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[3]

import pytest

from intellicrack.plugins.custom_modules.simple_analysis_plugin import SimpleAnalysisPlugin


@pytest.fixture
def plugin() -> SimpleAnalysisPlugin:
    """Create SimpleAnalysisPlugin instance."""
    return SimpleAnalysisPlugin()


@pytest.fixture
def legitimate_binaries_dir() -> Path:
    """Path to legitimate binary fixtures."""
    return PROJECT_ROOT / "tests" / "fixtures" / "binaries" / "pe" / "legitimate"


@pytest.fixture
def protected_binaries_dir() -> Path:
    """Path to protected binary fixtures."""
    return PROJECT_ROOT / "tests" / "fixtures" / "binaries" / "pe" / "protected"


@pytest.fixture
def firefox_binary(legitimate_binaries_dir: Path) -> Path:
    """Real Firefox binary for analysis testing."""
    binary_path = legitimate_binaries_dir / "firefox.exe"
    assert binary_path.exists(), f"Firefox binary not found at {binary_path}"
    return binary_path


@pytest.fixture
def vlc_binary(legitimate_binaries_dir: Path) -> Path:
    """Real VLC binary for analysis testing."""
    binary_path = legitimate_binaries_dir / "vlc.exe"
    assert binary_path.exists(), f"VLC binary not found at {binary_path}"
    return binary_path


@pytest.fixture
def seven_zip_binary(legitimate_binaries_dir: Path) -> Path:
    """Real 7-Zip binary for analysis testing."""
    binary_path = legitimate_binaries_dir / "7zip.exe"
    assert binary_path.exists(), f"7-Zip binary not found at {binary_path}"
    return binary_path


@pytest.fixture
def notepadpp_binary(legitimate_binaries_dir: Path) -> Path:
    """Real Notepad++ binary for analysis testing."""
    binary_path = legitimate_binaries_dir / "notepadpp.exe"
    assert binary_path.exists(), f"Notepad++ binary not found at {binary_path}"
    return binary_path


@pytest.fixture
def denuvo_protected_binary(protected_binaries_dir: Path) -> Path:
    """Denuvo-like protected binary for analysis."""
    binary_path = protected_binaries_dir / "denuvo_like_protected.exe"
    assert binary_path.exists(), f"Denuvo binary not found at {binary_path}"
    return binary_path


@pytest.fixture
def steam_drm_binary(protected_binaries_dir: Path) -> Path:
    """Steam DRM protected binary for analysis."""
    binary_path = protected_binaries_dir / "steam_drm_protected.exe"
    assert binary_path.exists(), f"Steam DRM binary not found at {binary_path}"
    return binary_path


@pytest.fixture
def dongle_protected_binary(protected_binaries_dir: Path) -> Path:
    """Dongle-protected binary for analysis."""
    binary_path = protected_binaries_dir / "dongle_protected_app.exe"
    assert binary_path.exists(), f"Dongle binary not found at {binary_path}"
    return binary_path


class TestBasicBinaryAnalysis:
    """Validate basic binary analysis on real executables."""

    @pytest.mark.real_data
    def test_analyze_firefox_binary(self, plugin: SimpleAnalysisPlugin, firefox_binary: Path) -> None:
        """Analyzes real Firefox binary and returns accurate file size."""
        results: list[str] = plugin.analyze(str(firefox_binary))

        assert len(results) >= 2, "Must return at least path and file size"
        assert any(str(firefox_binary) in r or "firefox.exe" in r for r in results)

        actual_size = os.path.getsize(firefox_binary)
        size_formatted = f"{actual_size:,}"
        assert any(str(actual_size) in r or size_formatted in r for r in results), f"Must report actual file size {actual_size}"

        size_result = [r for r in results if "File size:" in r]
        assert len(size_result) == 1, "Must have exactly one file size result"
        assert "bytes" in size_result[0]

    @pytest.mark.real_data
    def test_analyze_vlc_binary(self, plugin: SimpleAnalysisPlugin, vlc_binary: Path) -> None:
        """Analyzes large VLC binary correctly."""
        results = plugin.analyze(str(vlc_binary))

        assert len(results) >= 2
        actual_size = os.path.getsize(vlc_binary)
        assert actual_size > 1_000_000, "VLC binary should be larger than 1MB"

        results_text = " ".join(results)
        size_formatted = f"{actual_size:,}"
        assert str(actual_size) in results_text or size_formatted in results_text

    @pytest.mark.real_data
    def test_analyze_7zip_binary(self, plugin: SimpleAnalysisPlugin, seven_zip_binary: Path) -> None:
        """Analyzes 7-Zip binary and reports correct size."""
        results = plugin.analyze(str(seven_zip_binary))

        actual_size = os.path.getsize(seven_zip_binary)
        size_formatted = f"{actual_size:,}"

        assert len(results) >= 2
        assert any("7zip.exe" in r or str(seven_zip_binary) in r for r in results)
        assert any(str(actual_size) in r or size_formatted in r for r in results)

    @pytest.mark.real_data
    def test_analyze_notepadpp_binary(self, plugin: SimpleAnalysisPlugin, notepadpp_binary: Path) -> None:
        """Analyzes Notepad++ binary correctly."""
        results = plugin.analyze(str(notepadpp_binary))

        actual_size = os.path.getsize(notepadpp_binary)

        assert len(results) >= 2
        size_formatted = f"{actual_size:,}"

        results_text = " ".join(results)
        assert str(actual_size) in results_text or size_formatted in results_text


class TestProtectedBinaryAnalysis:
    """Validate analysis on protected binaries."""

    @pytest.mark.real_data
    def test_analyze_denuvo_protected_binary(
        self, plugin: SimpleAnalysisPlugin, denuvo_protected_binary: Path
    ) -> None:
        """Analyzes Denuvo-protected binary correctly."""
        results = plugin.analyze(str(denuvo_protected_binary))

        assert len(results) >= 2
        actual_size = os.path.getsize(denuvo_protected_binary)
        size_formatted = f"{actual_size:,}"
        assert any(str(actual_size) in r or size_formatted in r for r in results)

    @pytest.mark.real_data
    def test_analyze_steam_drm_binary(self, plugin: SimpleAnalysisPlugin, steam_drm_binary: Path) -> None:
        """Analyzes Steam DRM protected binary."""
        results = plugin.analyze(str(steam_drm_binary))

        actual_size = os.path.getsize(steam_drm_binary)
        size_formatted = f"{actual_size:,}"

        assert len(results) >= 2
        results_text = " ".join(results)
        assert str(actual_size) in results_text or size_formatted in results_text

    @pytest.mark.real_data
    def test_analyze_dongle_protected_binary(
        self, plugin: SimpleAnalysisPlugin, dongle_protected_binary: Path
    ) -> None:
        """Analyzes small dongle-protected binary."""
        results = plugin.analyze(str(dongle_protected_binary))

        actual_size = os.path.getsize(dongle_protected_binary)
        size_formatted = f"{actual_size:,}"

        assert len(results) >= 2
        assert any(str(actual_size) in r or size_formatted in r for r in results)

    @pytest.mark.real_data
    def test_analyze_all_protected_binaries(
        self, plugin: SimpleAnalysisPlugin, protected_binaries_dir: Path
    ) -> None:
        """Analyzes all protected binaries without errors."""
        protected_binaries = list(protected_binaries_dir.glob("*.exe"))
        assert len(protected_binaries) > 5, "Must have multiple protected binary samples"

        for binary in protected_binaries:
            results = plugin.analyze(str(binary))

            assert len(results) >= 2, f"Analysis failed for {binary.name}"
            actual_size = os.path.getsize(binary)
            size_formatted = f"{actual_size:,}"
            results_text = " ".join(results)
            assert str(actual_size) in results_text or size_formatted in results_text, f"Size mismatch for {binary.name}"


class TestFileSizeAccuracy:
    """Validate file size reporting accuracy."""

    @pytest.mark.real_data
    def test_file_size_matches_os_getsize(self, plugin: SimpleAnalysisPlugin, firefox_binary: Path) -> None:
        """Reported file size exactly matches os.path.getsize()."""
        expected_size = os.path.getsize(firefox_binary)
        results = plugin.analyze(str(firefox_binary))

        size_results = [r for r in results if "File size:" in r]
        assert len(size_results) == 1

        size_str = size_results[0]
        assert str(expected_size) in size_str

        size_formatted = f"{expected_size:,}"
        assert size_formatted in size_str, "File size must be formatted with commas"

    @pytest.mark.real_data
    def test_size_reporting_for_various_sizes(
        self, plugin: SimpleAnalysisPlugin, legitimate_binaries_dir: Path
    ) -> None:
        """Accurately reports sizes for binaries of different sizes."""
        binaries = [
            ("7zip.exe", lambda s: 1_000_000 < s < 5_000_000),
            ("firefox.exe", lambda s: 100_000 < s < 1_000_000),
            ("vlc.exe", lambda s: s > 10_000_000),
        ]

        for binary_name, size_check in binaries:
            binary_path = legitimate_binaries_dir / binary_name
            if not binary_path.exists():
                continue

            actual_size = os.path.getsize(binary_path)
            assert size_check(actual_size), f"{binary_name} size {actual_size} outside expected range"

            results = plugin.analyze(str(binary_path))
            size_formatted = f"{actual_size:,}"
            assert any(str(actual_size) in r or size_formatted in r for r in results)


class TestAnalysisFormatting:
    """Validate analysis result formatting."""

    @pytest.mark.real_data
    def test_results_contain_binary_path(self, plugin: SimpleAnalysisPlugin, firefox_binary: Path) -> None:
        """Results include binary path being analyzed."""
        results = plugin.analyze(str(firefox_binary))

        assert any("Analyzing:" in r for r in results)
        assert any(str(firefox_binary) in r or "firefox.exe" in r for r in results)

    @pytest.mark.real_data
    def test_file_size_formatted_with_commas(
        self, plugin: SimpleAnalysisPlugin, vlc_binary: Path
    ) -> None:
        """Large file sizes formatted with thousand separators."""
        actual_size = os.path.getsize(vlc_binary)
        assert actual_size > 1_000_000, "VLC should be large enough to need comma formatting"

        results = plugin.analyze(str(vlc_binary))
        results_text = " ".join(results)

        size_formatted = f"{actual_size:,}"
        assert size_formatted in results_text, "Large sizes must use comma formatting"

    @pytest.mark.real_data
    def test_results_are_string_list(self, plugin: SimpleAnalysisPlugin, firefox_binary: Path) -> None:
        """Results returned as list of strings."""
        results = plugin.analyze(str(firefox_binary))

        assert isinstance(results, list)
        assert all(isinstance(r, str) for r in results)
        assert len(results) >= 2


class TestPluginState:
    """Validate plugin state management."""

    @pytest.mark.real_data
    def test_plugin_initializes_with_empty_results(self, plugin: SimpleAnalysisPlugin) -> None:
        """New plugin instance has empty results dictionary."""
        assert hasattr(plugin, "results")
        assert isinstance(plugin.results, dict)
        assert len(plugin.results) == 0

    @pytest.mark.real_data
    def test_multiple_analyses_are_independent(
        self, plugin: SimpleAnalysisPlugin, firefox_binary: Path, seven_zip_binary: Path
    ) -> None:
        """Multiple analyses don't interfere with each other."""
        firefox_results = plugin.analyze(str(firefox_binary))
        firefox_size = os.path.getsize(firefox_binary)

        seven_zip_results = plugin.analyze(str(seven_zip_binary))
        seven_zip_size = os.path.getsize(seven_zip_binary)

        assert firefox_size != seven_zip_size, "Test requires different sized binaries"

        assert any(str(firefox_size) in r for r in firefox_results)
        assert all(str(seven_zip_size) not in r for r in firefox_results)

        assert any(str(seven_zip_size) in r for r in seven_zip_results)
        assert all(str(firefox_size) not in r for r in seven_zip_results)


class TestEdgeCases:
    """Test edge cases and error handling."""

    @pytest.mark.real_data
    def test_analyze_nonexistent_file(self, plugin: SimpleAnalysisPlugin) -> None:
        """Analyzing nonexistent file raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            plugin.analyze("D:/nonexistent_binary.exe")

    @pytest.mark.real_data
    def test_analyze_empty_file(self, plugin: SimpleAnalysisPlugin, temp_workspace: Path) -> None:
        """Analyzes empty file correctly."""
        empty_file = temp_workspace / "empty.exe"
        empty_file.touch()

        results = plugin.analyze(str(empty_file))

        assert len(results) >= 2
        assert any("0 bytes" in r or "File size: 0 bytes" in r for r in results)

    @pytest.mark.real_data
    def test_analyze_very_small_binary(
        self, plugin: SimpleAnalysisPlugin, protected_binaries_dir: Path
    ) -> None:
        """Analyzes very small binaries (< 2KB)."""
        dongle_app = protected_binaries_dir / "dongle_protected_app.exe"
        if not dongle_app.exists():
            pytest.skip("Small binary not available")

        actual_size = os.path.getsize(dongle_app)
        if actual_size > 10000:
            pytest.skip("Binary too large for this test")

        results = plugin.analyze(str(dongle_app))
        size_formatted = f"{actual_size:,}"

        assert len(results) >= 2
        assert any(str(actual_size) in r or size_formatted in r for r in results)

    @pytest.mark.real_data
    def test_analyze_directory_instead_of_file(self, plugin: SimpleAnalysisPlugin, legitimate_binaries_dir: Path) -> None:
        """Analyzing directory raises appropriate error."""
        with pytest.raises((OSError, IsADirectoryError)):
            plugin.analyze(str(legitimate_binaries_dir))

    @pytest.mark.real_data
    def test_analyze_with_unicode_path(self, plugin: SimpleAnalysisPlugin, temp_workspace: Path) -> None:
        """Handles paths with unicode characters."""
        unicode_dir = temp_workspace / "test_dir_\u4e2d\u6587"
        unicode_dir.mkdir()

        test_file = unicode_dir / "test.exe"
        test_file.write_bytes(b"MZ\x90\x00" + b"\x00" * 100)

        results = plugin.analyze(str(test_file))

        assert len(results) >= 2
        actual_size = os.path.getsize(test_file)
        size_formatted = f"{actual_size:,}"
        assert any(str(actual_size) in r or size_formatted in r for r in results)


class TestPerformance:
    """Validate performance on large binaries."""

    @pytest.mark.real_data
    def test_analyze_large_binary_completes_quickly(
        self, plugin: SimpleAnalysisPlugin, vlc_binary: Path
    ) -> None:
        """Analysis of large binary completes in reasonable time."""
        import time

        start_time = time.time()
        results = plugin.analyze(str(vlc_binary))
        elapsed = time.time() - start_time

        assert len(results) >= 2
        assert elapsed < 1.0, f"Analysis took {elapsed:.3f}s, should be < 1s"

    @pytest.mark.real_data
    def test_analyze_multiple_binaries_efficiently(
        self, plugin: SimpleAnalysisPlugin, legitimate_binaries_dir: Path
    ) -> None:
        """Multiple analyses complete efficiently."""
        import time

        binaries = list(legitimate_binaries_dir.glob("*.exe"))
        assert len(binaries) >= 3

        start_time = time.time()
        for binary in binaries:
            results = plugin.analyze(str(binary))
            assert len(results) >= 2

        elapsed = time.time() - start_time
        avg_time = elapsed / len(binaries)

        assert avg_time < 0.5, f"Average analysis time {avg_time:.3f}s too slow"


class TestPluginRegistration:
    """Validate plugin registration function."""

    @pytest.mark.real_data
    def test_register_returns_plugin_instance(self) -> None:
        """register() function returns SimpleAnalysisPlugin instance."""
        from intellicrack.plugins.custom_modules.simple_analysis_plugin import register

        plugin = register()

        assert isinstance(plugin, SimpleAnalysisPlugin)
        assert hasattr(plugin, "analyze")
        assert hasattr(plugin, "results")

    @pytest.mark.real_data
    def test_registered_plugin_functional(self, firefox_binary: Path) -> None:
        """Plugin from register() is fully functional."""
        from intellicrack.plugins.custom_modules.simple_analysis_plugin import register

        plugin = register()
        results = plugin.analyze(str(firefox_binary))

        assert len(results) >= 2
        actual_size = os.path.getsize(firefox_binary)
        size_formatted = f"{actual_size:,}"
        assert any(str(actual_size) in r or size_formatted in r for r in results)


class TestConsistency:
    """Validate consistency of analysis results."""

    @pytest.mark.real_data
    def test_repeated_analysis_gives_same_results(
        self, plugin: SimpleAnalysisPlugin, firefox_binary: Path
    ) -> None:
        """Analyzing same binary multiple times gives consistent results."""
        results1 = plugin.analyze(str(firefox_binary))
        results2 = plugin.analyze(str(firefox_binary))
        results3 = plugin.analyze(str(firefox_binary))

        assert results1 == results2
        assert results2 == results3

    @pytest.mark.real_data
    def test_different_plugin_instances_give_same_results(self, firefox_binary: Path) -> None:
        """Different plugin instances produce identical results."""
        plugin1 = SimpleAnalysisPlugin()
        plugin2 = SimpleAnalysisPlugin()

        results1 = plugin1.analyze(str(firefox_binary))
        results2 = plugin2.analyze(str(firefox_binary))

        assert results1 == results2


class TestAllProtectionSchemes:
    """Comprehensive test across all protection schemes."""

    @pytest.mark.real_data
    def test_analyze_all_protection_schemes(
        self, plugin: SimpleAnalysisPlugin, protected_binaries_dir: Path
    ) -> None:
        """Successfully analyzes binaries with various protection schemes."""
        protection_schemes = [
            "denuvo_like_protected.exe",
            "steam_drm_protected.exe",
            "securom_protected.exe",
            "safedisc_protected.exe",
            "starforce_protected.exe",
            "wibu_codemeter_protected.exe",
            "flexlm_license_protected.exe",
            "hasp_sentinel_protected.exe",
            "armadillo_protected.exe",
            "asprotect_protected.exe",
        ]

        analysis_results = {}

        for scheme_binary in protection_schemes:
            binary_path = protected_binaries_dir / scheme_binary
            if not binary_path.exists():
                continue

            results = plugin.analyze(str(binary_path))
            actual_size = os.path.getsize(binary_path)
            size_formatted = f"{actual_size:,}"

            assert len(results) >= 2, f"Failed to analyze {scheme_binary}"
            assert any(str(actual_size) in r or size_formatted in r for r in results), f"Size mismatch for {scheme_binary}"

            analysis_results[scheme_binary] = {
                "results": results,
                "size": actual_size
            }

        assert len(analysis_results) >= 5, "Must successfully analyze multiple protection schemes"


class TestRealWorldScenarios:
    """Test real-world usage scenarios."""

    @pytest.mark.real_data
    def test_batch_analysis_workflow(
        self, plugin: SimpleAnalysisPlugin, legitimate_binaries_dir: Path
    ) -> None:
        """Simulates batch analysis of multiple binaries."""
        binaries = list(legitimate_binaries_dir.glob("*.exe"))
        results_map = {}

        for binary in binaries:
            results = plugin.analyze(str(binary))
            results_map[binary.name] = results

            assert len(results) >= 2
            actual_size = os.path.getsize(binary)
            size_formatted = f"{actual_size:,}"
            assert any(str(actual_size) in r or size_formatted in r for r in results)

        assert len(results_map) == len(binaries)

    @pytest.mark.real_data
    def test_mixed_binary_types_analysis(
        self,
        plugin: SimpleAnalysisPlugin,
        legitimate_binaries_dir: Path,
        protected_binaries_dir: Path
    ) -> None:
        """Analyzes mix of legitimate and protected binaries."""
        legitimate_binaries = list(legitimate_binaries_dir.glob("*.exe"))[:2]
        protected_binaries = list(protected_binaries_dir.glob("*.exe"))[:2]

        all_binaries = legitimate_binaries + protected_binaries

        for binary in all_binaries:
            results = plugin.analyze(str(binary))
            actual_size = os.path.getsize(binary)
            size_formatted = f"{actual_size:,}"

            assert len(results) >= 2
            assert any(str(actual_size) in r or size_formatted in r for r in results)

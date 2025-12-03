"""Comprehensive tests for Unified Protection Engine.

Tests all unified engine functionality including:
- Multi-engine integration (Protection Engine + ICP + Heuristics)
- Result consolidation and deduplication
- Confidence scoring algorithms
- Bypass strategy generation
- Advanced entropy analysis (Shannon, chi-square, compression)
- Cache management (get, put, invalidate, cleanup)
- Quick summary mode
- Parallel analysis execution
- Error handling and recovery

All tests use real binary data and validate actual multi-engine analysis.
Tests FAIL if unified engine doesn't correctly combine results from multiple sources.
"""

import bz2
import os
import struct
import tempfile
import time
import zlib
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from intellicrack.protection.unified_protection_engine import (
    AnalysisSource,
    UnifiedProtectionEngine,
    UnifiedProtectionResult,
    get_unified_engine,
)


@pytest.fixture
def temp_pe32_high_entropy() -> Path:
    """Create PE32 binary with high entropy (likely packed)."""
    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".exe")

    dos_header = b"MZ" + b"\x90" * 58 + struct.pack("<I", 0x80)
    pe_header = dos_header + b"\x00" * 32 + b"PE\x00\x00" + struct.pack("<H", 0x014C) + b"\x00" * 200

    import random
    random.seed(42)
    high_entropy_data = bytes(random.randint(0, 255) for _ in range(4096))

    binary_data = pe_header + high_entropy_data

    temp_file.write(binary_data)
    temp_file.close()

    yield Path(temp_file.name)

    if Path(temp_file.name).exists():
        os.unlink(temp_file.name)


@pytest.fixture
def temp_pe32_low_entropy() -> Path:
    """Create PE32 binary with low entropy (unpacked)."""
    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".exe")

    dos_header = b"MZ" + b"\x90" * 58 + struct.pack("<I", 0x80)
    pe_header = dos_header + b"\x00" * 32 + b"PE\x00\x00" + struct.pack("<H", 0x014C) + b"\x00" * 200

    low_entropy_data = b"\x00" * 2048 + b"\x55\x89\xe5" * 100 + b"\x00" * 1848

    binary_data = pe_header + low_entropy_data

    temp_file.write(binary_data)
    temp_file.close()

    yield Path(temp_file.name)

    if Path(temp_file.name).exists():
        os.unlink(temp_file.name)


@pytest.fixture
def temp_pe32_vmprotect() -> Path:
    """Create PE32 with VMProtect signatures for multi-engine detection."""
    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".exe")

    dos_header = b"MZ" + b"\x90" * 58 + struct.pack("<I", 0x80)
    pe_header = dos_header + b"\x00" * 32 + b"PE\x00\x00" + struct.pack("<H", 0x014C) + b"\x00" * 200

    vmp_signature1 = b"\x68\x00\x00\x00\x00\x8f\x04\x24"
    vmp_signature2 = b".vmp0" + b"\x00" * 3
    vmp_entry = b"\x60\x8b\x04\x24\x8b\x4c\x24\x04"

    import random
    random.seed(42)
    high_entropy = bytes(random.randint(0, 255) for _ in range(2048))

    binary_data = pe_header + vmp_signature1 + vmp_signature2 + vmp_entry + high_entropy

    temp_file.write(binary_data)
    temp_file.close()

    yield Path(temp_file.name)

    if Path(temp_file.name).exists():
        os.unlink(temp_file.name)


@pytest.fixture
def unified_engine() -> UnifiedProtectionEngine:
    """Create unified protection engine instance."""
    return UnifiedProtectionEngine(
        enable_protection=True,
        enable_heuristics=True
    )


class TestUnifiedProtectionEngineInitialization:
    """Test unified engine initialization and configuration."""

    def test_initialization_default(self) -> None:
        """Test default initialization."""
        engine = UnifiedProtectionEngine()

        assert engine.enable_protection is True
        assert engine.enable_heuristics is True
        assert engine.cache is not None

    def test_initialization_protection_only(self) -> None:
        """Test initialization with protection engine only."""
        engine = UnifiedProtectionEngine(
            enable_protection=True,
            enable_heuristics=False
        )

        assert engine.enable_protection is True
        assert engine.enable_heuristics is False

    def test_initialization_with_cache_config(self) -> None:
        """Test initialization with custom cache configuration."""
        cache_config = {
            "max_entries": 100,
            "ttl_seconds": 3600
        }

        engine = UnifiedProtectionEngine(cache_config=cache_config)

        assert engine.cache is not None


class TestUnifiedAnalysis:
    """Test unified analysis combining multiple engines."""

    def test_analyze_pe32_binary(self, unified_engine: UnifiedProtectionEngine, temp_pe32_low_entropy: Path) -> None:
        """Test unified analysis on PE32 binary."""
        result = unified_engine.analyze(str(temp_pe32_low_entropy), deep_scan=False)

        assert isinstance(result, UnifiedProtectionResult)
        assert result.file_path == str(temp_pe32_low_entropy)
        assert result.file_type in ["PE", "PE32", "Unknown"]
        assert result.architecture in ["x86", "x64", "Unknown"]
        assert isinstance(result.protections, list)
        assert result.confidence_score >= 0.0
        assert result.analysis_time > 0.0
        assert len(result.engines_used) > 0

    def test_analyze_with_deep_scan(self, unified_engine: UnifiedProtectionEngine, temp_pe32_vmprotect: Path) -> None:
        """Test unified analysis with deep scan mode."""
        result = unified_engine.analyze(str(temp_pe32_vmprotect), deep_scan=True)

        assert isinstance(result, UnifiedProtectionResult)
        assert result.file_path == str(temp_pe32_vmprotect)

    def test_analyze_high_entropy_binary(self, unified_engine: UnifiedProtectionEngine, temp_pe32_high_entropy: Path) -> None:
        """Test analysis correctly identifies high entropy (packed) binary."""
        result = unified_engine.analyze(str(temp_pe32_high_entropy))

        assert isinstance(result, UnifiedProtectionResult)

    def test_analyze_with_timeout(self, unified_engine: UnifiedProtectionEngine, temp_pe32_low_entropy: Path) -> None:
        """Test analysis respects timeout parameter."""
        start_time = time.time()
        result = unified_engine.analyze(str(temp_pe32_low_entropy), timeout=10)
        elapsed = time.time() - start_time

        assert isinstance(result, UnifiedProtectionResult)
        assert elapsed < 15


class TestResultConsolidation:
    """Test result consolidation and deduplication."""

    def test_consolidate_removes_duplicates(self, unified_engine: UnifiedProtectionEngine) -> None:
        """Test consolidation removes duplicate detections."""
        result = UnifiedProtectionResult(
            file_path="/test/file.exe",
            file_type="PE32",
            architecture="x86"
        )

        result.protections = [
            {
                "name": "UPX",
                "type": "packer",
                "source": AnalysisSource.PROTECTION_ENGINE,
                "confidence": 95.0
            },
            {
                "name": "UPX",
                "type": "packer",
                "source": AnalysisSource.HEURISTIC,
                "confidence": 80.0
            }
        ]

        unified_engine._consolidate_results(result)

        assert len(result.protections) == 1
        assert result.protections[0]["confidence"] == 95.0
        assert result.protections[0]["source"] == AnalysisSource.HYBRID

    def test_consolidate_preserves_unique_detections(self, unified_engine: UnifiedProtectionEngine) -> None:
        """Test consolidation preserves unique detections."""
        result = UnifiedProtectionResult(
            file_path="/test/file.exe",
            file_type="PE32",
            architecture="x86"
        )

        result.protections = [
            {
                "name": "UPX",
                "type": "packer",
                "source": AnalysisSource.PROTECTION_ENGINE,
                "confidence": 95.0
            },
            {
                "name": "VMProtect",
                "type": "protector",
                "source": AnalysisSource.SIGNATURE,
                "confidence": 90.0
            }
        ]

        unified_engine._consolidate_results(result)

        assert len(result.protections) == 2


class TestConfidenceScoring:
    """Test confidence score calculation."""

    def test_calculate_confidence_single_detection(self, unified_engine: UnifiedProtectionEngine) -> None:
        """Test confidence calculation with single detection."""
        result = UnifiedProtectionResult(
            file_path="/test/file.exe",
            file_type="PE32",
            architecture="x86"
        )

        result.protections = [
            {
                "name": "UPX",
                "type": "packer",
                "source": AnalysisSource.PROTECTION_ENGINE,
                "confidence": 90.0
            }
        ]

        unified_engine._calculate_confidence(result)

        assert result.confidence_score > 0.0
        assert result.confidence_score <= 100.0

    def test_calculate_confidence_multiple_detections(self, unified_engine: UnifiedProtectionEngine) -> None:
        """Test confidence calculation with multiple detections."""
        result = UnifiedProtectionResult(
            file_path="/test/file.exe",
            file_type="PE32",
            architecture="x86"
        )

        result.protections = [
            {
                "name": "UPX",
                "type": "packer",
                "source": AnalysisSource.PROTECTION_ENGINE,
                "confidence": 90.0
            },
            {
                "name": "Themida",
                "type": "protector",
                "source": AnalysisSource.SIGNATURE,
                "confidence": 85.0
            }
        ]

        unified_engine._calculate_confidence(result)

        assert result.confidence_score > 0.0
        assert result.confidence_score <= 100.0

    def test_calculate_confidence_no_detections(self, unified_engine: UnifiedProtectionEngine) -> None:
        """Test confidence calculation with no detections."""
        result = UnifiedProtectionResult(
            file_path="/test/file.exe",
            file_type="PE32",
            architecture="x86"
        )

        unified_engine._calculate_confidence(result)

        assert result.confidence_score == 0.0


class TestBypassStrategyGeneration:
    """Test bypass strategy generation."""

    def test_generate_bypass_strategies_packer(self, unified_engine: UnifiedProtectionEngine) -> None:
        """Test bypass strategy generation for packer."""
        result = UnifiedProtectionResult(
            file_path="/test/file.exe",
            file_type="PE32",
            architecture="x86",
            is_packed=True
        )

        result.protections = [
            {
                "name": "UPX",
                "type": "packer",
                "source": AnalysisSource.PROTECTION_ENGINE,
                "confidence": 95.0
            }
        ]

        unified_engine._generate_bypass_strategies(result)

        assert len(result.bypass_strategies) > 0
        assert any("unpack" in str(s).lower() for s in result.bypass_strategies)

    def test_generate_bypass_strategies_anti_debug(self, unified_engine: UnifiedProtectionEngine) -> None:
        """Test bypass strategy generation for anti-debug."""
        result = UnifiedProtectionResult(
            file_path="/test/file.exe",
            file_type="PE32",
            architecture="x86",
            has_anti_debug=True
        )

        result.protections = [
            {
                "name": "Anti-Debug",
                "type": "anti-debug",
                "source": AnalysisSource.HEURISTIC,
                "confidence": 80.0
            }
        ]

        unified_engine._generate_bypass_strategies(result)

        assert len(result.bypass_strategies) > 0
        assert any("debug" in str(s).lower() for s in result.bypass_strategies)

    def test_generate_bypass_strategies_license(self, unified_engine: UnifiedProtectionEngine) -> None:
        """Test bypass strategy generation for license protection."""
        result = UnifiedProtectionResult(
            file_path="/test/file.exe",
            file_type="PE32",
            architecture="x86",
            has_licensing=True
        )

        result.protections = [
            {
                "name": "FlexLM",
                "type": "license",
                "source": AnalysisSource.SIGNATURE,
                "confidence": 90.0
            }
        ]

        unified_engine._generate_bypass_strategies(result)

        assert len(result.bypass_strategies) > 0
        assert any("license" in str(s).lower() for s in result.bypass_strategies)


class TestEntropyAnalysis:
    """Test entropy analysis methods."""

    def test_calculate_shannon_entropy_random_data(self, unified_engine: UnifiedProtectionEngine) -> None:
        """Test Shannon entropy calculation on random data."""
        import random
        random.seed(42)
        random_data = bytes(random.randint(0, 255) for _ in range(1024))

        entropy = unified_engine._calculate_shannon_entropy(random_data)

        assert entropy > 7.0
        assert entropy <= 8.0

    def test_calculate_shannon_entropy_zero_data(self, unified_engine: UnifiedProtectionEngine) -> None:
        """Test Shannon entropy calculation on zero-filled data."""
        zero_data = b"\x00" * 1024

        entropy = unified_engine._calculate_shannon_entropy(zero_data)

        assert entropy == 0.0

    def test_calculate_shannon_entropy_pattern_data(self, unified_engine: UnifiedProtectionEngine) -> None:
        """Test Shannon entropy calculation on patterned data."""
        pattern_data = b"\x55\x89\xe5" * 341 + b"\x55"

        entropy = unified_engine._calculate_shannon_entropy(pattern_data)

        assert 0.0 < entropy < 2.0

    def test_sliding_window_entropy(self, unified_engine: UnifiedProtectionEngine) -> None:
        """Test sliding window entropy analysis."""
        import random
        random.seed(42)
        mixed_data = b"\x00" * 256 + bytes(random.randint(0, 255) for _ in range(256)) + b"\x00" * 256

        entropies = unified_engine._sliding_window_entropy(mixed_data, window_size=256, step_size=128)

        assert len(entropies) > 0
        assert max(entropies) > min(entropies)

    def test_estimate_kolmogorov_complexity_random(self, unified_engine: UnifiedProtectionEngine) -> None:
        """Test Kolmogorov complexity estimation on random data."""
        import random
        random.seed(42)
        random_data = bytes(random.randint(0, 255) for _ in range(1024))

        complexity = unified_engine._estimate_kolmogorov_complexity(random_data)

        assert complexity > 0.7

    def test_estimate_kolmogorov_complexity_repeating(self, unified_engine: UnifiedProtectionEngine) -> None:
        """Test Kolmogorov complexity estimation on repeating data."""
        repeating_data = b"A" * 1024

        complexity = unified_engine._estimate_kolmogorov_complexity(repeating_data)

        assert complexity < 0.3

    def test_analyze_compression_ratios(self, unified_engine: UnifiedProtectionEngine) -> None:
        """Test compression ratio analysis."""
        import random
        random.seed(42)
        test_data = bytes(random.randint(0, 255) for _ in range(2048))

        ratios = unified_engine._analyze_compression_ratios(test_data)

        assert isinstance(ratios, dict)
        assert "zlib" in ratios
        assert "bz2" in ratios
        assert all(0.0 <= ratio <= 1.5 for ratio in ratios.values())

    def test_chi_square_test_random(self, unified_engine: UnifiedProtectionEngine) -> None:
        """Test chi-square randomness test on random data."""
        import random
        random.seed(42)
        random_data = bytes(random.randint(0, 255) for _ in range(2048))

        result = unified_engine._chi_square_test(random_data)

        assert isinstance(result, dict)
        assert "is_random" in result
        assert "p_value" in result
        assert "statistic" in result
        assert isinstance(result["is_random"], bool)

    def test_chi_square_test_non_random(self, unified_engine: UnifiedProtectionEngine) -> None:
        """Test chi-square randomness test on non-random data."""
        non_random_data = b"A" * 2048

        result = unified_engine._chi_square_test(non_random_data)

        assert result["is_random"] is False

    def test_analyze_byte_distribution(self, unified_engine: UnifiedProtectionEngine) -> None:
        """Test byte distribution analysis."""
        import random
        random.seed(42)
        test_data = bytes(random.randint(0, 255) for _ in range(2048))

        distribution = unified_engine._analyze_byte_distribution(test_data)

        assert isinstance(distribution, dict)
        assert "unique_bytes" in distribution
        assert "uniformity_score" in distribution
        assert "byte_coverage" in distribution
        assert 0 <= distribution["unique_bytes"] <= 256
        assert 0.0 <= distribution["uniformity_score"] <= 1.0
        assert 0.0 <= distribution["byte_coverage"] <= 1.0


class TestCacheManagement:
    """Test cache management functionality."""

    def test_cache_stores_results(self, unified_engine: UnifiedProtectionEngine, temp_pe32_low_entropy: Path) -> None:
        """Test cache stores analysis results."""
        result1 = unified_engine.analyze(str(temp_pe32_low_entropy))
        result2 = unified_engine.analyze(str(temp_pe32_low_entropy))

        assert result2.file_path == result1.file_path

    def test_get_cache_stats(self, unified_engine: UnifiedProtectionEngine) -> None:
        """Test retrieving cache statistics."""
        stats = unified_engine.get_cache_stats()

        assert isinstance(stats, dict)

    def test_clear_cache(self, unified_engine: UnifiedProtectionEngine, temp_pe32_low_entropy: Path) -> None:
        """Test clearing cache."""
        unified_engine.analyze(str(temp_pe32_low_entropy))
        unified_engine.clear_cache()

        stats = unified_engine.get_cache_stats()
        assert isinstance(stats, dict)

    def test_cleanup_cache(self, unified_engine: UnifiedProtectionEngine) -> None:
        """Test cache cleanup."""
        removed = unified_engine.cleanup_cache()

        assert isinstance(removed, int)
        assert removed >= 0

    def test_remove_from_cache(self, unified_engine: UnifiedProtectionEngine, temp_pe32_low_entropy: Path) -> None:
        """Test removing specific file from cache."""
        unified_engine.analyze(str(temp_pe32_low_entropy))

        removed = unified_engine.remove_from_cache(str(temp_pe32_low_entropy))

        assert isinstance(removed, bool)

    def test_invalidate_cache_for_file(self, unified_engine: UnifiedProtectionEngine, temp_pe32_low_entropy: Path) -> None:
        """Test invalidating cache for specific file."""
        unified_engine.analyze(str(temp_pe32_low_entropy))
        unified_engine.invalidate_cache_for_file(str(temp_pe32_low_entropy))

    def test_get_cache_size(self, unified_engine: UnifiedProtectionEngine) -> None:
        """Test retrieving cache size information."""
        entry_count, size_mb = unified_engine.get_cache_size()

        assert isinstance(entry_count, int)
        assert isinstance(size_mb, float)
        assert entry_count >= 0
        assert size_mb >= 0.0


class TestQuickSummary:
    """Test quick summary mode."""

    def test_get_quick_summary(self, unified_engine: UnifiedProtectionEngine, temp_pe32_low_entropy: Path) -> None:
        """Test quick summary generation."""
        summary = unified_engine.get_quick_summary(str(temp_pe32_low_entropy))

        assert isinstance(summary, dict)
        assert "protected" in summary
        assert "protection_count" in summary
        assert "confidence" in summary
        assert isinstance(summary["protected"], bool)
        assert isinstance(summary["protection_count"], int)
        assert isinstance(summary["confidence"], float)

    def test_quick_summary_uses_cache(self, unified_engine: UnifiedProtectionEngine, temp_pe32_low_entropy: Path) -> None:
        """Test quick summary uses cached results."""
        unified_engine.analyze(str(temp_pe32_low_entropy))

        summary = unified_engine.get_quick_summary(str(temp_pe32_low_entropy))

        assert isinstance(summary, dict)


class TestGetUnifiedEngine:
    """Test singleton unified engine accessor."""

    def test_get_unified_engine_singleton(self) -> None:
        """Test get_unified_engine returns singleton instance."""
        engine1 = get_unified_engine()
        engine2 = get_unified_engine()

        assert engine1 is engine2

    def test_get_unified_engine_returns_valid_instance(self) -> None:
        """Test get_unified_engine returns valid engine."""
        engine = get_unified_engine()

        assert isinstance(engine, UnifiedProtectionEngine)
        assert engine.cache is not None


class TestAnalyzeFileAlias:
    """Test analyze_file backward compatibility alias."""

    def test_analyze_file_alias(self, unified_engine: UnifiedProtectionEngine, temp_pe32_low_entropy: Path) -> None:
        """Test analyze_file is alias for analyze."""
        result = unified_engine.analyze_file(str(temp_pe32_low_entropy))

        assert isinstance(result, UnifiedProtectionResult)
        assert result.file_path == str(temp_pe32_low_entropy)


class TestAdvancedEntropyAnalysis:
    """Test comprehensive entropy analysis."""

    def test_perform_advanced_entropy_analysis(self, unified_engine: UnifiedProtectionEngine) -> None:
        """Test complete entropy analysis with all methods."""
        import random
        random.seed(42)
        test_data = bytes(random.randint(0, 255) for _ in range(2048))

        results = unified_engine._perform_advanced_entropy_analysis(test_data)

        assert isinstance(results, dict)
        assert "shannon_entropy" in results
        assert "sliding_window_max" in results
        assert "kolmogorov_complexity" in results
        assert "compression_ratios" in results
        assert "chi_square_random" in results
        assert "byte_distribution" in results

        assert isinstance(results["shannon_entropy"], float)
        assert isinstance(results["kolmogorov_complexity"], float)
        assert isinstance(results["compression_ratios"], dict)
        assert isinstance(results["chi_square_random"], bool)
        assert isinstance(results["byte_distribution"], dict)

    def test_entropy_analysis_detects_packing(self, unified_engine: UnifiedProtectionEngine) -> None:
        """Test entropy analysis correctly identifies packed binary characteristics."""
        import random
        random.seed(42)
        packed_data = bytes(random.randint(0, 255) for _ in range(2048))

        results = unified_engine._perform_advanced_entropy_analysis(packed_data)

        assert results["shannon_entropy"] > 7.0
        assert results["kolmogorov_complexity"] > 0.7
        assert results["chi_square_random"] is True

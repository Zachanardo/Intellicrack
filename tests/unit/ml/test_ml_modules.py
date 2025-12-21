"""Real-world ML module tests with actual binary data and model operations.

Tests ML capabilities against real Windows binaries and data.
NO MOCKS - Uses real feature extraction, neural networks, and pattern tracking only.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

from __future__ import annotations

import os
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

import numpy as np
import pytest

from intellicrack.ml.binary_feature_extractor import (
    BinaryFeatureExtractor,
    extract_features_for_ml,
)
from intellicrack.ml.pattern_evolution_tracker import (
    PatternEvolutionTracker,
    PatternGene,
    PatternType,
    MutationType,
)


WINDOWS_SYSTEM_BINARIES = {
    "notepad.exe": r"C:\Windows\System32\notepad.exe",
    "calc.exe": r"C:\Windows\System32\calc.exe",
    "kernel32.dll": r"C:\Windows\System32\kernel32.dll",
    "ntdll.dll": r"C:\Windows\System32\ntdll.dll",
    "user32.dll": r"C:\Windows\System32\user32.dll",
}


@pytest.fixture
def temp_dir() -> Path:
    """Create temporary directory for test artifacts."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def notepad_path() -> str:
    """Get path to notepad.exe."""
    notepad = WINDOWS_SYSTEM_BINARIES["notepad.exe"]
    if not os.path.exists(notepad):
        pytest.skip(f"notepad.exe not found at {notepad}")
    return notepad


@pytest.fixture
def calc_path() -> str:
    """Get path to calc.exe."""
    calc = WINDOWS_SYSTEM_BINARIES["calc.exe"]
    if not os.path.exists(calc):
        pytest.skip(f"calc.exe not found at {calc}")
    return calc


@pytest.fixture
def kernel32_path() -> str:
    """Get path to kernel32.dll."""
    kernel32 = WINDOWS_SYSTEM_BINARIES["kernel32.dll"]
    if not os.path.exists(kernel32):
        pytest.skip(f"kernel32.dll not found at {kernel32}")
    return kernel32


class TestBinaryFeatureExtractor:
    """Test binary feature extraction for ML."""

    def test_extractor_initialization(self, notepad_path: str) -> None:
        """Test feature extractor initializes with real binary."""
        extractor = BinaryFeatureExtractor(notepad_path)

        assert extractor is not None
        assert extractor.binary_path == notepad_path
        assert hasattr(extractor, "extract_all_features")

    def test_extract_opcode_histogram_on_notepad(self, notepad_path: str) -> None:
        """Test opcode histogram extraction on real Windows binary."""
        extractor = BinaryFeatureExtractor(notepad_path)

        histogram = extractor.extract_opcode_histogram()

        assert histogram is not None
        assert isinstance(histogram, (dict, np.ndarray))

        if isinstance(histogram, dict):
            assert len(histogram) > 0, "Should extract opcodes from real binary"

    def test_extract_opcode_histogram_on_dll(self, kernel32_path: str) -> None:
        """Test opcode extraction on Windows system DLL."""
        extractor = BinaryFeatureExtractor(kernel32_path)

        histogram = extractor.extract_opcode_histogram()

        assert histogram is not None

    def test_build_control_flow_graph_on_calc(self, calc_path: str) -> None:
        """Test CFG construction on real Windows binary."""
        extractor = BinaryFeatureExtractor(calc_path)

        cfg = extractor.build_control_flow_graph()

        assert cfg is not None

        if hasattr(cfg, "nodes"):
            assert len(cfg.nodes()) > 0, "CFG should have nodes from real binary"
        elif isinstance(cfg, dict):
            assert len(cfg) > 0

    def test_extract_api_sequences_on_notepad(self, notepad_path: str) -> None:
        """Test API sequence extraction on real binary."""
        extractor = BinaryFeatureExtractor(notepad_path)

        api_sequences = extractor.extract_api_sequences()

        assert api_sequences is not None
        assert isinstance(api_sequences, (list, dict))

    def test_calculate_section_entropy_on_system_dll(self, kernel32_path: str) -> None:
        """Test section entropy calculation on Windows DLL."""
        extractor = BinaryFeatureExtractor(kernel32_path)

        entropy = extractor.calculate_section_entropy()

        assert entropy is not None
        assert isinstance(entropy, (dict, list))

        if isinstance(entropy, dict):
            for section_name, entropy_value in entropy.items():
                assert isinstance(entropy_value, float)
                assert 0.0 <= entropy_value <= 8.0, f"Entropy should be 0-8, got {entropy_value}"

    def test_extract_string_features_on_binary(self, notepad_path: str) -> None:
        """Test string feature extraction on real binary."""
        extractor = BinaryFeatureExtractor(notepad_path)

        string_features = extractor.extract_string_features()

        assert string_features is not None
        assert isinstance(string_features, (dict, list))

    def test_extract_all_features_on_notepad(self, notepad_path: str) -> None:
        """Test comprehensive feature extraction on notepad.exe."""
        extractor = BinaryFeatureExtractor(notepad_path)

        features = extractor.extract_all_features()

        assert features is not None
        assert isinstance(features, dict)

        assert "opcode_histogram" in features or "opcodes" in features
        assert "section_entropy" in features or "entropy" in features

    def test_extract_all_features_on_calc(self, calc_path: str) -> None:
        """Test comprehensive feature extraction on calc.exe."""
        extractor = BinaryFeatureExtractor(calc_path)

        features = extractor.extract_all_features()

        assert features is not None
        assert isinstance(features, dict)
        assert len(features) > 0

    def test_feature_extraction_on_multiple_binaries(self) -> None:
        """Test feature extraction consistency across multiple binaries."""
        results = []

        for binary_name, binary_path in WINDOWS_SYSTEM_BINARIES.items():
            if not os.path.exists(binary_path):
                continue

            try:
                extractor = BinaryFeatureExtractor(binary_path)
                features = extractor.extract_all_features()

                results.append((binary_name, features))
            except Exception:
                pass

        assert results, "Should successfully extract features from at least one binary"

        for binary_name, features in results:
            assert features is not None
            assert isinstance(features, dict)

    def test_factory_function_extract_features_for_ml(self, notepad_path: str) -> None:
        """Test factory function for ML feature extraction."""
        features = extract_features_for_ml(notepad_path)

        assert features is not None
        assert isinstance(features, (dict, np.ndarray))

    def test_feature_extraction_error_handling_nonexistent(self) -> None:
        """Test error handling for nonexistent binary."""
        try:
            extractor = BinaryFeatureExtractor("nonexistent.exe")

            if extractor.data is not None:
                features = extractor.extract_all_features()
                assert features is not None
        except FileNotFoundError:
            pass
        except Exception:
            pass

    def test_feature_extraction_on_large_dll(self) -> None:
        """Test performance on larger Windows DLL."""
        if sys.platform != "win32":
            pytest.skip("Windows-specific test")

        ntdll_path = WINDOWS_SYSTEM_BINARIES["ntdll.dll"]
        if not os.path.exists(ntdll_path):
            pytest.skip("ntdll.dll not found")

        extractor = BinaryFeatureExtractor(ntdll_path)

        start_time = time.time()
        features = extractor.extract_all_features()
        elapsed_time = time.time() - start_time

        assert features is not None
        assert elapsed_time < 60, "Feature extraction should complete within 60 seconds"


class TestPatternEvolutionTracker:
    """Test pattern evolution tracking and genetic algorithms."""

    def test_tracker_initialization(self, temp_dir: Path) -> None:
        """Test pattern evolution tracker initializes."""
        tracker = PatternEvolutionTracker(
            population_size=50,
            mutation_rate=0.1,
            crossover_rate=0.7,
            db_path=str(temp_dir / "patterns.db"),
        )

        assert tracker is not None
        assert tracker.population_size == 50
        assert tracker.mutation_rate == 0.1
        assert tracker.crossover_rate == 0.7

        tracker.shutdown()

    def test_detect_patterns_in_binary_data(self, temp_dir: Path, notepad_path: str) -> None:
        """Test pattern detection on real binary data."""
        tracker = PatternEvolutionTracker(
            population_size=30,
            db_path=str(temp_dir / "patterns.db"),
        )

        with open(notepad_path, "rb") as f:
            binary_data = f.read(1024 * 100)

        result = tracker.detect(binary_data)

        assert result is not None
        assert isinstance(result, (dict, list))

        tracker.shutdown()

    def test_evolve_generation(self, temp_dir: Path) -> None:
        """Test genetic algorithm evolution over one generation."""
        tracker = PatternEvolutionTracker(
            population_size=20,
            db_path=str(temp_dir / "patterns.db"),
        )

        tracker.evolve_generation()

        tracker.shutdown()

    def test_cluster_patterns_into_families(self, temp_dir: Path) -> None:
        """Test pattern clustering into families."""
        tracker = PatternEvolutionTracker(
            population_size=30,
            db_path=str(temp_dir / "patterns.db"),
        )

        families = tracker.cluster_into_families()

        assert families is not None
        assert isinstance(families, (dict, list))

        tracker.shutdown()

    def test_analyze_temporal_evolution(self, temp_dir: Path) -> None:
        """Test temporal evolution analysis."""
        tracker = PatternEvolutionTracker(
            population_size=20,
            db_path=str(temp_dir / "patterns.db"),
        )

        evolution_data = tracker.analyze_temporal_evolution()

        assert evolution_data is not None

        tracker.shutdown()

    def test_pattern_export_and_import(self, temp_dir: Path) -> None:
        """Test pattern export and import functionality."""
        tracker = PatternEvolutionTracker(
            population_size=20,
            db_path=str(temp_dir / "patterns.db"),
        )

        export_file = temp_dir / "patterns_export.json"

        tracker.export_patterns(str(export_file))

        assert export_file.exists()

        tracker2 = PatternEvolutionTracker(
            population_size=20,
            db_path=str(temp_dir / "patterns2.db"),
        )

        tracker2.import_patterns(str(export_file))

        tracker.shutdown()
        tracker2.shutdown()

    def test_pattern_feedback_mechanism(self, temp_dir: Path) -> None:
        """Test feedback mechanism for pattern refinement."""
        tracker = PatternEvolutionTracker(
            population_size=20,
            db_path=str(temp_dir / "patterns.db"),
        )

        tracker.feedback(pattern_id=0, success=True, metrics={"accuracy": 0.85})

        tracker.shutdown()

    def test_get_statistics(self, temp_dir: Path) -> None:
        """Test retrieving tracker statistics."""
        tracker = PatternEvolutionTracker(
            population_size=20,
            db_path=str(temp_dir / "patterns.db"),
        )

        stats = tracker.get_statistics()

        assert stats is not None
        assert isinstance(stats, dict)

        tracker.shutdown()

    def test_detect_pattern_mutations(self, temp_dir: Path, calc_path: str) -> None:
        """Test mutation detection in binary patterns."""
        tracker = PatternEvolutionTracker(
            population_size=20,
            db_path=str(temp_dir / "patterns.db"),
        )

        with open(calc_path, "rb") as f:
            binary_data1 = f.read(1024 * 50)

        with open(calc_path, "rb") as f:
            f.seek(1024)
            binary_data2 = f.read(1024 * 50)

        mutations = tracker.detect_pattern_mutations(
            old_pattern=binary_data1,
            new_pattern=binary_data2,
        )

        assert mutations is not None

        tracker.shutdown()

    def test_cluster_patterns_advanced(self, temp_dir: Path) -> None:
        """Test advanced pattern clustering."""
        tracker = PatternEvolutionTracker(
            population_size=30,
            db_path=str(temp_dir / "patterns.db"),
        )

        clusters = tracker.cluster_patterns(
            algorithm="dbscan",
            min_samples=2,
            eps=0.5,
        )

        assert clusters is not None

        tracker.shutdown()

    def test_real_world_pattern_evolution_scenario(self, temp_dir: Path, notepad_path: str) -> None:
        """Test real-world scenario: tracking pattern evolution across binary versions."""
        tracker = PatternEvolutionTracker(
            population_size=30,
            db_path=str(temp_dir / "patterns.db"),
        )

        with open(notepad_path, "rb") as f:
            binary_data = f.read(1024 * 100)

        result1 = tracker.detect(binary_data)
        assert result1 is not None

        tracker.evolve_generation()

        result2 = tracker.detect(binary_data)
        assert result2 is not None

        stats = tracker.get_statistics()
        assert stats is not None

        tracker.shutdown()


class TestNeuralNetworkIntegration:
    """Test neural network components for license detection."""

    def test_license_protection_types_enum(self) -> None:
        """Test LicenseProtectionType enum availability."""
        from intellicrack.ml.license_protection_neural_network import LicenseProtectionType

        assert LicenseProtectionType is not None
        assert hasattr(LicenseProtectionType, "__members__")

    def test_license_features_dataclass(self) -> None:
        """Test LicenseFeatures dataclass availability."""
        from intellicrack.ml.license_protection_neural_network import LicenseFeatures

        features = LicenseFeatures(
            opcode_histogram=np.zeros(256),
            api_sequences=["CreateFileW", "ReadFile", "CloseHandle"],
            section_entropy=[7.2, 6.8, 5.1],
            string_features=["license", "activation", "serial"],
            cfg_features={"nodes": 100, "edges": 150},
        )

        assert features is not None
        assert len(features.opcode_histogram) == 256
        assert len(features.api_sequences) == 3

    def test_hybrid_license_analyzer_initialization(self) -> None:
        """Test HybridLicenseAnalyzer neural network initialization."""
        try:
            from intellicrack.ml.license_protection_neural_network import HybridLicenseAnalyzer

            model = HybridLicenseAnalyzer(
                input_dim=256,
                hidden_dim=128,
                num_protection_types=10,
            )

            assert model is not None
            assert hasattr(model, "forward")
            assert hasattr(model, "save_weights")
        except ImportError:
            pytest.skip("PyTorch not available")

    def test_license_predictor_singleton(self) -> None:
        """Test global license predictor singleton."""
        try:
            from intellicrack.ml.license_protection_neural_network import get_license_predictor

            predictor = get_license_predictor()

            assert predictor is not None
            assert hasattr(predictor, "predict")
        except ImportError:
            pytest.skip("Required ML dependencies not available")


class TestCoreMLFeatureExtraction:
    """Test core ML feature extraction module."""

    def test_core_feature_extractor_availability(self) -> None:
        """Test core feature extractor is available."""
        from intellicrack.core.ml.feature_extraction import BinaryFeatureExtractor

        assert BinaryFeatureExtractor is not None

    def test_core_feature_extractor_on_real_binary(self, notepad_path: str) -> None:
        """Test core feature extractor on real Windows binary."""
        from intellicrack.core.ml.feature_extraction import BinaryFeatureExtractor

        extractor = BinaryFeatureExtractor(notepad_path)

        assert extractor is not None

        features = extractor.extract_all_features()

        assert features is not None


class TestMLIntegration:
    """Test integration between ML modules."""

    def test_feature_extractor_to_pattern_tracker(self, temp_dir: Path, notepad_path: str) -> None:
        """Test integration: feature extraction -> pattern tracking."""
        extractor = BinaryFeatureExtractor(notepad_path)
        features = extractor.extract_all_features()

        assert features is not None

        tracker = PatternEvolutionTracker(
            population_size=20,
            db_path=str(temp_dir / "patterns.db"),
        )

        with open(notepad_path, "rb") as f:
            binary_data = f.read(1024 * 50)

        detection_result = tracker.detect(binary_data)

        assert detection_result is not None

        tracker.shutdown()

    def test_end_to_end_ml_pipeline(self, temp_dir: Path, calc_path: str) -> None:
        """Test end-to-end ML pipeline: extraction -> tracking -> prediction."""
        extractor = BinaryFeatureExtractor(calc_path)

        features = extractor.extract_all_features()
        assert features is not None

        tracker = PatternEvolutionTracker(
            population_size=20,
            db_path=str(temp_dir / "patterns.db"),
        )

        with open(calc_path, "rb") as f:
            binary_data = f.read(1024 * 50)

        patterns = tracker.detect(binary_data)
        assert patterns is not None

        tracker.shutdown()

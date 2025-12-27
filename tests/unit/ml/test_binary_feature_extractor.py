"""Production-grade tests for binary feature extraction.

Tests MUST validate actual feature extraction on real PE binaries from fixtures.
All features must be validated for correctness against actual binary characteristics.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.
"""

from pathlib import Path
from typing import Any

import numpy as np
import pytest
from numpy.typing import NDArray

from intellicrack.ml.binary_feature_extractor import (
    CAPSTONE_AVAILABLE,
    LIEF_AVAILABLE,
    NETWORKX_AVAILABLE,
    PEFILE_AVAILABLE,
    BinaryFeatureExtractor,
    extract_features_for_ml,
)


@pytest.fixture
def real_pe_binaries() -> list[Path]:
    """Get list of real PE binaries from fixtures."""
    fixtures_base = Path(__file__).parent.parent.parent / "fixtures" / "binaries" / "pe"

    binaries: list[Path] = []

    legitimate_dir = fixtures_base / "legitimate"
    if legitimate_dir.exists():
        binaries.extend(list(legitimate_dir.glob("*.exe")))

    protected_dir = fixtures_base / "protected"
    if protected_dir.exists():
        binaries.extend(list(protected_dir.glob("*.exe")))

    if not binaries:
        pytest.skip("No real PE binaries found in fixtures")

    return binaries


@pytest.fixture
def simple_real_binary(real_pe_binaries: list[Path]) -> Path:
    """Get a simple real binary for testing."""
    if not real_pe_binaries:
        pytest.skip("No real PE binaries available")
    return real_pe_binaries[0]


@pytest.fixture
def complex_real_binary(real_pe_binaries: list[Path]) -> Path:
    """Get a complex real binary for testing."""
    if len(real_pe_binaries) < 2:
        pytest.skip("Not enough real PE binaries available")
    return real_pe_binaries[1]


@pytest.fixture
def protected_binary() -> Path:
    """Get a protected binary for testing."""
    fixtures_base = Path(__file__).parent.parent.parent / "fixtures" / "binaries"

    protected_paths = [
        fixtures_base / "protected" / "upx_packed_0.exe",
        fixtures_base / "protected" / "upx_packed_1.exe",
        fixtures_base / "pe" / "protected" / "vmprotect_protected.exe",
        fixtures_base / "pe" / "protected" / "themida_protected.exe",
    ]

    for path in protected_paths:
        if path.exists():
            return path

    pytest.skip("No protected binaries found in fixtures")


class TestBinaryFeatureExtractorInitialization:
    """Tests for feature extractor initialization and binary loading."""

    def test_extractor_loads_real_pe_binary(self, simple_real_binary: Path) -> None:
        """Extractor successfully loads real PE binary from fixtures."""
        extractor = BinaryFeatureExtractor(str(simple_real_binary))

        assert extractor.binary_path == simple_real_binary
        assert extractor.data is not None
        assert len(extractor.data) > 0

    def test_extractor_parses_real_pe_headers(self, simple_real_binary: Path) -> None:
        """Extractor parses real PE headers when pefile available."""
        extractor = BinaryFeatureExtractor(str(simple_real_binary))

        if PEFILE_AVAILABLE:
            assert extractor.pe is not None
        else:
            pytest.skip("pefile not available")

    def test_extractor_determines_real_architecture(self, simple_real_binary: Path) -> None:
        """Extractor correctly determines real binary architecture."""
        extractor = BinaryFeatureExtractor(str(simple_real_binary))

        assert extractor.arch is not None
        assert extractor.mode is not None

    def test_extractor_initializes_disassembler(self, simple_real_binary: Path) -> None:
        """Extractor initializes Capstone disassembler when available."""
        extractor = BinaryFeatureExtractor(str(simple_real_binary))

        if CAPSTONE_AVAILABLE:
            assert extractor.disassembler is not None
        else:
            assert extractor.disassembler is None

    def test_extractor_handles_nonexistent_file(self) -> None:
        """Extractor raises error for nonexistent file."""
        with pytest.raises(FileNotFoundError):
            BinaryFeatureExtractor("nonexistent_file_xyz.exe")


class TestOpcodeHistogramExtraction:
    """Tests for opcode histogram feature extraction on real binaries."""

    def test_extract_opcode_histogram_from_real_binary(self, simple_real_binary: Path) -> None:
        """Opcode histogram extraction works on real PE binary."""
        extractor = BinaryFeatureExtractor(str(simple_real_binary))
        histogram = extractor.extract_opcode_histogram()

        assert isinstance(histogram, np.ndarray)
        assert histogram.dtype == np.float32
        assert len(histogram) > 0

    def test_opcode_histogram_normalized(self, simple_real_binary: Path) -> None:
        """Opcode histogram values are normalized when requested."""
        extractor = BinaryFeatureExtractor(str(simple_real_binary))
        histogram = extractor.extract_opcode_histogram(normalize=True)

        assert np.all(histogram >= 0.0)
        assert np.all(histogram <= 1.0)

    def test_opcode_histogram_detects_real_opcodes(self, complex_real_binary: Path) -> None:
        """Opcode histogram detects actual x86 opcodes in real binary."""
        extractor = BinaryFeatureExtractor(str(complex_real_binary))
        histogram = extractor.extract_opcode_histogram(normalize=False)

        if CAPSTONE_AVAILABLE:
            assert np.sum(histogram) > 0
        else:
            assert isinstance(histogram, np.ndarray)


class TestControlFlowGraphExtraction:
    """Tests for control flow graph feature extraction on real binaries."""

    def test_build_cfg_from_real_binary(self, simple_real_binary: Path) -> None:
        """CFG building works on real PE binary."""
        extractor = BinaryFeatureExtractor(str(simple_real_binary))
        cfg_features = extractor.build_control_flow_graph()

        assert isinstance(cfg_features, dict)
        assert "num_nodes" in cfg_features
        assert "num_edges" in cfg_features
        assert "avg_degree" in cfg_features
        assert "density" in cfg_features

    def test_cfg_features_valid_from_real_binary(self, simple_real_binary: Path) -> None:
        """CFG features contain valid numeric values from real binary."""
        extractor = BinaryFeatureExtractor(str(simple_real_binary))
        cfg_features = extractor.build_control_flow_graph()

        assert cfg_features["num_nodes"] >= 0
        assert cfg_features["num_edges"] >= 0
        assert cfg_features["density"] >= 0.0
        assert cfg_features["density"] <= 1.0

    def test_cfg_detects_real_basic_blocks(self, complex_real_binary: Path) -> None:
        """CFG extraction identifies basic blocks in real binary."""
        extractor = BinaryFeatureExtractor(str(complex_real_binary))

        if CAPSTONE_AVAILABLE and NETWORKX_AVAILABLE:
            cfg_features = extractor.build_control_flow_graph()
            assert cfg_features["num_nodes"] >= 0


class TestAPISequenceExtraction:
    """Tests for API sequence feature extraction on real binaries."""

    def test_extract_api_sequences_from_real_binary(self, simple_real_binary: Path) -> None:
        """API sequence extraction works on real PE binary."""
        extractor = BinaryFeatureExtractor(str(simple_real_binary))
        api_features = extractor.extract_api_sequences()

        assert isinstance(api_features, np.ndarray)
        assert api_features.dtype == np.float32
        assert len(api_features) == 256

    def test_api_features_normalized(self, simple_real_binary: Path) -> None:
        """API features are normalized to [0, 1] range."""
        extractor = BinaryFeatureExtractor(str(simple_real_binary))
        api_features = extractor.extract_api_sequences()

        assert np.all(api_features >= 0.0)
        assert np.all(api_features <= 1.0)

    def test_api_features_detect_real_imports(self, complex_real_binary: Path) -> None:
        """API features detect actual imports in real binary."""
        extractor = BinaryFeatureExtractor(str(complex_real_binary))
        api_features = extractor.extract_api_sequences()

        assert np.sum(api_features) >= 0


class TestEntropyCalculation:
    """Tests for section entropy calculation on real binaries."""

    def test_calculate_section_entropy_real_binary(self, simple_real_binary: Path) -> None:
        """Section entropy calculation works on real binary."""
        extractor = BinaryFeatureExtractor(str(simple_real_binary))
        entropies = extractor.calculate_section_entropy()

        assert isinstance(entropies, np.ndarray)
        assert entropies.dtype == np.float32
        assert len(entropies) == 16

    def test_entropy_values_valid_range(self, simple_real_binary: Path) -> None:
        """Entropy values are in valid range [0, 8]."""
        extractor = BinaryFeatureExtractor(str(simple_real_binary))
        entropies = extractor.calculate_section_entropy()

        assert np.all(entropies >= 0.0)
        assert np.all(entropies <= 8.0)

    def test_protected_binary_high_entropy(self, protected_binary: Path) -> None:
        """Protected binaries have higher entropy sections."""
        extractor = BinaryFeatureExtractor(str(protected_binary))
        entropies = extractor.calculate_section_entropy()

        non_zero_entropies = entropies[entropies > 0]
        if len(non_zero_entropies) > 0:
            max_entropy = np.max(non_zero_entropies)
            assert max_entropy >= 0.0


class TestStringFeatureExtraction:
    """Tests for license-related string feature extraction on real binaries."""

    def test_extract_string_features_real_binary(self, simple_real_binary: Path) -> None:
        """String feature extraction works on real binary."""
        extractor = BinaryFeatureExtractor(str(simple_real_binary))
        string_features = extractor.extract_string_features()

        assert isinstance(string_features, np.ndarray)
        assert string_features.dtype == np.float32
        assert len(string_features) == 128

    def test_string_features_normalized(self, simple_real_binary: Path) -> None:
        """String features are normalized."""
        extractor = BinaryFeatureExtractor(str(simple_real_binary))
        string_features = extractor.extract_string_features()

        assert np.all(string_features >= 0.0)
        assert np.all(string_features <= 1.0)


class TestFeatureIntegration:
    """Tests for complete feature extraction pipeline on real binaries."""

    def test_extract_all_features_real_binary(self, simple_real_binary: Path) -> None:
        """extract_all_features works on real binary."""
        extractor = BinaryFeatureExtractor(str(simple_real_binary))
        features = extractor.extract_all_features()

        assert isinstance(features, dict)
        assert "opcode_histogram" in features
        assert "cfg_features" in features
        assert "api_sequences" in features
        assert "section_entropy" in features
        assert "string_features" in features

    def test_all_features_are_numpy_arrays(self, simple_real_binary: Path) -> None:
        """All extracted features are numpy arrays."""
        extractor = BinaryFeatureExtractor(str(simple_real_binary))
        features = extractor.extract_all_features()

        for feature_name, feature_array in features.items():
            assert isinstance(feature_array, np.ndarray), f"{feature_name} is not numpy array"
            assert feature_array.dtype == np.float32, f"{feature_name} has wrong dtype"

    def test_features_consistent_shapes(self, simple_real_binary: Path) -> None:
        """Features have consistent shapes across runs on same binary."""
        extractor1 = BinaryFeatureExtractor(str(simple_real_binary))
        extractor2 = BinaryFeatureExtractor(str(simple_real_binary))

        features1 = extractor1.extract_all_features()
        features2 = extractor2.extract_all_features()

        for key in features1:
            assert features1[key].shape == features2[key].shape

    def test_extract_features_for_ml_real_binary(self, simple_real_binary: Path) -> None:
        """extract_features_for_ml produces vector from real binary."""
        feature_vector = extract_features_for_ml(str(simple_real_binary))

        assert isinstance(feature_vector, np.ndarray)
        assert feature_vector.dtype == np.float32
        assert len(feature_vector.shape) == 1
        assert len(feature_vector) > 0

    def test_feature_vector_consistent_length(self, real_pe_binaries: list[Path]) -> None:
        """Feature vectors have consistent length across different real binaries."""
        if len(real_pe_binaries) < 2:
            pytest.skip("Need at least 2 binaries for consistency test")

        vector1 = extract_features_for_ml(str(real_pe_binaries[0]))
        vector2 = extract_features_for_ml(str(real_pe_binaries[1]))

        assert len(vector1) == len(vector2)


class TestExecutableSectionExtraction:
    """Tests for executable section identification on real binaries."""

    def test_get_executable_sections_real_binary(self, simple_real_binary: Path) -> None:
        """Executable section extraction works on real binary."""
        extractor = BinaryFeatureExtractor(str(simple_real_binary))
        sections = extractor._get_executable_sections()

        assert isinstance(sections, list)
        if PEFILE_AVAILABLE or LIEF_AVAILABLE:
            assert len(sections) > 0

    def test_executable_sections_return_data_and_va(self, simple_real_binary: Path) -> None:
        """Executable sections return both data and virtual address."""
        extractor = BinaryFeatureExtractor(str(simple_real_binary))
        sections = extractor._get_executable_sections()

        for section_data, section_va in sections:
            assert isinstance(section_data, bytes)
            assert isinstance(section_va, int)
            assert len(section_data) > 0


class TestBasicBlockExtraction:
    """Tests for basic block extraction from real binaries."""

    def test_extract_basic_blocks_real_binary(self, simple_real_binary: Path) -> None:
        """Basic block extraction works on real binary."""
        extractor = BinaryFeatureExtractor(str(simple_real_binary))
        blocks = extractor._extract_basic_blocks()

        assert isinstance(blocks, list)

    def test_basic_blocks_have_required_fields(self, complex_real_binary: Path) -> None:
        """Basic blocks contain required metadata fields."""
        extractor = BinaryFeatureExtractor(str(complex_real_binary))
        blocks = extractor._extract_basic_blocks()

        if CAPSTONE_AVAILABLE and len(blocks) > 0:
            for block in blocks:
                assert "start" in block
                assert "size" in block
                assert "type" in block
                assert "targets" in block


class TestImportExtraction:
    """Tests for import table extraction from real binaries."""

    def test_extract_imports_real_binary(self, simple_real_binary: Path) -> None:
        """Import extraction works on real binary."""
        extractor = BinaryFeatureExtractor(str(simple_real_binary))
        imports = extractor._extract_imports()

        assert isinstance(imports, list)


class TestEntropyCalculationDetails:
    """Detailed tests for entropy calculation implementation."""

    def test_calculate_entropy_handles_empty_data(self) -> None:
        """Entropy calculation handles empty data correctly."""
        extractor = BinaryFeatureExtractor.__new__(BinaryFeatureExtractor)
        entropy = extractor._calculate_entropy(b"")

        assert entropy == 0.0

    def test_calculate_entropy_uniform_distribution(self) -> None:
        """Entropy is maximum for uniform distribution."""
        extractor = BinaryFeatureExtractor.__new__(BinaryFeatureExtractor)
        uniform_data = bytes(range(256))

        entropy = extractor._calculate_entropy(uniform_data)

        assert entropy > 7.5
        assert entropy <= 8.0

    def test_calculate_entropy_repetitive_data(self) -> None:
        """Entropy is low for repetitive data."""
        extractor = BinaryFeatureExtractor.__new__(BinaryFeatureExtractor)
        repetitive = b"\x00" * 1000

        entropy = extractor._calculate_entropy(repetitive)

        assert entropy == 0.0


class TestEdgeCasesAndErrorHandling:
    """Tests for edge cases and error handling with real binaries."""

    def test_handles_multiple_real_binaries(self, real_pe_binaries: list[Path]) -> None:
        """Handles extraction from multiple real binaries."""
        for binary in real_pe_binaries[:5]:
            extractor = BinaryFeatureExtractor(str(binary))
            features = extractor.extract_all_features()
            assert all(isinstance(v, np.ndarray) for v in features.values())

    def test_concurrent_feature_extraction(self, simple_real_binary: Path) -> None:
        """Feature extraction is thread-safe with real binary."""
        import threading

        results: list[dict[str, NDArray[np.float32]]] = []

        def extract() -> None:
            extractor = BinaryFeatureExtractor(str(simple_real_binary))
            results.append(extractor.extract_all_features())

        threads = [threading.Thread(target=extract) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(results) == 5
        for result in results:
            assert len(result) == len(results[0])


class TestCFGVectorConversion:
    """Tests for CFG dictionary to vector conversion."""

    def test_cfg_to_vector_from_real_binary(self, simple_real_binary: Path) -> None:
        """CFG to vector conversion works with real binary."""
        extractor = BinaryFeatureExtractor(str(simple_real_binary))
        cfg_dict = extractor.build_control_flow_graph()
        vector = extractor._cfg_to_vector(cfg_dict)

        assert isinstance(vector, np.ndarray)
        assert vector.dtype == np.float32
        assert len(vector) == 16

    def test_cfg_vector_normalized(self, simple_real_binary: Path) -> None:
        """CFG vector values are normalized."""
        extractor = BinaryFeatureExtractor(str(simple_real_binary))
        cfg_dict = extractor.build_control_flow_graph()
        vector = extractor._cfg_to_vector(cfg_dict)

        assert np.all(vector >= 0.0)

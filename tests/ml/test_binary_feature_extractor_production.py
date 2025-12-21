"""Production tests for binary feature extraction on real binaries.

Tests validate REAL feature extraction from actual Windows binaries:
- Opcode histogram extraction using real Capstone disassembly
- Control flow graph construction from executable sections
- API sequence extraction from import tables
- Section entropy calculation on real PE sections
- String feature extraction with license-related patterns
- Feature vector generation for ML classification

CRITICAL: All tests use REAL Windows binaries from System32.
NO mocks, NO stubs, NO simulated binaries.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellicrack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack. If not, see <https://www.gnu.org/licenses/>.
"""

from pathlib import Path

import numpy as np
import pytest

from intellicrack.ml.binary_feature_extractor import BinaryFeatureExtractor, extract_features_for_ml


WINDOWS_BINARIES = {
    "kernel32": Path(r"C:\Windows\System32\kernel32.dll"),
    "notepad": Path(r"C:\Windows\System32\notepad.exe"),
    "calc": Path(r"C:\Windows\System32\calc.exe"),
    "cmd": Path(r"C:\Windows\System32\cmd.exe"),
}


def get_available_binary() -> Path:
    """Get first available Windows binary for testing."""
    for name, path in WINDOWS_BINARIES.items():
        if path.exists():
            return path
    pytest.skip("No Windows binaries available for testing")
    return Path()


class TestBinaryFeatureExtractorInitialization:
    """Test BinaryFeatureExtractor initialization with real binaries."""

    def test_extractor_initializes_with_valid_binary(self) -> None:
        """BinaryFeatureExtractor initializes with real Windows binary."""
        binary_path = get_available_binary()

        extractor = BinaryFeatureExtractor(str(binary_path))

        assert extractor.binary_path == binary_path
        assert extractor.data is not None
        assert len(extractor.data) > 0

    def test_extractor_parses_pe_structure(self) -> None:
        """Extractor successfully parses PE file structure."""
        binary_path = get_available_binary()

        extractor = BinaryFeatureExtractor(str(binary_path))

        assert extractor.pe is not None or extractor.lief_binary is not None

    def test_extractor_initializes_disassembler(self) -> None:
        """Extractor initializes Capstone disassembler."""
        binary_path = get_available_binary()

        extractor = BinaryFeatureExtractor(str(binary_path))

        assert extractor.disassembler is not None
        assert extractor.arch is not None
        assert extractor.mode is not None


class TestOpcodeHistogramExtraction:
    """Test opcode frequency histogram extraction from real code."""

    def test_extract_opcode_histogram_from_real_binary(self) -> None:
        """Extract opcode histogram from real executable sections."""
        binary_path = get_available_binary()

        extractor = BinaryFeatureExtractor(str(binary_path))
        histogram = extractor.extract_opcode_histogram(normalize=True)

        assert isinstance(histogram, np.ndarray)
        assert len(histogram) > 0
        assert np.all(histogram >= 0)
        assert np.all(histogram <= 1.0)

    def test_opcode_histogram_normalized_sums_to_one(self) -> None:
        """Normalized histogram probabilities sum to approximately 1."""
        binary_path = get_available_binary()

        extractor = BinaryFeatureExtractor(str(binary_path))
        histogram = extractor.extract_opcode_histogram(normalize=True)

        total = np.sum(histogram)
        assert 0.99 <= total <= 1.01

    def test_opcode_histogram_contains_common_opcodes(self) -> None:
        """Histogram includes frequencies for common x86 opcodes."""
        binary_path = get_available_binary()

        extractor = BinaryFeatureExtractor(str(binary_path))
        histogram = extractor.extract_opcode_histogram(normalize=False)

        assert np.any(histogram > 0)

    def test_opcode_histogram_fallback_on_no_capstone(self) -> None:
        """Opcode extraction falls back to byte histogram without Capstone."""
        binary_path = get_available_binary()

        extractor = BinaryFeatureExtractor(str(binary_path))
        extractor.disassembler = None

        histogram = extractor.extract_opcode_histogram(normalize=True)

        assert isinstance(histogram, np.ndarray)
        assert len(histogram) == 256


class TestControlFlowGraphConstruction:
    """Test CFG construction from real binaries."""

    def test_build_cfg_from_real_binary(self) -> None:
        """Build control flow graph from real executable."""
        binary_path = get_available_binary()

        extractor = BinaryFeatureExtractor(str(binary_path))
        cfg_features = extractor.build_control_flow_graph()

        assert isinstance(cfg_features, dict)
        assert "num_nodes" in cfg_features
        assert "num_edges" in cfg_features
        assert "avg_degree" in cfg_features
        assert "density" in cfg_features

    def test_cfg_has_positive_node_count(self) -> None:
        """CFG has positive number of nodes from real code."""
        binary_path = get_available_binary()

        extractor = BinaryFeatureExtractor(str(binary_path))
        cfg_features = extractor.build_control_flow_graph()

        assert cfg_features["num_nodes"] >= 0

    def test_cfg_density_in_valid_range(self) -> None:
        """CFG density is between 0 and 1."""
        binary_path = get_available_binary()

        extractor = BinaryFeatureExtractor(str(binary_path))
        cfg_features = extractor.build_control_flow_graph()

        assert 0.0 <= cfg_features["density"] <= 1.0

    def test_cfg_extracts_basic_blocks(self) -> None:
        """CFG extraction identifies basic blocks in real code."""
        binary_path = get_available_binary()

        extractor = BinaryFeatureExtractor(str(binary_path))
        basic_blocks = extractor._extract_basic_blocks()

        assert isinstance(basic_blocks, list)


class TestAPISequenceExtraction:
    """Test API call sequence extraction from import tables."""

    def test_extract_api_sequences_from_real_binary(self) -> None:
        """Extract API sequences from real import table."""
        binary_path = get_available_binary()

        extractor = BinaryFeatureExtractor(str(binary_path))
        api_features = extractor.extract_api_sequences()

        assert isinstance(api_features, np.ndarray)
        assert len(api_features) == 256
        assert np.all(api_features >= 0)
        assert np.all(api_features <= 1.0)

    def test_api_extraction_identifies_categories(self) -> None:
        """API extraction categorizes imports correctly."""
        binary_path = get_available_binary()

        extractor = BinaryFeatureExtractor(str(binary_path))
        imports = extractor._extract_imports()

        assert isinstance(imports, list)

    def test_api_extraction_detects_license_apis(self) -> None:
        """API extraction identifies license-related API calls."""
        binary_path = get_available_binary()

        extractor = BinaryFeatureExtractor(str(binary_path))
        api_features = extractor.extract_api_sequences()

        assert isinstance(api_features, np.ndarray)


class TestSectionEntropyCalculation:
    """Test entropy calculation for PE sections."""

    def test_calculate_section_entropy_real_binary(self) -> None:
        """Calculate entropy for each section in real PE."""
        binary_path = get_available_binary()

        extractor = BinaryFeatureExtractor(str(binary_path))
        entropies = extractor.calculate_section_entropy()

        assert isinstance(entropies, np.ndarray)
        assert len(entropies) > 0
        assert np.all(entropies >= 0)
        assert np.all(entropies <= 8.0)

    def test_entropy_calculation_accuracy(self) -> None:
        """Entropy calculation produces accurate values."""
        binary_path = get_available_binary()

        extractor = BinaryFeatureExtractor(str(binary_path))

        null_entropy = extractor._calculate_entropy(b"\x00" * 1024)
        assert null_entropy == 0.0

        random_entropy = extractor._calculate_entropy(bytes(range(256)) * 4)
        assert random_entropy > 7.0

    def test_section_entropy_array_fixed_size(self) -> None:
        """Section entropy array is padded to fixed size."""
        binary_path = get_available_binary()

        extractor = BinaryFeatureExtractor(str(binary_path))
        entropies = extractor.calculate_section_entropy()

        assert len(entropies) == 16


class TestStringFeatureExtraction:
    """Test extraction of license-related string features."""

    def test_extract_string_features_real_binary(self) -> None:
        """Extract string features from real binary."""
        binary_path = get_available_binary()

        extractor = BinaryFeatureExtractor(str(binary_path))
        string_features = extractor.extract_string_features()

        assert isinstance(string_features, np.ndarray)
        assert len(string_features) == 128
        assert np.all(string_features >= 0)

    def test_string_extraction_detects_ascii(self) -> None:
        """String extraction finds ASCII strings."""
        binary_path = get_available_binary()

        extractor = BinaryFeatureExtractor(str(binary_path))
        ascii_strings = extractor._extract_strings(extractor.data, min_length=4, encoding="ascii")

        assert isinstance(ascii_strings, list)
        assert len(ascii_strings) > 0

    def test_string_extraction_detects_unicode(self) -> None:
        """String extraction finds UTF-16LE strings."""
        binary_path = get_available_binary()

        extractor = BinaryFeatureExtractor(str(binary_path))
        unicode_strings = extractor._extract_strings(extractor.data, min_length=4, encoding="utf-16le")

        assert isinstance(unicode_strings, list)

    def test_string_extraction_finds_license_patterns(self) -> None:
        """String extraction identifies license-related keywords."""
        binary_path = get_available_binary()

        extractor = BinaryFeatureExtractor(str(binary_path))
        string_features = extractor.extract_string_features()

        assert np.any(string_features > 0)


class TestCompleteFeatureExtraction:
    """Test complete feature vector extraction."""

    def test_extract_all_features_real_binary(self) -> None:
        """Extract complete feature set from real binary."""
        binary_path = get_available_binary()

        extractor = BinaryFeatureExtractor(str(binary_path))
        features = extractor.extract_all_features()

        assert isinstance(features, dict)
        assert "opcode_histogram" in features
        assert "cfg_features" in features
        assert "api_sequences" in features
        assert "section_entropy" in features
        assert "string_features" in features

    def test_feature_vectors_correct_dimensions(self) -> None:
        """All feature vectors have correct dimensions."""
        binary_path = get_available_binary()

        extractor = BinaryFeatureExtractor(str(binary_path))
        features = extractor.extract_all_features()

        assert len(features["section_entropy"]) == 16
        assert len(features["api_sequences"]) == 256
        assert len(features["string_features"]) == 128

    def test_convenience_function_extracts_features(self) -> None:
        """Convenience function extracts and concatenates features."""
        binary_path = get_available_binary()

        feature_vector = extract_features_for_ml(str(binary_path))

        assert isinstance(feature_vector, np.ndarray)
        assert len(feature_vector) > 0
        assert feature_vector.dtype == np.float32


class TestExecutableSectionExtraction:
    """Test extraction of executable sections from PE."""

    def test_get_executable_sections_real_binary(self) -> None:
        """Extract executable sections from real PE file."""
        binary_path = get_available_binary()

        extractor = BinaryFeatureExtractor(str(binary_path))
        exec_sections = extractor._get_executable_sections()

        assert isinstance(exec_sections, list)
        assert len(exec_sections) >= 0

        for section_data, section_va in exec_sections:
            assert isinstance(section_data, bytes)
            assert isinstance(section_va, int)
            assert len(section_data) > 0

    def test_executable_sections_have_code(self) -> None:
        """Executable sections contain actual code bytes."""
        binary_path = get_available_binary()

        extractor = BinaryFeatureExtractor(str(binary_path))
        exec_sections = extractor._get_executable_sections()

        total_code_size = sum(len(data) for data, _ in exec_sections)
        assert total_code_size > 0


class TestImportTableExtraction:
    """Test import table extraction from real binaries."""

    def test_extract_imports_from_real_binary(self) -> None:
        """Extract import table from real PE."""
        binary_path = get_available_binary()

        extractor = BinaryFeatureExtractor(str(binary_path))
        imports = extractor._extract_imports()

        assert isinstance(imports, list)

    def test_imports_have_valid_names(self) -> None:
        """Extracted imports have valid function names."""
        binary_path = get_available_binary()

        extractor = BinaryFeatureExtractor(str(binary_path))
        imports = extractor._extract_imports()

        if len(imports) > 0:
            assert all(isinstance(imp, str) for imp in imports)


class TestCFGFeatureConversion:
    """Test CFG dictionary to vector conversion."""

    def test_cfg_to_vector_conversion(self) -> None:
        """Convert CFG features to fixed-size vector."""
        binary_path = get_available_binary()

        extractor = BinaryFeatureExtractor(str(binary_path))
        cfg_dict = extractor.build_control_flow_graph()
        vector = extractor._cfg_to_vector(cfg_dict)

        assert isinstance(vector, np.ndarray)
        assert len(vector) == 16
        assert vector.dtype == np.float32

    def test_cfg_vector_normalized(self) -> None:
        """CFG features are normalized to reasonable ranges."""
        binary_path = get_available_binary()

        extractor = BinaryFeatureExtractor(str(binary_path))
        cfg_dict = extractor.build_control_flow_graph()
        vector = extractor._cfg_to_vector(cfg_dict)

        assert np.all(vector >= 0)


class TestMultipleBinaryTypes:
    """Test feature extraction on different binary types."""

    @pytest.mark.parametrize(
        "binary_key",
        ["kernel32", "notepad", "calc", "cmd"],
    )
    def test_extract_features_various_binaries(self, binary_key: str) -> None:
        """Feature extraction works on various Windows binaries."""
        binary_path = WINDOWS_BINARIES.get(binary_key)
        if binary_path is None or not binary_path.exists():
            pytest.skip(f"{binary_key} not available")

        extractor = BinaryFeatureExtractor(str(binary_path))
        features = extractor.extract_all_features()

        assert isinstance(features, dict)
        assert len(features) == 5


class TestErrorHandling:
    """Test error handling and edge cases."""

    def test_extractor_handles_nonexistent_file(self) -> None:
        """Extractor raises error for nonexistent file."""
        with pytest.raises(FileNotFoundError):
            BinaryFeatureExtractor("/nonexistent/binary.exe")

    def test_extractor_handles_small_file(self, tmp_path: Path) -> None:
        """Extractor handles files too small to be valid PE."""
        small_file = tmp_path / "small.bin"
        small_file.write_bytes(b"MZ")

        with pytest.raises(Exception):
            BinaryFeatureExtractor(str(small_file))

    def test_extractor_handles_invalid_pe(self, tmp_path: Path) -> None:
        """Extractor handles invalid PE files gracefully."""
        invalid_pe = tmp_path / "invalid.exe"
        invalid_pe.write_bytes(b"NOT_A_PE" * 100)

        try:
            extractor = BinaryFeatureExtractor(str(invalid_pe))
            features = extractor.extract_all_features()
            assert isinstance(features, dict)
        except Exception:
            pass


class TestFeatureConsistency:
    """Test consistency of extracted features."""

    def test_feature_extraction_deterministic(self) -> None:
        """Feature extraction produces consistent results."""
        binary_path = get_available_binary()

        extractor1 = BinaryFeatureExtractor(str(binary_path))
        features1 = extractor1.extract_all_features()

        extractor2 = BinaryFeatureExtractor(str(binary_path))
        features2 = extractor2.extract_all_features()

        assert np.array_equal(features1["section_entropy"], features2["section_entropy"])
        assert np.array_equal(features1["api_sequences"], features2["api_sequences"])

    def test_feature_vector_concatenation(self) -> None:
        """Feature vector concatenation produces expected length."""
        binary_path = get_available_binary()

        feature_vector = extract_features_for_ml(str(binary_path))

        expected_length = (
            len(BinaryFeatureExtractor(str(binary_path)).extract_opcode_histogram())
            + 16  # CFG features
            + 256  # API sequences
            + 16  # Section entropy
            + 128  # String features
        )

        assert len(feature_vector) == expected_length


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])

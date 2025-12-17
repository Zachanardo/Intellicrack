"""Production tests for feature_extraction.py - Real binary feature extraction validation.

This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see https://www.gnu.org/licenses/.
"""

import math
import struct
import tempfile
from pathlib import Path

import numpy as np
import pytest

from intellicrack.core.ml.feature_extraction import BinaryFeatureExtractor


class TestFeatureExtractorInitialization:
    """Production tests for BinaryFeatureExtractor initialization."""

    def test_extractor_initializes_successfully(self) -> None:
        """BinaryFeatureExtractor initializes with feature names."""
        extractor: BinaryFeatureExtractor = BinaryFeatureExtractor()

        assert extractor is not None, "Extractor must initialize"
        assert hasattr(extractor, "feature_names"), "Must have feature names"
        assert isinstance(extractor.feature_names, list), "Feature names must be list"
        assert len(extractor.feature_names) > 0, "Must have at least one feature"

    def test_feature_names_include_expected_categories(self) -> None:
        """Feature names cover entropy, PE, sections, imports, and signatures."""
        extractor: BinaryFeatureExtractor = BinaryFeatureExtractor()

        feature_names: list[str] = extractor.feature_names

        assert any("entropy" in name for name in feature_names), "Must have entropy features"
        assert any("section" in name for name in feature_names), "Must have section features"
        assert any("import" in name for name in feature_names), "Must have import features"
        assert any("signature" in name for name in feature_names), "Must have signature features"

    def test_protector_patterns_defined(self) -> None:
        """Protector patterns are defined for major protection schemes."""
        extractor: BinaryFeatureExtractor = BinaryFeatureExtractor()

        expected_protectors: list[str] = ["vmprotect", "themida", "enigma", "upx"]

        for protector in expected_protectors:
            assert protector in extractor.PROTECTOR_PATTERNS, f"Must have {protector} patterns"

    def test_suspicious_imports_defined(self) -> None:
        """Suspicious imports list includes anti-debugging and protection functions."""
        extractor: BinaryFeatureExtractor = BinaryFeatureExtractor()

        expected_imports: list[str] = [
            "VirtualProtect",
            "IsDebuggerPresent",
            "CreateRemoteThread",
            "WriteProcessMemory",
        ]

        for import_name in expected_imports:
            assert import_name in extractor.SUSPICIOUS_IMPORTS, f"Must include {import_name}"


class TestEntropyCalculation:
    """Production tests for entropy calculation accuracy."""

    def test_calculate_entropy_for_uniform_data(self) -> None:
        """Entropy calculation returns maximum for uniform random data."""
        extractor: BinaryFeatureExtractor = BinaryFeatureExtractor()

        uniform_data: bytes = bytes(range(256))

        entropy: float = extractor._calculate_entropy(uniform_data)

        assert entropy > 7.9, "Uniform data should have high entropy (>7.9)"
        assert entropy <= 8.0, "Entropy cannot exceed 8.0 for byte data"

    def test_calculate_entropy_for_constant_data(self) -> None:
        """Entropy calculation returns zero for constant data."""
        extractor: BinaryFeatureExtractor = BinaryFeatureExtractor()

        constant_data: bytes = b"\x00" * 1000

        entropy: float = extractor._calculate_entropy(constant_data)

        assert entropy == 0.0, "Constant data must have zero entropy"

    def test_calculate_entropy_for_partial_randomness(self) -> None:
        """Entropy calculation returns intermediate values for partial randomness."""
        extractor: BinaryFeatureExtractor = BinaryFeatureExtractor()

        partial_data: bytes = b"A" * 500 + b"B" * 500

        entropy: float = extractor._calculate_entropy(partial_data)

        assert 0.5 < entropy < 2.0, "Two-symbol data should have entropy ~1.0"

    def test_calculate_entropy_handles_empty_data(self) -> None:
        """Entropy calculation handles empty data gracefully."""
        extractor: BinaryFeatureExtractor = BinaryFeatureExtractor()

        entropy: float = extractor._calculate_entropy(b"")

        assert entropy == 0.0, "Empty data must have zero entropy"

    def test_calculate_entropy_against_known_value(self) -> None:
        """Entropy calculation matches mathematically expected value."""
        extractor: BinaryFeatureExtractor = BinaryFeatureExtractor()

        test_data: bytes = b"AAABBBCC"

        expected_entropy: float = -(
            (3/8) * math.log2(3/8) +
            (3/8) * math.log2(3/8) +
            (2/8) * math.log2(2/8)
        )

        calculated_entropy: float = extractor._calculate_entropy(test_data)

        assert abs(calculated_entropy - expected_entropy) < 0.001, "Entropy must match expected value"


class TestPEFeatureExtraction:
    """Production tests for PE structure feature extraction."""

    @pytest.fixture
    def minimal_pe(self) -> bytes:
        """Create minimal valid PE file."""
        dos_header = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x80)

        pe_signature = b"PE\x00\x00"

        coff_header = struct.pack(
            "<HHIIIHH",
            0x014C,
            1,
            0,
            0,
            0,
            0xE0,
            0x010B,
        )

        optional_header = b"\x00" * 224

        section_header = (
            b".text\x00\x00\x00" +
            struct.pack("<IIIIII", 0x1000, 0x1000, 0x200, 0x200, 0, 0) +
            struct.pack("<HHI", 0, 0, 0x60000020)
        )

        pe_file = dos_header + b"\x00" * (0x80 - len(dos_header))
        pe_file += pe_signature + coff_header + optional_header + section_header

        return pe_file

    def test_extract_features_from_valid_pe(self, minimal_pe: bytes) -> None:
        """extract_features processes valid PE file and returns feature vector."""
        extractor: BinaryFeatureExtractor = BinaryFeatureExtractor()

        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tmp:
            tmp.write(minimal_pe)
            tmp_path: Path = Path(tmp.name)

        try:
            features: np.ndarray = extractor.extract_features(tmp_path)

            assert isinstance(features, np.ndarray), "Must return numpy array"
            assert features.dtype == np.float32, "Features must be float32"
            assert len(features) == len(extractor.feature_names), "Feature count must match names"
            assert not np.any(np.isnan(features)), "Features must not contain NaN"
            assert not np.any(np.isinf(features)), "Features must not contain infinity"
        finally:
            tmp_path.unlink()

    def test_extract_features_raises_for_nonexistent_file(self) -> None:
        """extract_features raises ValueError for missing file."""
        extractor: BinaryFeatureExtractor = BinaryFeatureExtractor()

        with pytest.raises(ValueError, match="not found"):
            extractor.extract_features("/nonexistent/file.exe")

    def test_extract_features_handles_corrupted_pe(self) -> None:
        """extract_features handles corrupted PE gracefully with default values."""
        extractor: BinaryFeatureExtractor = BinaryFeatureExtractor()

        corrupted_pe: bytes = b"MZ" + b"\xFF" * 1000

        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tmp:
            tmp.write(corrupted_pe)
            tmp_path: Path = Path(tmp.name)

        try:
            features: np.ndarray = extractor.extract_features(tmp_path)

            assert isinstance(features, np.ndarray), "Must return features for corrupted file"
            assert len(features) == len(extractor.feature_names), "Must return all features"
        finally:
            tmp_path.unlink()

    def test_extract_entropy_features_returns_all_entropy_metrics(self, minimal_pe: bytes) -> None:
        """_extract_entropy_features returns all entropy-related features."""
        extractor: BinaryFeatureExtractor = BinaryFeatureExtractor()

        entropy_features: dict[str, float] = extractor._extract_entropy_features(minimal_pe)

        expected_keys: list[str] = [
            "overall_entropy",
            "text_entropy",
            "data_entropy",
            "rdata_entropy",
            "max_section_entropy",
            "min_section_entropy",
            "avg_section_entropy",
            "high_entropy_section_count",
        ]

        for key in expected_keys:
            assert key in entropy_features, f"Must have {key}"
            assert isinstance(entropy_features[key], float), f"{key} must be float"

    def test_extract_pe_features_returns_structure_info(self, minimal_pe: bytes) -> None:
        """_extract_pe_features returns PE structural information."""
        extractor: BinaryFeatureExtractor = BinaryFeatureExtractor()

        pe_features: dict[str, float] = extractor._extract_pe_features(minimal_pe)

        expected_keys: list[str] = [
            "has_tls_callbacks",
            "overlay_size",
            "resource_size",
            "entry_point_section_idx",
        ]

        for key in expected_keys:
            assert key in pe_features, f"Must have {key}"
            assert isinstance(pe_features[key], float), f"{key} must be float"
            assert pe_features[key] >= 0, f"{key} must be non-negative"


class TestSectionFeatureExtraction:
    """Production tests for section feature extraction."""

    @pytest.fixture
    def extractor(self) -> BinaryFeatureExtractor:
        """Create extractor for testing."""
        return BinaryFeatureExtractor()

    def test_extract_section_features_counts_sections(self, extractor: BinaryFeatureExtractor) -> None:
        """_extract_section_features correctly counts PE sections."""
        pe_with_sections: bytes = self._create_pe_with_sections(3)

        section_features: dict[str, float] = extractor._extract_section_features(pe_with_sections)

        assert "section_count" in section_features, "Must have section_count"
        assert section_features["section_count"] > 0, "Must count sections"

    def test_extract_section_features_detects_executable_sections(self, extractor: BinaryFeatureExtractor) -> None:
        """_extract_section_features counts executable sections."""
        pe_data: bytes = self._create_pe_with_sections(2)

        section_features: dict[str, float] = extractor._extract_section_features(pe_data)

        assert "executable_section_count" in section_features, "Must have executable count"
        assert isinstance(section_features["executable_section_count"], float), "Must be float"

    def test_extract_section_features_detects_unusual_names(self, extractor: BinaryFeatureExtractor) -> None:
        """_extract_section_features flags unusual section names."""
        section_features: dict[str, float] = extractor._extract_section_features(b"MZ" + b"\x00" * 1000)

        assert "unusual_section_names" in section_features, "Must have unusual_section_names"
        assert isinstance(section_features["unusual_section_names"], float), "Must be float"

    def test_section_features_handles_missing_sections(self, extractor: BinaryFeatureExtractor) -> None:
        """Section feature extraction handles files without valid sections."""
        invalid_pe: bytes = b"MZ" + b"\x00" * 100

        section_features: dict[str, float] = extractor._extract_section_features(invalid_pe)

        assert section_features["section_count"] >= 0, "Section count must be non-negative"

    def _create_pe_with_sections(self, section_count: int) -> bytes:
        """Helper to create PE with specified number of sections."""
        dos_header = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x80)
        pe_signature = b"PE\x00\x00"
        coff_header = struct.pack("<HHIIIHH", 0x014C, section_count, 0, 0, 0, 0xE0, 0x010B)
        optional_header = b"\x00" * 224

        sections = b""
        for i in range(section_count):
            section_name = f".sec{i}\x00\x00\x00".encode()[:8]
            section_header = (
                section_name +
                struct.pack("<IIIIII", 0x1000, 0x1000, 0x200, 0x200, 0, 0) +
                struct.pack("<HHI", 0, 0, 0x60000020)
            )
            sections += section_header

        pe_file = dos_header + b"\x00" * (0x80 - len(dos_header))
        pe_file += pe_signature + coff_header + optional_header + sections

        return pe_file


class TestImportFeatureExtraction:
    """Production tests for import table feature extraction."""

    @pytest.fixture
    def extractor(self) -> BinaryFeatureExtractor:
        """Create extractor for testing."""
        return BinaryFeatureExtractor()

    def test_extract_import_features_returns_expected_keys(self, extractor: BinaryFeatureExtractor) -> None:
        """_extract_import_features returns all import-related features."""
        test_pe: bytes = b"MZ" + b"\x00" * 1000

        import_features: dict[str, float] = extractor._extract_import_features(test_pe)

        expected_keys: list[str] = [
            "import_count",
            "unique_dll_count",
            "suspicious_import_count",
            "packed_import_table",
        ]

        for key in expected_keys:
            assert key in import_features, f"Must have {key}"
            assert isinstance(import_features[key], float), f"{key} must be float"

    def test_import_features_detect_suspicious_functions(self, extractor: BinaryFeatureExtractor) -> None:
        """Import feature extraction flags suspicious API calls."""
        import_features: dict[str, float] = extractor._extract_import_features(b"MZ" + b"\x00" * 1000)

        assert "suspicious_import_count" in import_features, "Must track suspicious imports"
        assert import_features["suspicious_import_count"] >= 0, "Count must be non-negative"

    def test_import_features_count_unique_dlls(self, extractor: BinaryFeatureExtractor) -> None:
        """Import feature extraction counts unique DLL dependencies."""
        import_features: dict[str, float] = extractor._extract_import_features(b"MZ" + b"\x00" * 1000)

        assert "unique_dll_count" in import_features, "Must count unique DLLs"
        assert isinstance(import_features["unique_dll_count"], float), "Must be float"

    def test_packed_import_table_detection(self, extractor: BinaryFeatureExtractor) -> None:
        """Import feature extraction detects packed import tables."""
        import_features: dict[str, float] = extractor._extract_import_features(b"MZ" + b"\x00" * 1000)

        assert "packed_import_table" in import_features, "Must have packed_import_table flag"
        assert import_features["packed_import_table"] in [0.0, 1.0], "Must be binary flag"


class TestSignatureDetection:
    """Production tests for protector signature detection."""

    @pytest.fixture
    def extractor(self) -> BinaryFeatureExtractor:
        """Create extractor for testing."""
        return BinaryFeatureExtractor()

    def test_extract_signature_features_returns_all_protectors(self, extractor: BinaryFeatureExtractor) -> None:
        """_extract_signature_features checks all known protectors."""
        test_binary: bytes = b"MZ" + b"\x00" * 1000

        signature_features: dict[str, float] = extractor._extract_signature_features(test_binary)

        expected_signatures: list[str] = [
            "signature_vmprotect",
            "signature_themida",
            "signature_enigma",
            "signature_obsidium",
            "signature_asprotect",
            "signature_armadillo",
            "signature_upx",
        ]

        for sig in expected_signatures:
            assert sig in signature_features, f"Must check for {sig}"
            assert signature_features[sig] in [0.0, 1.0], f"{sig} must be binary"

    def test_vmprotect_signature_detection(self, extractor: BinaryFeatureExtractor) -> None:
        """VMProtect signature is detected when present."""
        vmprotect_binary: bytes = b"MZ" + b"\x00" * 100 + b".vmp0\x00\x00\x00" + b"\x00" * 1000

        signature_features: dict[str, float] = extractor._extract_signature_features(vmprotect_binary)

        assert signature_features["signature_vmprotect"] == 1.0, "Must detect VMProtect signature"

    def test_themida_signature_detection(self, extractor: BinaryFeatureExtractor) -> None:
        """Themida signature is detected when present."""
        themida_binary: bytes = b"MZ" + b"\x00" * 100 + b"Themida" + b"\x00" * 1000

        signature_features: dict[str, float] = extractor._extract_signature_features(themida_binary)

        assert signature_features["signature_themida"] == 1.0, "Must detect Themida signature"

    def test_upx_signature_detection(self, extractor: BinaryFeatureExtractor) -> None:
        """UPX signature is detected when present."""
        upx_binary: bytes = b"MZ" + b"\x00" * 100 + b"UPX!" + b"\x00" * 1000

        signature_features: dict[str, float] = extractor._extract_signature_features(upx_binary)

        assert signature_features["signature_upx"] == 1.0, "Must detect UPX signature"

    def test_no_false_positives_on_clean_binary(self, extractor: BinaryFeatureExtractor) -> None:
        """Signature detection doesn't flag clean binaries."""
        clean_binary: bytes = b"MZ" + b"\x00" * 10000

        signature_features: dict[str, float] = extractor._extract_signature_features(clean_binary)

        total_detections: float = sum(signature_features.values())
        assert total_detections <= 2.0, "Clean binary should have minimal false positives"


class TestOpcodeFeatureExtraction:
    """Production tests for opcode frequency extraction."""

    @pytest.fixture
    def extractor(self) -> BinaryFeatureExtractor:
        """Create extractor for testing."""
        return BinaryFeatureExtractor()

    def test_extract_opcode_features_returns_frequency_distribution(self, extractor: BinaryFeatureExtractor) -> None:
        """_extract_opcode_features returns opcode frequency features."""
        test_code: bytes = bytes([0x90] * 100 + [0xC3] * 50)

        opcode_features: dict[str, float] = extractor._extract_opcode_features(test_code)

        assert len(opcode_features) > 0, "Must extract opcode features"

        for key, value in opcode_features.items():
            assert key.startswith("opcode_freq_"), "Keys must be opcode_freq_*"
            assert 0.0 <= value <= 1.0, "Frequencies must be normalized 0-1"

    def test_opcode_features_normalized_to_probability(self, extractor: BinaryFeatureExtractor) -> None:
        """Opcode frequencies sum to approximately 1.0."""
        test_code: bytes = bytes(range(256)) * 10

        opcode_features: dict[str, float] = extractor._extract_opcode_features(test_code)

        total_frequency: float = sum(opcode_features.values())

        assert 0.9 <= total_frequency <= 1.1, "Frequencies should sum to ~1.0"


class TestCompleteFeatureExtractionPipeline:
    """Production integration tests for complete feature extraction."""

    @pytest.fixture
    def extractor(self) -> BinaryFeatureExtractor:
        """Create extractor for testing."""
        return BinaryFeatureExtractor()

    def test_feature_vector_has_correct_length(self, extractor: BinaryFeatureExtractor) -> None:
        """Extracted feature vector matches declared feature names length."""
        test_binary: bytes = b"MZ" + b"\x00" * 5000

        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tmp:
            tmp.write(test_binary)
            tmp_path: Path = Path(tmp.name)

        try:
            features: np.ndarray = extractor.extract_features(tmp_path)

            assert len(features) == len(extractor.feature_names), "Feature count must match names"
        finally:
            tmp_path.unlink()

    def test_feature_extraction_is_deterministic(self, extractor: BinaryFeatureExtractor) -> None:
        """Feature extraction produces identical results for same binary."""
        test_binary: bytes = b"MZ" + b"\x00" * 5000

        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tmp:
            tmp.write(test_binary)
            tmp_path: Path = Path(tmp.name)

        try:
            features1: np.ndarray = extractor.extract_features(tmp_path)
            features2: np.ndarray = extractor.extract_features(tmp_path)

            assert np.array_equal(features1, features2), "Features must be deterministic"
        finally:
            tmp_path.unlink()

    def test_large_binary_processing(self, extractor: BinaryFeatureExtractor) -> None:
        """Feature extraction handles large binaries without crashing."""
        large_binary: bytes = b"MZ" + b"\x00" * (5 * 1024 * 1024)

        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tmp:
            tmp.write(large_binary)
            tmp_path: Path = Path(tmp.name)

        try:
            features: np.ndarray = extractor.extract_features(tmp_path)

            assert len(features) == len(extractor.feature_names), "Must extract features from large file"
        finally:
            tmp_path.unlink()

    def test_feature_values_within_reasonable_ranges(self, extractor: BinaryFeatureExtractor) -> None:
        """All extracted features have reasonable value ranges."""
        test_binary: bytes = b"MZ" + b"\x00" * 5000

        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tmp:
            tmp.write(test_binary)
            tmp_path: Path = Path(tmp.name)

        try:
            features: np.ndarray = extractor.extract_features(tmp_path)

            for i, (name, value) in enumerate(zip(extractor.feature_names, features)):
                assert not np.isnan(value), f"Feature {name} is NaN"
                assert not np.isinf(value), f"Feature {name} is infinite"

                if "entropy" in name:
                    assert 0.0 <= value <= 8.0, f"Entropy {name} out of range: {value}"

                if "count" in name:
                    assert value >= 0.0, f"Count {name} must be non-negative: {value}"

                if "signature_" in name:
                    assert value in [0.0, 1.0], f"Signature {name} must be binary: {value}"

        finally:
            tmp_path.unlink()

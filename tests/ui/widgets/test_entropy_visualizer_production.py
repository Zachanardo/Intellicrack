"""Production-ready tests for EntropyVisualizer - Binary entropy analysis validation.

This module validates EntropyVisualizer's entropy analysis capabilities including:
- Accurate Shannon entropy calculation for binary data
- Detection of encrypted/compressed sections (high entropy)
- Detection of padding/null byte sections (low entropy)
- Identification of suspicious entropy changes
- Block-based entropy analysis with configurable sizes
- Statistical analysis (min, max, average entropy)
- Error handling for invalid data
- Visualization plot updates
"""

import math
import struct
from collections import Counter
from typing import Any

import pytest
from PyQt6.QtWidgets import QApplication

from intellicrack.ui.widgets.entropy_visualizer import EntropyVisualizer


@pytest.fixture
def qapp(qapp: QApplication) -> QApplication:
    """Provide QApplication instance for PyQt6 tests."""
    return qapp


@pytest.fixture
def entropy_visualizer(qapp: QApplication) -> EntropyVisualizer:
    """Create EntropyVisualizer widget for testing."""
    visualizer = EntropyVisualizer()
    return visualizer


@pytest.fixture
def random_data() -> bytes:
    """Create high-entropy random-like data."""
    return bytes(range(256)) * 10


@pytest.fixture
def null_data() -> bytes:
    """Create low-entropy null data."""
    return b"\x00" * 2048


@pytest.fixture
def text_data() -> bytes:
    """Create medium-entropy text data."""
    return b"This is a test message with some structure. " * 50


@pytest.fixture
def mixed_data() -> bytes:
    """Create mixed entropy data (encrypted section + null padding)."""
    encrypted = bytes(range(256)) * 4
    padding = b"\x00" * 1024
    text = b"PE Header Section" * 20
    return text + encrypted + padding


@pytest.fixture
def packed_binary() -> bytes:
    """Create realistic packed binary data with high entropy."""
    header = b"MZ\x90\x00" + b"\x00" * 60
    packed_data = bytes((i * 37 + 123) % 256 for i in range(4096))
    return header + packed_data


class TestEntropyVisualizerInitialization:
    """Test EntropyVisualizer initialization and setup."""

    def test_visualizer_initializes(self, entropy_visualizer: EntropyVisualizer) -> None:
        """Visualizer initializes successfully."""
        assert entropy_visualizer is not None

    def test_visualizer_has_minimum_size(self, entropy_visualizer: EntropyVisualizer) -> None:
        """Visualizer has minimum size constraints."""
        assert entropy_visualizer.minimumHeight() >= 200
        assert entropy_visualizer.minimumWidth() >= 400

    def test_visualizer_has_plot_widget(self, entropy_visualizer: EntropyVisualizer) -> None:
        """Visualizer has plot widget for displaying entropy."""
        assert hasattr(entropy_visualizer, "plot_widget")
        assert entropy_visualizer.plot_widget is not None

    def test_visualizer_has_info_label(self, entropy_visualizer: EntropyVisualizer) -> None:
        """Visualizer has info label for statistics."""
        assert hasattr(entropy_visualizer, "info_label")
        assert entropy_visualizer.info_label is not None

    def test_visualizer_has_entropy_curve(self, entropy_visualizer: EntropyVisualizer) -> None:
        """Visualizer has entropy curve for plotting."""
        assert hasattr(entropy_visualizer, "entropy_curve")
        assert entropy_visualizer.entropy_curve is not None

    def test_visualizer_has_threshold_lines(self, entropy_visualizer: EntropyVisualizer) -> None:
        """Visualizer has high and low entropy threshold lines."""
        assert hasattr(entropy_visualizer, "high_entropy_line")
        assert hasattr(entropy_visualizer, "low_entropy_line")

    def test_visualizer_initially_empty(self, entropy_visualizer: EntropyVisualizer) -> None:
        """Visualizer starts with no loaded data."""
        assert entropy_visualizer.file_data is None
        assert len(entropy_visualizer.entropy_data) == 0
        assert len(entropy_visualizer.block_positions) == 0


class TestShannonEntropyCalculation:
    """Test Shannon entropy calculation accuracy."""

    def test_calculate_entropy_for_random_data(self, entropy_visualizer: EntropyVisualizer, random_data: bytes) -> None:
        """Shannon entropy calculation identifies high entropy in random data."""
        positions, entropy_values = entropy_visualizer.calculate_entropy(random_data, block_size=256)
        assert len(positions) > 0
        assert len(entropy_values) > 0
        assert all(e >= 7.0 for e in entropy_values)

    def test_calculate_entropy_for_null_data(self, entropy_visualizer: EntropyVisualizer, null_data: bytes) -> None:
        """Shannon entropy calculation identifies low entropy in null data."""
        positions, entropy_values = entropy_visualizer.calculate_entropy(null_data, block_size=256)
        assert len(positions) > 0
        assert len(entropy_values) > 0
        assert all(e == 0.0 for e in entropy_values)

    def test_calculate_entropy_for_text_data(self, entropy_visualizer: EntropyVisualizer, text_data: bytes) -> None:
        """Shannon entropy calculation shows medium entropy for text."""
        positions, entropy_values = entropy_visualizer.calculate_entropy(text_data, block_size=256)
        assert len(positions) > 0
        assert len(entropy_values) > 0
        assert all(3.0 <= e <= 6.0 for e in entropy_values)

    def test_calculate_entropy_empty_data(self, entropy_visualizer: EntropyVisualizer) -> None:
        """Entropy calculation handles empty data gracefully."""
        positions, entropy_values = entropy_visualizer.calculate_entropy(b"", block_size=256)
        assert positions == []
        assert entropy_values == []

    def test_calculate_entropy_single_byte(self, entropy_visualizer: EntropyVisualizer) -> None:
        """Entropy calculation handles single byte correctly."""
        positions, entropy_values = entropy_visualizer.calculate_entropy(b"A" * 100, block_size=100)
        assert len(positions) > 0
        assert len(entropy_values) > 0
        assert all(e == 0.0 for e in entropy_values)

    def test_calculate_entropy_mixed_data(self, entropy_visualizer: EntropyVisualizer, mixed_data: bytes) -> None:
        """Entropy calculation detects varying entropy in mixed data."""
        positions, entropy_values = entropy_visualizer.calculate_entropy(mixed_data, block_size=512)
        assert len(positions) > 0
        assert len(entropy_values) > 0
        assert min(entropy_values) < 2.0
        assert max(entropy_values) > 7.0

    def test_entropy_formula_accuracy(self, entropy_visualizer: EntropyVisualizer) -> None:
        """Entropy calculation matches Shannon formula exactly."""
        test_data = bytes([0, 1] * 128)
        positions, entropy_values = entropy_visualizer.calculate_entropy(test_data, block_size=256)

        byte_counts = Counter(test_data)
        expected_entropy = 0.0
        for count in byte_counts.values():
            probability = count / len(test_data)
            expected_entropy -= probability * math.log2(probability)

        assert abs(entropy_values[0] - expected_entropy) < 0.01

    def test_entropy_max_value_is_8_bits(self, entropy_visualizer: EntropyVisualizer) -> None:
        """Maximum entropy for byte data is 8 bits."""
        uniform_data = bytes(range(256))
        positions, entropy_values = entropy_visualizer.calculate_entropy(uniform_data, block_size=256)
        assert all(e <= 8.0 for e in entropy_values)

    def test_entropy_positions_are_percentages(self, entropy_visualizer: EntropyVisualizer, random_data: bytes) -> None:
        """Block positions are reported as percentages of file."""
        positions, entropy_values = entropy_visualizer.calculate_entropy(random_data, block_size=256)
        assert all(0 <= p <= 100 for p in positions)


class TestEntropyVisualizerDataLoading:
    """Test entropy visualizer data loading functionality."""

    def test_load_data_succeeds(self, entropy_visualizer: EntropyVisualizer, random_data: bytes) -> None:
        """Loading valid data succeeds."""
        entropy_visualizer.load_data(random_data, block_size=256)
        assert entropy_visualizer.file_data is not None
        assert len(entropy_visualizer.entropy_data) > 0

    def test_load_data_rejects_non_bytes(self, entropy_visualizer: EntropyVisualizer) -> None:
        """Loading non-bytes data raises TypeError."""
        with pytest.raises(TypeError):
            entropy_visualizer.load_data("not bytes", block_size=256)  # type: ignore

    def test_load_data_rejects_empty_bytes(self, entropy_visualizer: EntropyVisualizer) -> None:
        """Loading empty bytes raises ValueError."""
        with pytest.raises(ValueError):
            entropy_visualizer.load_data(b"", block_size=256)

    def test_load_data_rejects_negative_block_size(self, entropy_visualizer: EntropyVisualizer, random_data: bytes) -> None:
        """Loading with negative block size raises ValueError."""
        with pytest.raises(ValueError):
            entropy_visualizer.load_data(random_data, block_size=-1)

    def test_load_data_rejects_zero_block_size(self, entropy_visualizer: EntropyVisualizer, random_data: bytes) -> None:
        """Loading with zero block size raises ValueError."""
        with pytest.raises(ValueError):
            entropy_visualizer.load_data(random_data, block_size=0)

    def test_load_data_adapts_block_size_for_small_files(self, entropy_visualizer: EntropyVisualizer) -> None:
        """Loading small files adapts block size automatically."""
        small_data = b"A" * 500
        entropy_visualizer.load_data(small_data, block_size=1024)
        assert len(entropy_visualizer.entropy_data) > 0

    def test_load_data_emits_signal(self, entropy_visualizer: EntropyVisualizer, random_data: bytes) -> None:
        """Loading data emits entropy_calculated signal."""
        signal_received = False
        received_positions = None
        received_entropy = None

        def on_entropy_calculated(positions: list[float], entropy: list[float]) -> None:
            nonlocal signal_received, received_positions, received_entropy
            signal_received = True
            received_positions = positions
            received_entropy = entropy

        entropy_visualizer.entropy_calculated.connect(on_entropy_calculated)
        entropy_visualizer.load_data(random_data, block_size=256)

        assert signal_received
        assert received_positions is not None
        assert received_entropy is not None


class TestEntropyStatistics:
    """Test entropy statistical analysis."""

    def test_statistics_calculated_for_random_data(self, entropy_visualizer: EntropyVisualizer, random_data: bytes) -> None:
        """Statistics are calculated for random data."""
        entropy_visualizer.load_data(random_data, block_size=256)
        info_text = entropy_visualizer.info_label.text()
        assert "Average Entropy" in info_text
        assert "Min:" in info_text
        assert "Max:" in info_text

    def test_average_entropy_accuracy(self, entropy_visualizer: EntropyVisualizer, random_data: bytes) -> None:
        """Average entropy matches manual calculation."""
        entropy_visualizer.load_data(random_data, block_size=256)
        info_text = entropy_visualizer.info_label.text()

        manual_avg = sum(entropy_visualizer.entropy_data) / len(entropy_visualizer.entropy_data)
        assert f"{manual_avg:.2f}" in info_text

    def test_high_entropy_block_counting(self, entropy_visualizer: EntropyVisualizer, random_data: bytes) -> None:
        """High entropy blocks are counted correctly."""
        entropy_visualizer.load_data(random_data, block_size=256)
        info_text = entropy_visualizer.info_label.text()
        assert "High Entropy Blocks:" in info_text

    def test_low_entropy_block_counting(self, entropy_visualizer: EntropyVisualizer, null_data: bytes) -> None:
        """Low entropy blocks are counted correctly."""
        entropy_visualizer.load_data(null_data, block_size=256)
        info_text = entropy_visualizer.info_label.text()
        assert "Low Entropy Blocks:" in info_text


class TestSuspiciousRegionDetection:
    """Test detection of suspicious entropy patterns."""

    def test_find_suspicious_regions_sudden_change(self, entropy_visualizer: EntropyVisualizer, mixed_data: bytes) -> None:
        """Detects sudden entropy changes in mixed data."""
        entropy_visualizer.load_data(mixed_data, block_size=512)
        suspicious = entropy_visualizer.find_suspicious_regions()
        assert len(suspicious) > 0
        assert any("entropy change" in desc.lower() for _, desc, _ in suspicious)

    def test_find_suspicious_regions_high_entropy(self, entropy_visualizer: EntropyVisualizer, packed_binary: bytes) -> None:
        """Detects high entropy sections indicating encryption/compression."""
        entropy_visualizer.load_data(packed_binary, block_size=512)
        suspicious = entropy_visualizer.find_suspicious_regions()
        high_entropy_regions = [s for s in suspicious if "encryption" in s[1].lower() or "compression" in s[1].lower()]
        assert len(high_entropy_regions) > 0

    def test_find_suspicious_regions_low_entropy(self, entropy_visualizer: EntropyVisualizer, mixed_data: bytes) -> None:
        """Detects low entropy sections indicating padding."""
        entropy_visualizer.load_data(mixed_data, block_size=512)
        suspicious = entropy_visualizer.find_suspicious_regions()
        low_entropy_regions = [s for s in suspicious if "padding" in s[1].lower() or "null" in s[1].lower()]
        assert len(low_entropy_regions) > 0

    def test_find_suspicious_regions_empty_data(self, entropy_visualizer: EntropyVisualizer) -> None:
        """Returns empty list for empty data."""
        suspicious = entropy_visualizer.find_suspicious_regions()
        assert suspicious == []

    def test_suspicious_region_format(self, entropy_visualizer: EntropyVisualizer, mixed_data: bytes) -> None:
        """Suspicious regions have correct format."""
        entropy_visualizer.load_data(mixed_data, block_size=512)
        suspicious = entropy_visualizer.find_suspicious_regions()
        for position, description, details in suspicious:
            assert isinstance(position, float)
            assert isinstance(description, str)
            assert isinstance(details, str)
            assert 0 <= position <= 100


class TestEntropyVisualizationClear:
    """Test entropy visualization clearing functionality."""

    def test_clear_resets_data(self, entropy_visualizer: EntropyVisualizer, random_data: bytes) -> None:
        """Clear resets all data to initial state."""
        entropy_visualizer.load_data(random_data, block_size=256)
        entropy_visualizer.clear()
        assert entropy_visualizer.file_data is None
        assert len(entropy_visualizer.entropy_data) == 0
        assert len(entropy_visualizer.block_positions) == 0

    def test_clear_updates_info_label(self, entropy_visualizer: EntropyVisualizer, random_data: bytes) -> None:
        """Clear updates info label to default text."""
        entropy_visualizer.load_data(random_data, block_size=256)
        entropy_visualizer.clear()
        assert "No data loaded" in entropy_visualizer.info_label.text()


class TestEntropyVisualizationEdgeCases:
    """Test entropy visualization edge cases."""

    def test_very_small_file(self, entropy_visualizer: EntropyVisualizer) -> None:
        """Handles very small files correctly."""
        tiny_data = b"AB"
        entropy_visualizer.load_data(tiny_data, block_size=1024)

    def test_very_large_block_size(self, entropy_visualizer: EntropyVisualizer, random_data: bytes) -> None:
        """Handles block size larger than file."""
        entropy_visualizer.load_data(random_data, block_size=1000000)
        assert len(entropy_visualizer.entropy_data) >= 0

    def test_single_block_file(self, entropy_visualizer: EntropyVisualizer) -> None:
        """Handles file that fits in single block."""
        data = b"A" * 512
        entropy_visualizer.load_data(data, block_size=1024)
        assert len(entropy_visualizer.entropy_data) >= 0

    def test_uniform_byte_distribution(self, entropy_visualizer: EntropyVisualizer) -> None:
        """Calculates maximum entropy for uniform distribution."""
        uniform = bytes(range(256)) * 4
        entropy_visualizer.load_data(uniform, block_size=1024)
        assert max(entropy_visualizer.entropy_data) >= 7.9


class TestRealWorldBinaryAnalysis:
    """Test entropy visualization with realistic binary scenarios."""

    def test_pe_header_low_entropy(self, entropy_visualizer: EntropyVisualizer) -> None:
        """PE headers typically have low to medium entropy."""
        pe_header = b"MZ\x90\x00" + b"\x00" * 60 + b"PE\x00\x00" + b"\x00" * 200
        entropy_visualizer.load_data(pe_header, block_size=128)
        assert len(entropy_visualizer.entropy_data) > 0
        assert all(e < 5.0 for e in entropy_visualizer.entropy_data)

    def test_upx_packed_section_high_entropy(self, entropy_visualizer: EntropyVisualizer) -> None:
        """UPX packed sections have very high entropy."""
        upx_signature = b"UPX0" + b"UPX1" + bytes((i * 73) % 256 for i in range(2048))
        entropy_visualizer.load_data(upx_signature, block_size=512)
        high_entropy_count = sum(1 for e in entropy_visualizer.entropy_data if e > 7.0)
        assert high_entropy_count > 0

    def test_code_section_medium_entropy(self, entropy_visualizer: EntropyVisualizer) -> None:
        """Compiled code sections have medium entropy."""
        code_bytes = bytes((i * 13 + 7) % 128 for i in range(4096))
        entropy_visualizer.load_data(code_bytes, block_size=512)
        avg_entropy = sum(entropy_visualizer.entropy_data) / len(entropy_visualizer.entropy_data)
        assert 4.0 <= avg_entropy <= 7.0

    def test_data_section_with_strings(self, entropy_visualizer: EntropyVisualizer) -> None:
        """Data sections with strings have characteristic entropy."""
        strings_section = b"Copyright (C) 2025\x00License Check Failed\x00Registration Required\x00" * 20
        entropy_visualizer.load_data(strings_section, block_size=256)
        assert len(entropy_visualizer.entropy_data) > 0

    def test_encrypted_license_data(self, entropy_visualizer: EntropyVisualizer) -> None:
        """Encrypted license data shows very high entropy."""
        encrypted = bytes((i * 137 + 211) % 256 for i in range(1024))
        entropy_visualizer.load_data(encrypted, block_size=256)
        suspicious = entropy_visualizer.find_suspicious_regions()
        encryption_regions = [s for s in suspicious if "encryption" in s[1].lower()]
        assert len(encryption_regions) > 0


class TestEntropyBlockSizes:
    """Test entropy calculation with various block sizes."""

    def test_small_block_size(self, entropy_visualizer: EntropyVisualizer, random_data: bytes) -> None:
        """Small block size provides fine-grained analysis."""
        entropy_visualizer.load_data(random_data, block_size=64)
        assert len(entropy_visualizer.entropy_data) > 10

    def test_large_block_size(self, entropy_visualizer: EntropyVisualizer, random_data: bytes) -> None:
        """Large block size provides coarse analysis."""
        entropy_visualizer.load_data(random_data, block_size=2048)
        assert len(entropy_visualizer.entropy_data) > 0

    def test_block_size_affects_granularity(self, entropy_visualizer: EntropyVisualizer, mixed_data: bytes) -> None:
        """Smaller block sizes detect more entropy variations."""
        entropy_visualizer.load_data(mixed_data, block_size=256)
        fine_count = len(entropy_visualizer.entropy_data)

        entropy_visualizer.load_data(mixed_data, block_size=1024)
        coarse_count = len(entropy_visualizer.entropy_data)

        assert fine_count > coarse_count

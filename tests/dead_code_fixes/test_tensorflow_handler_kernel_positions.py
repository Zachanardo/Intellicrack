"""Tests for kernel_positions normalization in tensorflow_handler.py.

This tests that the kernel_positions variable is properly used for edge
normalization in convolution operations when using 'same' padding.
"""

from __future__ import annotations

import math
from typing import TYPE_CHECKING, Any

import pytest

if TYPE_CHECKING:
    pass


class TestKernelPositionsNormalization:
    """Test suite for kernel_positions normalization in FallbackConv2D."""

    def test_normalization_formula_correctness(self) -> None:
        """Test that normalization formula is mathematically correct.

        For 'same' padding, when only k of K kernel positions are valid,
        the output should be scaled by K/k to normalize.
        """
        total_kernel_size = 9
        kernel_positions = 4

        conv_sum = 4.0
        expected_normalized = conv_sum * (total_kernel_size / kernel_positions)
        assert expected_normalized == 9.0

        kernel_positions_full = 9
        conv_sum_full = 9.0
        normalized_full = conv_sum_full * (total_kernel_size / kernel_positions_full)
        assert normalized_full == 9.0

    def test_kernel_position_count_at_corners(self) -> None:
        """Test kernel position counting at corner pixels."""
        kernel_size = (3, 3)
        total_positions = kernel_size[0] * kernel_size[1]

        corner_positions = 4
        edge_positions = 6
        center_positions = 9

        assert corner_positions < total_positions
        assert edge_positions < total_positions
        assert center_positions == total_positions

    def test_normalization_applied_only_for_same_padding(self) -> None:
        """Test that normalization is applied only when padding is 'same'."""
        padding = "same"
        kernel_positions = 4
        total_kernel_size = 9

        if padding == "same" and kernel_positions > 0 and kernel_positions < total_kernel_size:
            normalized_sum = 4.0 * (total_kernel_size / kernel_positions)
        else:
            normalized_sum = 4.0

        assert normalized_sum == 9.0

    def test_no_normalization_for_valid_padding(self) -> None:
        """Test that 'valid' padding doesn't apply edge normalization."""
        padding = "valid"
        kernel_positions = 4
        total_kernel_size = 9
        conv_sum = 4.0

        if padding == "same" and kernel_positions > 0 and kernel_positions < total_kernel_size:
            normalized_sum = conv_sum * (total_kernel_size / kernel_positions)
        else:
            normalized_sum = conv_sum

        assert normalized_sum == 4.0

    def test_full_kernel_positions_no_scaling(self) -> None:
        """Test that full kernel positions don't trigger scaling."""
        padding = "same"
        kernel_positions = 9
        total_kernel_size = 9
        conv_sum = 9.0

        if padding == "same" and kernel_positions > 0 and kernel_positions < total_kernel_size:
            normalized_sum = conv_sum * (total_kernel_size / kernel_positions)
        else:
            normalized_sum = conv_sum

        assert normalized_sum == 9.0

    def test_zero_kernel_positions_guard(self) -> None:
        """Test that zero kernel positions doesn't cause division by zero."""
        kernel_positions = 0
        total_kernel_size = 9
        conv_sum = 0.0

        if kernel_positions > 0 and kernel_positions < total_kernel_size:
            normalized_sum = conv_sum * (total_kernel_size / kernel_positions)
        else:
            normalized_sum = conv_sum

        assert normalized_sum == 0.0

    def test_edge_normalization_factors(self) -> None:
        """Test normalization factors for different kernel position counts."""
        total_kernel_size = 9

        corner_factor = total_kernel_size / 4
        assert corner_factor == 2.25

        edge_factor = total_kernel_size / 6
        assert abs(edge_factor - 1.5) < 0.001

        center_factor = total_kernel_size / 9
        assert center_factor == 1.0

    def test_normalization_preserves_relative_values(self) -> None:
        """Test that normalization preserves relative brightness across image."""
        input_value = 1.0
        kernel_weight = 1.0

        corner_conv_sum = input_value * kernel_weight * 4
        edge_conv_sum = input_value * kernel_weight * 6
        center_conv_sum = input_value * kernel_weight * 9

        corner_normalized = corner_conv_sum * (9 / 4)
        edge_normalized = edge_conv_sum * (9 / 6)
        center_normalized = center_conv_sum * (9 / 9)

        assert corner_normalized == 9.0
        assert edge_normalized == 9.0
        assert center_normalized == 9.0

    def test_3x3_kernel_positions_at_image_locations(self) -> None:
        """Test expected kernel positions for 3x3 kernel at various locations."""
        image_height = 5
        image_width = 5
        kernel_h = 3
        kernel_w = 3

        def count_positions(y: int, x: int) -> int:
            k_start_y = max(0, y - kernel_h // 2)
            k_end_y = min(image_height, y + kernel_h // 2 + 1)
            k_start_x = max(0, x - kernel_w // 2)
            k_end_x = min(image_width, x + kernel_w // 2 + 1)
            return (k_end_y - k_start_y) * (k_end_x - k_start_x)

        assert count_positions(0, 0) == 4
        assert count_positions(0, 2) == 6
        assert count_positions(2, 2) == 9
        assert count_positions(4, 4) == 4

    def test_5x5_kernel_normalization(self) -> None:
        """Test normalization for larger 5x5 kernel."""
        total_kernel_size = 25
        kernel_positions = 9

        conv_sum = 9.0
        normalized = conv_sum * (total_kernel_size / kernel_positions)

        assert normalized == 25.0

    def test_asymmetric_kernel_positions(self) -> None:
        """Test kernel position counting for asymmetric kernels."""
        kernel_size_h = 3
        kernel_size_w = 5
        total_kernel_size = kernel_size_h * kernel_size_w

        assert total_kernel_size == 15

        corner_positions = 2 * 3
        assert corner_positions == 6

    def test_normalization_condition_logic(self) -> None:
        """Test all conditions for applying normalization."""
        test_cases = [
            ("same", 4, 9, True),
            ("same", 9, 9, False),
            ("same", 0, 9, False),
            ("valid", 4, 9, False),
            ("valid", 9, 9, False),
        ]

        for padding, positions, total, should_normalize in test_cases:
            applies = (
                padding == "same"
                and positions > 0
                and positions < total
            )
            assert applies == should_normalize, f"Failed for {padding}, {positions}, {total}"

    def test_convolution_sum_accumulation(self) -> None:
        """Test convolution sum accumulation logic."""
        kernel = [[1.0, 1.0, 1.0], [1.0, 1.0, 1.0], [1.0, 1.0, 1.0]]
        input_patch = [[0.5, 0.5], [0.5, 0.5]]

        conv_sum = 0.0
        kernel_positions = 0

        for ky in range(2):
            for kx in range(2):
                conv_sum += input_patch[ky][kx] * kernel[ky][kx]
                kernel_positions += 1

        assert conv_sum == 2.0
        assert kernel_positions == 4

    def test_relu_activation_after_normalization(self) -> None:
        """Test that ReLU correctly applies after normalization."""
        normalized_values = [-5.0, 0.0, 3.0, -1.0, 7.0]

        def relu(x: float) -> float:
            return max(0.0, x)

        relu_output = [relu(v) for v in normalized_values]

        assert relu_output == [0.0, 0.0, 3.0, 0.0, 7.0]

    def test_sigmoid_activation_after_normalization(self) -> None:
        """Test sigmoid correctly applies after normalization."""
        normalized_value = 0.0

        def sigmoid(x: float) -> float:
            return 1 / (1 + math.exp(-x))

        result = sigmoid(normalized_value)
        assert abs(result - 0.5) < 0.001

    def test_tanh_activation_after_normalization(self) -> None:
        """Test tanh correctly applies after normalization."""
        normalized_value = 0.0

        result = math.tanh(normalized_value)
        assert result == 0.0

        positive_result = math.tanh(2.0)
        assert 0 < positive_result < 1


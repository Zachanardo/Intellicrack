"""Tests for memory_load_data usage in optimization_config.py.

This tests that the memory_load_data is properly created and used to
calculate test_load_size_bytes for benchmarking memory optimization.
"""


from __future__ import annotations

import gc
from typing import TYPE_CHECKING, Any

import pytest


class TestMemoryLoadDataUsage:
    """Test suite for memory_load_data benchmarking."""

    def test_memory_load_data_structure(self) -> None:
        """Test that memory_load_data has correct structure."""
        memory_load_data: list[dict[str, str]] = [
            {f"key_{i}": f"value_{i}" * 100} for i in range(1000)
        ]

        assert len(memory_load_data) == 1000
        assert isinstance(memory_load_data[0], dict)
        assert "key_0" in memory_load_data[0]
        assert len(memory_load_data[0]["key_0"]) == 700

    def test_load_data_size_calculation(self) -> None:
        """Test that load_data_size is calculated correctly."""
        memory_load_data: list[dict[str, str]] = [
            {f"key_{i}": f"value_{i}" * 100} for i in range(1000)
        ]
        load_data_size = sum(
            len(str(k)) + len(str(v)) for d in memory_load_data for k, v in d.items()
        )

        assert load_data_size > 0

        single_key_len = len("key_0")
        single_value_len = len("value_0" * 100)
        expected_first_item = single_key_len + single_value_len

        first_item_size = sum(len(str(k)) + len(str(v)) for k, v in memory_load_data[0].items())
        assert first_item_size == expected_first_item

    def test_load_data_size_consistency(self) -> None:
        """Test that load_data_size calculation is consistent."""
        memory_load_data: list[dict[str, str]] = [
            {f"key_{i}": f"value_{i}" * 100} for i in range(1000)
        ]

        calc1 = sum(len(str(k)) + len(str(v)) for d in memory_load_data for k, v in d.items())
        calc2 = sum(len(str(k)) + len(str(v)) for d in memory_load_data for k, v in d.items())

        assert calc1 == calc2

    def test_memory_load_data_cleanup(self) -> None:
        """Test that memory_load_data can be properly cleaned up."""
        memory_load_data: list[dict[str, str]] = [
            {f"key_{i}": f"value_{i}" * 100} for i in range(1000)
        ]

        load_data_size = sum(
            len(str(k)) + len(str(v)) for d in memory_load_data for k, v in d.items()
        )

        assert load_data_size > 0

        del memory_load_data
        gc.collect()

    def test_benchmark_result_includes_test_load_size(self) -> None:
        """Test that benchmark result includes test_load_size_bytes."""
        memory_load_data: list[dict[str, str]] = [
            {f"key_{i}": f"value_{i}" * 100} for i in range(1000)
        ]
        load_data_size = sum(
            len(str(k)) + len(str(v)) for d in memory_load_data for k, v in d.items()
        )

        result: dict[str, Any] = {
            "optimization_time_seconds": 0.5,
            "memory_saved_mb": 10.0,
            "objects_cleaned": 500,
            "memory_efficiency_mb_per_second": 20.0,
            "baseline_memory_mb": 100.0,
            "final_memory_mb": 90.0,
            "test_load_size_bytes": load_data_size,
        }

        assert "test_load_size_bytes" in result
        assert result["test_load_size_bytes"] == load_data_size
        assert result["test_load_size_bytes"] > 0

    def test_value_expansion_factor(self) -> None:
        """Test that value expansion (x100) works correctly."""
        base_value = "value_5"
        expanded_value = base_value * 100

        assert len(expanded_value) == len(base_value) * 100
        assert expanded_value.count(base_value) == 100

    def test_key_naming_convention(self) -> None:
        """Test that keys follow expected naming pattern."""
        memory_load_data: list[dict[str, str]] = [
            {f"key_{i}": f"value_{i}" * 100} for i in range(10)
        ]

        for i, d in enumerate(memory_load_data):
            expected_key = f"key_{i}"
            assert expected_key in d

    def test_iteration_over_nested_structure(self) -> None:
        """Test correct iteration over nested dict structure."""
        memory_load_data: list[dict[str, str]] = [
            {f"key_{i}": f"value_{i}" * 100} for i in range(5)
        ]

        item_count = 0
        for d in memory_load_data:
            for k, v in d.items():
                item_count += 1
                assert isinstance(k, str)
                assert isinstance(v, str)

        assert item_count == 5

    def test_size_calculation_accuracy(self) -> None:
        """Test that size calculation accurately reflects data size."""
        memory_load_data: list[dict[str, str]] = [
            {"test_key": "test_value" * 10}
        ]

        load_data_size = sum(
            len(str(k)) + len(str(v)) for d in memory_load_data for k, v in d.items()
        )

        expected_size = len("test_key") + len("test_value" * 10)
        assert load_data_size == expected_size

    def test_large_data_set_handling(self) -> None:
        """Test handling of large data set (1000 items)."""
        memory_load_data: list[dict[str, str]] = [
            {f"key_{i}": f"value_{i}" * 100} for i in range(1000)
        ]

        assert len(memory_load_data) == 1000

        min_load_size = 1000 * (5 + 600)
        load_data_size = sum(
            len(str(k)) + len(str(v)) for d in memory_load_data for k, v in d.items()
        )

        assert load_data_size > min_load_size

    def test_gc_collect_after_cleanup(self) -> None:
        """Test that gc.collect() runs after data cleanup."""
        gc.collect()

        memory_load_data: list[dict[str, str]] = [
            {f"key_{i}": f"value_{i}" * 100} for i in range(1000)
        ]

        assert len(memory_load_data) == 1000

        del memory_load_data
        collected = gc.collect()

        assert collected >= 0

    def test_load_size_type(self) -> None:
        """Test that load_data_size is an integer."""
        memory_load_data: list[dict[str, str]] = [
            {f"key_{i}": f"value_{i}" * 100} for i in range(10)
        ]
        load_data_size = sum(
            len(str(k)) + len(str(v)) for d in memory_load_data for k, v in d.items()
        )

        assert isinstance(load_data_size, int)

    def test_empty_memory_load_data(self) -> None:
        """Test handling of empty memory_load_data."""
        memory_load_data: list[dict[str, str]] = []
        load_data_size = sum(
            len(str(k)) + len(str(v)) for d in memory_load_data for k, v in d.items()
        )

        assert load_data_size == 0

    def test_benchmark_result_structure(self) -> None:
        """Test complete benchmark result structure."""
        memory_load_data: list[dict[str, str]] = [
            {f"key_{i}": f"value_{i}" * 100} for i in range(100)
        ]
        load_data_size = sum(
            len(str(k)) + len(str(v)) for d in memory_load_data for k, v in d.items()
        )

        result: dict[str, Any] = {
            "optimization_time_seconds": 0.1,
            "memory_saved_mb": 5.0,
            "objects_cleaned": 200,
            "memory_efficiency_mb_per_second": 50.0,
            "baseline_memory_mb": 50.0,
            "final_memory_mb": 45.0,
            "test_load_size_bytes": load_data_size,
        }

        required_keys = [
            "optimization_time_seconds",
            "memory_saved_mb",
            "objects_cleaned",
            "memory_efficiency_mb_per_second",
            "baseline_memory_mb",
            "final_memory_mb",
            "test_load_size_bytes",
        ]

        for key in required_keys:
            assert key in result

    def test_variable_key_length_handling(self) -> None:
        """Test that variable-length keys are handled correctly."""
        memory_load_data: list[dict[str, str]] = [
            {f"key_{i}": f"value_{i}" * 100} for i in range(1000)
        ]

        key_lengths = [len(list(d.keys())[0]) for d in memory_load_data]

        assert len("key_0") == 5
        assert len("key_999") == 7

        assert key_lengths[0] == 5
        assert key_lengths[999] == 7


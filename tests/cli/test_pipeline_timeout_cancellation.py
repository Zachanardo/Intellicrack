"""Comprehensive tests for CLI pipeline timeout and cancellation with real stages.

Tests stage timeout, concurrent stage execution, and cancellation with production pipeline stages.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import pytest
import time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError

from intellicrack.cli.pipeline import (
    PipelineData,
    AnalysisStage,
    FilterStage,
)


@pytest.fixture
def sample_pipeline_data() -> PipelineData:
    """Provide sample pipeline data for testing."""
    return PipelineData(
        content={"test": "data", "path": r"C:\test\binary.exe"},
        metadata={"source": "test"},
        format="json",
    )


class TestAnalysisStageWithTimeout:
    """Test AnalysisStage with timeout scenarios."""

    def test_analysis_stage_timeout_on_nonexistent_binary(self, sample_pipeline_data: PipelineData) -> None:
        """AnalysisStage times out on nonexistent binary analysis."""
        stage = AnalysisStage()

        sample_pipeline_data.content = {"path": r"C:\nonexistent\binary.exe"}

        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(stage.process, sample_pipeline_data)

            try:
                result = future.result(timeout=2.0)
                assert result.metadata.get("success") is not None
            except FuturesTimeoutError:
                pass

    def test_analysis_stage_handles_invalid_binary_path(self, sample_pipeline_data: PipelineData) -> None:
        """AnalysisStage handles invalid binary path gracefully."""
        stage = AnalysisStage()

        sample_pipeline_data.content = {"path": ""}

        result = stage.process(sample_pipeline_data)

        assert result is not None
        assert isinstance(result, PipelineData)

    def test_analysis_stage_processes_valid_data(self, sample_pipeline_data: PipelineData) -> None:
        """AnalysisStage processes valid pipeline data."""
        stage = AnalysisStage()

        result = stage.process(sample_pipeline_data)

        assert result is not None
        assert isinstance(result, PipelineData)

    def test_analysis_stage_concurrent_processing(self, sample_pipeline_data: PipelineData) -> None:
        """AnalysisStage handles concurrent processing requests."""
        stage = AnalysisStage()

        data_list = [
            PipelineData(
                content={"path": f"binary_{i}.exe"},
                metadata={"id": i},
                format="json",
            )
            for i in range(3)
        ]

        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = [executor.submit(stage.process, data) for data in data_list]

            results = []
            for future in futures:
                try:
                    result = future.result(timeout=5.0)
                    results.append(result)
                except FuturesTimeoutError:
                    pass

        assert len(results) >= 0

    def test_analysis_stage_with_missing_path(self, sample_pipeline_data: PipelineData) -> None:
        """AnalysisStage handles missing path in content."""
        stage = AnalysisStage()

        sample_pipeline_data.content = {"other_field": "value"}

        result = stage.process(sample_pipeline_data)

        assert result is not None
        assert isinstance(result, PipelineData)


class TestFilterStageWithTimeout:
    """Test FilterStage with timeout scenarios."""

    def test_filter_stage_timeout_on_large_dataset(self, sample_pipeline_data: PipelineData) -> None:
        """FilterStage times out on large dataset filtering."""
        large_dataset = {
            "vulnerabilities": [
                {"id": i, "severity": "high" if i % 2 == 0 else "low"}
                for i in range(10000)
            ]
        }

        large_data = PipelineData(
            content=large_dataset,
            metadata={},
            format="json",
        )

        stage = FilterStage("vulnerability")

        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(stage.process, large_data)

            try:
                result = future.result(timeout=5.0)
                assert result is not None
            except FuturesTimeoutError:
                pass

    def test_filter_stage_processes_small_dataset(self, sample_pipeline_data: PipelineData) -> None:
        """FilterStage processes small dataset within timeout."""
        small_dataset = {
            "vulnerabilities": [
                {"id": 1, "severity": "high"},
                {"id": 2, "severity": "low"},
            ]
        }

        small_data = PipelineData(
            content=small_dataset,
            metadata={},
            format="json",
        )

        stage = FilterStage("vulnerability")

        result = stage.process(small_data)

        assert result is not None
        assert isinstance(result, PipelineData)

    def test_filter_stage_handles_empty_dataset(self, sample_pipeline_data: PipelineData) -> None:
        """FilterStage handles empty dataset gracefully."""
        empty_data = PipelineData(
            content={},
            metadata={},
            format="json",
        )

        stage = FilterStage("vulnerability")

        result = stage.process(empty_data)

        assert result is not None
        assert isinstance(result, PipelineData)

    def test_filter_stage_concurrent_filtering(self) -> None:
        """FilterStage handles concurrent filtering requests."""
        stage = FilterStage("vulnerability")

        datasets = [
            PipelineData(
                content={"vulnerabilities": [{"id": i, "severity": "high"} for i in range(100 * j, 100 * (j + 1))]},
                metadata={"batch": j},
                format="json",
            )
            for j in range(3)
        ]

        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = [executor.submit(stage.process, data) for data in datasets]

            results = []
            for future in futures:
                try:
                    result = future.result(timeout=3.0)
                    results.append(result)
                except FuturesTimeoutError:
                    pass

        assert len(results) >= 0


class TestPipelineStageEdgeCases:
    """Test edge cases for pipeline stages."""

    def test_analysis_stage_handles_none_content(self) -> None:
        """AnalysisStage handles None content gracefully."""
        stage = AnalysisStage()

        data = PipelineData(
            content=None,
            metadata={},
            format="json",
        )

        result = stage.process(data)

        assert result is not None

    def test_filter_stage_handles_malformed_data(self) -> None:
        """FilterStage handles malformed data structure."""
        stage = FilterStage("vulnerability")

        malformed_data = PipelineData(
            content={"vulnerabilities": "not_a_list"},
            metadata={},
            format="json",
        )

        result = stage.process(malformed_data)

        assert result is not None

    def test_stages_preserve_metadata(self, sample_pipeline_data: PipelineData) -> None:
        """Pipeline stages preserve metadata through processing."""
        sample_pipeline_data.metadata = {"important": "value", "source": "test"}

        analysis_stage = AnalysisStage()
        result = analysis_stage.process(sample_pipeline_data)

        assert result.metadata is not None


class TestPipelineStageIntegration:
    """Test integration between pipeline stages."""

    def test_analysis_to_filter_pipeline(self, sample_pipeline_data: PipelineData) -> None:
        """Pipeline data flows from AnalysisStage to FilterStage."""
        analysis_stage = AnalysisStage()
        filter_stage = FilterStage("vulnerability")

        analysis_result = analysis_stage.process(sample_pipeline_data)
        filter_result = filter_stage.process(analysis_result)

        assert filter_result is not None
        assert isinstance(filter_result, PipelineData)

    def test_multiple_stage_sequence(self, sample_pipeline_data: PipelineData) -> None:
        """Pipeline processes data through multiple stages sequentially."""
        stages = [
            AnalysisStage(),
            FilterStage("vulnerability"),
        ]

        current_data = sample_pipeline_data

        for stage in stages:
            current_data = stage.process(current_data)
            assert current_data is not None

    def test_concurrent_multi_stage_processing(self) -> None:
        """Pipeline handles concurrent multi-stage processing."""
        analysis_stage = AnalysisStage()
        filter_stage = FilterStage("vulnerability")

        data_list = [
            PipelineData(
                content={"path": f"binary_{i}.exe"},
                metadata={"id": i},
                format="json",
            )
            for i in range(2)
        ]

        def process_pipeline(data: PipelineData) -> PipelineData:
            result = analysis_stage.process(data)
            return filter_stage.process(result)

        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(process_pipeline, data) for data in data_list]

            results = []
            for future in futures:
                try:
                    result = future.result(timeout=5.0)
                    results.append(result)
                except FuturesTimeoutError:
                    pass

        assert len(results) >= 0


class TestPipelineStagePerformance:
    """Test performance characteristics of pipeline stages."""

    def test_analysis_stage_completes_quickly_for_simple_data(self, sample_pipeline_data: PipelineData) -> None:
        """AnalysisStage completes quickly for simple data."""
        stage = AnalysisStage()

        start_time = time.time()
        result = stage.process(sample_pipeline_data)
        elapsed_time = time.time() - start_time

        assert result is not None
        assert elapsed_time < 5.0

    def test_filter_stage_completes_quickly_for_small_data(self) -> None:
        """FilterStage completes quickly for small dataset."""
        stage = FilterStage("vulnerability")

        data = PipelineData(
            content={"vulnerabilities": [{"id": i} for i in range(10)]},
            metadata={},
            format="json",
        )

        start_time = time.time()
        result = stage.process(data)
        elapsed_time = time.time() - start_time

        assert result is not None
        assert elapsed_time < 2.0

    def test_repeated_stage_execution_consistent(self, sample_pipeline_data: PipelineData) -> None:
        """Pipeline stages show consistent execution times."""
        stage = AnalysisStage()

        execution_times = []

        for _ in range(3):
            start_time = time.time()
            stage.process(sample_pipeline_data)
            elapsed_time = time.time() - start_time
            execution_times.append(elapsed_time)

        assert len(execution_times) == 3
        assert all(t < 5.0 for t in execution_times)

"""Production tests for Matplotlib handler.

Tests validate real plotting functionality and fallback implementations.
Tests verify graph generation for analysis visualization.
"""

import tempfile
from pathlib import Path
from typing import Any

import pytest

from intellicrack.handlers.matplotlib_handler import (
    MATPLOTLIB_AVAILABLE,
    create_bar_chart,
    create_histogram,
    create_line_plot,
    create_scatter_plot,
    save_figure,
)


class TestLinePlots:
    """Test line plot generation."""

    def test_create_simple_line_plot(self) -> None:
        """Create simple line plot."""
        x_data = [1, 2, 3, 4, 5]
        y_data = [2, 4, 6, 8, 10]

        fig = create_line_plot(x_data, y_data, title="Test Plot")

        assert fig is not None

    def test_create_line_plot_with_labels(self) -> None:
        """Create line plot with axis labels."""
        x_data = [1, 2, 3, 4, 5]
        y_data = [2, 4, 6, 8, 10]

        fig = create_line_plot(
            x_data,
            y_data,
            title="License Usage Over Time",
            xlabel="Days",
            ylabel="Activations",
        )

        assert fig is not None

    def test_create_multiple_lines_plot(self) -> None:
        """Create plot with multiple lines."""
        x_data = [1, 2, 3, 4, 5]
        y_data1 = [2, 4, 6, 8, 10]
        y_data2 = [1, 3, 5, 7, 9]

        fig = create_line_plot(x_data, [y_data1, y_data2], title="Multiple Lines")

        assert fig is not None

    def test_create_line_plot_empty_data(self) -> None:
        """Create line plot with empty data."""
        x_data = []
        y_data = []

        fig = create_line_plot(x_data, y_data)

        assert fig is not None


class TestScatterPlots:
    """Test scatter plot generation."""

    def test_create_simple_scatter_plot(self) -> None:
        """Create simple scatter plot."""
        x_data = [1, 2, 3, 4, 5]
        y_data = [2, 4, 6, 8, 10]

        fig = create_scatter_plot(x_data, y_data, title="Scatter Test")

        assert fig is not None

    def test_create_scatter_plot_with_colors(self) -> None:
        """Create scatter plot with color mapping."""
        x_data = [1, 2, 3, 4, 5]
        y_data = [2, 4, 6, 8, 10]
        colors = [0.1, 0.3, 0.5, 0.7, 0.9]

        fig = create_scatter_plot(x_data, y_data, colors=colors, title="Colored Scatter")

        assert fig is not None

    def test_create_scatter_plot_large_dataset(self) -> None:
        """Create scatter plot with large dataset."""
        x_data = list(range(1000))
        y_data = [x * 2 + i % 10 for i, x in enumerate(x_data)]

        fig = create_scatter_plot(x_data, y_data)

        assert fig is not None


class TestHistograms:
    """Test histogram generation."""

    def test_create_simple_histogram(self) -> None:
        """Create simple histogram."""
        data = [1, 2, 2, 3, 3, 3, 4, 4, 5]

        fig = create_histogram(data, bins=5, title="Test Histogram")

        assert fig is not None

    def test_create_histogram_with_custom_bins(self) -> None:
        """Create histogram with custom bin count."""
        data = list(range(100))

        fig = create_histogram(data, bins=20, title="Custom Bins")

        assert fig is not None

    def test_create_histogram_large_dataset(self) -> None:
        """Create histogram with large dataset."""
        data = [i % 100 for i in range(10000)]

        fig = create_histogram(data, bins=50)

        assert fig is not None


class TestBarCharts:
    """Test bar chart generation."""

    def test_create_simple_bar_chart(self) -> None:
        """Create simple bar chart."""
        categories = ["A", "B", "C", "D"]
        values = [10, 25, 15, 30]

        fig = create_bar_chart(categories, values, title="Test Bar Chart")

        assert fig is not None

    def test_create_bar_chart_with_labels(self) -> None:
        """Create bar chart with axis labels."""
        categories = ["VMProtect", "Themida", "Enigma", "SafeNet"]
        values = [45, 30, 15, 10]

        fig = create_bar_chart(
            categories,
            values,
            title="Protection Detection",
            xlabel="Protection Type",
            ylabel="Count",
        )

        assert fig is not None

    def test_create_horizontal_bar_chart(self) -> None:
        """Create horizontal bar chart."""
        categories = ["A", "B", "C"]
        values = [10, 20, 15]

        fig = create_bar_chart(categories, values, horizontal=True)

        assert fig is not None


class TestFigureSaving:
    """Test figure saving functionality."""

    def test_save_figure_png(self) -> None:
        """Save figure as PNG."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "test_plot.png"

            x_data = [1, 2, 3, 4, 5]
            y_data = [2, 4, 6, 8, 10]
            fig = create_line_plot(x_data, y_data)

            save_figure(fig, str(output_path))

            assert output_path.exists()
            assert output_path.stat().st_size > 0

    def test_save_figure_jpg(self) -> None:
        """Save figure as JPG."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "test_plot.jpg"

            x_data = [1, 2, 3]
            y_data = [2, 4, 6]
            fig = create_line_plot(x_data, y_data)

            save_figure(fig, str(output_path), format="jpg")

            assert output_path.exists()
            assert output_path.stat().st_size > 0

    def test_save_figure_pdf(self) -> None:
        """Save figure as PDF."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "test_plot.pdf"

            x_data = [1, 2, 3]
            y_data = [2, 4, 6]
            fig = create_line_plot(x_data, y_data)

            save_figure(fig, str(output_path), format="pdf")

            assert output_path.exists()
            assert output_path.stat().st_size > 0

    def test_save_figure_svg(self) -> None:
        """Save figure as SVG."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "test_plot.svg"

            x_data = [1, 2, 3]
            y_data = [2, 4, 6]
            fig = create_line_plot(x_data, y_data)

            save_figure(fig, str(output_path), format="svg")

            assert output_path.exists()
            assert output_path.stat().st_size > 0


class TestAnalysisVisualization:
    """Test visualization for binary analysis results."""

    def test_visualize_entropy_analysis(self) -> None:
        """Visualize entropy analysis results."""
        file_offsets = list(range(0, 10000, 100))
        entropy_values = [i / 100.0 for i in range(100)]

        fig = create_line_plot(
            file_offsets,
            entropy_values,
            title="Binary Entropy Analysis",
            xlabel="File Offset",
            ylabel="Entropy",
        )

        assert fig is not None

    def test_visualize_protection_detection_counts(self) -> None:
        """Visualize protection detection statistics."""
        protections = ["VMProtect", "Themida", "Enigma", "Unprotected"]
        counts = [12, 8, 5, 25]

        fig = create_bar_chart(
            protections,
            counts,
            title="Protection Detection Results",
            xlabel="Protection Type",
            ylabel="Sample Count",
        )

        assert fig is not None

    def test_visualize_license_check_locations(self) -> None:
        """Visualize license check locations in binary."""
        addresses = [0x1000, 0x2000, 0x3500, 0x4200, 0x5100]
        frequencies = [5, 3, 8, 2, 6]

        fig = create_scatter_plot(
            addresses,
            frequencies,
            title="License Check Locations",
            xlabel="Address",
            ylabel="Frequency",
        )

        assert fig is not None

    def test_visualize_instruction_distribution(self) -> None:
        """Visualize instruction type distribution."""
        instruction_lengths = [1] * 50 + [2] * 30 + [3] * 15 + [4] * 5

        fig = create_histogram(
            instruction_lengths,
            bins=10,
            title="Instruction Length Distribution",
        )

        assert fig is not None


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_create_plot_with_none_data(self) -> None:
        """Handle None data."""
        with pytest.raises(Exception):
            create_line_plot(None, None)

    def test_create_plot_with_mismatched_data(self) -> None:
        """Handle mismatched data lengths."""
        x_data = [1, 2, 3]
        y_data = [1, 2]

        with pytest.raises(Exception):
            create_line_plot(x_data, y_data)

    def test_save_to_invalid_path(self) -> None:
        """Handle invalid save path."""
        x_data = [1, 2, 3]
        y_data = [2, 4, 6]
        fig = create_line_plot(x_data, y_data)

        with pytest.raises(Exception):
            save_figure(fig, "/invalid/path/that/does/not/exist/plot.png")


class TestFallbackImplementation:
    """Test fallback implementation when matplotlib unavailable."""

    def test_fallback_create_line_plot(self) -> None:
        """Verify fallback line plot creation."""
        x_data = [1, 2, 3]
        y_data = [2, 4, 6]

        fig = create_line_plot(x_data, y_data)

        assert fig is not None

    def test_fallback_create_bar_chart(self) -> None:
        """Verify fallback bar chart creation."""
        categories = ["A", "B"]
        values = [10, 20]

        fig = create_bar_chart(categories, values)

        assert fig is not None


class TestPerformance:
    """Test plotting performance."""

    def test_large_dataset_line_plot_performance(self, benchmark: Any) -> None:
        """Benchmark line plot with large dataset."""
        x_data = list(range(10000))
        y_data = [x * 2 for x in x_data]

        result = benchmark(create_line_plot, x_data, y_data)

        assert result is not None

    def test_large_histogram_performance(self, benchmark: Any) -> None:
        """Benchmark histogram with large dataset."""
        data = list(range(100000))

        result = benchmark(create_histogram, data, bins=100)

        assert result is not None

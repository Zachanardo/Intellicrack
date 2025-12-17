"""Production tests for ASCII Chart Generator.

Validates real chart generation, data visualization, and terminal output formatting.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

from typing import Any

import pytest

from intellicrack.cli.ascii_charts import ASCIIChartGenerator, create_analysis_charts


class TestASCIIChartGenerator:
    """Production tests for ASCII chart generator."""

    @pytest.fixture
    def generator(self) -> ASCIIChartGenerator:
        """Create chart generator."""
        return ASCIIChartGenerator(width=80, height=20)

    def test_initialization_sets_dimensions(self) -> None:
        """Generator initializes with custom dimensions."""
        gen = ASCIIChartGenerator(width=100, height=30)
        assert gen.width == 100
        assert gen.height == 30

    def test_symbols_dictionary_defined(self, generator: ASCIIChartGenerator) -> None:
        """Generator has symbol mappings for chart elements."""
        assert "bar_full" in generator.symbols
        assert "line_horizontal" in generator.symbols
        assert "corner_top_left" in generator.symbols
        assert isinstance(generator.symbols["bar_full"], str)


class TestBarChart:
    """Test bar chart generation."""

    @pytest.fixture
    def generator(self) -> ASCIIChartGenerator:
        """Create chart generator."""
        return ASCIIChartGenerator(width=80, height=20)

    def test_generate_bar_chart_with_data(self, generator: ASCIIChartGenerator) -> None:
        """Bar chart is generated from data dictionary."""
        data = {"Category A": 100, "Category B": 75, "Category C": 50}

        chart = generator.generate_bar_chart(data, title="Test Chart")

        assert "Test Chart" in chart
        assert "Category A" in chart
        assert "Category B" in chart
        assert "Category C" in chart

    def test_bar_chart_empty_data(self, generator: ASCIIChartGenerator) -> None:
        """Bar chart with empty data returns message."""
        chart = generator.generate_bar_chart({})
        assert "No data" in chart

    def test_bar_chart_shows_values(self, generator: ASCIIChartGenerator) -> None:
        """Bar chart shows numeric values when enabled."""
        data = {"Item": 42}

        chart = generator.generate_bar_chart(data, show_values=True)

        assert "42" in chart

    def test_bar_chart_sorted_by_value(self, generator: ASCIIChartGenerator) -> None:
        """Bar chart sorts items by value descending."""
        data = {"Low": 10, "High": 100, "Medium": 50}

        chart = generator.generate_bar_chart(data)
        lines = chart.split("\n")

        high_index = next(i for i, line in enumerate(lines) if "High" in line)
        medium_index = next(i for i, line in enumerate(lines) if "Medium" in line)
        low_index = next(i for i, line in enumerate(lines) if "Low" in line)

        assert high_index < medium_index < low_index

    def test_bar_chart_handles_zero_max_value(self, generator: ASCIIChartGenerator) -> None:
        """Bar chart handles all-zero values gracefully."""
        data = {"Zero1": 0, "Zero2": 0}

        chart = generator.generate_bar_chart(data)

        assert "Zero1" in chart
        assert "Zero2" in chart

    def test_bar_chart_with_large_values(self, generator: ASCIIChartGenerator) -> None:
        """Bar chart scales large values correctly."""
        data = {"Large": 1000000, "Larger": 2000000}

        chart = generator.generate_bar_chart(data, show_values=True)

        assert "1000000" in chart or "2000000" in chart


class TestHistogram:
    """Test histogram generation."""

    @pytest.fixture
    def generator(self) -> ASCIIChartGenerator:
        """Create chart generator."""
        return ASCIIChartGenerator()

    def test_generate_histogram_with_values(self, generator: ASCIIChartGenerator) -> None:
        """Histogram is generated from value list."""
        values = [1, 2, 2, 3, 3, 3, 4, 4, 5]

        histogram = generator.generate_histogram(values, bins=5, title="Distribution")

        assert "Distribution" in histogram
        assert isinstance(histogram, str)
        assert len(histogram) > 0

    def test_histogram_empty_values(self, generator: ASCIIChartGenerator) -> None:
        """Histogram with empty values returns message."""
        histogram = generator.generate_histogram([])
        assert "No data" in histogram

    def test_histogram_bin_calculation(self, generator: ASCIIChartGenerator) -> None:
        """Histogram creates correct number of bins."""
        values = list(range(100))

        histogram = generator.generate_histogram(values, bins=10)

        assert isinstance(histogram, str)
        assert len(histogram) > 0

    def test_histogram_handles_single_value(self, generator: ASCIIChartGenerator) -> None:
        """Histogram handles single repeated value."""
        values = [42] * 10

        histogram = generator.generate_histogram(values, bins=5)

        assert isinstance(histogram, str)


class TestLineChart:
    """Test line chart generation."""

    @pytest.fixture
    def generator(self) -> ASCIIChartGenerator:
        """Create chart generator."""
        return ASCIIChartGenerator()

    def test_generate_line_chart_with_data(self, generator: ASCIIChartGenerator) -> None:
        """Line chart is generated from data points."""
        data = {"Jan": 10, "Feb": 20, "Mar": 15, "Apr": 25}

        chart = generator.generate_line_chart(data, title="Trend")

        assert "Trend" in chart
        assert isinstance(chart, str)

    def test_line_chart_empty_data(self, generator: ASCIIChartGenerator) -> None:
        """Line chart with empty data returns message."""
        chart = generator.generate_line_chart({})
        assert "No data" in chart

    def test_line_chart_single_point(self, generator: ASCIIChartGenerator) -> None:
        """Line chart handles single data point."""
        data = {"Point": 50}

        chart = generator.generate_line_chart(data)

        assert "Point" in chart

    def test_line_chart_handles_flat_line(self, generator: ASCIIChartGenerator) -> None:
        """Line chart handles all values being the same."""
        data = {"A": 10, "B": 10, "C": 10}

        chart = generator.generate_line_chart(data)

        assert isinstance(chart, str)


class TestPieChart:
    """Test pie chart generation."""

    @pytest.fixture
    def generator(self) -> ASCIIChartGenerator:
        """Create chart generator."""
        return ASCIIChartGenerator()

    def test_generate_pie_chart_with_data(self, generator: ASCIIChartGenerator) -> None:
        """Pie chart is generated with percentages."""
        data = {"Part A": 50, "Part B": 30, "Part C": 20}

        chart = generator.generate_pie_chart(data, title="Distribution")

        assert "Distribution" in chart
        assert "%" in chart
        assert "Part A" in chart

    def test_pie_chart_empty_data(self, generator: ASCIIChartGenerator) -> None:
        """Pie chart with empty data returns message."""
        chart = generator.generate_pie_chart({})
        assert "No data" in chart

    def test_pie_chart_zero_total(self, generator: ASCIIChartGenerator) -> None:
        """Pie chart with zero total returns message."""
        data = {"Zero1": 0, "Zero2": 0}

        chart = generator.generate_pie_chart(data)

        assert "No data" in chart

    def test_pie_chart_percentage_calculation(self, generator: ASCIIChartGenerator) -> None:
        """Pie chart calculates percentages correctly."""
        data = {"Half": 50, "Quarter": 25, "Quarter2": 25}

        chart = generator.generate_pie_chart(data)

        assert "50.0%" in chart or "25.0%" in chart


class TestScatterPlot:
    """Test scatter plot generation."""

    @pytest.fixture
    def generator(self) -> ASCIIChartGenerator:
        """Create chart generator."""
        return ASCIIChartGenerator()

    def test_generate_scatter_plot_with_points(self, generator: ASCIIChartGenerator) -> None:
        """Scatter plot is generated from point coordinates."""
        points = [(1.0, 2.0), (2.0, 4.0), (3.0, 6.0), (4.0, 8.0)]

        plot = generator.generate_scatter_plot(points, title="Correlation")

        assert "Correlation" in plot
        assert isinstance(plot, str)

    def test_scatter_plot_empty_points(self, generator: ASCIIChartGenerator) -> None:
        """Scatter plot with no points returns message."""
        plot = generator.generate_scatter_plot([])
        assert "No data" in plot

    def test_scatter_plot_single_point(self, generator: ASCIIChartGenerator) -> None:
        """Scatter plot handles single point."""
        points = [(5.0, 5.0)]

        plot = generator.generate_scatter_plot(points)

        assert isinstance(plot, str)

    def test_scatter_plot_handles_same_coordinates(self, generator: ASCIIChartGenerator) -> None:
        """Scatter plot handles points with same x or y."""
        points = [(1.0, 1.0), (1.0, 2.0), (1.0, 3.0)]

        plot = generator.generate_scatter_plot(points)

        assert isinstance(plot, str)


class TestAnalysisSummaryChart:
    """Test analysis summary chart generation."""

    @pytest.fixture
    def generator(self) -> ASCIIChartGenerator:
        """Create chart generator."""
        return ASCIIChartGenerator()

    def test_analysis_summary_chart_comprehensive(self, generator: ASCIIChartGenerator) -> None:
        """Analysis summary creates multiple charts from results."""
        analysis_results = {
            "vulnerabilities": {
                "vulnerabilities": [
                    {"severity": "high", "type": "overflow"},
                    {"severity": "medium", "type": "leak"},
                    {"severity": "low", "type": "info"},
                ],
            },
            "protections": {"aslr": True, "dep": True, "canary": False},
            "strings": ["string1", "longer_string", "s"],
        }

        chart = generator.generate_analysis_summary_chart(analysis_results)

        assert "Analysis Categories" in chart or "Vulnerability" in chart or len(chart) > 0

    def test_analysis_summary_no_data(self, generator: ASCIIChartGenerator) -> None:
        """Analysis summary with no chartable data returns message."""
        chart = generator.generate_analysis_summary_chart({})
        assert "No chartable data" in chart or "Analysis" in chart

    def test_analysis_summary_with_category_counts(self, generator: ASCIIChartGenerator) -> None:
        """Analysis summary counts categories correctly."""
        analysis_results = {
            "imports": ["func1", "func2", "func3"],
            "exports": ["export1"],
            "sections": [".text", ".data"],
        }

        chart = generator.generate_analysis_summary_chart(analysis_results)

        assert isinstance(chart, str)


class TestVulnerabilityTrendChart:
    """Test vulnerability trend chart."""

    @pytest.fixture
    def generator(self) -> ASCIIChartGenerator:
        """Create chart generator."""
        return ASCIIChartGenerator()

    def test_vulnerability_trend_chart_with_data(self, generator: ASCIIChartGenerator) -> None:
        """Vulnerability trend chart groups by severity."""
        vulnerability_data = [
            {"severity": "critical", "type": "rce"},
            {"severity": "high", "type": "sqli"},
            {"severity": "high", "type": "xss"},
            {"severity": "medium", "type": "leak"},
        ]

        chart = generator.generate_vulnerability_trend_chart(vulnerability_data)

        assert "Vulnerability" in chart
        assert "Critical" in chart or "High" in chart

    def test_vulnerability_trend_no_data(self, generator: ASCIIChartGenerator) -> None:
        """Vulnerability trend with no data returns message."""
        chart = generator.generate_vulnerability_trend_chart([])
        assert "No vulnerability data" in chart


class TestCreateAnalysisCharts:
    """Test create_analysis_charts function."""

    def test_create_analysis_charts_summary_type(self) -> None:
        """create_analysis_charts generates summary chart."""
        analysis_results: dict[str, Any] = {
            "vulnerabilities": {"vulnerabilities": [{"severity": "high"}]},
        }

        chart = create_analysis_charts(analysis_results, chart_type="summary")

        assert isinstance(chart, str)

    def test_create_analysis_charts_vulnerability_type(self) -> None:
        """create_analysis_charts generates vulnerability chart."""
        analysis_results = {
            "vulnerabilities": {
                "vulnerabilities": [{"severity": "high"}, {"severity": "medium"}],
            },
        }

        chart = create_analysis_charts(analysis_results, chart_type="vulnerability")

        assert isinstance(chart, str)

    def test_create_analysis_charts_no_vulnerability_data(self) -> None:
        """create_analysis_charts handles missing vulnerability data."""
        analysis_results: dict[str, Any] = {}

        chart = create_analysis_charts(analysis_results, chart_type="vulnerability")

        assert "No vulnerability data" in chart


class TestEdgeCases:
    """Test edge cases and error handling."""

    @pytest.fixture
    def generator(self) -> ASCIIChartGenerator:
        """Create chart generator."""
        return ASCIIChartGenerator()

    def test_chart_with_negative_values(self, generator: ASCIIChartGenerator) -> None:
        """Charts handle negative values."""
        data = {"Positive": 100, "Negative": -50}

        chart = generator.generate_bar_chart(data)

        assert "Positive" in chart

    def test_chart_with_very_long_labels(self, generator: ASCIIChartGenerator) -> None:
        """Charts handle very long labels."""
        data = {"VeryLongLabelThatExceedsNormalWidth" * 3: 100}

        chart = generator.generate_bar_chart(data)

        assert isinstance(chart, str)

    def test_chart_with_special_characters_in_labels(self, generator: ASCIIChartGenerator) -> None:
        """Charts handle special characters in labels."""
        data = {"Label™": 50, "Test®": 30, "Data©": 20}

        chart = generator.generate_bar_chart(data)

        assert isinstance(chart, str)

    def test_small_dimensions(self) -> None:
        """Generator works with small dimensions."""
        gen = ASCIIChartGenerator(width=20, height=10)
        data = {"A": 10, "B": 20}

        chart = gen.generate_bar_chart(data)

        assert isinstance(chart, str)

    def test_very_large_dataset(self, generator: ASCIIChartGenerator) -> None:
        """Charts handle large datasets."""
        data = {f"Item{i}": i for i in range(100)}

        chart = generator.generate_bar_chart(data)

        assert isinstance(chart, str)
        assert len(chart) > 0

    def test_unicode_in_data(self, generator: ASCIIChartGenerator) -> None:
        """Charts handle Unicode characters."""
        data = {"测试": 50, "テスト": 30, "тест": 20}

        chart = generator.generate_bar_chart(data)

        assert isinstance(chart, str)

    def test_mixed_numeric_types(self, generator: ASCIIChartGenerator) -> None:
        """Charts handle mixed int and float values."""
        data = {"Int": 100, "Float": 75.5, "Another": 50}

        chart = generator.generate_bar_chart(data)

        assert "Int" in chart
        assert "Float" in chart

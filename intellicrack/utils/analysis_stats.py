"""Copyright (C) 2025 Zachary Flint

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
along with Intellicrack.  If not, see <https://www.gnu.org/licenses/>.
"""

import logging
import time
from collections import Counter, defaultdict
from collections.abc import Callable
from typing import Any

logger = logging.getLogger(__name__)


class AnalysisStatsGenerator:
    """Utility class for generating analysis statistics and reports.
    """

    @staticmethod
    def count_by_attribute(items: list[dict[str, Any]], attribute: str) -> dict[str, int]:
        """Count items by a specific attribute.

        Args:
            items: List of dictionaries to analyze
            attribute: Attribute to count by

        Returns:
            Dictionary with counts for each attribute value

        """
        try:
            if not items:
                return {}

            counts = Counter()
            for item in items:
                if isinstance(item, dict) and attribute in item:
                    value = item[attribute]
                    # Convert value to string for consistent counting
                    counts[str(value)] += 1

            return dict(counts)

        except Exception as e:
            logger.debug(f"Attribute counting failed: {e}")
            return {}

    @staticmethod
    def calculate_distribution(items: list[dict[str, Any]],
                             attribute: str) -> dict[str, float]:
        """Calculate percentage distribution of an attribute.

        Args:
            items: List of dictionaries to analyze
            attribute: Attribute to calculate distribution for

        Returns:
            Dictionary with percentage distribution

        """
        try:
            counts = AnalysisStatsGenerator.count_by_attribute(items, attribute)
            total = sum(counts.values())

            if total == 0:
                return {}

            distribution = {}
            for key, count in counts.items():
                distribution[key] = (count / total) * 100.0

            return distribution

        except Exception as e:
            logger.debug(f"Distribution calculation failed: {e}")
            return {}

    @staticmethod
    def aggregate_numeric_stats(items: list[dict[str, Any]],
                              attribute: str) -> dict[str, float]:
        """Calculate numeric statistics for an attribute.

        Args:
            items: List of dictionaries to analyze
            attribute: Numeric attribute to analyze

        Returns:
            Dictionary with min, max, avg, sum statistics

        """
        try:
            values = []
            for item in items:
                if isinstance(item, dict) and attribute in item:
                    value = item[attribute]
                    if isinstance(value, (int, float)):
                        values.append(value)

            if not values:
                return {
                    "count": 0,
                    "min": 0.0,
                    "max": 0.0,
                    "avg": 0.0,
                    "sum": 0.0,
                }

            return {
                "count": len(values),
                "min": float(min(values)),
                "max": float(max(values)),
                "avg": float(sum(values) / len(values)),
                "sum": float(sum(values)),
            }

        except Exception as e:
            logger.debug(f"Numeric stats calculation failed: {e}")
            return {
                "count": 0,
                "min": 0.0,
                "max": 0.0,
                "avg": 0.0,
                "sum": 0.0,
            }

    @staticmethod
    def generate_correlation_matrix(items: list[dict[str, Any]],
                                  attributes: list[str]) -> dict[str, dict[str, float]]:
        """Generate correlation matrix between numeric attributes.

        Args:
            items: List of dictionaries to analyze
            attributes: List of numeric attributes to correlate

        Returns:
            Correlation matrix as nested dictionary

        """
        try:
            # Extract numeric values for each attribute
            attribute_values = {}
            for attr in attributes:
                values = []
                for item in items:
                    if isinstance(item, dict) and attr in item:
                        value = item[attr]
                        if isinstance(value, (int, float)):
                            values.append(float(value))
                attribute_values[attr] = values

            # Calculate correlations
            correlation_matrix = {}
            for attr1 in attributes:
                correlation_matrix[attr1] = {}
                for attr2 in attributes:
                    if attr1 == attr2:
                        correlation_matrix[attr1][attr2] = 1.0
                    else:
                        correlation = AnalysisStatsGenerator._calculate_correlation(
                            attribute_values.get(attr1, []),
                            attribute_values.get(attr2, []),
                        )
                        correlation_matrix[attr1][attr2] = correlation

            return correlation_matrix

        except Exception as e:
            logger.debug(f"Correlation matrix generation failed: {e}")
            return {}

    @staticmethod
    def _calculate_correlation(values1: list[float], values2: list[float]) -> float:
        """Calculate Pearson correlation coefficient."""
        try:
            if len(values1) != len(values2) or len(values1) < 2:
                return 0.0

            # Calculate means
            mean1 = sum(values1) / len(values1)
            mean2 = sum(values2) / len(values2)

            # Calculate correlation components
            numerator = sum((x - mean1) * (y - mean2) for x, y in zip(values1, values2, strict=False))
            sum_sq1 = sum((x - mean1) ** 2 for x in values1)
            sum_sq2 = sum((y - mean2) ** 2 for y in values2)

            denominator = (sum_sq1 * sum_sq2) ** 0.5

            if denominator == 0:
                return 0.0

            return numerator / denominator

        except Exception as e:
            logger.debug(f"Correlation calculation failed: {e}")
            return 0.0

    @staticmethod
    def generate_time_series_stats(items: list[dict[str, Any]],
                                 time_attribute: str = "timestamp",
                                 value_attribute: str = "value",
                                 interval_seconds: int = 3600) -> dict[str, Any]:
        """Generate time series statistics.

        Args:
            items: List of dictionaries with time and value data
            time_attribute: Name of timestamp attribute
            value_attribute: Name of value attribute
            interval_seconds: Time interval for aggregation (default: 1 hour)

        Returns:
            Time series statistics

        """
        try:
            # Group items by time intervals
            time_buckets = defaultdict(list)

            for item in items:
                if (isinstance(item, dict) and
                    time_attribute in item and
                    value_attribute in item):

                    timestamp = item[time_attribute]
                    value = item[value_attribute]

                    # Convert timestamp to bucket
                    if isinstance(timestamp, (int, float)):
                        bucket = int(timestamp // interval_seconds) * interval_seconds
                        time_buckets[bucket].append(value)

            # Calculate statistics for each bucket
            time_series = {}
            for bucket_time, values in time_buckets.items():
                numeric_values = [v for v in values if isinstance(v, (int, float))]

                if numeric_values:
                    time_series[bucket_time] = {
                        "count": len(numeric_values),
                        "min": min(numeric_values),
                        "max": max(numeric_values),
                        "avg": sum(numeric_values) / len(numeric_values),
                        "sum": sum(numeric_values),
                    }

            return {
                "interval_seconds": interval_seconds,
                "total_buckets": len(time_series),
                "data": time_series,
            }

        except Exception as e:
            logger.debug(f"Time series stats generation failed: {e}")
            return {
                "interval_seconds": interval_seconds,
                "total_buckets": 0,
                "data": {},
            }

    @staticmethod
    def safe_stats_generation(stats_function: Callable[[], Any],
                            default_return: Any | None = None) -> Any:
        """Safely execute a statistics generation function with error handling.

        Args:
            stats_function: Function to execute
            default_return: Default value to return on error

        Returns:
            Function result or default value on error

        """
        try:
            return stats_function()
        except Exception as e:
            logger.debug(f"Stats generation failed: {e}")
            return default_return

    @staticmethod
    def generate_summary_report(items: list[dict[str, Any]],
                              title: str = "Analysis Summary") -> str:
        """Generate a text summary report.

        Args:
            items: List of dictionaries to summarize
            title: Report title

        Returns:
            Formatted text report

        """
        try:
            report_lines = [
                f"{title}",
                "=" * len(title),
                "",
                f"Total Items: {len(items)}",
                "",
            ]

            if not items:
                report_lines.append("No data to analyze.")
                return "\n".join(report_lines)

            # Identify common attributes
            all_attributes = set()
            for item in items:
                if isinstance(item, dict):
                    all_attributes.update(item.keys())

            common_attributes = []
            for attr in all_attributes:
                count = sum(1 for item in items if isinstance(item, dict) and attr in item)
                if count >= len(items) * 0.5:  # Present in at least 50% of items
                    common_attributes.append(attr)

            # Generate statistics for common attributes
            for attr in sorted(common_attributes):
                report_lines.append(f"{attr.title()}:")

                # Check if attribute has numeric values
                numeric_values = []
                for item in items:
                    if isinstance(item, dict) and attr in item:
                        value = item[attr]
                        if isinstance(value, (int, float)):
                            numeric_values.append(value)

                if len(numeric_values) > len(items) * 0.3:  # Mostly numeric
                    stats = AnalysisStatsGenerator.aggregate_numeric_stats(items, attr)
                    report_lines.extend([
                        f"  Count: {stats['count']}",
                        f"  Min: {stats['min']:.2f}",
                        f"  Max: {stats['max']:.2f}",
                        f"  Average: {stats['avg']:.2f}",
                        f"  Sum: {stats['sum']:.2f}",
                    ])
                else:
                    # Categorical data
                    counts = AnalysisStatsGenerator.count_by_attribute(items, attr)
                    top_values = sorted(counts.items(), key=lambda x: x[1], reverse=True)[:5]

                    for value, count in top_values:
                        percentage = (count / len(items)) * 100
                        report_lines.append(f"  {value}: {count} ({percentage:.1f}%)")

                report_lines.append("")

            return "\n".join(report_lines)

        except Exception as e:
            logger.debug(f"Summary report generation failed: {e}")
            return f"{title}\n{'=' * len(title)}\n\nError generating report: {e}"

    @staticmethod
    def calculate_growth_rate(current_value: float,
                            previous_value: float) -> float:
        """Calculate growth rate between two values.

        Args:
            current_value: Current measurement
            previous_value: Previous measurement

        Returns:
            Growth rate as percentage

        """
        try:
            if previous_value == 0:
                return 100.0 if current_value > 0 else 0.0

            growth_rate = ((current_value - previous_value) / previous_value) * 100
            return round(growth_rate, 2)

        except Exception as e:
            logger.debug(f"Growth rate calculation failed: {e}")
            return 0.0

    @staticmethod
    def detect_outliers(values: list[int | float],
                       method: str = "iqr") -> list[int]:
        """Detect outliers in a list of numeric values.

        Args:
            values: List of numeric values
            method: Outlier detection method ('iqr' or 'zscore')

        Returns:
            List of indices of outlier values

        """
        try:
            if len(values) < 4:
                return []

            outlier_indices = []

            if method == "iqr":
                # Interquartile Range method
                sorted_values = sorted(values)
                n = len(sorted_values)

                q1_idx = n // 4
                q3_idx = 3 * n // 4

                q1 = sorted_values[q1_idx]
                q3 = sorted_values[q3_idx]
                iqr = q3 - q1

                lower_bound = q1 - 1.5 * iqr
                upper_bound = q3 + 1.5 * iqr

                for i, value in enumerate(values):
                    if value < lower_bound or value > upper_bound:
                        outlier_indices.append(i)

            elif method == "zscore":
                # Z-score method
                mean_val = sum(values) / len(values)
                variance = sum((x - mean_val) ** 2 for x in values) / len(values)
                std_dev = variance ** 0.5

                if std_dev > 0:
                    for i, value in enumerate(values):
                        z_score = abs((value - mean_val) / std_dev)
                        if z_score > 2.5:  # Threshold for outlier
                            outlier_indices.append(i)

            return outlier_indices

        except Exception as e:
            logger.debug(f"Outlier detection failed: {e}")
            return []

    @staticmethod
    def generate_percentiles(values: list[int | float],
                           percentiles: list[int] = None) -> dict[int, float]:
        """Calculate percentiles for a list of values.

        Args:
            values: List of numeric values
            percentiles: List of percentile values to calculate (default: [25, 50, 75, 90, 95])

        Returns:
            Dictionary mapping percentile to value

        """
        try:
            if not values:
                return {}

            if percentiles is None:
                percentiles = [25, 50, 75, 90, 95]

            sorted_values = sorted(values)
            n = len(sorted_values)

            result = {}
            for p in percentiles:
                if 0 <= p <= 100:
                    index = (p / 100) * (n - 1)

                    if index.is_integer():
                        result[p] = sorted_values[int(index)]
                    else:
                        # Linear interpolation
                        lower_idx = int(index)
                        upper_idx = min(lower_idx + 1, n - 1)
                        weight = index - lower_idx

                        result[p] = (sorted_values[lower_idx] * (1 - weight) +
                                   sorted_values[upper_idx] * weight)

            return result

        except Exception as e:
            logger.debug(f"Percentile calculation failed: {e}")
            return {}


class PerformanceTracker:
    """Track performance metrics for analysis operations.
    """

    def __init__(self):
        """Initialize the performance tracker with empty metrics and timing data."""
        self.metrics = {}
        self.start_times = {}

    def start_operation(self, operation_name: str):
        """Start tracking an operation."""
        self.start_times[operation_name] = time.time()

    def end_operation(self, operation_name: str, item_count: int = 1):
        """End tracking an operation and record metrics."""
        try:
            if operation_name in self.start_times:
                duration = time.time() - self.start_times[operation_name]

                if operation_name not in self.metrics:
                    self.metrics[operation_name] = {
                        "total_time": 0.0,
                        "total_items": 0,
                        "call_count": 0,
                        "avg_time_per_call": 0.0,
                        "avg_time_per_item": 0.0,
                    }

                self.metrics[operation_name]["total_time"] += duration
                self.metrics[operation_name]["total_items"] += item_count
                self.metrics[operation_name]["call_count"] += 1

                # Update averages
                call_count = self.metrics[operation_name]["call_count"]
                total_time = self.metrics[operation_name]["total_time"]
                total_items = self.metrics[operation_name]["total_items"]

                self.metrics[operation_name]["avg_time_per_call"] = total_time / call_count
                if total_items > 0:
                    self.metrics[operation_name]["avg_time_per_item"] = total_time / total_items

                del self.start_times[operation_name]

        except Exception as e:
            logger.debug(f"Performance tracking failed: {e}")

    def get_metrics(self) -> dict[str, Any]:
        """Get all collected metrics."""
        return dict(self.metrics)

    def reset_metrics(self):
        """Reset all metrics."""
        self.metrics.clear()
        self.start_times.clear()


# Export commonly used classes and functions
__all__ = [
    "AnalysisStatsGenerator",
    "PerformanceTracker",
]

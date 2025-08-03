"""This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

"""
Analysis Statistics Utilities

Common utilities for generating statistics and recommendations in analysis modules.
"""

import logging
from typing import Any


class AnalysisStatsGenerator:
    """Common utilities for generating analysis statistics and recommendations.
    Eliminates duplicate statistics generation code.
    """

    @staticmethod
    def safe_stats_generation(stats_func, *args, **kwargs) -> dict[str, Any]:
        """Safely execute statistics generation with error handling.

        Args:
            stats_func: Function to execute for statistics generation
            *args: Arguments to pass to the function
            **kwargs: Keyword arguments to pass to the function

        Returns:
            Statistics dictionary or empty dict on error

        """
        try:
            return stats_func(*args, **kwargs)
        except Exception as e:
            logger = logging.getLogger(__name__)
            logger.debug(f"Statistics generation error: {e}")
            return {}

    @staticmethod
    def count_by_attribute(
        items: list[dict[str, Any]], attribute: str, default_value: str = "unknown"
    ) -> dict[str, int]:
        """Count items by a specific attribute.

        Args:
            items: List of items to count
            attribute: Attribute name to count by
            default_value: Default value for missing attributes

        Returns:
            Dictionary with counts by attribute value

        """
        counts = {}
        for item in items:
            value = item.get(attribute, default_value)
            counts[value] = counts.get(value, 0) + 1
        return counts

    @staticmethod
    def safe_recommendation_generation(rec_func, *args, **kwargs) -> list[str]:
        """Safely execute recommendation generation with error handling.

        Args:
            rec_func: Function to execute for recommendation generation
            *args: Arguments to pass to the function
            **kwargs: Keyword arguments to pass to the function

        Returns:
            List of recommendations or empty list on error

        """
        try:
            return rec_func(*args, **kwargs)
        except Exception as e:
            logger = logging.getLogger(__name__)
            logger.debug(f"Recommendation generation error: {e}")
            return []

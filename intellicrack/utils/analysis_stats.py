"""
Analysis Statistics Utilities

Common utilities for generating statistics and recommendations in analysis modules.
"""

import logging
from typing import Any, Dict, List


class AnalysisStatsGenerator:
    """
    Common utilities for generating analysis statistics and recommendations.
    Eliminates duplicate statistics generation code.
    """

    @staticmethod
    def safe_stats_generation(stats_func, *args, **kwargs) -> Dict[str, Any]:
        """
        Safely execute statistics generation with error handling.
        
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
    def count_by_attribute(items: List[Dict[str, Any]], attribute: str,
                          default_value: str = 'unknown') -> Dict[str, int]:
        """
        Count items by a specific attribute.
        
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
    def safe_recommendation_generation(rec_func, *args, **kwargs) -> List[str]:
        """
        Safely execute recommendation generation with error handling.
        
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

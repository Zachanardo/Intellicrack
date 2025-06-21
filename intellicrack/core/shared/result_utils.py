"""
Result Dictionary Utilities

Common functionality for result dictionary operations to eliminate code duplication.
"""

from typing import Any, Dict


class ResultMixin:
    """Mixin class providing common result dictionary operations."""

    def init_result(self, **kwargs) -> Dict[str, Any]:
        """
        Initialize a standard result dictionary.

        Args:
            **kwargs: Additional fields to include in the result

        Returns:
            Initialized result dictionary with success=False and error=None
        """
        result = {
            'success': False,
            'error': None
        }
        result.update(kwargs)
        return result

    def create_analysis_result(self, **kwargs) -> Dict[str, Any]:
        """
        Create a standardized analysis result dictionary.
        Alias for init_result to maintain compatibility.

        Args:
            **kwargs: Additional fields to include in the result

        Returns:
            Standardized result dictionary
        """
        return self.init_result(**kwargs)

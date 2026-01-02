"""Provide common result dictionary operations to eliminate code duplication.

This module offers utility classes and functions for handling standardized
result dictionaries across the Intellicrack analysis framework.

This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see https://www.gnu.org/licenses/.
"""


class ResultMixin:
    """Mixin class providing common result dictionary operations."""

    def init_result(self, **kwargs: object) -> dict[str, object]:
        """Initialize a standard result dictionary.

        Args:
            **kwargs: Additional fields to include in the result

        Returns:
            Initialized result dictionary with success=False and error=None

        """
        return {
            "success": False,
            "error": None,
        } | kwargs

    def create_analysis_result(self, **kwargs: object) -> dict[str, object]:
        """Create a standardized analysis result dictionary.

        Alias for init_result to maintain compatibility.

        Args:
            **kwargs: Additional fields to include in the result

        Returns:
            Standardized result dictionary

        """
        return self.init_result(**kwargs)

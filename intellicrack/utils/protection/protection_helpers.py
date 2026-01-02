"""Provide protection bypass helper functions.

Copyright (C) 2025 Zachary Flint

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
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""

from typing import Any


def create_bypass_result() -> dict[str, Any]:
    """Create standard bypass result structure.

    Returns:
        Standard result dictionary for bypass operations with success flag,
        methods applied, and error tracking capabilities.

    """
    return {
        "success": False,
        "methods_applied": [],
        "errors": [],
    }


def add_bypass_method(result: dict[str, Any], method_name: str) -> None:
    """Add a successful bypass method to results.

    Args:
        result: Bypass result dictionary to update with successful method.
        method_name: Name of the bypass method to add to the methods applied list.

    """
    if "methods_applied" not in result:
        result["methods_applied"] = []
    result["methods_applied"].append(method_name)


def add_bypass_error(result: dict[str, Any], error: str) -> None:
    """Add an error to bypass results.

    Args:
        result: Bypass result dictionary to update with error information.
        error: Error message describing the bypass attempt failure or issue.

    """
    if "errors" not in result:
        result["errors"] = []
    result["errors"].append(error)


def finalize_bypass_result(result: dict[str, Any]) -> dict[str, Any]:
    """Finalize bypass result by setting success flag.

    Args:
        result: Bypass result dictionary to finalize with success determination.

    Returns:
        The finalized result dictionary with the success flag set based on
        whether any bypass methods were successfully applied.

    """
    result["success"] = len(result.get("methods_applied", [])) > 0
    return result

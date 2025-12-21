"""Production tests for protection helpers - bypass result management.

Tests REAL bypass result creation and management functionality.
All tests validate genuine helper capability for license crack operations.
"""

from typing import Any

import pytest

from intellicrack.utils.protection.protection_helpers import (
    add_bypass_error,
    add_bypass_method,
    create_bypass_result,
    finalize_bypass_result,
)


class TestCreateBypassResult:
    """Test bypass result structure creation."""

    def test_create_bypass_result_returns_dict(self) -> None:
        """Create bypass result returns dictionary."""
        result = create_bypass_result()

        assert isinstance(result, dict)

    def test_create_bypass_result_has_success_field(self) -> None:
        """Bypass result contains success field."""
        result = create_bypass_result()

        assert "success" in result
        assert result["success"] is False

    def test_create_bypass_result_has_methods_applied(self) -> None:
        """Bypass result contains methods_applied list."""
        result = create_bypass_result()

        assert "methods_applied" in result
        assert isinstance(result["methods_applied"], list)
        assert len(result["methods_applied"]) == 0

    def test_create_bypass_result_has_errors_list(self) -> None:
        """Bypass result contains errors list."""
        result = create_bypass_result()

        assert "errors" in result
        assert isinstance(result["errors"], list)
        assert len(result["errors"]) == 0


class TestAddBypassMethod:
    """Test adding bypass methods to results."""

    def test_add_bypass_method_appends_to_list(self) -> None:
        """Add bypass method appends method name to list."""
        result: dict[str, Any] = {"methods_applied": []}

        add_bypass_method(result, "nop_license_check")

        assert "nop_license_check" in result["methods_applied"]
        assert len(result["methods_applied"]) == 1

    def test_add_bypass_method_creates_list_if_missing(self) -> None:
        """Add bypass method creates list if not present."""
        result: dict[str, Any] = {}

        add_bypass_method(result, "patch_trial_check")

        assert "methods_applied" in result
        assert "patch_trial_check" in result["methods_applied"]

    def test_add_multiple_bypass_methods(self) -> None:
        """Add multiple bypass methods accumulates them."""
        result: dict[str, Any] = {"methods_applied": []}

        add_bypass_method(result, "method1")
        add_bypass_method(result, "method2")
        add_bypass_method(result, "method3")

        assert len(result["methods_applied"]) == 3
        assert result["methods_applied"] == ["method1", "method2", "method3"]


class TestAddBypassError:
    """Test adding bypass errors to results."""

    def test_add_bypass_error_appends_to_list(self) -> None:
        """Add bypass error appends error message to list."""
        result: dict[str, Any] = {"errors": []}

        add_bypass_error(result, "Failed to parse PE header")

        assert "Failed to parse PE header" in result["errors"]
        assert len(result["errors"]) == 1

    def test_add_bypass_error_creates_list_if_missing(self) -> None:
        """Add bypass error creates list if not present."""
        result: dict[str, Any] = {}

        add_bypass_error(result, "Binary not found")

        assert "errors" in result
        assert "Binary not found" in result["errors"]


class TestFinalizeBypassResult:
    """Test finalizing bypass results."""

    def test_finalize_bypass_result_sets_success_true(self) -> None:
        """Finalize sets success to True when methods applied."""
        result: dict[str, Any] = {
            "success": False,
            "methods_applied": ["method1", "method2"],
            "errors": [],
        }

        finalized = finalize_bypass_result(result)

        assert finalized["success"] is True

    def test_finalize_bypass_result_sets_success_false(self) -> None:
        """Finalize sets success to False when no methods applied."""
        result: dict[str, Any] = {
            "success": False,
            "methods_applied": [],
            "errors": ["Error 1"],
        }

        finalized = finalize_bypass_result(result)

        assert finalized["success"] is False


class TestBypassResultWorkflows:
    """Integration tests for complete bypass result workflows."""

    def test_complete_successful_bypass_workflow(self) -> None:
        """Complete workflow for successful bypass."""
        result = create_bypass_result()

        add_bypass_method(result, "nop_time_check")
        add_bypass_method(result, "patch_license_validation")

        finalized = finalize_bypass_result(result)

        assert finalized["success"] is True
        assert len(finalized["methods_applied"]) == 2
        assert len(finalized["errors"]) == 0

    def test_complete_failed_bypass_workflow(self) -> None:
        """Complete workflow for failed bypass."""
        result = create_bypass_result()

        add_bypass_error(result, "Failed to locate license function")
        add_bypass_error(result, "Binary is protected with VMProtect")

        finalized = finalize_bypass_result(result)

        assert finalized["success"] is False
        assert len(finalized["methods_applied"]) == 0
        assert len(finalized["errors"]) == 2

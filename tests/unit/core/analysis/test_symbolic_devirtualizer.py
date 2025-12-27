"""Tests for symbolic execution-based devirtualization engine.

DISABLED: ALL TESTS REMOVED DUE TO MOCK VIOLATIONS

This file violated the strict no-mock policy by using unittest.mock (Mock, patch, MagicMock).

To re-enable these tests:
1. Remove all unittest.mock imports and usage
2. Use real virtualized binaries (VMProtect, Themida, etc.)
3. Use pytest.skip() if angr is not installed
"""

import pytest

pytestmark = pytest.mark.skip(reason="All tests disabled - violated no-mock policy.")


class TestSymbolicDevirtualizer:
    """Disabled test class."""

    def test_placeholder(self):
        """Placeholder to prevent empty test class errors."""
        pytest.skip("All tests disabled - require removal of mocks")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

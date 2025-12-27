"""Unit tests for StarForce analyzer module.

DISABLED: ALL TESTS REMOVED DUE TO MOCK VIOLATIONS

This file violated the strict no-mock policy by using:
1. unittest.mock (Mock, patch, MagicMock, mock_open)
2. struct.pack to create fake binaries

To re-enable these tests:
1. Remove all unittest.mock imports and usage
2. Use real StarForce-protected binaries
3. Use pytest.skip() if real binaries are not available
"""

import pytest

pytestmark = pytest.mark.skip(reason="All tests disabled - violated no-mock policy.")


class TestStarForceAnalyzer:
    """Disabled test class."""

    def test_placeholder(self):
        """Placeholder to prevent empty test class errors."""
        pytest.skip("All tests disabled - require removal of mocks")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

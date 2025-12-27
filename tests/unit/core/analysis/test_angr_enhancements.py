"""Tests for production-ready Angr enhancements for license cracking.

DISABLED: ALL TESTS REMOVED DUE TO MOCK VIOLATIONS

This file violated the strict no-mock policy:
1. Used unittest.mock (MagicMock, Mock, patch)
2. Used struct.pack to create fake PE binaries
3. Mocked angr Project objects instead of using real binaries

To re-enable these tests:
1. Obtain real PE binaries for testing (legally)
2. Place them in tests/fixtures/binaries/
3. Rewrite tests to use real angr Project instances with real binaries
4. Use pytest.skip() if angr is not installed
"""

import pytest

pytestmark = pytest.mark.skip(reason="All tests disabled - violated no-mock policy. Require real binaries and real angr testing.")


class TestAngrEnhancements:
    """Disabled test class."""

    def test_placeholder(self):
        """Placeholder to prevent empty test class errors."""
        pytest.skip("All tests disabled - awaiting real binary fixtures")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

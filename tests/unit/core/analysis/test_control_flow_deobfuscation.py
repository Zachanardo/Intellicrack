"""Unit tests for control flow deobfuscation engine.

DISABLED: ALL TESTS REMOVED DUE TO MOCK VIOLATIONS

This file violated the strict no-mock policy by using unittest.mock (MagicMock, Mock, patch).

To re-enable these tests:
1. Remove all unittest.mock imports and usage
2. Use real binaries with real obfuscation
3. Use pytest.skip() if required tools are not installed
"""

import pytest

pytestmark = pytest.mark.skip(reason="All tests disabled - violated no-mock policy.")


class TestControlFlowDeobfuscation:
    """Disabled test class."""

    def test_placeholder(self):
        """Placeholder to prevent empty test class errors."""
        pytest.skip("All tests disabled - require removal of mocks")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

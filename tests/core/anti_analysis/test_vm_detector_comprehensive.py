"""Comprehensive production-grade tests for VMDetector.

DISABLED: ALL TESTS REMOVED DUE TO MOCK VIOLATIONS

This file violated the strict no-mock policy by using:
1. unittest.mock (MagicMock, patch)
2. struct.pack to create fake data

To re-enable these tests:
1. Remove all unittest.mock imports and usage
2. Run tests on real VM and bare-metal systems
3. Use pytest.skip() for tests that require specific environments
"""

import pytest

pytestmark = pytest.mark.skip(reason="All tests disabled - violated no-mock policy.")


class TestVMDetector:
    """Disabled test class."""

    def test_placeholder(self):
        """Placeholder to prevent empty test class errors."""
        pytest.skip("All tests disabled - require removal of mocks and real VM/bare-metal testing")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

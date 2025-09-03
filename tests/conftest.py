"""
Minimal pytest configuration for testing import issues.
"""

import os
import pytest
import sys
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


def pytest_sessionstart(session):
    """Set up testing environment before any tests run."""
    # Disable AI background services during testing
    os.environ["INTELLICRACK_TESTING"] = "1"
    os.environ["DISABLE_AI_WORKERS"] = "1"
    os.environ["DISABLE_BACKGROUND_THREADS"] = "1"
    os.environ["NO_AUTO_START"] = "1"

    # Disable resource monitoring during tests
    os.environ["DISABLE_RESOURCE_MONITORING"] = "1"
    os.environ["DISABLE_AUDIT_LOGGING"] = "1"

    # Threading environment variables for stability
    os.environ["OMP_NUM_THREADS"] = "1"
    os.environ["MKL_NUM_THREADS"] = "1"
    os.environ["NUMEXPR_NUM_THREADS"] = "1"

    # Qt testing environment
    os.environ["QT_QPA_PLATFORM"] = "offscreen"
    os.environ["QT_LOGGING_RULES"] = "*.debug=false"


@pytest.fixture(scope="session", autouse=True)
def setup_test_environment():
    """Set up test environment automatically for all tests."""
    # Additional setup if needed
    yield
    # Cleanup if needed


@pytest.fixture
def temp_workspace():
    """Provide a temporary directory for test operations."""
    import tempfile
    import shutil

    temp_dir = tempfile.mkdtemp(prefix="intellicrack_test_")
    yield Path(temp_dir)
    shutil.rmtree(temp_dir, ignore_errors=True)


# Simple markers for test categorization
def pytest_configure(config):
    """Register custom markers."""
    config.addinivalue_line(
        "markers", "real_data: test validates real functionality"
    )

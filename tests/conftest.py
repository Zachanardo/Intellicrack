"""Minimal pytest configuration for testing import issues."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from dotenv import load_dotenv


if TYPE_CHECKING:
    from collections.abc import Iterator

    from _pytest.python import Function
    from _pytest.unittest import TestCaseFunction

COLLECT_TYPES = False
if os.environ.get("PYANNOTATE_COLLECT", "0") == "1":
    try:
        from pyannotate_runtime import collect_types
        COLLECT_TYPES = True
    except ImportError:
        pass

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Load environment variables from .env file
ENV_FILE = PROJECT_ROOT / ".env"
if ENV_FILE.exists():
    load_dotenv(ENV_FILE, override=True)
else:
    # Fallback to default .env location
    load_dotenv(override=True)


def pytest_sessionstart(session: object) -> None:  # noqa: ARG001
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
def setup_test_environment() -> Iterator[None]:
    """Set up test environment automatically for all tests."""
    yield


@pytest.fixture
def temp_workspace() -> Iterator[Path]:
    """Provide a temporary directory for test operations."""
    import shutil
    import tempfile

    temp_dir = tempfile.mkdtemp(prefix="intellicrack_test_")
    yield Path(temp_dir)
    shutil.rmtree(temp_dir, ignore_errors=True)


def pytest_configure(config: pytest.Config) -> None:
    """Register custom markers and initialize type collection."""
    config.addinivalue_line(
        "markers", "real_data: test validates real functionality"
    )
    if COLLECT_TYPES:
        collect_types.init_types_collection()


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_call(item: Function | TestCaseFunction) -> Iterator[None]:  # noqa: ARG001
    """Wrap each test call with pyannotate type collection."""
    if COLLECT_TYPES:
        collect_types.start()
    yield
    if COLLECT_TYPES:
        collect_types.stop()


def pytest_unconfigure(config: object) -> None:  # noqa: ARG001
    """Dump collected type information after test session."""
    if COLLECT_TYPES:
        output_path = str(PROJECT_ROOT / "scripts" / "type_info.json")
        collect_types.dump_stats(output_path)

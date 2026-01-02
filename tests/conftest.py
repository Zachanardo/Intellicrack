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


def refresh_bool(value: bool) -> bool:
    """Return boolean value, defeating mypy type narrowing.

    Use this when you need to check a property/attribute value after
    it may have changed but mypy has narrowed the type based on a
    previous assertion.
    """
    return value


def refresh_optional(value: object | None) -> object | None:
    """Return optional value, defeating mypy type narrowing."""
    return value

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
    """Register custom markers, set env vars, and initialize type collection.

    CRITICAL: Environment variables MUST be set here in pytest_configure,
    NOT in pytest_sessionstart. The hook order is:
      1. pytest_configure (BEFORE collection)
      2. test collection (imports modules)
      3. pytest_sessionstart (AFTER collection)

    Modules like background_loader.py and lazy_model_loader.py check
    env vars during __init__ at import time. If we set env vars in
    pytest_sessionstart, background threads will already have started,
    causing coverage to hang indefinitely while tracing those threads.
    """
    # Disable AI background services during testing - MUST be set before imports
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

    # Register custom markers
    config.addinivalue_line(
        "markers", "real_data: test validates real functionality"
    )
    config.addinivalue_line(
        "markers", "asyncio: async test requiring asyncio event loop"
    )
    config.addinivalue_line(
        "markers", "performance: performance-focused test"
    )
    config.addinivalue_line(
        "markers", "requires_vm: test requires virtual machine"
    )
    config.addinivalue_line(
        "markers", "timeout: test with explicit timeout"
    )
    config.addinivalue_line(
        "markers", "requires_admin: test requires administrator privileges"
    )
    config.addinivalue_line(
        "markers", "requires_hardware: test requires specific hardware"
    )
    config.addinivalue_line(
        "markers", "slow: slow running test"
    )
    config.addinivalue_line(
        "markers", "integration: integration test"
    )
    config.addinivalue_line(
        "markers", "unit: unit test"
    )
    config.addinivalue_line(
        "markers", "e2e: end-to-end test"
    )
    config.addinivalue_line(
        "markers", "benchmark: benchmark test for performance measurement"
    )
    config.addinivalue_line(
        "markers", "requires_process_attach: test requires debugger attachment to a process"
    )
    config.addinivalue_line(
        "markers", "requires_pyqt6: test requires PyQt6 to be installed"
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

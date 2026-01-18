"""Pytest configuration and fixtures for UI tests.

Provides shared fixtures including QApplication instance
required for Qt widget testing.
"""

from __future__ import annotations

from collections.abc import Generator
from typing import cast

import pytest
from PyQt6.QtWidgets import QApplication


@pytest.fixture(scope="session")
def qapp() -> Generator[QApplication]:
    """Provide a QApplication instance for the test session.

    Qt requires exactly one QApplication instance per process.
    This fixture creates one for the entire test session and
    cleans it up afterward.

    Yields:
        QApplication instance for widget testing.
    """
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    else:
        app = cast("QApplication", app)

    yield app

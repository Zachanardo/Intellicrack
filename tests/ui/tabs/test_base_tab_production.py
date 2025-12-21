"""Production tests for BaseTab lazy loading and lifecycle management.

This module validates that BaseTab correctly implements lazy initialization,
resource cleanup, and shared context management for all tab implementations.

Tests prove real lifecycle management, NOT UI rendering.

Copyright (C) 2025 Zachary Flint
Licensed under GNU GPL v3.0
"""

import sys
from typing import Any
from unittest.mock import Mock, patch

import pytest
from PyQt6.QtWidgets import QApplication, QVBoxLayout, QWidget

from intellicrack.ui.tabs.base_tab import BaseTab


class TestTab(BaseTab):
    """Concrete test implementation of BaseTab."""

    def __init__(self, shared_context: dict[str, Any]) -> None:
        """Initialize test tab."""
        super().__init__(shared_context)
        self.init_ui_called = False
        self.cleanup_called = False

    def init_ui(self) -> None:
        """Initialize test UI."""
        self.init_ui_called = True
        layout = QVBoxLayout(self)
        self.setLayout(layout)

    def cleanup(self) -> None:
        """Cleanup test resources."""
        self.cleanup_called = True
        super().cleanup()


@pytest.fixture
def qapp() -> QApplication:
    """Create QApplication instance for Qt tests."""
    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv)
    return app


@pytest.fixture
def shared_context() -> dict[str, Any]:
    """Create shared context with minimal dependencies."""
    return {
        "app_context": None,
        "task_manager": None,
        "main_window": None,
        "test_data": "test_value",
    }


@pytest.fixture
def base_tab(qapp: QApplication, shared_context: dict[str, Any]) -> TestTab:
    """Create TestTab instance."""
    tab = TestTab(shared_context)
    yield tab
    tab.cleanup()


class TestBaseTabLazyInitialization:
    """Tests for lazy initialization functionality."""

    def test_init_ui_not_called_on_construction(
        self,
        qapp: QApplication,
        shared_context: dict[str, Any],
    ) -> None:
        """init_ui is not called during tab construction."""
        tab = TestTab(shared_context)

        assert not tab.init_ui_called
        tab.cleanup()

    def test_init_ui_called_on_first_show(
        self,
        base_tab: TestTab,
    ) -> None:
        """init_ui is called when tab is first shown."""
        assert not base_tab.init_ui_called

        base_tab.showEvent(None)

        assert base_tab.init_ui_called

    def test_init_ui_called_only_once(
        self,
        base_tab: TestTab,
    ) -> None:
        """init_ui is called only once even with multiple show events."""
        base_tab.showEvent(None)
        assert base_tab.init_ui_called

        base_tab.init_ui_called = False
        base_tab.showEvent(None)

        assert not base_tab.init_ui_called

    def test_is_initialized_flag_set_after_init(
        self,
        base_tab: TestTab,
    ) -> None:
        """is_initialized flag is set after initialization."""
        assert not base_tab.is_initialized

        base_tab.showEvent(None)

        assert base_tab.is_initialized


class TestBaseTabSharedContext:
    """Tests for shared context management."""

    def test_shared_context_accessible_in_tab(
        self,
        base_tab: TestTab,
    ) -> None:
        """Shared context is accessible from tab instance."""
        assert base_tab.shared_context is not None
        assert base_tab.shared_context["test_data"] == "test_value"

    def test_shared_context_modifications_visible(
        self,
        base_tab: TestTab,
    ) -> None:
        """Modifications to shared context are visible."""
        base_tab.shared_context["new_key"] = "new_value"

        assert base_tab.shared_context["new_key"] == "new_value"

    def test_context_persists_across_init(
        self,
        base_tab: TestTab,
    ) -> None:
        """Shared context persists after initialization."""
        base_tab.shared_context["persistent_key"] = "persistent_value"

        base_tab.showEvent(None)

        assert base_tab.shared_context["persistent_key"] == "persistent_value"


class TestBaseTabCleanup:
    """Tests for resource cleanup."""

    def test_cleanup_calls_subclass_cleanup(
        self,
        base_tab: TestTab,
    ) -> None:
        """Cleanup calls subclass cleanup method."""
        base_tab.cleanup()

        assert base_tab.cleanup_called

    def test_cleanup_sets_cleanup_flag(
        self,
        base_tab: TestTab,
    ) -> None:
        """Cleanup sets is_cleaned_up flag."""
        assert not base_tab.is_cleaned_up

        base_tab.cleanup()

        assert base_tab.is_cleaned_up

    def test_cleanup_safe_to_call_multiple_times(
        self,
        base_tab: TestTab,
    ) -> None:
        """Cleanup can be called multiple times safely."""
        base_tab.cleanup()
        first_cleanup = base_tab.cleanup_called

        base_tab.cleanup_called = False
        base_tab.cleanup()

        assert first_cleanup
        assert not base_tab.cleanup_called


class TestBaseTabSignalConnections:
    """Tests for signal connection management."""

    def test_tab_shown_signal_emitted_on_init(
        self,
        base_tab: TestTab,
    ) -> None:
        """tab_shown signal is emitted when tab is initialized."""
        signal_emitted = False

        def signal_handler() -> None:
            nonlocal signal_emitted
            signal_emitted = True

        base_tab.tab_shown.connect(signal_handler)
        base_tab.showEvent(None)

        assert signal_emitted

    def test_cleanup_started_signal_emitted(
        self,
        base_tab: TestTab,
    ) -> None:
        """cleanup_started signal is emitted during cleanup."""
        signal_emitted = False

        def signal_handler() -> None:
            nonlocal signal_emitted
            signal_emitted = True

        base_tab.cleanup_started.connect(signal_handler)
        base_tab.cleanup()

        assert signal_emitted


class TestBaseTabErrorHandling:
    """Tests for error handling during initialization."""

    def test_init_ui_exception_handled_gracefully(
        self,
        qapp: QApplication,
        shared_context: dict[str, Any],
    ) -> None:
        """Exceptions in init_ui are handled without crashing."""

        class FailingTab(BaseTab):
            def init_ui(self) -> None:
                raise RuntimeError("Test initialization failure")

        tab = FailingTab(shared_context)

        try:
            tab.showEvent(None)
        except RuntimeError:
            pytest.fail("Exception not handled in showEvent")

        tab.cleanup()

    def test_cleanup_exception_handled_gracefully(
        self,
        qapp: QApplication,
        shared_context: dict[str, Any],
    ) -> None:
        """Exceptions in cleanup are handled without crashing."""

        class FailingCleanupTab(BaseTab):
            def init_ui(self) -> None:
                layout = QVBoxLayout(self)
                self.setLayout(layout)

            def cleanup(self) -> None:
                raise RuntimeError("Test cleanup failure")

        tab = FailingCleanupTab(shared_context)

        try:
            tab.cleanup()
        except RuntimeError:
            pytest.fail("Exception not handled in cleanup")


class TestBaseTabLayoutManagement:
    """Tests for layout initialization."""

    def test_layout_created_after_init(
        self,
        base_tab: TestTab,
    ) -> None:
        """Layout is created after initialization."""
        base_tab.showEvent(None)

        assert base_tab.layout() is not None

    def test_layout_not_created_before_init(
        self,
        qapp: QApplication,
        shared_context: dict[str, Any],
    ) -> None:
        """Layout is not created before initialization."""

        class EmptyTab(BaseTab):
            def init_ui(self) -> None:
                pass

        tab = EmptyTab(shared_context)

        assert tab.layout() is None

        tab.cleanup()


class TestBaseTabStatePersistence:
    """Tests for state persistence across show/hide."""

    def test_state_persists_after_hide(
        self,
        base_tab: TestTab,
    ) -> None:
        """Tab state persists after hiding."""
        base_tab.showEvent(None)
        base_tab.shared_context["state_key"] = "state_value"

        base_tab.hide()

        assert base_tab.shared_context["state_key"] == "state_value"
        assert base_tab.is_initialized

    def test_initialization_not_repeated_after_show_hide_show(
        self,
        base_tab: TestTab,
    ) -> None:
        """Initialization is not repeated after show-hide-show cycle."""
        base_tab.showEvent(None)
        first_init = base_tab.init_ui_called

        base_tab.hide()
        base_tab.init_ui_called = False
        base_tab.showEvent(None)

        assert first_init
        assert not base_tab.init_ui_called

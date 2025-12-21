"""Production-grade tests for PyQt6 handler.

This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from collections.abc import Generator


@pytest.fixture
def enable_fallback_mode() -> Generator[None, None, None]:
    old_testing = os.environ.get("INTELLICRACK_TESTING")
    os.environ["INTELLICRACK_TESTING"] = "1"
    yield
    if old_testing is not None:
        os.environ["INTELLICRACK_TESTING"] = old_testing
    else:
        os.environ.pop("INTELLICRACK_TESTING", None)


@pytest.fixture
def disable_threads() -> Generator[None, None, None]:
    old_threads = os.environ.get("DISABLE_BACKGROUND_THREADS")
    os.environ["DISABLE_BACKGROUND_THREADS"] = "1"
    yield
    if old_threads is not None:
        os.environ["DISABLE_BACKGROUND_THREADS"] = old_threads
    else:
        os.environ.pop("DISABLE_BACKGROUND_THREADS", None)


class TestPyQt6HandlerFallbackMode:
    """Test PyQt6 handler fallback implementations work correctly."""

    def test_fallback_widget_creation_and_lifecycle(
        self, enable_fallback_mode: None, disable_threads: None
    ) -> None:
        import importlib

        import intellicrack.handlers.pyqt6_handler as handler

        importlib.reload(handler)

        assert not handler.HAS_PYQT
        assert handler.PYQT_VERSION_STR is not None

        widget = handler.FallbackWidget()
        assert widget is not None
        assert not widget._destroyed

        widget.show()
        assert widget._visible

        widget.hide()
        assert not widget._visible

        widget.setText("test text")
        assert widget.text() == "test text"

        widget.setValue(42)
        assert widget.value() == 42

        widget.setEnabled(False)
        assert not widget.isEnabled()

        widget._cleanup()
        assert widget._destroyed

    def test_fallback_signal_connection_and_emission(
        self, enable_fallback_mode: None, disable_threads: None
    ) -> None:
        import importlib

        import intellicrack.handlers.pyqt6_handler as handler

        importlib.reload(handler)

        signal = handler.FallbackSignal(str, name="testSignal")

        callback_results: list[str] = []

        def test_callback(value: str) -> None:
            callback_results.append(value)

        signal.connect(test_callback)
        signal.emit("test value")

        assert len(callback_results) == 1
        assert callback_results[0] == "test value"

        signal.disconnect(test_callback)
        signal.emit("should not trigger")
        assert len(callback_results) == 1

    def test_fallback_widget_event_queue_processing(
        self, enable_fallback_mode: None, disable_threads: None
    ) -> None:
        import importlib

        import intellicrack.handlers.pyqt6_handler as handler

        importlib.reload(handler)

        widget = handler.FallbackWidget()
        widget.show()

        widget._emit_event("testEvent", {"data": "value"})
        widget.processEvents()

    def test_fallback_qt_namespace_enum_values(
        self, enable_fallback_mode: None, disable_threads: None
    ) -> None:
        import importlib

        import intellicrack.handlers.pyqt6_handler as handler

        importlib.reload(handler)

        qt = handler.FallbackQt()

        assert qt.AlignLeft == 0x0001
        assert qt.AlignRight == 0x0002
        assert qt.AlignCenter == 0x0084
        assert qt.NoModifier == 0x00000000
        assert qt.ShiftModifier == 0x02000000
        assert qt.LeftButton == 0x00000001

    def test_fallback_qrgba_color_conversion(
        self, enable_fallback_mode: None, disable_threads: None
    ) -> None:
        import importlib

        import intellicrack.handlers.pyqt6_handler as handler

        importlib.reload(handler)

        rgba = handler.qRgba(255, 128, 64, 200)
        assert rgba == (200 << 24) | (255 << 16) | (128 << 8) | 64

        clamped = handler.qRgba(300, -10, 128, 500)
        assert clamped == (255 << 24) | (255 << 16) | (0 << 8) | 128

    def test_fallback_widget_timer_execution(
        self, enable_fallback_mode: None, disable_threads: None
    ) -> None:
        import importlib
        import time

        import intellicrack.handlers.pyqt6_handler as handler

        importlib.reload(handler)

        widget = handler.FallbackWidget()
        callback_count: list[int] = [0]

        def timer_callback() -> None:
            callback_count[0] += 1

        timer_id = widget.startTimer(10, timer_callback, single_shot=False)
        assert timer_id >= 0

        time.sleep(0.015)
        widget.processEvents()

        assert callback_count[0] > 0

        widget.killTimer(timer_id)

    def test_fallback_widget_signal_callback_errors_handled(
        self, enable_fallback_mode: None, disable_threads: None
    ) -> None:
        import importlib

        import intellicrack.handlers.pyqt6_handler as handler

        importlib.reload(handler)

        signal = handler.FallbackSignal(str)

        def failing_callback(value: str) -> None:
            raise ValueError("Intentional test error")

        signal.connect(failing_callback)
        signal.emit("test")

    def test_fallback_application_lifecycle(
        self, enable_fallback_mode: None, disable_threads: None
    ) -> None:
        import importlib

        import intellicrack.handlers.pyqt6_handler as handler

        importlib.reload(handler)

        app = handler.FallbackWidget.instance()
        assert app is not None

        app.quit()

    def test_fallback_widget_delete_later_cleanup(
        self, enable_fallback_mode: None, disable_threads: None
    ) -> None:
        import importlib
        import time

        import intellicrack.handlers.pyqt6_handler as handler

        importlib.reload(handler)

        widget = handler.FallbackWidget()
        widget_id = widget.__class__.__name__

        widget.deleteLater()
        time.sleep(0.2)

        assert widget._destroyed


class TestPyQt6HandlerRealMode:
    """Test PyQt6 handler with real PyQt6 (if available)."""

    def test_real_pyqt6_detection(self) -> None:
        import intellicrack.handlers.pyqt6_handler as handler

        if handler.HAS_PYQT:
            assert handler.PYQT_VERSION_STR != "Fallback"
            assert handler.QApplication is not None
            assert handler.QWidget is not None
            assert handler.pyqtSignal is not None
        else:
            assert handler.PYQT_VERSION_STR in ("Fallback", None)

    def test_critical_qt_classes_available(self) -> None:
        import intellicrack.handlers.pyqt6_handler as handler

        required_classes = [
            "QApplication",
            "QWidget",
            "QLabel",
            "QPushButton",
            "QVBoxLayout",
            "QHBoxLayout",
            "QMainWindow",
        ]

        for class_name in required_classes:
            assert hasattr(handler, class_name)
            assert getattr(handler, class_name) is not None

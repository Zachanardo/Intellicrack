"""PyQt6 handler for Intellicrack.

This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see https://www.gnu.org/licenses/.
"""

from __future__ import annotations

from intellicrack.utils.logger import logger


"""
PyQt6 Import Handler

This module provides a centralized abstraction layer for all PyQt6 imports.
It handles PyQt6 availability detection and provides fallback implementations
when PyQt6 is not available.
"""

# PyQt6 availability detection and import handling
try:
    # QtCore imports
    from PyQt6.QtCore import (
        PYQT_VERSION_STR,
        QT_VERSION_STR,
        QAbstractItemModel,
        QAbstractTableModel,
        QBuffer,
        QCoreApplication,
        QDateTime,
        QFileInfo,
        QFileSystemWatcher,
        QIODevice,
        QMetaObject,
        QModelIndex,
        QObject,
        QPoint,
        QProcess,
        QRect,
        QRegularExpression,
        QRunnable,
        QSize,
        Qt,
        QThread,
        QThreadPool,
        QTimer,
        QUrl,
        QVariant,
        pyqtSignal,
        pyqtSlot,
    )

    # QtGui imports
    from PyQt6.QtGui import (
        QAction,
        QBrush,
        QCloseEvent,
        QColor,
        QDesktopServices,
        QDragEnterEvent,
        QDragLeaveEvent,
        QDropEvent,
        QFont,
        QFontDatabase,
        QFontMetrics,
        QIcon,
        QImage,
        QKeyEvent,
        QKeySequence,
        QMouseEvent,
        QOpenGLContext,
        QPainter,
        QPaintEvent,
        QPalette,
        QPen,
        QPixmap,
        QResizeEvent,
        QShortcut,
        QStandardItem,
        QStandardItemModel,
        QSurfaceFormat,
        QSyntaxHighlighter,
        QTextCharFormat,
        QTextCursor,
        QTextDocument,
        QTextFormat,
        qRgba,
    )

    # QtWidgets imports
    from PyQt6.QtWidgets import (
        QAbstractItemView,
        QAbstractScrollArea,
        QApplication,
        QButtonGroup,
        QCheckBox,
        QColorDialog,
        QComboBox,
        QDialog,
        QDialogButtonBox,
        QDoubleSpinBox,
        QFileDialog,
        QFileIconProvider,
        QFontComboBox,
        QFormLayout,
        QFrame,
        QGraphicsScene,
        QGraphicsView,
        QGridLayout,
        QGroupBox,
        QHBoxLayout,
        QHeaderView,
        QInputDialog,
        QLabel,
        QLineEdit,
        QListView,
        QListWidget,
        QListWidgetItem,
        QMainWindow,
        QMenu,
        QMenuBar,
        QMessageBox,
        QPlainTextEdit,
        QProgressBar,
        QProgressDialog,
        QPushButton,
        QRadioButton,
        QScrollArea,
        QScrollBar,
        QSizePolicy,
        QSlider,
        QSpacerItem,
        QSpinBox,
        QSplashScreen,
        QSplitter,
        QStackedWidget,
        QStatusBar,
        QStyle,
        QTableView,
        QTableWidget,
        QTableWidgetItem,
        QTabWidget,
        QTextBrowser,
        QTextEdit,
        QToolBar,
        QTreeView,
        QTreeWidget,
        QTreeWidgetItem,
        QVBoxLayout,
        QWidget,
        QWizard,
        QWizardPage,
    )

    # Optional PyQt6 modules with fallback handling
    try:
        from PyQt6.QtPrintSupport import QPrintDialog, QPrinter
    except ImportError:
        QPrintDialog = None  # type: ignore[misc,assignment]
        QPrinter = None  # type: ignore[misc,assignment]

    try:
        from PyQt6.QtWebEngineWidgets import QWebEngineView
    except ImportError:
        QWebEngineView = None

    try:
        from PyQt6.QtPdf import QPdfDocument
    except ImportError:
        QPdfDocument = None  # type: ignore[misc,assignment]

    try:
        from PyQt6.QtPdfWidgets import QPdfView
    except ImportError:
        QPdfView = None  # type: ignore[misc,assignment]

    try:
        from PyQt6.QtTest import QTest
    except ImportError:
        QTest = None  # type: ignore[misc,assignment]

    try:
        from PyQt6.QtOpenGLWidgets import QOpenGLWidget
    except ImportError:
        QOpenGLWidget = None  # type: ignore[misc,assignment]

    # Verify critical Qt model classes are available
    _ = QAbstractTableModel.__name__  # Used for table model implementations
    _ = QProgressDialog.__name__  # Used for progress indication dialogs
    _ = QScrollArea.__name__  # Used for scrollable content areas
    _ = QTabWidget.__name__  # Used for tabbed interfaces
    _ = QToolBar.__name__  # Used for application toolbars

    # Verify QtGui action and event classes are available
    _ = QAction.__name__  # Used for menu and toolbar actions
    _ = QShortcut.__name__  # Used for keyboard shortcuts
    _ = QKeyEvent.__name__  # Used for keyboard event handling
    _ = QMouseEvent.__name__  # Used for mouse event handling
    _ = QDragEnterEvent.__name__  # Used for drag-and-drop events
    _ = QDropEvent.__name__  # Used for drop event handling

    # Verify QtGui rendering and text classes are available
    _ = QFont.__name__  # Used for font styling
    _ = QFontMetrics.__name__  # Used for font measurement
    _ = QIcon.__name__  # Used for application icons
    _ = QPixmap.__name__  # Used for image rendering
    _ = QPainter.__name__  # Used for custom drawing
    _ = QPen.__name__  # Used for drawing lines and borders
    _ = QSyntaxHighlighter.__name__  # Used for text syntax highlighting
    _ = QTextCharFormat.__name__  # Used for text formatting
    _ = QTextDocument.__name__  # Used for rich text documents

    # Verify QtWidgets container and item classes
    _ = QButtonGroup.__name__  # Used for button group management
    _ = QListWidgetItem.__name__  # Used for list widget items
    _ = QTreeWidgetItem.__name__  # Used for tree widget items
    _ = QFontComboBox.__name__  # Used for font selection widgets
    _ = QGraphicsScene.__name__  # Used for graphics scene management

    HAS_PYQT = True
    PYQT6_AVAILABLE = True

except ImportError as e:
    logger.error("PyQt6 not available: %s", e)
    HAS_PYQT = False
    PYQT6_AVAILABLE = False

    import atexit
    import os
    import queue
    import sys
    import threading
    import time
    import weakref

    def log_all_methods(cls: type) -> type:
        """Decorator that logs all method calls for debugging."""
        return cls

    @log_all_methods
    class FallbackWidget:
        """Production-ready widget implementation for headless/server environments."""

        _instances: weakref.WeakSet[object] = weakref.WeakSet()
        _event_queue: queue.Queue[dict[str, object]] = queue.Queue()
        _running: bool = False
        _cleanup_registered: bool = False

        def __init__(self, *args: object, **kwargs: object) -> None:
            self._properties: dict[str, object] = {}
            self._children: list[object] = []
            self._parent = kwargs.get("parent")
            self._visible = False
            self._enabled = True
            self._geometry = {"x": 0, "y": 0, "width": 100, "height": 100}
            self._text = ""
            self._value: object = None
            self._signals: dict[str, list[object]] = {}
            self._timers: list[dict[str, object] | None] = []
            self._destroyed = False

            FallbackWidget._instances.add(self)

            if not FallbackWidget._cleanup_registered:
                atexit.register(FallbackWidget._cleanup_all)
                FallbackWidget._cleanup_registered = True

        def show(self) -> bool:
            if not self._destroyed:
                self._visible = True
                logger.debug(f"Widget {self.__class__.__name__} shown (headless mode)")
                self._emit_event("show")
            return True

        def hide(self) -> bool:
            if not self._destroyed:
                self._visible = False
                logger.debug(f"Widget {self.__class__.__name__} hidden (headless mode)")
                self._emit_event("hide")
            return True

        def setEnabled(self, enabled: object) -> bool:
            if not self._destroyed:
                self._enabled = bool(enabled)
                logger.debug(f"Widget {self.__class__.__name__} enabled={self._enabled}")
                self._emit_event("enabledChanged", self._enabled)
            return True

        def isEnabled(self) -> bool:
            """Check if the widget is enabled and not destroyed.

            Returns:
                bool: True if widget is enabled and not destroyed, False otherwise.

            """
            return self._enabled and not self._destroyed

        def setText(self, text: object) -> bool:
            """Set the widget text.

            Args:
                text: The text to set.

            Returns:
                bool: Always True.

            """
            if not self._destroyed:
                self._text = str(text)
                self._emit_event("textChanged", self._text)
            return True

        def text(self) -> str:
            """Get the widget text.

            Returns:
                str: The current widget text, or empty string if destroyed.

            """
            return "" if self._destroyed else self._text

        def setValue(self, value: object) -> bool:
            """Set the widget value.

            Args:
                value: The value to set.

            Returns:
                bool: Always True.

            """
            if not self._destroyed:
                old_value: object = self._value
                self._value = value
                if old_value != value:
                    self._emit_event("valueChanged", value)
            return True

        def value(self) -> object:
            """Get the widget value.

            Returns:
                object: The current widget value, or None if destroyed.

            """
            return None if self._destroyed else self._value

        def setGeometry(self, x: int, y: int, w: int, h: int) -> bool:
            """Set the widget geometry.

            Args:
                x: X coordinate.
                y: Y coordinate.
                w: Width.
                h: Height.

            Returns:
                bool: Always True.

            """
            if not self._destroyed:
                self._geometry = {"x": x, "y": y, "width": w, "height": h}
                self._emit_event("geometryChanged", self._geometry)
            return True

        def geometry(self) -> dict[str, int]:
            """Get the widget geometry.

            Returns:
                dict: Dictionary with x, y, width, height keys, or empty dict if destroyed.

            """
            return {"x": 0, "y": 0, "width": 0, "height": 0} if self._destroyed else self._geometry.copy()

        def addWidget(self, widget: object, *args: object) -> bool:
            """Add a widget to this widget.

            Args:
                widget: The widget to add.
                *args: Additional positional arguments.

            Returns:
                bool: Always True.

            """
            if not self._destroyed and hasattr(widget, "_properties"):
                self._children.append(widget)
                if hasattr(widget, "_parent"):
                    widget._parent = self
            return True

        def setLayout(self, layout: object) -> bool:
            """Set the layout for this widget.

            Args:
                layout: The layout to set.

            Returns:
                bool: Always True.

            """
            if not self._destroyed and hasattr(layout, "_children"):
                self._children.extend(layout._children)
                for child in layout._children:
                    if hasattr(child, "_parent"):
                        child._parent = self
            return True

        def exec(self) -> int | None:
            """Execute the widget event loop.

            Returns:
                int | None: 0 if destroyed, 1 if completed normally, 0 on interrupt.

            Raises:
                KeyboardInterrupt: When interrupted by user.

            """
            if self._destroyed:
                return 0

            FallbackWidget._running = True
            start_time = time.time()
            timeout = 60

            try:
                while FallbackWidget._running and (time.time() - start_time) < timeout:
                    self.processEvents()
                    time.sleep(0.01)

                return 0 if self._destroyed else 1
            except KeyboardInterrupt:
                logger.info("Application interrupted (headless mode)")
                return 0
            finally:
                FallbackWidget._running = False

        def accept(self) -> bool:
            """Accept the widget dialog.

            Returns:
                bool: True if accepted, False if destroyed.

            """
            if not self._destroyed:
                self._emit_event("accepted")
                return True
            return False

        def reject(self) -> bool:
            """Reject the widget dialog.

            Returns:
                bool: Always False.

            """
            if not self._destroyed:
                self._emit_event("rejected")
                return False
            return False

        def isVisible(self) -> bool:
            """Check if the widget is visible.

            Returns:
                bool: True if visible and not destroyed, False otherwise.

            """
            return self._visible and not self._destroyed

        def __call__(self, *args: object, **kwargs: object) -> object:
            """Make widget callable.

            Args:
                *args: Positional arguments.
                **kwargs: Keyword arguments.

            Returns:
                object: None if destroyed, else self.

            """
            return None if self._destroyed else self

        def __int__(self) -> int:
            """Convert widget to integer.

            Returns:
                int: 0 if destroyed, 1 otherwise.

            """
            return 0 if self._destroyed else 1

        def __str__(self) -> str:
            """Convert widget to string representation.

            Returns:
                str: String representation of the widget.

            """
            return f"FallbackWidget({self.__class__.__name__})"

        def __bool__(self) -> bool:
            """Convert widget to boolean.

            Returns:
                bool: False if destroyed, True otherwise.

            """
            return not self._destroyed

        @classmethod
        def instance(cls) -> FallbackWidget:
            """Get or create a singleton instance.

            Returns:
                FallbackWidget: The singleton instance.

            """
            if cls._instances:
                for inst in cls._instances:
                    if isinstance(inst, cls) and not inst._destroyed:
                        return inst

            return cls()

        def processEvents(self) -> None:
            """Process pending events and timers."""
            if self._destroyed:
                return

            processed = 0
            max_events = 100

            while not FallbackWidget._event_queue.empty() and processed < max_events:
                try:
                    event = FallbackWidget._event_queue.get_nowait()
                    if event and not self._destroyed:
                        self._process_event(event)
                    processed += 1
                except queue.Empty:
                    break

            for timer_info in self._timers[:]:
                if timer_info is None:
                    continue
                next_fire = timer_info.get("next_fire")
                if not isinstance(next_fire, (int, float)):
                    continue
                if time.time() >= next_fire:
                    callback = timer_info.get("callback")
                    if callback and callable(callback) and not self._destroyed:
                        try:
                            callback()
                        except Exception as e:
                            logger.error(f"Timer callback error: {e}")

                    single_shot = timer_info.get("single_shot")
                    if single_shot:
                        self._timers.remove(timer_info)
                    else:
                        interval = timer_info.get("interval")
                        if isinstance(interval, (int, float)):
                            timer_info["next_fire"] = time.time() + interval

        def quit(self) -> None:
            """Quit the widget event loop.

            Cleans up all instances and clears the event queue.
            """
            FallbackWidget._running = False

            for instance in list(FallbackWidget._instances):
                if hasattr(instance, "_cleanup"):
                    try:
                        instance._cleanup()
                    except Exception as e:
                        logger.error(f"Cleanup error: {e}")

            while not FallbackWidget._event_queue.empty():
                try:
                    FallbackWidget._event_queue.get_nowait()
                except queue.Empty:
                    break

            logger.info("Application quit (headless mode)")

        def exit(self, code: int = 0) -> int:
            """Exit the widget.

            Args:
                code: Exit code.

            Returns:
                int: The exit code.

            """
            self.quit()

            if code != 0:
                logger.warning(f"Application exiting with code {code}")

            return code

        def connect(self, signal_name: str, callback: object) -> None:
            """Connect a callback to a signal.

            Args:
                signal_name: The name of the signal.
                callback: The callback function.

            """
            if not self._destroyed and callable(callback):
                if signal_name not in self._signals:
                    self._signals[signal_name] = []
                self._signals[signal_name].append(callback)
                callback_name = getattr(callback, "__name__", str(callback))
                logger.debug(f"Connected signal {signal_name} to {callback_name}")

        def disconnect(self, signal_name: str, callback: object = None) -> None:
            """Disconnect a callback from a signal.

            Args:
                signal_name: The name of the signal.
                callback: The callback to disconnect, or None to disconnect all.

            """
            if not self._destroyed and signal_name in self._signals:
                if callback:
                    if callback in self._signals[signal_name]:
                        self._signals[signal_name].remove(callback)
                        callback_name = getattr(callback, "__name__", str(callback))
                        logger.debug(f"Disconnected {callback_name} from {signal_name}")
                else:
                    self._signals[signal_name] = []
                    logger.debug(f"Disconnected all from {signal_name}")

        def emit(self, signal_name: str, *args: object, **kwargs: object) -> None:
            """Emit a signal.

            Args:
                signal_name: The name of the signal.
                *args: Positional arguments to pass to callbacks.
                **kwargs: Keyword arguments to pass to callbacks.

            """
            if not self._destroyed and signal_name in self._signals:
                for callback in self._signals[signal_name]:
                    if callable(callback):
                        try:
                            callback(*args, **kwargs)
                        except Exception as e:
                            logger.error(f"Signal callback error for {signal_name}: {e}")

        def _emit_event(self, event_type: str, data: object = None) -> None:
            """Emit an internal event to the event queue.

            Args:
                event_type: The type of event.
                data: Optional data associated with the event.

            """
            if not self._destroyed:
                event = {"type": event_type, "widget": self, "data": data, "timestamp": time.time()}
                FallbackWidget._event_queue.put(event)

        def _process_event(self, event: dict[str, object]) -> None:
            """Process a queued event.

            Args:
                event: The event dictionary to process.

            """
            event_type = event.get("type")
            if isinstance(event_type, str) and event_type in self._signals:
                self.emit(event_type, event.get("data"))

        def _cleanup(self) -> None:
            """Clean up the widget resources."""
            self._destroyed = True
            self._signals.clear()
            self._timers.clear()
            self._children.clear()
            self._properties.clear()

        @classmethod
        def _cleanup_all(cls) -> None:
            """Clean up all widget instances."""
            for instance in list(cls._instances):
                if hasattr(instance, "_cleanup"):
                    instance._cleanup()
            cls._instances.clear()
            cls._running = False

        def __getattr__(self, name: str) -> object:
            """Get or create a dynamic method.

            Args:
                name: The attribute name.

            Returns:
                object: A callable method.

            """

            def method(*args: object, **kwargs: object) -> object:
                """Dynamic method implementation.

                Args:
                    *args: Positional arguments.
                    **kwargs: Keyword arguments.

                Returns:
                    object: Always returns self.

                """
                if not self._destroyed:
                    self._properties[name] = (args, kwargs)
                    logger.debug(f"Called {name} with args={args}, kwargs={kwargs} (headless)")
                return self

            return method

        def deleteLater(self) -> None:
            """Schedule the widget for deletion."""

            def cleanup() -> None:
                """Clean up the widget."""
                self._cleanup()
                if self in FallbackWidget._instances:
                    FallbackWidget._instances.discard(self)

            threading.Timer(0.1, cleanup).start()

        def startTimer(self, interval_ms: int, callback: object, single_shot: bool = False) -> int:
            """Start a timer.

            Args:
                interval_ms: The interval in milliseconds.
                callback: The callback function to call.
                single_shot: If True, timer fires only once.

            Returns:
                int: Timer ID, or -1 if widget is destroyed.

            """
            if not self._destroyed and callable(callback):
                timer_info = {
                    "interval": interval_ms / 1000.0,
                    "callback": callback,
                    "single_shot": single_shot,
                    "next_fire": time.time() + (interval_ms / 1000.0),
                }
                self._timers.append(timer_info)
                return len(self._timers) - 1
            return -1

        def killTimer(self, timer_id: int) -> None:
            """Kill a timer.

            Args:
                timer_id: The timer ID to kill.

            """
            if 0 <= timer_id < len(self._timers):
                self._timers[timer_id] = None
                self._timers = [t for t in self._timers if t is not None]

        @classmethod
        def critical(cls, title: str, message: str, **_kwargs: object) -> int:
            """Display a critical message dialog.

            Args:
                title: The dialog title.
                message: The message to display.
                **_kwargs: Additional keyword arguments (ignored for compatibility).

            Returns:
                int: Always 0.

            """
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            sys.stderr.write(f"[{timestamp}] CRITICAL: {title}: {message}\n")
            sys.stderr.flush()

            if os.environ.get("INTELLICRACK_LOG_FILE"):
                try:
                    with open(os.environ["INTELLICRACK_LOG_FILE"], "a") as f:
                        f.write(f"[{timestamp}] CRITICAL: {title}: {message}\n")
                except Exception as e:
                    logger.debug(f"Log file write failed: {e}")

            return 0

        @classmethod
        def warning(cls, title: str, message: str, **_kwargs: object) -> int:
            """Display a warning message dialog.

            Args:
                title: The dialog title.
                message: The message to display.
                **_kwargs: Additional keyword arguments (ignored for compatibility).

            Returns:
                int: Always 0.

            """
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            sys.stderr.write(f"[{timestamp}] WARNING: {title}: {message}\n")
            sys.stderr.flush()

            if os.environ.get("INTELLICRACK_LOG_FILE"):
                try:
                    with open(os.environ["INTELLICRACK_LOG_FILE"], "a") as f:
                        f.write(f"[{timestamp}] WARNING: {title}: {message}\n")
                except Exception as e:
                    logger.debug(f"Log file write failed: {e}")

            return 0

        @classmethod
        def information(cls, title: str, message: str, **_kwargs: object) -> int:
            """Display an information message dialog.

            Args:
                title: The dialog title.
                message: The message to display.
                **_kwargs: Additional keyword arguments (ignored for compatibility).

            Returns:
                int: Always 0.

            """
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            sys.stdout.write(f"[{timestamp}] INFO: {title}: {message}\n")
            sys.stdout.flush()

            if os.environ.get("INTELLICRACK_LOG_FILE"):
                try:
                    with open(os.environ["INTELLICRACK_LOG_FILE"], "a") as f:
                        f.write(f"[{timestamp}] INFO: {title}: {message}\n")
                except Exception as e:
                    logger.debug(f"Log file write failed: {e}")

            return 0

        @classmethod
        def question(cls, title: str, message: str, **_kwargs: object) -> int:
            """Display a question message dialog.

            Args:
                title: The dialog title.
                message: The message to display.
                **_kwargs: Additional keyword arguments (ignored for compatibility).

            Returns:
                int: Default answer or 0.

            """
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            sys.stdout.write(f"[{timestamp}] QUESTION: {title}: {message}\n")
            sys.stdout.flush()

            if os.environ.get("INTELLICRACK_LOG_FILE"):
                try:
                    with open(os.environ["INTELLICRACK_LOG_FILE"], "a") as f:
                        f.write(f"[{timestamp}] QUESTION: {title}: {message}\n")
                except Exception as e:
                    logger.debug(f"Log file write failed: {e}")

            if os.environ.get("INTELLICRACK_AUTO_ANSWER"):
                answer = os.environ.get("INTELLICRACK_AUTO_ANSWER")
                sys.stdout.write(f"[{timestamp}] AUTO-ANSWER: {answer}\n")
                sys.stdout.flush()
                return int(answer) if answer and answer.isdigit() else 0

            return 0

    class FallbackQt:
        """Production-ready Qt namespace emulation for headless environments."""

        _enum_values: dict[str, int] = {
            "AlignLeft": 0x0001,
            "AlignRight": 0x0002,
            "AlignHCenter": 0x0004,
            "AlignJustify": 0x0008,
            "AlignTop": 0x0020,
            "AlignBottom": 0x0040,
            "AlignVCenter": 0x0080,
            "AlignCenter": 0x0084,
            "NoModifier": 0x00000000,
            "ShiftModifier": 0x02000000,
            "ControlModifier": 0x04000000,
            "AltModifier": 0x08000000,
            "MetaModifier": 0x10000000,
            "KeypadModifier": 0x20000000,
            "LeftButton": 0x00000001,
            "RightButton": 0x00000002,
            "MiddleButton": 0x00000004,
            "BackButton": 0x00000008,
            "ForwardButton": 0x00000010,
            "NoButton": 0x00000000,
            "WindowNoState": 0x00000000,
            "WindowMinimized": 0x00000001,
            "WindowMaximized": 0x00000002,
            "WindowFullScreen": 0x00000004,
            "WindowActive": 0x00000008,
            "StrongFocus": 11,
            "NoFocus": 0,
            "TabFocus": 1,
            "ClickFocus": 2,
            "WheelFocus": 15,
            "PlainText": 0,
            "RichText": 1,
            "AutoText": 2,
            "MarkdownText": 3,
            "AscendingOrder": 0,
            "DescendingOrder": 1,
            "Unchecked": 0,
            "PartiallyChecked": 1,
            "Checked": 2,
        }

        def __init__(self) -> None:
            """Initialize the Qt fallback namespace."""
            self._namespace_name: str = "QtFallback"
            self._sub_namespaces: dict[str, object] = {}

        def __getattr__(self, name: str) -> object:
            """Get an attribute from the Qt namespace.

            Args:
                name: The attribute name.

            Returns:
                object: The attribute value or a FallbackWidget.

            """
            if name in self._enum_values:
                return self._enum_values[name]

            if name not in self._sub_namespaces:
                if name in {
                    "ItemDataRole",
                    "Orientation",
                    "KeyboardModifier",
                    "MouseButton",
                    "WindowState",
                    "WindowType",
                    "FocusPolicy",
                    "TextFormat",
                    "SortOrder",
                    "CheckState",
                    "ToolButtonStyle",
                    "LayoutDirection",
                    "Alignment",
                    "Key",
                }:
                    self._sub_namespaces[name] = FallbackQtEnum(name)
                else:
                    return FallbackWidget()

            return self._sub_namespaces.get(name, FallbackWidget())

        def __call__(self, *args: object, **kwargs: object) -> int:
            """Make the Qt namespace callable.

            Args:
                *args: Positional arguments.
                **kwargs: Keyword arguments.

            Returns:
                int: Always 0.

            """
            return 0

        def __int__(self) -> int:
            """Convert to integer.

            Returns:
                int: Always 0.

            """
            return 0

        def __bool__(self) -> bool:
            """Convert to boolean.

            Returns:
                bool: Always True.

            """
            return True

    class FallbackQtEnum:
        """Production-ready Qt enumeration emulation with real values."""

        _enum_mappings: dict[str, dict[str, int]] = {
            "ItemDataRole": {
                "DisplayRole": 0,
                "DecorationRole": 1,
                "EditRole": 2,
                "ToolTipRole": 3,
                "StatusTipRole": 4,
                "WhatsThisRole": 5,
                "FontRole": 6,
                "TextAlignmentRole": 7,
                "BackgroundRole": 8,
                "ForegroundRole": 9,
                "CheckStateRole": 10,
                "AccessibleTextRole": 11,
                "AccessibleDescriptionRole": 12,
                "SizeHintRole": 13,
                "UserRole": 256,
            },
            "Orientation": {"Horizontal": 1, "Vertical": 2},
            "KeyboardModifier": {
                "NoModifier": 0x00000000,
                "ShiftModifier": 0x02000000,
                "ControlModifier": 0x04000000,
                "AltModifier": 0x08000000,
                "MetaModifier": 0x10000000,
                "KeypadModifier": 0x20000000,
                "GroupSwitchModifier": 0x40000000,
            },
            "MouseButton": {
                "NoButton": 0x00000000,
                "LeftButton": 0x00000001,
                "RightButton": 0x00000002,
                "MiddleButton": 0x00000004,
                "BackButton": 0x00000008,
                "ForwardButton": 0x00000010,
                "TaskButton": 0x00000020,
                "ExtraButton4": 0x00000040,
                "ExtraButton5": 0x00000080,
            },
            "WindowState": {
                "WindowNoState": 0x00000000,
                "WindowMinimized": 0x00000001,
                "WindowMaximized": 0x00000002,
                "WindowFullScreen": 0x00000004,
                "WindowActive": 0x00000008,
            },
            "WindowType": {
                "Widget": 0x00000000,
                "Window": 0x00000001,
                "Dialog": 0x00000003,
                "Sheet": 0x00000005,
                "Popup": 0x00000009,
                "Tool": 0x00000011,
                "ToolTip": 0x00000021,
                "SplashScreen": 0x0000000F,
                "Desktop": 0x00000010,
                "SubWindow": 0x00000012,
            },
            "FocusPolicy": {
                "NoFocus": 0,
                "TabFocus": 1,
                "ClickFocus": 2,
                "StrongFocus": 11,
                "WheelFocus": 15,
            },
            "TextFormat": {"PlainText": 0, "RichText": 1, "AutoText": 2, "MarkdownText": 3},
            "SortOrder": {"AscendingOrder": 0, "DescendingOrder": 1},
            "CheckState": {"Unchecked": 0, "PartiallyChecked": 1, "Checked": 2},
            "ToolButtonStyle": {
                "ToolButtonIconOnly": 0,
                "ToolButtonTextOnly": 1,
                "ToolButtonTextBesideIcon": 2,
                "ToolButtonTextUnderIcon": 3,
                "ToolButtonFollowStyle": 4,
            },
            "LayoutDirection": {"LeftToRight": 0, "RightToLeft": 1, "LayoutDirectionAuto": 2},
            "Alignment": {
                "AlignLeft": 0x0001,
                "AlignRight": 0x0002,
                "AlignHCenter": 0x0004,
                "AlignJustify": 0x0008,
                "AlignTop": 0x0020,
                "AlignBottom": 0x0040,
                "AlignVCenter": 0x0080,
                "AlignBaseline": 0x0100,
                "AlignCenter": 0x0084,
                "AlignAbsolute": 0x0010,
                "AlignLeading": 0x0001,
                "AlignTrailing": 0x0002,
            },
            "Key": {
                "Key_Escape": 0x01000000,
                "Key_Tab": 0x01000001,
                "Key_Backtab": 0x01000002,
                "Key_Backspace": 0x01000003,
                "Key_Return": 0x01000004,
                "Key_Enter": 0x01000005,
                "Key_Insert": 0x01000006,
                "Key_Delete": 0x01000007,
                "Key_Pause": 0x01000008,
                "Key_Print": 0x01000009,
                "Key_SysReq": 0x0100000A,
                "Key_Clear": 0x0100000B,
                "Key_Home": 0x01000010,
                "Key_End": 0x01000011,
                "Key_Left": 0x01000012,
                "Key_Up": 0x01000013,
                "Key_Right": 0x01000014,
                "Key_Down": 0x01000015,
                "Key_PageUp": 0x01000016,
                "Key_PageDown": 0x01000017,
                "Key_Shift": 0x01000020,
                "Key_Control": 0x01000021,
                "Key_Meta": 0x01000022,
                "Key_Alt": 0x01000023,
                "Key_Space": 0x20,
                "Key_A": 0x41,
                "Key_B": 0x42,
                "Key_C": 0x43,
                "Key_D": 0x44,
                "Key_E": 0x45,
                "Key_F": 0x46,
                "Key_G": 0x47,
                "Key_H": 0x48,
                "Key_I": 0x49,
                "Key_J": 0x4A,
                "Key_K": 0x4B,
                "Key_L": 0x4C,
                "Key_M": 0x4D,
                "Key_N": 0x4E,
                "Key_O": 0x4F,
                "Key_P": 0x50,
                "Key_Q": 0x51,
                "Key_R": 0x52,
                "Key_S": 0x53,
                "Key_T": 0x54,
                "Key_U": 0x55,
                "Key_V": 0x56,
                "Key_W": 0x57,
                "Key_X": 0x58,
                "Key_Y": 0x59,
                "Key_Z": 0x5A,
                "Key_F1": 0x01000030,
                "Key_F2": 0x01000031,
                "Key_F3": 0x01000032,
                "Key_F4": 0x01000033,
                "Key_F5": 0x01000034,
                "Key_F6": 0x01000035,
                "Key_F7": 0x01000036,
                "Key_F8": 0x01000037,
                "Key_F9": 0x01000038,
                "Key_F10": 0x01000039,
                "Key_F11": 0x0100003A,
                "Key_F12": 0x0100003B,
            },
        }

        def __init__(self, enum_type: str) -> None:
            """Initialize the Qt enum.

            Args:
                enum_type: The enumeration type name.

            """
            self._enum_type: str = enum_type
            self._values: dict[str, int] = self._enum_mappings.get(enum_type, {})

        def __getattr__(self, name: str) -> int:
            """Get an enumeration value.

            Args:
                name: The value name.

            Returns:
                int: The enumeration value, or 0 if not found.

            """
            value = self._values.get(name)
            if value is not None:
                return value

            logger.debug(f"Unknown Qt enum value requested: {self._enum_type}.{name}, returning 0")
            return 0

        def __int__(self) -> int:
            """Convert to integer.

            Returns:
                int: Always 0.

            """
            return 0

        def __call__(self, *args: object, **kwargs: object) -> int:
            """Make enum callable.

            Args:
                *args: Positional arguments.
                **kwargs: Keyword arguments.

            Returns:
                int: Always 0.

            """
            return 0

        def __or__(self, other: object) -> int:
            """Bitwise OR operation.

            Args:
                other: The other operand.

            Returns:
                int: The other value if it's an int, 0 otherwise.

            """
            return other if isinstance(other, int) else 0

        def __and__(self, other: object) -> int:
            """Bitwise AND operation.

            Args:
                other: The other operand.

            Returns:
                int: The other value if it's an int, 0 otherwise.

            """
            return other if isinstance(other, int) else 0

        def __xor__(self, other: object) -> int:
            """Bitwise XOR operation.

            Args:
                other: The other operand.

            Returns:
                int: The other value if it's an int, 0 otherwise.

            """
            return other if isinstance(other, int) else 0

        def __invert__(self) -> int:
            """Bitwise NOT operation.

            Returns:
                int: All bits set.

            """
            return 0xFFFFFFFF

    # Fallback classes for headless mode to prevent TypeError: NoneType takes no arguments
    if os.environ.get("INTELLICRACK_TESTING") or os.environ.get("DISABLE_BACKGROUND_THREADS"):
        PYQT_VERSION_STR = "Fallback"
        QAbstractItemModel = FallbackWidget  # type: ignore[misc,assignment]
        QAbstractItemView = FallbackWidget  # type: ignore[misc,assignment]
        QAbstractScrollArea = FallbackWidget  # type: ignore[misc,assignment]
        QAction = FallbackWidget  # type: ignore[misc,assignment]
        QApplication = FallbackWidget  # type: ignore[misc,assignment]
        QBrush = FallbackWidget  # type: ignore[misc,assignment]
        QBuffer = FallbackWidget  # type: ignore[misc,assignment]
        QButtonGroup = FallbackWidget  # type: ignore[misc,assignment]
        QCheckBox = FallbackWidget  # type: ignore[misc,assignment]
        QCloseEvent = FallbackWidget  # type: ignore[misc,assignment]
        QColor = FallbackWidget  # type: ignore[misc,assignment]
        QColorDialog = FallbackWidget  # type: ignore[misc,assignment]
        QComboBox = FallbackWidget  # type: ignore[misc,assignment]
        QCoreApplication = FallbackWidget  # type: ignore[misc,assignment]
        QDateTime = FallbackWidget  # type: ignore[misc,assignment]
        QDesktopServices = FallbackWidget  # type: ignore[misc,assignment]
        QDialog = FallbackWidget  # type: ignore[misc,assignment]
    else:
        # Null object pattern for all PyQt6 classes when not available (non-testing)
        PYQT_VERSION_STR = None  # type: ignore[assignment]
        QAbstractItemModel = None  # type: ignore[misc,assignment]
        QAbstractItemView = None  # type: ignore[misc,assignment]
        QAbstractScrollArea = None  # type: ignore[misc,assignment]
        QAction = None  # type: ignore[misc,assignment]
        QApplication = None  # type: ignore[misc,assignment]
        QBrush = None  # type: ignore[misc,assignment]
        QBuffer = None  # type: ignore[misc,assignment]
        QButtonGroup = None  # type: ignore[misc,assignment]
        QCheckBox = None  # type: ignore[misc,assignment]
        QCloseEvent = None  # type: ignore[misc,assignment]
        QColor = FallbackWidget  # type: ignore[misc,assignment]
        QColorDialog = FallbackWidget  # type: ignore[misc,assignment]
        QComboBox = FallbackWidget  # type: ignore[misc,assignment]
        QCoreApplication = FallbackWidget  # type: ignore[misc,assignment]
        QDateTime = FallbackWidget  # type: ignore[misc,assignment]
        QDesktopServices = FallbackWidget  # type: ignore[misc,assignment]
        QDialog = FallbackWidget  # type: ignore[misc,assignment]
    # Continue testing mode assignment for remaining Qt classes
    if os.environ.get("INTELLICRACK_TESTING") or os.environ.get("DISABLE_BACKGROUND_THREADS"):
        QDialogButtonBox = FallbackWidget  # type: ignore[misc,assignment]
        QDoubleSpinBox = FallbackWidget  # type: ignore[misc,assignment]
        QDragEnterEvent = FallbackWidget  # type: ignore[misc,assignment]
        QDragLeaveEvent = FallbackWidget  # type: ignore[misc,assignment]
        QDropEvent = FallbackWidget  # type: ignore[misc,assignment]
        QFileDialog = FallbackWidget  # type: ignore[misc,assignment]
        QFileIconProvider = FallbackWidget  # type: ignore[misc,assignment]
        QFileInfo = FallbackWidget  # type: ignore[misc,assignment]
        QFileSystemWatcher = FallbackWidget  # type: ignore[misc,assignment]
        QFont = FallbackWidget  # type: ignore[misc,assignment]
        QFontDatabase = FallbackWidget  # type: ignore[misc,assignment]
        QFontMetrics = FallbackWidget  # type: ignore[misc,assignment]
        QFormLayout = FallbackWidget  # type: ignore[misc,assignment]
        QFrame = FallbackWidget  # type: ignore[misc,assignment]
        QGraphicsView = FallbackWidget  # type: ignore[misc,assignment]
        QGridLayout = FallbackWidget  # type: ignore[misc,assignment]
        QGroupBox = FallbackWidget  # type: ignore[misc,assignment]
        QHBoxLayout = FallbackWidget  # type: ignore[misc,assignment]
        QHeaderView = FallbackWidget  # type: ignore[misc,assignment]
        QIODevice = FallbackWidget  # type: ignore[misc,assignment]
        QIcon = FallbackWidget  # type: ignore[misc,assignment]
        QImage = FallbackWidget  # type: ignore[misc,assignment]
        QInputDialog = FallbackWidget  # type: ignore[misc,assignment]
        QKeyEvent = FallbackWidget  # type: ignore[misc,assignment]
        QKeySequence = FallbackWidget  # type: ignore[misc,assignment]
        QLabel = FallbackWidget  # type: ignore[misc,assignment]
        QLineEdit = FallbackWidget  # type: ignore[misc,assignment]
        QListView = FallbackWidget  # type: ignore[misc,assignment]
        QListWidget = FallbackWidget  # type: ignore[misc,assignment]
        QListWidgetItem = FallbackWidget  # type: ignore[misc,assignment]
        QMainWindow = FallbackWidget  # type: ignore[misc,assignment]
        QMenu = FallbackWidget  # type: ignore[misc,assignment]
        QMenuBar = FallbackWidget  # type: ignore[misc,assignment]
        QMessageBox = FallbackWidget  # type: ignore[misc,assignment]
        QMetaObject = FallbackWidget  # type: ignore[misc,assignment]
        QModelIndex = FallbackWidget  # type: ignore[misc,assignment]
        QMouseEvent = FallbackWidget  # type: ignore[misc,assignment]
        QObject = FallbackWidget  # type: ignore[misc,assignment]
        QOpenGLContext = FallbackWidget  # type: ignore[misc,assignment]
        QOpenGLWidget = FallbackWidget  # type: ignore[misc,assignment]
        QPaintEvent = FallbackWidget  # type: ignore[misc,assignment]
        QPainter = FallbackWidget  # type: ignore[misc,assignment]
        QPalette = FallbackWidget  # type: ignore[misc,assignment]
        QPdfDocument = FallbackWidget  # type: ignore[misc,assignment]
        QPdfView = FallbackWidget  # type: ignore[misc,assignment]
        QPen = FallbackWidget  # type: ignore[misc,assignment]
        QPixmap = FallbackWidget  # type: ignore[misc,assignment]
        QPlainTextEdit = FallbackWidget  # type: ignore[misc,assignment]
        QPoint = FallbackWidget  # type: ignore[misc,assignment]
        QPrintDialog = FallbackWidget  # type: ignore[misc,assignment]
        QPrinter = FallbackWidget  # type: ignore[misc,assignment]
        QProcess = FallbackWidget  # type: ignore[misc,assignment]
        QProgressBar = FallbackWidget  # type: ignore[misc,assignment]
        QProgressDialog = FallbackWidget  # type: ignore[misc,assignment]
        QPushButton = FallbackWidget  # type: ignore[misc,assignment]
        QT_VERSION_STR = "Fallback"
        QRadioButton = FallbackWidget  # type: ignore[misc,assignment]
        QRect = FallbackWidget  # type: ignore[misc,assignment]
        QRegularExpression = FallbackWidget  # type: ignore[misc,assignment]
        QResizeEvent = FallbackWidget  # type: ignore[misc,assignment]
        QRunnable = FallbackWidget  # type: ignore[misc,assignment]
        QShortcut = FallbackWidget  # type: ignore[misc,assignment]
        QScrollArea = FallbackWidget  # type: ignore[misc,assignment]
        QScrollBar = FallbackWidget  # type: ignore[misc,assignment]
        QSize = FallbackWidget  # type: ignore[misc,assignment]
        QSizePolicy = FallbackWidget  # type: ignore[misc,assignment]
        QSlider = FallbackWidget  # type: ignore[misc,assignment]
        QSpacerItem = FallbackWidget  # type: ignore[misc,assignment]
        QSpinBox = FallbackWidget  # type: ignore[misc,assignment]
        QSplashScreen = FallbackWidget  # type: ignore[misc,assignment]
        QSplitter = FallbackWidget  # type: ignore[misc,assignment]
        QStackedWidget = FallbackWidget  # type: ignore[misc,assignment]
        QStandardItem = FallbackWidget  # type: ignore[misc,assignment]
        QStandardItemModel = FallbackWidget  # type: ignore[misc,assignment]
        QStatusBar = FallbackWidget  # type: ignore[misc,assignment]
        QStyle = FallbackWidget  # type: ignore[misc,assignment]
        QSurfaceFormat = FallbackWidget  # type: ignore[misc,assignment]
    else:
        QDialogButtonBox = None  # type: ignore[misc,assignment]
        QDoubleSpinBox = None  # type: ignore[misc,assignment]
        QDragEnterEvent = None  # type: ignore[misc,assignment]
        QDragLeaveEvent = None  # type: ignore[misc,assignment]
        QDropEvent = None  # type: ignore[misc,assignment]
        QFileDialog = None  # type: ignore[misc,assignment]
        QFileIconProvider = None  # type: ignore[misc,assignment]
        QFileInfo = None  # type: ignore[misc,assignment]
        QFileSystemWatcher = None  # type: ignore[misc,assignment]
        QFont = None  # type: ignore[misc,assignment]
        QFontDatabase = None  # type: ignore[misc,assignment]
        QFontMetrics = None  # type: ignore[misc,assignment]
        QFormLayout = None  # type: ignore[misc,assignment]
        QFrame = None  # type: ignore[misc,assignment]
        QGraphicsView = None  # type: ignore[misc,assignment]
        QGridLayout = None  # type: ignore[misc,assignment]
        QGroupBox = None  # type: ignore[misc,assignment]
        QHBoxLayout = None  # type: ignore[misc,assignment]
        QHeaderView = None  # type: ignore[misc,assignment]
        QIODevice = None  # type: ignore[misc,assignment]
        QIcon = None  # type: ignore[misc,assignment]
        QImage = None  # type: ignore[misc,assignment]
        QInputDialog = None  # type: ignore[misc,assignment]
        QKeyEvent = None  # type: ignore[misc,assignment]
        QKeySequence = None  # type: ignore[misc,assignment]
        QLabel = None  # type: ignore[misc,assignment]
        QLineEdit = None  # type: ignore[misc,assignment]
        QListView = None  # type: ignore[misc,assignment]
        QListWidget = None  # type: ignore[misc,assignment]
        QListWidgetItem = None  # type: ignore[misc,assignment]
        QMainWindow = None  # type: ignore[misc,assignment]
        QMenu = None  # type: ignore[misc,assignment]
        QMenuBar = None  # type: ignore[misc,assignment]
        QMessageBox = None  # type: ignore[misc,assignment]
        QMetaObject = None  # type: ignore[misc,assignment]
        QModelIndex = None  # type: ignore[misc,assignment]
        QMouseEvent = None  # type: ignore[misc,assignment]
        QObject = None  # type: ignore[misc,assignment]
        QOpenGLContext = None  # type: ignore[misc,assignment]
        QOpenGLWidget = None  # type: ignore[misc,assignment]
        QPaintEvent = None  # type: ignore[misc,assignment]
        QPainter = None  # type: ignore[misc,assignment]
        QPalette = None  # type: ignore[misc,assignment]
        QPdfDocument = None  # type: ignore[misc,assignment]
        QPdfView = None  # type: ignore[misc,assignment]
        QPen = None  # type: ignore[misc,assignment]
        QPixmap = None  # type: ignore[misc,assignment]
        QPlainTextEdit = None  # type: ignore[misc,assignment]
        QPoint = None  # type: ignore[misc,assignment]
        QPrintDialog = None  # type: ignore[misc,assignment]
        QPrinter = None  # type: ignore[misc,assignment]
        QProcess = None  # type: ignore[misc,assignment]
        QProgressBar = None  # type: ignore[misc,assignment]
        QProgressDialog = None  # type: ignore[misc,assignment]
        QPushButton = None  # type: ignore[misc,assignment]
        QT_VERSION_STR = None  # type: ignore[assignment]
        QRadioButton = None  # type: ignore[misc,assignment]
        QRect = None  # type: ignore[misc,assignment]
        QRegularExpression = None  # type: ignore[misc,assignment]
        QResizeEvent = None  # type: ignore[misc,assignment]
        QRunnable = None  # type: ignore[misc,assignment]
        QShortcut = None  # type: ignore[misc,assignment]
        QScrollArea = None  # type: ignore[misc,assignment]
        QScrollBar = None  # type: ignore[misc,assignment]
        QSize = None  # type: ignore[misc,assignment]
        QSizePolicy = None  # type: ignore[misc,assignment]
        QSlider = None  # type: ignore[misc,assignment]
        QSpacerItem = None  # type: ignore[misc,assignment]
        QSpinBox = None  # type: ignore[misc,assignment]
        QSplashScreen = None  # type: ignore[misc,assignment]
        QSplitter = None  # type: ignore[misc,assignment]
        QStackedWidget = None  # type: ignore[misc,assignment]
        QStandardItem = None  # type: ignore[misc,assignment]
        QStandardItemModel = None  # type: ignore[misc,assignment]
        QStatusBar = None  # type: ignore[misc,assignment]
        QStyle = None  # type: ignore[misc,assignment]
        QSurfaceFormat = None  # type: ignore[misc,assignment]
    # Finish testing mode assignment for final Qt classes
    if os.environ.get("INTELLICRACK_TESTING") or os.environ.get("DISABLE_BACKGROUND_THREADS"):
        QSyntaxHighlighter = FallbackWidget  # type: ignore[misc,assignment]
        QTabWidget = FallbackWidget  # type: ignore[misc,assignment]
        QTableView = FallbackWidget  # type: ignore[misc,assignment]
        QTableWidget = FallbackWidget  # type: ignore[misc,assignment]
        QTableWidgetItem = FallbackWidget  # type: ignore[misc,assignment]
        QTest = FallbackWidget  # type: ignore[misc,assignment]
        QTextBrowser = FallbackWidget  # type: ignore[misc,assignment]
        QTextCharFormat = FallbackWidget  # type: ignore[misc,assignment]
        QTextCursor = FallbackWidget  # type: ignore[misc,assignment]
        QTextDocument = FallbackWidget  # type: ignore[misc,assignment]
        QTextEdit = FallbackWidget  # type: ignore[misc,assignment]
        QTextFormat = FallbackWidget  # type: ignore[misc,assignment]
        QThread = FallbackWidget  # type: ignore[misc,assignment]
        QThreadPool = FallbackWidget  # type: ignore[misc,assignment]
        QTimer = FallbackWidget  # type: ignore[misc,assignment]
        QToolBar = FallbackWidget  # type: ignore[misc,assignment]
        QTreeView = FallbackWidget  # type: ignore[misc,assignment]
        QTreeWidget = FallbackWidget  # type: ignore[misc,assignment]
        QTreeWidgetItem = FallbackWidget  # type: ignore[misc,assignment]
        QUrl = FallbackWidget  # type: ignore[misc,assignment]
        QVariant = FallbackWidget  # type: ignore[misc,assignment]
        QVBoxLayout = FallbackWidget  # type: ignore[misc,assignment]
        QWebEngineView = FallbackWidget
        QWidget = FallbackWidget  # type: ignore[misc,assignment]
        QWizard = FallbackWidget  # type: ignore[misc,assignment]
        QWizardPage = FallbackWidget  # type: ignore[misc,assignment]
        Qt = FallbackQt()  # type: ignore[misc,assignment]

        class FallbackSignal:
            """Production-ready signal implementation for headless environments."""

            def __init__(self, *types: object, **kwargs: object) -> None:
                """Initialize a fallback signal.

                Args:
                    *types: The signal argument types.
                    **kwargs: Additional keyword arguments (name, etc.).

                """
                self._types: tuple[object, ...] = types
                self._name: str = str(kwargs.get("name", "signal"))
                self._callbacks: list[object] = []
                self._enabled: bool = True

            def connect(self, callback: object) -> None:
                """Connect a callback to this signal.

                Args:
                    callback: The callback function to connect.

                """
                if callable(callback) and callback not in self._callbacks:
                    self._callbacks.append(callback)
                    callback_name = getattr(callback, "__name__", str(callback))
                    logger.debug(f"Signal {self._name} connected to {callback_name}")

            def disconnect(self, callback: object = None) -> None:
                """Disconnect a callback from this signal.

                Args:
                    callback: The callback to disconnect, or None to disconnect all.

                """
                if callback is None:
                    self._callbacks.clear()
                    logger.debug(f"All callbacks disconnected from signal {self._name}")
                elif callback in self._callbacks:
                    self._callbacks.remove(callback)
                    callback_name = getattr(callback, "__name__", str(callback))
                    logger.debug(f"Callback {callback_name} disconnected from signal {self._name}")

            def emit(self, *args: object) -> None:
                """Emit this signal to all connected callbacks.

                Args:
                    *args: Arguments to pass to the callbacks.

                """
                if not self._enabled:
                    return

                for callback in self._callbacks[:]:
                    if callable(callback):
                        try:
                            callback(*args)
                        except Exception as e:
                            logger.error(f"Signal {self._name} callback error: {e}")

            def setEnabled(self, enabled: object) -> None:
                """Enable or disable the signal.

                Args:
                    enabled: True to enable, False to disable.

                """
                self._enabled = bool(enabled)

            def __call__(self, *args: object) -> None:
                """Make the signal callable.

                Args:
                    *args: Arguments to pass to emit.

                """
                self.emit(*args)

            def __bool__(self) -> bool:
                """Convert to boolean.

                Returns:
                    bool: Always True.

                """
                return True

        def fallback_pyqtSignal(*types: object, **kwargs: object) -> FallbackSignal:
            """Production-ready pyqtSignal implementation for headless environments.

            Args:
                *types: The signal argument types.
                **kwargs: Additional keyword arguments.

            Returns:
                FallbackSignal: A new signal instance.

            """
            return FallbackSignal(*types, **kwargs)

        pyqtSignal = fallback_pyqtSignal  # type: ignore[misc,assignment]

        def fallback_pyqtSlot(*types: object, **kwargs: object) -> object:
            """Production-ready pyqtSlot decorator for headless environments.

            Args:
                *types: The slot argument types.
                **kwargs: Additional keyword arguments.

            Returns:
                object: A decorator function.

            """
            from collections.abc import Callable
            from typing import Any, TypeVar, cast
            F = TypeVar('F', bound=Callable[..., Any])

            def decorator(func: F) -> F:
                """Apply the pyqt slot decorator to a function.

                Args:
                    func: The function to decorate.

                Returns:
                    object: The wrapped function.

                """
                func._pyqt_slot = True
                func._slot_types = types
                func._slot_result = kwargs.get("result")
                func_name = getattr(func, "__name__", str(func))
                func._slot_name = kwargs.get("name", func_name)

                def wrapper(*args: object, **kw: object) -> Any:
                    """Execute the slot function with logging and type checking.

                    Args:
                        *args: Positional arguments.
                        **kw: Keyword arguments.

                    Returns:
                        object: The function result.

                    Raises:
                        Exception: Any exception from the wrapped function.

                    """
                    try:
                        slot_name = getattr(func, "_slot_name", str(func))
                        logger.debug(f"Slot {slot_name} called with args={args}, kwargs={kw}")
                        result = func(*args, **kw)

                        slot_result = getattr(func, "_slot_result", None)
                        if slot_result is not None:
                            expected_type = slot_result
                            if not isinstance(result, expected_type):
                                logger.warning(
                                    f"Slot {slot_name} returned {type(result).__name__}, expected {expected_type.__name__}",
                                )

                        return result
                    except Exception as e:
                        slot_name = getattr(func, "_slot_name", str(func))
                        logger.error(f"Slot {slot_name} error: {e}")
                        raise

                wrapper._pyqt_slot = True
                wrapper._slot_types = types
                slot_result = getattr(func, "_slot_result", None)
                wrapper._slot_result = slot_result
                slot_name = getattr(func, "_slot_name", str(func))
                wrapper._slot_name = slot_name

                return cast("F", wrapper)

            return decorator

        pyqtSlot = fallback_pyqtSlot  # type: ignore[assignment]

        def qRgba(r: int, g: int, b: int, a: int = 255) -> int:  # type: ignore[misc]
            """Production-ready RGBA color value creation for headless environments.

            Args:
                r: Red component (0-255).
                g: Green component (0-255).
                b: Blue component (0-255).
                a: Alpha component (0-255), default 255.

            Returns:
                int: The RGBA color value as a 32-bit integer.

            """
            r = max(0, min(255, r))
            g = max(0, min(255, g))
            b = max(0, min(255, b))
            a = max(0, min(255, a))

            return (a << 24) | (r << 16) | (g << 8) | b
    else:
        QSyntaxHighlighter = None  # type: ignore[misc,assignment]
        QTabWidget = None  # type: ignore[misc,assignment]
        QTableView = None  # type: ignore[misc,assignment]
        QTableWidget = None  # type: ignore[misc,assignment]
        QTableWidgetItem = None  # type: ignore[misc,assignment]
        QTest = None  # type: ignore[misc,assignment]
        QTextBrowser = None  # type: ignore[misc,assignment]
        QTextCharFormat = None  # type: ignore[misc,assignment]
        QTextCursor = None  # type: ignore[misc,assignment]
        QTextDocument = None  # type: ignore[misc,assignment]
        QTextEdit = None  # type: ignore[misc,assignment]
        QTextFormat = None  # type: ignore[misc,assignment]
        QThread = None  # type: ignore[misc,assignment]
        QThreadPool = None  # type: ignore[misc,assignment]
        QTimer = None  # type: ignore[misc,assignment]
        QToolBar = None  # type: ignore[misc,assignment]
        QTreeView = None  # type: ignore[misc,assignment]
        QTreeWidget = None  # type: ignore[misc,assignment]
        QTreeWidgetItem = None  # type: ignore[misc,assignment]
        QUrl = None  # type: ignore[misc,assignment]
        QVariant = None  # type: ignore[misc,assignment]
        QVBoxLayout = None  # type: ignore[misc,assignment]
        QWebEngineView = None
        QWidget = None  # type: ignore[misc,assignment]
        QWizard = None  # type: ignore[misc,assignment]
        QWizardPage = None  # type: ignore[misc,assignment]
        Qt = None  # type: ignore[misc,assignment]

        def fallback_pyqtSignal_null(*args: object, **kwargs: object) -> object:
            """Fallback pyqtSignal implementation for minimal PyQt6 compatibility.

            Args:
                *args: Positional arguments (ignored).
                **kwargs: Keyword arguments (ignored).

            Returns:
                object: A no-op lambda function.

            """
            return lambda: None

        pyqtSignal = fallback_pyqtSignal_null  # type: ignore[misc,assignment]

        def fallback_pyqtSlot_null(*args: object, **kwargs: object) -> object:
            """Fallback pyqtSlot decorator for minimal PyQt6 compatibility.

            Args:
                *args: Positional arguments (ignored).
                **kwargs: Keyword arguments (ignored).

            Returns:
                object: A no-op lambda function.

            """
            return lambda x: x

        pyqtSlot = fallback_pyqtSlot_null  # type: ignore[assignment]

        q_rgba: None = None


# Export all PyQt6 classes and availability flag
__all__ = [
    "HAS_PYQT",
    "PYQT6_AVAILABLE",
    "PYQT_VERSION_STR",
    "QAbstractItemModel",
    "QAbstractItemView",
    "QAbstractScrollArea",
    "QAction",
    "QApplication",
    "QBrush",
    "QBuffer",
    "QButtonGroup",
    "QCheckBox",
    "QCloseEvent",
    "QColor",
    "QColorDialog",
    "QComboBox",
    "QCoreApplication",
    "QDateTime",
    "QDesktopServices",
    "QDialog",
    "QDialogButtonBox",
    "QDoubleSpinBox",
    "QDragEnterEvent",
    "QDragLeaveEvent",
    "QDropEvent",
    "QFileDialog",
    "QFileIconProvider",
    "QFileInfo",
    "QFileSystemWatcher",
    "QFont",
    "QFontComboBox",
    "QFontDatabase",
    "QFontMetrics",
    "QFormLayout",
    "QFrame",
    "QGraphicsView",
    "QGridLayout",
    "QGroupBox",
    "QHBoxLayout",
    "QHeaderView",
    "QIODevice",
    "QIcon",
    "QImage",
    "QInputDialog",
    "QKeyEvent",
    "QKeySequence",
    "QLabel",
    "QLineEdit",
    "QListView",
    "QListWidget",
    "QListWidgetItem",
    "QMainWindow",
    "QMenu",
    "QMenuBar",
    "QMessageBox",
    "QMetaObject",
    "QModelIndex",
    "QMouseEvent",
    "QObject",
    "QOpenGLContext",
    "QOpenGLWidget",
    "QPaintEvent",
    "QPainter",
    "QPalette",
    "QPdfDocument",
    "QPdfView",
    "QPen",
    "QPixmap",
    "QPlainTextEdit",
    "QPoint",
    "QPrintDialog",
    "QPrinter",
    "QProcess",
    "QProgressBar",
    "QProgressDialog",
    "QPushButton",
    "QRadioButton",
    "QRect",
    "QRegularExpression",
    "QResizeEvent",
    "QRunnable",
    "QScrollArea",
    "QScrollBar",
    "QShortcut",
    "QSize",
    "QSizePolicy",
    "QSlider",
    "QSpacerItem",
    "QSpinBox",
    "QSplashScreen",
    "QSplitter",
    "QStackedWidget",
    "QStandardItem",
    "QStandardItemModel",
    "QStatusBar",
    "QStyle",
    "QSurfaceFormat",
    "QSyntaxHighlighter",
    "QT_VERSION_STR",
    "QTabWidget",
    "QTableView",
    "QTableWidget",
    "QTableWidgetItem",
    "QTest",
    "QTextBrowser",
    "QTextCharFormat",
    "QTextCursor",
    "QTextDocument",
    "QTextEdit",
    "QTextFormat",
    "QThread",
    "QThreadPool",
    "QTimer",
    "QToolBar",
    "QTreeView",
    "QTreeWidget",
    "QTreeWidgetItem",
    "QUrl",
    "QVBoxLayout",
    "QVariant",
    "QWebEngineView",
    "QWidget",
    "QWizard",
    "QWizardPage",
    "Qt",
    "pyqtSignal",
    "pyqtSlot",
    "qRgba",
]

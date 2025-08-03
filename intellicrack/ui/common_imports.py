"""Common imports module for UI components."""
from intellicrack.logger import logger

"""
Common PyQt6 imports used across UI components

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellicrack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack.  If not, see <https://www.gnu.org/licenses/>.
"""


try:
    from PyQt6.QtCore import QPoint, QRect, QSize, Qt, QThread, QTimer, pyqtSignal
    from PyQt6.QtGui import (
        QAction,
        QColor,
        QFont,
        QFontMetrics,
        QIcon,
        QKeyEvent,
        QKeySequence,
        QMouseEvent,
        QPainter,
        QPaintEvent,
        QPen,
        QPixmap,
        QResizeEvent,
    )
    from PyQt6.QtWidgets import (
        QAbstractItemView,
        QAbstractScrollArea,
        QApplication,
        QButtonGroup,
        QCheckBox,
        QComboBox,
        QDialog,
        QDialogButtonBox,
        QFileDialog,
        QFormLayout,
        QFrame,
        QGridLayout,
        QGroupBox,
        QHBoxLayout,
        QHeaderView,
        QInputDialog,
        QLabel,
        QLineEdit,
        QListWidget,
        QListWidgetItem,
        QMainWindow,
        QMenu,
        QMessageBox,
        QPlainTextEdit,
        QProgressBar,
        QPushButton,
        QRadioButton,
        QScrollArea,
        QSizePolicy,
        QSlider,
        QSpacerItem,
        QSpinBox,
        QSplashScreen,
        QSplitter,
        QStatusBar,
        QTableWidget,
        QTableWidgetItem,
        QTabWidget,
        QTextBrowser,
        QTextEdit,
        QToolBar,
        QTreeWidget,
        QTreeWidgetItem,
        QVBoxLayout,
        QWidget,
        QWizard,
        QWizardPage,
    )
    PYQT6_AVAILABLE = True

    # Utility functions that use the imported classes
    def create_point(x: int, y: int) -> QPoint:
        """Create a QPoint instance"""
        return QPoint(x, y)

    def create_rect(x: int, y: int, width: int, height: int) -> QRect:
        """Create a QRect instance"""
        return QRect(x, y, width, height)

    def create_size(width: int, height: int) -> QSize:
        """Create a QSize instance"""
        return QSize(width, height)

    def get_text_metrics(font: QFont, text: str) -> QFontMetrics:
        """Get font metrics for text measurement"""
        metrics = QFontMetrics(font)
        return metrics

    def create_icon_from_file(path: str) -> QIcon:
        """Create an icon from a file path"""
        return QIcon(path)

    def create_pixmap(width: int, height: int) -> QPixmap:
        """Create an empty pixmap"""
        return QPixmap(width, height)

    def create_pen(color: QColor, width: int = 1) -> QPen:
        """Create a pen for drawing"""
        return QPen(color, width)

    def handle_key_event(event: QKeyEvent) -> tuple:
        """Extract key information from a key event"""
        return (event.key(), event.modifiers(), event.text())

    def handle_mouse_event(event: QMouseEvent) -> tuple:
        """Extract mouse information from a mouse event"""
        return (event.x(), event.y(), event.button(), event.buttons())

    def handle_paint_event(widget: QWidget, event: QPaintEvent, paint_func=None):
        """Helper for handling paint events"""
        painter = QPainter(widget)
        try:
            if paint_func:
                paint_func(painter, event.rect())
        finally:
            painter.end()

    def handle_resize_event(event: QResizeEvent) -> tuple:
        """Extract size information from resize event"""
        return (event.size().width(), event.size().height(),
                event.oldSize().width(), event.oldSize().height())

    def create_standard_action(text: str, parent=None, slot=None, shortcut=None) -> QAction:
        """Create a standard action with optional shortcut"""
        action = QAction(text, parent)
        if slot:
            action.triggered.connect(slot)
        if shortcut:
            action.setShortcut(QKeySequence(shortcut))
        return action

    def create_button_group(buttons: list, parent=None) -> QButtonGroup:
        """Create a button group from a list of buttons"""
        group = QButtonGroup(parent)
        for i, button in enumerate(buttons):
            group.addButton(button, i)
        return group

    def get_desktop_geometry() -> tuple:
        """Get desktop geometry information"""
        app = QApplication.instance()
        if app:
            primary_screen = app.primaryScreen()
            if primary_screen:
                rect = primary_screen.geometry()
                return (rect.width(), rect.height())
        return (1920, 1080)  # Default fallback

    def create_frame_with_style(style=None, shadow=None) -> QFrame:
        """Create a styled frame"""
        if style is None:
            style = QFrame.Shape.Box
        if shadow is None:
            shadow = QFrame.Shadow.Raised
        frame = QFrame()
        frame.setFrameStyle(style | shadow)
        return frame

    def prompt_for_input(parent, title: str, label: str, default: str = "") -> tuple:
        """Show input dialog and return (text, ok)"""
        return QInputDialog.getText(parent, title, label, text=default)

    def create_context_menu(actions: list, parent=None) -> QMenu:
        """Create a context menu with actions"""
        menu = QMenu(parent)
        for action in actions:
            if action is None:
                menu.addSeparator()
            else:
                menu.addAction(action)
        return menu

    def create_radio_button_set(labels: list, parent=None) -> list:
        """Create a set of radio buttons"""
        buttons = []
        for label in labels:
            btn = QRadioButton(label, parent)
            buttons.append(btn)
        if buttons:
            buttons[0].setChecked(True)  # Default first option
        return buttons

    def create_scroll_area_with_widget(widget: QWidget) -> QScrollArea:
        """Create a scroll area containing a widget"""
        scroll = QScrollArea()
        scroll.setWidget(widget)
        scroll.setWidgetResizable(True)
        return scroll

    def create_slider_with_range(min_val: int, max_val: int,
                                orientation=None) -> QSlider:
        """Create a slider with specified range"""
        if orientation is None:
            orientation = Qt.Orientation.Horizontal
        slider = QSlider(orientation)
        slider.setMinimum(min_val)
        slider.setMaximum(max_val)
        return slider

    def create_splash_screen(pixmap_path: str, flags=None) -> QSplashScreen:
        """Create a splash screen with image"""
        if flags is None:
            flags = Qt.WindowType.WindowStaysOnTopHint
        pixmap = QPixmap(pixmap_path)
        splash = QSplashScreen(pixmap, flags)
        return splash

    def create_toolbar_with_actions(title: str, actions: list, parent=None) -> QToolBar:
        """Create a toolbar with actions"""
        toolbar = QToolBar(title, parent)
        for action in actions:
            if action is None:
                toolbar.addSeparator()
            else:
                toolbar.addAction(action)
        return toolbar

    def create_wizard_with_pages(title: str, pages: list) -> QWizard:
        """Create a wizard with pages"""
        wizard = QWizard()
        wizard.setWindowTitle(title)
        for page in pages:
            wizard.addPage(page)
        return wizard

    def create_wizard_page(title: str, subtitle: str = "") -> QWizardPage:
        """Create a wizard page"""
        page = QWizardPage()
        page.setTitle(title)
        if subtitle:
            page.setSubTitle(subtitle)
        return page

    def configure_abstract_item_view(view: QAbstractItemView,
                                   selection_mode=None):
        """Configure common settings for item views"""
        if selection_mode is None:
            selection_mode = QAbstractItemView.SelectionMode.SingleSelection
        view.setSelectionMode(selection_mode)
        view.setAlternatingRowColors(True)
        return view

    def configure_abstract_scroll_area(area: QAbstractScrollArea,
                                     h_policy=None,
                                     v_policy=None):
        """Configure scroll bar policies"""
        if h_policy is None:
            h_policy = Qt.ScrollBarPolicy.AsNeeded
        if v_policy is None:
            v_policy = Qt.ScrollBarPolicy.AsNeeded
        area.setHorizontalScrollBarPolicy(h_policy)
        area.setVerticalScrollBarPolicy(v_policy)
        return area

    def create_main_window_with_statusbar(title: str, status_text: str = "") -> tuple:
        """Create a main window with status bar"""
        window = QMainWindow()
        window.setWindowTitle(title)
        status_bar = QStatusBar()
        window.setStatusBar(status_bar)
        if status_text:
            status_bar.showMessage(status_text)
        return window, status_bar

    def create_text_browser_with_html(html: str) -> QTextBrowser:
        """Create a text browser with HTML content"""
        browser = QTextBrowser()
        browser.setHtml(html)
        browser.setOpenExternalLinks(True)
        return browser

    def create_standard_dialog_buttons(accept_text="OK", reject_text="Cancel",
                                     buttons=None) -> QDialogButtonBox:
        """Create standard dialog buttons"""
        if buttons is None:
            buttons = QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        button_box = QDialogButtonBox(buttons)
        if accept_text != "OK":
            button_box.button(QDialogButtonBox.StandardButton.Ok).setText(accept_text)
        if reject_text != "Cancel" and button_box.button(QDialogButtonBox.StandardButton.Cancel):
            button_box.button(QDialogButtonBox.StandardButton.Cancel).setText(reject_text)
        return button_box

    def create_spacer_item(width: int = 20, height: int = 20,
                          h_policy=None,
                          v_policy=None) -> QSpacerItem:
        """Create a spacer item for layouts"""
        if h_policy is None:
            h_policy = QSizePolicy.Policy.Minimum
        if v_policy is None:
            v_policy = QSizePolicy.Policy.Minimum
        return QSpacerItem(width, height, h_policy, v_policy)

    # Export all utility functions for easy access
    __all__ = [
        # PyQt6 availability flag
        "PYQT6_AVAILABLE",
        # Core classes
        "Qt", "QThread", "QTimer", "pyqtSignal",
        # Geometry classes
        "QPoint", "QRect", "QSize",
        # GUI classes
        "QColor", "QFont", "QFontMetrics", "QIcon", "QKeyEvent", "QKeySequence",
        "QMouseEvent", "QPainter", "QPaintEvent", "QPen", "QPixmap", "QResizeEvent",
        # Widget classes
        "QAbstractItemView", "QAbstractScrollArea", "QAction", "QApplication",
        "QButtonGroup", "QCheckBox", "QComboBox", "QDialog",
        "QDialogButtonBox", "QFileDialog", "QFormLayout", "QFrame", "QGridLayout",
        "QGroupBox", "QHBoxLayout", "QHeaderView", "QInputDialog", "QLabel",
        "QLineEdit", "QListWidget", "QListWidgetItem", "QMainWindow", "QMenu",
        "QMessageBox", "QPlainTextEdit", "QProgressBar", "QPushButton", "QRadioButton",
        "QScrollArea", "QSizePolicy", "QSlider", "QSpacerItem", "QSpinBox",
        "QSplashScreen", "QSplitter", "QStatusBar", "QTableWidget", "QTableWidgetItem",
        "QTabWidget", "QTextBrowser", "QTextEdit", "QToolBar", "QTreeWidget",
        "QTreeWidgetItem", "QVBoxLayout", "QWidget", "QWizard", "QWizardPage",
        # Utility functions
        "create_point", "create_rect", "create_size", "get_text_metrics",
        "create_icon_from_file", "create_pixmap", "create_pen", "handle_key_event",
        "handle_mouse_event", "handle_paint_event", "handle_resize_event",
        "create_standard_action", "create_button_group", "get_desktop_geometry",
        "create_frame_with_style", "prompt_for_input", "create_context_menu",
        "create_radio_button_set", "create_scroll_area_with_widget",
        "create_slider_with_range", "create_splash_screen", "create_toolbar_with_actions",
        "create_wizard_with_pages", "create_wizard_page", "configure_abstract_item_view",
        "configure_abstract_scroll_area", "create_main_window_with_statusbar",
        "create_text_browser_with_html", "create_standard_dialog_buttons",
        "create_spacer_item",
    ]

except ImportError as e:
    logger.error("Import error in common_imports: %s", e)
    PYQT6_AVAILABLE = False

    # Create dummy implementations when PyQt5 is not available
    def create_point(x, y):
        """Create a point object for UI positioning in exploit analysis tools."""
        class Point:
            def __init__(self, x, y):
                """Initialize point with x and y coordinates."""
                self.x = int(x)
                self.y = int(y)
            def __repr__(self):
                return f"Point({self.x}, {self.y})"
            def __iter__(self):
                return iter([self.x, self.y])
            def distance_to(self, other):
                import math
                return math.sqrt((self.x - other.x)**2 + (self.y - other.y)**2)
        return Point(x, y)

    def create_rect(x, y, w, h):
        """Create rectangle for exploit visualization bounds."""
        class Rect:
            def __init__(self, x, y, width, height):
                """Initialize rectangle with position and dimensions."""
                self.x = int(x)
                self.y = int(y)
                self.width = int(width)
                self.height = int(height)
            def contains(self, point):
                return (self.x <= point.x <= self.x + self.width and
                        self.y <= point.y <= self.y + self.height)
            def intersects(self, other):
                return not (self.x + self.width < other.x or other.x + other.width < self.x or
                           self.y + self.height < other.y or other.y + other.height < self.y)
            def center(self):
                return create_point(self.x + self.width // 2, self.y + self.height // 2)
        return Rect(x, y, w, h)

    def create_size(w, h):
        """Create size object for exploit analysis UI components."""
        class Size:
            def __init__(self, width, height):
                """Initialize size with width and height dimensions."""
                self.width = int(width)
                self.height = int(height)
            def area(self):
                return self.width * self.height
            def scale(self, factor):
                return Size(self.width * factor, self.height * factor)
            def __repr__(self):
                return f"Size({self.width}x{self.height})"
        return Size(w, h)

    def get_text_metrics(font, text):
        """Calculate text metrics for exploit data display."""
        # Estimate based on typical font sizes
        char_width = 8  # Average character width
        char_height = 16  # Average character height
        if font and hasattr(font, "pointSize"):
            char_height = font.pointSize() * 1.3
            char_width = char_height * 0.6

        width = len(text) * char_width
        height = char_height

        # Handle multiline text
        lines = text.split("\n")
        if len(lines) > 1:
            width = max(len(line) * char_width for line in lines)
            height = len(lines) * char_height * 1.2

        return {"width": int(width), "height": int(height), "ascent": int(height * 0.8)}

    def create_icon_from_file(path):
        """Create icon for exploit tool UI from file."""
        class Icon:
            def __init__(self, path):
                """Initialize icon from file path."""
                self.path = path
                self.icon_data = None
                self.size = (16, 16)  # Default icon size
            def isValid(self):
                return self.valid
            def actualSize(self):
                return create_size(*self.size)
        return Icon(path)

    def create_pixmap(w, h):
        """Create pixmap for exploit visualization rendering."""
        class Pixmap:
            def __init__(self, width, height):
                """Initialize pixmap with specified dimensions."""
                self.width = width
                self.height = height
                self.format = "RGBA"
                self.data = None
            def fill(self, color):
                r = (color >> 16) & 0xFF
                g = (color >> 8) & 0xFF
                b = color & 0xFF
                a = 255
                for i in range(0, len(self.data), 4):
                    self.data[i] = r
                    self.data[i+1] = g
                    self.data[i+2] = b
                    self.data[i+3] = a
            def size(self):
                return create_size(self.width, self.height)
        return Pixmap(w, h)

    def create_pen(color, width=1):
        """Create pen for exploit analysis drawing operations."""
        class Pen:
            def __init__(self, style=1, width=1, color=None):
                """Initialize pen with style, width, and color."""
                self.style = style
                self.width = width
                self.color = color or (0, 0, 0, 255)
                self.join_style = "miter"
                self.cap_style = "square"
            def setStyle(self, style):
                self.style = style
            def setCapStyle(self, cap):
                self.cap_style = cap
            def setJoinStyle(self, join):
                self.join_style = join
        return Pen(color, width)
    def handle_key_event(event):
        """Extract key information from a key event in fallback mode.

        Args:
            event: Key event object (unused in fallback)

        Returns:
            tuple: Default values (0, 0, '') representing key code, modifiers, and text

        """
        return (0, 0, "")
    def handle_mouse_event(event):
        """Extract mouse information from a mouse event in fallback mode.

        Args:
            event: Mouse event object (unused in fallback)

        Returns:
            tuple: Default values (0, 0, 0, 0) representing x, y, button, and buttons state

        """
        return (0, 0, 0, 0)
    def handle_paint_event(widget, event, func=None):
        """Handle paint events for UI components with exploit analysis visualization."""
        if not widget or not event:
            return

        try:
            # Get painter and widget dimensions
            painter = widget.getPainter() if hasattr(widget, "getPainter") else None
            if not painter:
                return

            rect = widget.geometry() if hasattr(widget, "geometry") else None
            if not rect:
                return

            width, height = rect.width(), rect.height()

            # Execute custom paint function if provided
            if func and callable(func):
                try:
                    func(painter, event, width, height)
                except Exception:
                    # Fallback to default painting
                    painter.fillRect(0, 0, width, height, 0x000000)
            else:
                # Default exploit analysis visualization
                # Dark background for security tool aesthetic
                painter.fillRect(0, 0, width, height, 0x1a1a1a)

                # Grid pattern for technical interface
                painter.setPen(0x333333, 1)
                grid_size = 20
                for x in range(0, width, grid_size):
                    painter.drawLine(x, 0, x, height)
                for y in range(0, height, grid_size):
                    painter.drawLine(0, y, width, y)

                # Status indicator in corner
                painter.setPen(0x00ff00, 2)
                painter.drawRect(width - 20, 5, 10, 10)

        except Exception:
            # Robust error handling for UI painting
            pass
    def handle_resize_event(event):
        """Extract size information from resize event in fallback mode.

        Args:
            event: Resize event object (unused in fallback)

        Returns:
            tuple: Default values (0, 0, 0, 0) for new width/height and old width/height

        """
        return (0, 0, 0, 0)
    def create_standard_action(text, parent=None, slot=None, shortcut=None):
        """Create standard action for exploit tool menus."""
        class Action:
            def __init__(self, icon=None, text="", parent=None):
                """Initialize action with optional icon, text, and parent."""
                self.icon = icon
                self.text = text
                self.parent = parent
                self.shortcut = None
                self.enabled = True
                self.visible = True
                self.checkable = False
                self.checked = False

            def setEnabled(self, enabled):
                self.enabled = bool(enabled)

            def setCheckable(self, checkable):
                self.checkable = bool(checkable)

            def setChecked(self, checked):
                self.checked = bool(checked)

            def setShortcut(self, shortcut):
                self.shortcut = shortcut

            def triggered(self):
                # Simulate signal
                class Signal:
                    def __init__(self, action):
                        self.action = action
                        self.callbacks = []
                    def connect(self, callback):
                        self.callbacks.append(callback)
                        self.action.triggered_callbacks.append(callback)
                return Signal(self)

            def setData(self, data):
                self.data = data

            def trigger(self):
                for callback in self.triggered_callbacks:
                    try:
                        callback()
                    except:
                        pass

        action = Action(text, parent)
        if shortcut:
            action.setShortcut(shortcut)
        if slot:
            action.triggered().connect(slot)
        return action

    def create_button_group(buttons, parent=None):
        """Create button group for exploit option selection."""
        class ButtonGroup:
            def __init__(self, parent=None):
                """Initialize button group with optional parent."""
                self.parent = parent
                self.buttons = []
                self.exclusive = True
                self.checked_button = None
                self.id_counter = 0

            def addButton(self, button, id=-1):
                if id == -1:
                    id = len(self.buttons)
                self.buttons.append((button, id))

                # Connect button to group
                if hasattr(button, "clicked"):
                    button.clicked.connect(lambda: self._button_clicked(id))

            def checkedId(self):
                return self.checked_id

            def setExclusive(self, exclusive):
                self.exclusive = bool(exclusive)

            def _button_clicked(self, id):
                if self.exclusive:
                    # Uncheck all other buttons
                    for btn, btn_id in self.buttons:
                        if btn_id != id and hasattr(btn, "setChecked"):
                            btn.setChecked(False)

                self.checked_id = id

                # Notify callbacks
                for callback in self.button_clicked_callbacks:
                    try:
                        callback(id)
                    except:
                        pass

            def buttonClicked(self):
                # Return signal-like object
                class Signal:
                    def __init__(self, group):
                        self.group = group
                    def connect(self, callback):
                        self.group.button_clicked_callbacks.append(callback)
                return Signal(self)

        group = ButtonGroup(parent)
        if buttons:
            for i, button in enumerate(buttons):
                group.addButton(button, i)
        return group
    def get_desktop_geometry():
        """Get desktop geometry in fallback mode.

        Returns:
            tuple: Default screen resolution (1920, 1080)

        """
        return (1920, 1080)
    def create_frame_with_style(style=None, shadow=None):
        """Create styled frame for exploit analysis UI."""
        class Frame:
            def __init__(self, parent=None, style=None):
                """Initialize frame with optional parent and style."""
                self.parent = parent
                self.style = style or "box"
                self.line_width = 1
                self.midline_width = 0
                self.shadow = "raised"

            def setFrameStyle(self, style):
                self.style = style

            def setFrameShadow(self, shadow):
                self.shadow = shadow

            def setLineWidth(self, width):
                self.line_width = int(width)

            def setMidLineWidth(self, width):
                self.mid_line_width = int(width)

            def setContentsMargins(self, left, top, right, bottom):
                self.margin = (left, top, right, bottom)

            def frameWidth(self):
                """Calculate total frame width from line widths.

                Returns:
                    int: Sum of line width and mid-line width

                """
                return self.line_width + self.mid_line_width

        return Frame()
    def prompt_for_input(parent, title, label, default=""):
        """Prompt for input in fallback mode (no actual dialog).

        Args:
            parent: Parent widget (unused)
            title: Dialog title (unused)
            label: Input label (unused)
            default: Default text value (unused)

        Returns:
            tuple: Empty string and False (no input provided)

        """
        return ("", False)
    def create_context_menu(actions, parent=None):
        """Create context menu for exploit tool interactions."""
        class ContextMenu:
            def __init__(self, parent=None):
                """Initialize context menu with optional parent."""
                self.parent = parent
                self.actions = []
                self.separators = []
                self.title = ""

            def addAction(self, action):
                self.actions.append(action)

            def addSeparator(self):
                self.actions.append(None)  # None represents separator

            def exec_(self, pos):
                self.position = pos
                self.visible = True
                # In a real implementation, this would show the menu
                # and return the selected action

            def popup(self, pos):
                self.exec_(pos)

            def clear(self):
                self.actions = []

        menu = ContextMenu(parent)
        if actions:
            for action in actions:
                menu.addAction(action)
        return menu
    def create_radio_button_set(labels, parent=None):
        """Create radio button set in fallback mode.

        Args:
            labels: List of button labels (unused)
            parent: Parent widget (unused)

        Returns:
            list: Empty list (no buttons created in fallback)

        """
        return []
    def create_scroll_area_with_widget(widget):
        """Create scrollable area for exploit data display."""
        class ScrollArea:
            def __init__(self, parent=None):
                """Initialize scroll area with optional parent."""
                self.parent = parent
                self.widget = None
                self.horizontal_scrollbar_policy = "as_needed"
                self.vertical_scrollbar_policy = "as_needed"

            def setWidget(self, widget):
                self.widget = widget

            def setHorizontalScrollBarPolicy(self, policy):
                self.h_scrollbar_policy = policy

            def setVerticalScrollBarPolicy(self, policy):
                self.v_scrollbar_policy = policy

            def setWidgetResizable(self, resizable):
                self.widget_resizable = bool(resizable)

            def ensureWidgetVisible(self, widget, x_margin=50, y_margin=50):
                # Scroll to make widget visible
                pass

        area = ScrollArea()
        if widget:
            area.setWidget(widget)
        return area

    def create_slider_with_range(min_val, max_val, orientation=None):
        """Create slider for exploit parameter adjustment."""
        class Slider:
            def __init__(self, orientation="horizontal", parent=None):
                """Initialize slider with orientation and optional parent."""
                self.orientation = orientation
                self.parent = parent
                self.minimum = 0
                self.maximum = 100
                self.value = 0
                self.single_step = 1
                self.page_step = 10

            def setMinimum(self, val):
                self.minimum = int(val)

            def setMaximum(self, val):
                self.maximum = int(val)

            def setValue(self, val):
                old_value = self.value
                self.value = max(self.minimum, min(self.maximum, int(val)))
                if self.value != old_value:
                    for callback in self.value_changed_callbacks:
                        try:
                            callback(self.value)
                        except:
                            pass

            def setTickPosition(self, pos):
                self.tick_position = pos

            def setTickInterval(self, interval):
                self.tick_interval = int(interval)

            def valueChanged(self):
                class Signal:
                    def __init__(self, slider):
                        self.slider = slider
                    def connect(self, callback):
                        self.slider.value_changed_callbacks.append(callback)
                return Signal(self)

        slider = Slider(orientation or "horizontal")
        slider.setMinimum(min_val)
        slider.setMaximum(max_val)
        return slider

    def create_splash_screen(pixmap_path, flags=None):
        """Create splash screen for exploit tool startup."""
        class SplashScreen:
            def __init__(self, pixmap=None, flags=None):
                """Initialize splash screen with optional pixmap and flags."""
                self.pixmap = pixmap
                self.flags = flags
                self.message = ""
                self.alignment = "center"

            def show(self):
                self.visible = True

            def showMessage(self, message, alignment=None, color=None):
                self.message = message

            def finish(self, widget):
                self.visible = False

            def close(self):
                self.visible = False

        return SplashScreen(pixmap_path, flags)

    def create_toolbar_with_actions(title, actions, parent=None):
        """Create toolbar for exploit tool actions."""
        class ToolBar:
            def __init__(self, title="", parent=None):
                """Initialize toolbar with optional title and parent."""
                self.title = title
                self.parent = parent
                self.actions = []
                self.orientation = "horizontal"
                self.icon_size = (24, 24)
                self.movable = True

            def addAction(self, action):
                self.actions.append(action)

            def addSeparator(self):
                self.actions.append(None)

            def setOrientation(self, orientation):
                self.orientation = orientation

            def setMovable(self, movable):
                self.movable = bool(movable)

            def setIconSize(self, size):
                self.icon_size = size

            def clear(self):
                self.actions = []

        toolbar = ToolBar(title, parent)
        if actions:
            for action in actions:
                toolbar.addAction(action)
        return toolbar

    def create_wizard_with_pages(title, pages):
        """Create wizard for exploit configuration."""
        class Wizard:
            def __init__(self, parent=None, flags=None):
                """Initialize wizard with optional parent and flags."""
                self.parent = parent
                self.flags = flags
                self.pages = []
                self.current_page = 0

            def addPage(self, page):
                self.pages.append(page)

            def currentPage(self):
                if 0 <= self.current_page < len(self.pages):
                    return self.pages[self.current_page]
                return None

            def next(self):
                if self.current_page < len(self.pages) - 1:
                    self.current_page += 1

            def back(self):
                if self.current_page > 0:
                    self.current_page -= 1

            def accept(self):
                for callback in self.finished_callbacks:
                    try:
                        callback()
                    except:
                        pass

            def finished(self):
                class Signal:
                    def __init__(self, wizard):
                        self.wizard = wizard
                    def connect(self, callback):
                        self.wizard.finished_callbacks.append(callback)
                return Signal(self)

        wizard = Wizard(title)
        if pages:
            for page in pages:
                wizard.addPage(page)
        return wizard

    def create_wizard_page(title, subtitle=""):
        """Create wizard page for exploit setup steps."""
        class WizardPage:
            def __init__(self, parent=None):
                """Initialize wizard page with optional parent."""
                self.parent = parent
                self.title = ""
                self.subtitle = ""
                self.layout = None
                self.widgets = []

            def setTitle(self, title):
                self.title = title

            def setSubTitle(self, subtitle):
                self.subtitle = subtitle

            def isComplete(self):
                return self.complete

            def setComplete(self, complete):
                self.complete = bool(complete)

            def setCommitPage(self, commit):
                self.commit_page = bool(commit)

            def setFinalPage(self, final):
                self.final_page = bool(final)

        return WizardPage(title, subtitle)
    def configure_abstract_item_view(view, selection_mode=None):
        """Configure item view in fallback mode.

        Args:
            view: View to configure (returned unchanged)
            selection_mode: Selection mode (unused)

        Returns:
            The same view object passed in

        """
        return view

    def configure_abstract_scroll_area(area, h_policy=None, v_policy=None):
        """Configure scroll area in fallback mode.

        Args:
            area: Scroll area to configure (returned unchanged)
            h_policy: Horizontal scrollbar policy (unused)
            v_policy: Vertical scrollbar policy (unused)

        Returns:
            The same scroll area object passed in

        """
        return area
    # Create dummy classes for missing imports
    class MockQtClass:
        """Mock class to stand in for PyQt5 classes when PyQt5 is not available.

        Provides a no-op implementation that allows the code to run without
        PyQt5 installed, returning itself for any attribute access or calls.
        """

        def __init__(self, *args, **kwargs):
            """Initialize mock Qt class with any arguments."""
        def __call__(self, *args, **kwargs):
            return self
        def __getattr__(self, name):
            return MockQtClass()

    # Core classes
    Qt = MockQtClass()
    QThread = MockQtClass
    QTimer = MockQtClass
    QPoint = MockQtClass
    QRect = MockQtClass
    QSize = MockQtClass

    # GUI classes
    QColor = MockQtClass
    QFont = MockQtClass
    QFontMetrics = MockQtClass
    QIcon = MockQtClass
    QKeyEvent = MockQtClass
    QKeySequence = MockQtClass
    QMouseEvent = MockQtClass
    QPainter = MockQtClass
    QPaintEvent = MockQtClass
    QPen = MockQtClass
    QPixmap = MockQtClass
    QResizeEvent = MockQtClass

    # Widget classes
    QAbstractItemView = MockQtClass
    QAbstractScrollArea = MockQtClass
    QAction = MockQtClass
    QApplication = MockQtClass
    QButtonGroup = MockQtClass
    QCheckBox = MockQtClass
    QComboBox = MockQtClass
    QDialog = MockQtClass
    QDialogButtonBox = MockQtClass
    QFileDialog = MockQtClass
    QFormLayout = MockQtClass
    QFrame = MockQtClass
    QGridLayout = MockQtClass
    QGroupBox = MockQtClass
    QHBoxLayout = MockQtClass
    QHeaderView = MockQtClass
    QInputDialog = MockQtClass
    QLabel = MockQtClass
    QLineEdit = MockQtClass
    QListWidget = MockQtClass
    QListWidgetItem = MockQtClass
    QMainWindow = MockQtClass
    QMenu = MockQtClass
    QMessageBox = MockQtClass
    QPlainTextEdit = MockQtClass
    QProgressBar = MockQtClass
    QPushButton = MockQtClass
    QRadioButton = MockQtClass
    QScrollArea = MockQtClass
    QSizePolicy = MockQtClass
    QSlider = MockQtClass
    QSpacerItem = MockQtClass
    QSpinBox = MockQtClass
    QSplashScreen = MockQtClass
    QSplitter = MockQtClass
    QStatusBar = MockQtClass
    QTableWidget = MockQtClass
    QTableWidgetItem = MockQtClass
    QTabWidget = MockQtClass
    QTextBrowser = MockQtClass
    QTextEdit = MockQtClass
    QToolBar = MockQtClass
    QTreeWidget = MockQtClass
    QTreeWidgetItem = MockQtClass
    QVBoxLayout = MockQtClass
    QWidget = MockQtClass
    QWizard = MockQtClass
    QWizardPage = MockQtClass

    def pyqtSignal(*args, **kwargs):  # pylint: disable=unused-argument
        """Mock implementation of PyQt5's pyqtSignal when PyQt5 is not available.

        Args:
            *args: Signal type arguments (ignored)
            **kwargs: Signal keyword arguments (ignored)

        Returns:
            lambda: A no-op function that can be used as a signal attribute

        """
        return lambda: None

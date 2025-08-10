"""Theme Manager for Intellicrack UI
Handles dynamic theme switching and stylesheet application

Copyright (C) 2025 Zachary Flint

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

import os

from intellicrack.handlers.pyqt6_handler import QApplication, QSettings


class ThemeManager:
    """Manages application themes and dynamic stylesheet switching"""

    def __init__(self):
        """Initialize theme manager with default themes and UI styling options."""
        self.themes = {
            "dark": "dark_theme.qss",
            "light": "light_theme.qss",
        }

        # Directory for theme files
        self.styles_dir = os.path.join(os.path.dirname(__file__), "styles")

        # Settings for persistence
        self.settings = QSettings("Intellicrack", "ThemeManager")

        # Initialize with saved or default theme
        self.current_theme = self.load_theme_preference()

        # Apply the initial theme
        self._apply_theme()

    def get_current_theme(self):
        """Get the currently active theme name"""
        return self.current_theme

    def load_theme_preference(self):
        """Load theme preference from QSettings, default to light"""
        return self.settings.value("theme", "light", type=str)

    def save_theme_preference(self):
        """Save current theme preference to QSettings"""
        self.settings.setValue("theme", self.current_theme)

    def set_theme(self, theme_name):
        """Set the application theme

        Args:
            theme_name: Name of the theme ("dark" or "light")

        """
        if theme_name not in self.themes:
            print(f"Warning: Unknown theme '{theme_name}', using light theme")
            theme_name = "light"

        self.current_theme = theme_name
        self.save_theme_preference()
        self._apply_theme()

    def _apply_theme(self):
        """Apply the current theme's stylesheet to the application"""
        try:
            # Get the stylesheet content
            stylesheet_content = self._get_theme_stylesheet()

            # Apply to the QApplication instance
            app = QApplication.instance()
            if app:
                app.setStyleSheet(stylesheet_content)
                print(f"Applied {self.current_theme} theme successfully")
            else:
                print("Warning: No QApplication instance found")

        except Exception as e:
            print(f"Error applying theme: {e}")
            # Fallback to built-in dark theme
            self._apply_builtin_dark_theme()

    def _get_theme_stylesheet(self):
        """Load theme stylesheet from file or return built-in stylesheet"""
        theme_file = self.themes[self.current_theme]
        theme_path = os.path.join(self.styles_dir, theme_file)

        # Try to load from file first
        if os.path.exists(theme_path):
            try:
                with open(theme_path, encoding="utf-8") as f:
                    return f.read()
            except Exception as e:
                print(f"Error loading theme file {theme_path}: {e}")

        # Fallback to built-in themes
        return self._get_builtin_theme_stylesheet()

    def _get_builtin_theme_stylesheet(self):
        """Get built-in theme stylesheet when external files are not available"""
        if self.current_theme == "dark":
            return self._get_builtin_dark_stylesheet()
        return self._get_builtin_light_stylesheet()

    def _get_builtin_dark_stylesheet(self):
        """Built-in dark theme stylesheet with proper contrast"""
        return """
/* Intellicrack Dark Theme */
QMainWindow {
    background-color: #1E1E1E;
    color: #FFFFFF;
}

/* Tab Styling - Dark Mode with High Contrast */
QTabWidget::pane {
    background-color: #2B2B2B;
    border: 1px solid #4A4A4A;
    border-radius: 4px;
}

QTabWidget::tab-bar {
    alignment: center;
}

QTabBar::tab {
    background-color: #3C3C3C;
    color: #E0E0E0;
    border: 1px solid #4A4A4A;
    border-bottom-color: #2B2B2B;
    border-top-left-radius: 6px;
    border-top-right-radius: 6px;
    padding: 12px 20px;
    margin-right: 2px;
    margin-bottom: 0px;
    font-weight: bold;
    font-size: 13px;
}

QTabBar::tab:selected {
    background-color: #2B2B2B;
    color: #FFFFFF;
    border-bottom-color: #2B2B2B;
    border-top: 2px solid #0078D4;
    font-weight: bold;
}

QTabBar::tab:hover:!selected {
    background-color: #4A4A4A;
    color: #FFFFFF;
}

/* Button Styling */
QPushButton {
    background-color: #3C3C3C;
    border: 1px solid #4A4A4A;
    color: #FFFFFF;
    padding: 6px 12px;
    border-radius: 4px;
    font-weight: bold;
}

QPushButton:hover {
    background-color: #4A4A4A;
    border-color: #5A5A5A;
}

QPushButton:pressed {
    background-color: #2B2B2B;
}

QPushButton:disabled {
    background-color: #2A2A2A;
    color: #808080;
    border-color: #3A3A3A;
}

/* Input Field Styling */
QLineEdit, QTextEdit, QPlainTextEdit {
    background-color: #2B2B2B;
    border: 1px solid #4A4A4A;
    color: #FFFFFF;
    padding: 6px;
    border-radius: 4px;
    selection-background-color: #0078D4;
}

QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus {
    border-color: #0078D4;
    background-color: #323232;
}

/* ComboBox Styling */
QComboBox {
    background-color: #3C3C3C;
    border: 1px solid #4A4A4A;
    color: #FFFFFF;
    padding: 6px;
    border-radius: 4px;
}

QComboBox:hover {
    border-color: #5A5A5A;
}

QComboBox::drop-down {
    subcontrol-origin: padding;
    subcontrol-position: top right;
    width: 20px;
    border-left: 1px solid #4A4A4A;
}

QComboBox::down-arrow {
    image: none;
    border-left: 4px solid transparent;
    border-right: 4px solid transparent;
    border-top: 4px solid #FFFFFF;
}

QComboBox QAbstractItemView {
    background-color: #2B2B2B;
    border: 1px solid #4A4A4A;
    color: #FFFFFF;
    selection-background-color: #0078D4;
}

/* CheckBox and RadioButton */
QCheckBox, QRadioButton {
    color: #FFFFFF;
    spacing: 8px;
}

QCheckBox::indicator, QRadioButton::indicator {
    width: 16px;
    height: 16px;
    background-color: #2B2B2B;
    border: 1px solid #4A4A4A;
    border-radius: 3px;
}

QCheckBox::indicator:checked {
    background-color: #0078D4;
    border-color: #0078D4;
}

QRadioButton::indicator {
    border-radius: 8px;
}

QRadioButton::indicator:checked {
    background-color: #0078D4;
    border-color: #0078D4;
}

/* SpinBox Styling */
QSpinBox, QDoubleSpinBox {
    background-color: #2B2B2B;
    border: 1px solid #4A4A4A;
    color: #FFFFFF;
    padding: 6px;
    border-radius: 4px;
}

/* Slider Styling */
QSlider::groove:horizontal {
    background-color: #4A4A4A;
    height: 6px;
    border-radius: 3px;
}

QSlider::handle:horizontal {
    background-color: #0078D4;
    width: 16px;
    height: 16px;
    border-radius: 8px;
    margin: -5px 0;
}

QSlider::sub-page:horizontal {
    background-color: #0078D4;
    border-radius: 3px;
}

/* Progress Bar */
QProgressBar {
    background-color: #2B2B2B;
    border: 1px solid #4A4A4A;
    border-radius: 4px;
    text-align: center;
    color: #FFFFFF;
}

QProgressBar::chunk {
    background-color: #0078D4;
    border-radius: 3px;
}

/* List and Tree Widgets */
QListWidget, QTreeWidget, QTableWidget {
    background-color: #2B2B2B;
    border: 1px solid #4A4A4A;
    color: #FFFFFF;
    alternate-background-color: #323232;
    selection-background-color: #0078D4;
    border-radius: 4px;
}

QListWidget::item, QTreeWidget::item, QTableWidget::item {
    padding: 4px;
    border-bottom: 1px solid #3A3A3A;
}

QListWidget::item:selected, QTreeWidget::item:selected, QTableWidget::item:selected {
    background-color: #0078D4;
    color: #FFFFFF;
}

QListWidget::item:hover, QTreeWidget::item:hover, QTableWidget::item:hover {
    background-color: #4A4A4A;
}

/* Headers */
QHeaderView::section {
    background-color: #3C3C3C;
    color: #FFFFFF;
    padding: 6px;
    border: 1px solid #4A4A4A;
    font-weight: bold;
}

QHeaderView::section:hover {
    background-color: #4A4A4A;
}

/* Group Box */
QGroupBox {
    color: #FFFFFF;
    border: 1px solid #4A4A4A;
    border-radius: 6px;
    margin-top: 8px;
    font-weight: bold;
}

QGroupBox::title {
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 8px 0 8px;
    background-color: #1E1E1E;
}

/* Labels */
QLabel {
    color: #FFFFFF;
    background-color: transparent;
}

/* Splitter */
QSplitter::handle {
    background-color: #4A4A4A;
    border: 1px solid #5A5A5A;
}

QSplitter::handle:hover {
    background-color: #5A5A5A;
}

/* Scrollbars */
QScrollBar:vertical {
    background-color: #2B2B2B;
    width: 12px;
    border-radius: 6px;
}

QScrollBar::handle:vertical {
    background-color: #4A4A4A;
    border-radius: 6px;
    min-height: 20px;
}

QScrollBar::handle:vertical:hover {
    background-color: #5A5A5A;
}

QScrollBar:horizontal {
    background-color: #2B2B2B;
    height: 12px;
    border-radius: 6px;
}

QScrollBar::handle:horizontal {
    background-color: #4A4A4A;
    border-radius: 6px;
    min-width: 20px;
}

QScrollBar::handle:horizontal:hover {
    background-color: #5A5A5A;
}

/* Toolbar */
QToolBar {
    background-color: #3C3C3C;
    border: 1px solid #4A4A4A;
    spacing: 2px;
    padding: 4px;
}

QToolBar::separator {
    background-color: #4A4A4A;
    width: 1px;
    margin: 0 4px;
}

/* Menu */
QMenuBar {
    background-color: #3C3C3C;
    color: #FFFFFF;
    border-bottom: 1px solid #4A4A4A;
}

QMenuBar::item {
    background-color: transparent;
    padding: 6px 8px;
}

QMenuBar::item:selected {
    background-color: #4A4A4A;
}

QMenu {
    background-color: #2B2B2B;
    border: 1px solid #4A4A4A;
    color: #FFFFFF;
}

QMenu::item {
    padding: 6px 20px;
}

QMenu::item:selected {
    background-color: #0078D4;
}

/* Status Bar */
QStatusBar {
    background-color: #3C3C3C;
    color: #FFFFFF;
    border-top: 1px solid #4A4A4A;
}
"""

    def _get_builtin_light_stylesheet(self):
        """Built-in light theme stylesheet"""
        return """
/* Intellicrack Light Theme */
QMainWindow {
    background-color: #FFFFFF;
    color: #000000;
}

/* Tab Styling - Light Mode */
QTabWidget::pane {
    background-color: #FFFFFF;
    border: 1px solid #AAAAAA;
    border-radius: 4px;
}

QTabWidget::tab-bar {
    alignment: center;
}

QTabBar::tab {
    background-color: #DEDEDE;
    color: #1A1A1A;
    border: 1px solid #AAAAAA;
    border-bottom-color: #F5F5F5;
    border-top-left-radius: 6px;
    border-top-right-radius: 6px;
    padding: 12px 20px;
    margin-right: 2px;
    margin-bottom: 0px;
    font-weight: bold;
    font-size: 13px;
}

QTabBar::tab:selected {
    background-color: #FFFFFF;
    color: #000000;
    border-bottom-color: #FFFFFF;
    border-top: 3px solid #0078D4;
    font-weight: bold;
}

QTabBar::tab:hover:!selected {
    background-color: #E8E8E8;
    color: #000000;
}

/* Button Styling */
QPushButton {
    background-color: #E8E8E8;
    border: 1px solid #999999;
    color: #000000;
    padding: 6px 12px;
    border-radius: 4px;
    font-weight: bold;
}

QPushButton:hover {
    background-color: #D8D8D8;
    border-color: #777777;
}

QPushButton:pressed {
    background-color: #C8C8C8;
}

QPushButton:disabled {
    background-color: #F5F5F5;
    color: #808080;
    border-color: #D0D0D0;
}

/* Input Field Styling */
QLineEdit, QTextEdit, QPlainTextEdit {
    background-color: #FFFFFF;
    border: 1px solid #C0C0C0;
    color: #000000;
    padding: 6px;
    border-radius: 4px;
    selection-background-color: #0078D4;
}

QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus {
    border-color: #0078D4;
    background-color: #FAFAFA;
}

/* ComboBox Styling */
QComboBox {
    background-color: #F0F0F0;
    border: 1px solid #C0C0C0;
    color: #000000;
    padding: 6px;
    border-radius: 4px;
}

QComboBox:hover {
    border-color: #A0A0A0;
}

QComboBox::drop-down {
    subcontrol-origin: padding;
    subcontrol-position: top right;
    width: 20px;
    border-left: 1px solid #C0C0C0;
}

QComboBox::down-arrow {
    image: none;
    border-left: 4px solid transparent;
    border-right: 4px solid transparent;
    border-top: 4px solid #000000;
}

QComboBox QAbstractItemView {
    background-color: #FFFFFF;
    border: 1px solid #C0C0C0;
    color: #000000;
    selection-background-color: #0078D4;
}

/* CheckBox and RadioButton */
QCheckBox, QRadioButton {
    color: #000000;
    spacing: 8px;
}

QCheckBox::indicator, QRadioButton::indicator {
    width: 16px;
    height: 16px;
    background-color: #FFFFFF;
    border: 1px solid #C0C0C0;
    border-radius: 3px;
}

QCheckBox::indicator:checked {
    background-color: #0078D4;
    border-color: #0078D4;
}

QRadioButton::indicator {
    border-radius: 8px;
}

QRadioButton::indicator:checked {
    background-color: #0078D4;
    border-color: #0078D4;
}

/* SpinBox Styling */
QSpinBox, QDoubleSpinBox {
    background-color: #FFFFFF;
    border: 1px solid #C0C0C0;
    color: #000000;
    padding: 6px;
    border-radius: 4px;
}

/* Slider Styling */
QSlider::groove:horizontal {
    background-color: #C0C0C0;
    height: 6px;
    border-radius: 3px;
}

QSlider::handle:horizontal {
    background-color: #0078D4;
    width: 16px;
    height: 16px;
    border-radius: 8px;
    margin: -5px 0;
}

QSlider::sub-page:horizontal {
    background-color: #0078D4;
    border-radius: 3px;
}

/* Progress Bar */
QProgressBar {
    background-color: #F5F5F5;
    border: 1px solid #C0C0C0;
    border-radius: 4px;
    text-align: center;
    color: #000000;
}

QProgressBar::chunk {
    background-color: #0078D4;
    border-radius: 3px;
}

/* List and Tree Widgets */
QListWidget, QTreeWidget, QTableWidget {
    background-color: #FFFFFF;
    border: 1px solid #C0C0C0;
    color: #000000;
    alternate-background-color: #F5F5F5;
    selection-background-color: #0078D4;
    border-radius: 4px;
}

QListWidget::item, QTreeWidget::item, QTableWidget::item {
    padding: 4px;
    border-bottom: 1px solid #E0E0E0;
}

QListWidget::item:selected, QTreeWidget::item:selected, QTableWidget::item:selected {
    background-color: #0078D4;
    color: #FFFFFF;
}

QListWidget::item:hover, QTreeWidget::item:hover, QTableWidget::item:hover {
    background-color: #E5E5E5;
}

/* Headers */
QHeaderView::section {
    background-color: #F0F0F0;
    color: #000000;
    padding: 6px;
    border: 1px solid #C0C0C0;
    font-weight: bold;
}

QHeaderView::section:hover {
    background-color: #E5E5E5;
}

/* Group Box */
QGroupBox {
    color: #000000;
    border: 1px solid #C0C0C0;
    border-radius: 6px;
    margin-top: 8px;
    font-weight: bold;
}

QGroupBox::title {
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 8px 0 8px;
    background-color: #FFFFFF;
}

/* Labels */
QLabel {
    color: #1A1A1A;
    background-color: transparent;
}

/* Splitter */
QSplitter::handle {
    background-color: #C0C0C0;
    border: 1px solid #A0A0A0;
}

QSplitter::handle:hover {
    background-color: #A0A0A0;
}

/* Scrollbars */
QScrollBar:vertical {
    background-color: #F5F5F5;
    width: 12px;
    border-radius: 6px;
}

QScrollBar::handle:vertical {
    background-color: #C0C0C0;
    border-radius: 6px;
    min-height: 20px;
}

QScrollBar::handle:vertical:hover {
    background-color: #A0A0A0;
}

QScrollBar:horizontal {
    background-color: #F5F5F5;
    height: 12px;
    border-radius: 6px;
}

QScrollBar::handle:horizontal {
    background-color: #C0C0C0;
    border-radius: 6px;
    min-width: 20px;
}

QScrollBar::handle:horizontal:hover {
    background-color: #A0A0A0;
}

/* Toolbar */
QToolBar {
    background-color: #F0F0F0;
    border: 1px solid #C0C0C0;
    spacing: 2px;
    padding: 4px;
}

QToolBar::separator {
    background-color: #C0C0C0;
    width: 1px;
    margin: 0 4px;
}

/* Menu */
QMenuBar {
    background-color: #F0F0F0;
    color: #000000;
    border-bottom: 1px solid #C0C0C0;
}

QMenuBar::item {
    background-color: transparent;
    padding: 6px 8px;
}

QMenuBar::item:selected {
    background-color: #E5E5E5;
}

QMenu {
    background-color: #FFFFFF;
    border: 1px solid #C0C0C0;
    color: #000000;
}

QMenu::item {
    padding: 6px 20px;
}

QMenu::item:selected {
    background-color: #0078D4;
    color: #FFFFFF;
}

/* Status Bar */
QStatusBar {
    background-color: #F0F0F0;
    color: #000000;
    border-top: 1px solid #C0C0C0;
}
"""

    def _apply_builtin_dark_theme(self):
        """Apply built-in dark theme as fallback"""
        try:
            app = QApplication.instance()
            if app:
                app.setStyleSheet(self._get_builtin_dark_stylesheet())
                print("Applied built-in dark theme as fallback")
        except Exception as e:
            print(f"Error applying fallback theme: {e}")


# Global theme manager instance (lazy initialization)
_theme_manager = None


def get_theme_manager():
    """Get the global theme manager instance (lazy initialization)"""
    global _theme_manager
    if _theme_manager is None:
        _theme_manager = ThemeManager()
    return _theme_manager


def apply_theme(theme_name):
    """Convenience function to apply a theme"""
    get_theme_manager().set_theme(theme_name)


def get_current_theme():
    """Convenience function to get current theme"""
    return get_theme_manager().get_current_theme()

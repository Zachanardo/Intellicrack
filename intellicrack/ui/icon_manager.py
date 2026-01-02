"""Icon Manager for Intellicrack.

Provides centralized icon management for consistent UI appearance.
Uses Material Design Icons as the primary icon set.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import os
from pathlib import Path
from typing import Any, ClassVar

from intellicrack.handlers.pyqt6_handler import QIcon


class IconManager:
    """Manages icons for the application with fallback support.

    Provides centralized icon management with caching and text fallback support
    for UI elements. Maps icon names to Unicode characters as fallbacks when
    icon files are not available.
    """

    # Icon paths mapping - using Unicode characters as fallback
    ICON_MAP: ClassVar[dict[str, str]] = {
        # File operations
        "file_open": "📂",
        "file_save": "💾",
        "file_save_as": "💾",
        "file_new": "📄",
        "file_close": "✖️",
        "file_export": "📤",
        "file_import": "📥",
        # Edit operations
        "edit_copy": "📋",
        "edit_paste": "📋",
        "edit_cut": "✂️",
        "edit_undo": "↩️",
        "edit_redo": "↪️",
        "edit_delete": "🗑️",
        "edit_search": "🔍",
        "edit_replace": "🔄",
        # Navigation
        "nav_back": "⬅️",
        "nav_forward": "➡️",
        "nav_up": "⬆️",
        "nav_down": "⬇️",
        "nav_home": "🏠",
        "nav_refresh": "🔄",
        # Actions
        "action_run": "▶️",
        "action_stop": "⏹️",
        "action_pause": "⏸️",
        "action_restart": "🔄",
        "action_generate": "⚡",
        "action_analyze": "🔬",
        "action_debug": "🐛",
        "action_test": "🧪",
        "action_build": "🔨",
        "action_deploy": "🚀",
        # Status
        "status_success": "✅",
        "status_error": "❌",
        "status_warning": "⚠️",
        "status_info": "🛈",
        "status_question": "❓",
        "status_loading": "⏳",
        "status_ready": "✅",
        "status_idle": "⏸️",
        # Tools
        "tool_settings": "⚙️",
        "tool_preferences": "🔧",
        "tool_plugin": "🔌",
        "tool_terminal": "💻",
        "tool_console": "📟",
        "tool_log": "📋",
        "tool_monitor": "📊",
        "tool_network": "🌐",
        # Security
        "security_lock": "🔒",
        "security_unlock": "🔓",
        "security_key": "🔑",
        "security_shield": "🛡️",
        "security_warning": "⚠️",
        "security_scan": "🔍",
        # AI/ML
        "ai_brain": "🧠",
        "ai_robot": "🤖",
        "ai_generate": "✨",
        "ai_analyze": "🔬",
        "ai_model": "🧮",
        # Binary Analysis
        "binary_exe": "🔷",
        "binary_dll": "📦",
        "binary_patch": "🩹",
        "binary_hex": "🔢",
        "binary_disasm": "📜",
        "binary_memory": "💽",
        # Database
        "db_connect": "🔗",
        "db_disconnect": "🔗",
        "db_query": "📝",
        "db_table": "📋",
        # Help
        "help_about": "i",
        "help_documentation": "📚",
        "help_tutorial": "📖",
        "help_support": "🆘",
    }

    def __init__(self, icon_path: Path | None = None) -> None:
        """Initialize the icon manager.

        Args:
            icon_path: Optional path to icon resources directory

        """
        self.icon_path: Path = icon_path or Path(__file__).parent.parent / "assets" / "icons"
        self._icon_cache: dict[str, QIcon] = {}

    def get_icon(self, icon_name: str, *, fallback: bool = True) -> QIcon:
        """Get an icon by name with fallback support.

        Args:
            icon_name: Name of the icon to retrieve
            fallback: Whether to use text fallback if icon file not found

        Returns:
            QIcon instance

        """
        # Check cache first
        if icon_name in self._icon_cache:
            return self._icon_cache[icon_name]

        # Try to load from file
        icon: QIcon = self._load_icon_from_file(icon_name)

        # Use fallback if needed
        if icon.isNull() and fallback:
            icon = self._create_text_icon(icon_name)

        # Cache the result
        self._icon_cache[icon_name] = icon
        return icon

    def _load_icon_from_file(self, icon_name: str) -> QIcon:
        """Try to load an icon from file.

        Args:
            icon_name: Name of the icon

        Returns:
            QIcon instance (may be null if not found)

        """
        # Try various extensions
        for ext in [".png", ".svg", ".ico"]:
            icon_file: Path = self.icon_path / f"{icon_name}{ext}"
            if icon_file.exists():
                return QIcon(str(icon_file))

        return QIcon()

    def _create_text_icon(self, icon_name: str, size: int = 32) -> QIcon:
        """Create a text-based fallback icon.

        Renders the icon text/emoji onto a QPixmap and converts it to a QIcon.

        Args:
            icon_name: Name of the icon to create.
            size: Size of the icon in pixels (default 32).

        Returns:
            QIcon with text or emoji representation rendered as an image.

        """
        from PyQt6.QtCore import Qt
        from PyQt6.QtGui import QColor, QFont, QPainter, QPixmap

        text: str = self.ICON_MAP.get(icon_name, "?")

        pixmap = QPixmap(size, size)
        pixmap.fill(QColor(0, 0, 0, 0))

        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setRenderHint(QPainter.RenderHint.TextAntialiasing)

        font = QFont()
        font.setPointSize(int(size * 0.6))
        painter.setFont(font)

        painter.setPen(QColor(0, 0, 0))

        painter.drawText(
            pixmap.rect(),
            Qt.AlignmentFlag.AlignCenter,
            text,
        )

        painter.end()

        return QIcon(pixmap)

    def get_icon_text(self, icon_name: str) -> str:
        """Get the text/emoji representation of an icon.

        Args:
            icon_name: Name of the icon

        Returns:
            Text or emoji string

        """
        return self.ICON_MAP.get(icon_name, "")

    def register_icon(self, icon_name: str, icon_path: str) -> None:
        """Register a custom icon.

        Args:
            icon_name: Name to register the icon under
            icon_path: Path to the icon file

        """
        if os.path.exists(icon_path):
            icon: QIcon = QIcon(icon_path)
            self._icon_cache[icon_name] = icon

    def clear_cache(self) -> None:
        """Clear the icon cache."""
        self._icon_cache.clear()


class _IconManagerHolder:
    """Singleton holder for IconManager instance."""

    instance: IconManager | None = None


def get_icon_manager() -> IconManager:
    """Get the singleton icon manager instance.

    Returns:
        IconManager instance

    """
    if _IconManagerHolder.instance is None:
        _IconManagerHolder.instance = IconManager()
    return _IconManagerHolder.instance


def get_icon(icon_name: str) -> QIcon:
    """Get an icon.

    Args:
        icon_name: Name of the icon

    Returns:
        QIcon instance

    """
    return get_icon_manager().get_icon(icon_name)


def get_icon_text(icon_name: str) -> str:
    """Get icon text/emoji.

    Args:
        icon_name: Name of the icon

    Returns:
        Text or emoji string

    """
    return get_icon_manager().get_icon_text(icon_name)


def set_button_icon(
    button: Any,
    icon_name: str,
    *,
    add_text_prefix: bool = True,
) -> None:
    """Set an icon on a button with optional text prefix.

    Args:
        button: QPushButton instance
        icon_name: Name of the icon
        add_text_prefix: Whether to add emoji as text prefix if icon not found

    """
    manager: IconManager = get_icon_manager()
    icon: QIcon = manager.get_icon(icon_name)

    if not icon.isNull() and hasattr(button, "setIcon"):
        button.setIcon(icon)
    elif add_text_prefix:
        if emoji := manager.get_icon_text(icon_name):
            current_text: str = getattr(button, "text", lambda: "")()
            if not current_text.startswith(emoji) and hasattr(button, "setText"):
                button.setText(f"{emoji} {current_text}")

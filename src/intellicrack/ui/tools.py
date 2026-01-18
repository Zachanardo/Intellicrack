"""Tool output panel widget for the Intellicrack UI.

This module provides the tool output display panel showing
decompiled code, disassembly, and analysis results from tools.
"""

from __future__ import annotations

from typing import Literal

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont, QTextCursor
from PyQt6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QSplitter,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from .highlighter import (
    get_highlighter_for_language,
)


OutputType = Literal["decompiled", "disassembly", "strings", "xrefs", "log"]


class CodeDisplay(QPlainTextEdit):
    """Code display widget with syntax highlighting.

    Provides a read-only text area for displaying code with
    appropriate syntax highlighting based on language.
    """

    def __init__(
        self,
        language: str = "c",
        parent: QWidget | None = None,
    ) -> None:
        """Initialize the code display.

        Args:
            language: Programming language for highlighting.
            parent: Parent widget.
        """
        super().__init__(parent)
        self._language = language
        self._highlighter = get_highlighter_for_language(language, self.document())
        self._setup_ui()

    def _setup_ui(self) -> None:
        """Set up the code display UI."""
        self.setReadOnly(True)
        self.setFont(QFont("JetBrains Mono", 10))
        self.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.setObjectName("code_display")

    def set_language(self, language: str) -> None:
        """Set the syntax highlighting language.

        Args:
            language: Programming language.
        """
        self._language = language
        self._highlighter = get_highlighter_for_language(language, self.document())

    def set_content(self, content: str) -> None:
        """Set the displayed content.

        Args:
            content: Text content to display.
        """
        self.setPlainText(content)
        self.moveCursor(QTextCursor.MoveOperation.Start)

    def append_content(self, content: str) -> None:
        """Append content to the display.

        Args:
            content: Text content to append.
        """
        self.appendPlainText(content)

    def goto_line(self, line_number: int) -> None:
        """Scroll to a specific line.

        Args:
            line_number: 1-based line number.
        """
        block = self.document().findBlockByLineNumber(line_number - 1)
        if block.isValid():
            cursor = QTextCursor(block)
            self.setTextCursor(cursor)
            self.centerCursor()


class ToolTab(QFrame):
    """A single tool output tab.

    Contains a code display area and optional metadata panel
    for showing tool-specific output.
    """

    def __init__(
        self,
        name: str,
        language: str = "c",
        parent: QWidget | None = None,
    ) -> None:
        """Initialize the tool tab.

        Args:
            name: Tab name.
            language: Default syntax highlighting language.
            parent: Parent widget.
        """
        super().__init__(parent)
        self._name = name
        self._language = language
        self._setup_ui()

    def _setup_ui(self) -> None:
        """Set up the tool tab UI."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self._splitter = QSplitter(Qt.Orientation.Vertical)

        self._code_display = CodeDisplay(self._language)
        self._splitter.addWidget(self._code_display)

        self._info_panel = QFrame()
        self._info_panel.setMaximumHeight(150)
        self._info_panel.setObjectName("info_panel")

        info_layout = QVBoxLayout(self._info_panel)
        info_layout.setContentsMargins(8, 8, 8, 8)
        info_layout.setSpacing(4)

        self._info_header = QLabel("Details")
        self._info_header.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
        self._info_header.setObjectName("panel_title")
        info_layout.addWidget(self._info_header)

        self._info_content = QLabel()
        self._info_content.setFont(QFont("JetBrains Mono", 9))
        self._info_content.setObjectName("code_label")
        self._info_content.setWordWrap(True)
        self._info_content.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )
        info_layout.addWidget(self._info_content)
        info_layout.addStretch()

        self._splitter.addWidget(self._info_panel)
        self._splitter.setSizes([400, 100])

        layout.addWidget(self._splitter)

    def set_content(self, content: str) -> None:
        """Set the main content.

        Args:
            content: Text content to display.
        """
        self._code_display.set_content(content)

    def set_info(self, header: str, content: str) -> None:
        """Set the info panel content.

        Args:
            header: Info header text.
            content: Info content text.
        """
        self._info_header.setText(header)
        self._info_content.setText(content)

    def set_language(self, language: str) -> None:
        """Set the syntax highlighting language.

        Args:
            language: Programming language.
        """
        self._code_display.set_language(language)

    def goto_line(self, line_number: int) -> None:
        """Scroll to a specific line.

        Args:
            line_number: 1-based line number.
        """
        self._code_display.goto_line(line_number)

    def append_content(self, content: str) -> None:
        """Append content to the display.

        Args:
            content: Text content to append.
        """
        self._code_display.append_content(content)


class FunctionListPanel(QFrame):
    """Panel showing list of functions in the binary.

    Allows navigation to specific functions by clicking.
    """

    function_selected = pyqtSignal(str, int)

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the function list panel.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent)
        self._functions: list[tuple[str, int]] = []
        self._setup_ui()

    def _setup_ui(self) -> None:
        """Set up the function list UI."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        header = QFrame()
        header.setFixedHeight(32)
        header.setObjectName("panel_header")
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(8, 0, 8, 0)

        title = QLabel("Functions")
        title.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
        title.setObjectName("panel_title")
        header_layout.addWidget(title)

        self._count_label = QLabel("(0)")
        self._count_label.setObjectName("secondary_text")
        header_layout.addWidget(self._count_label)
        header_layout.addStretch()

        layout.addWidget(header)

        self._list_widget = QPlainTextEdit()
        self._list_widget.setReadOnly(True)
        self._list_widget.setFont(QFont("JetBrains Mono", 9))
        self._list_widget.setObjectName("function_list")
        layout.addWidget(self._list_widget)

        self.setObjectName("function_list_panel")

    def set_functions(self, functions: list[tuple[str, int]]) -> None:
        """Set the function list.

        Args:
            functions: List of (name, address) tuples.
        """
        self._functions = functions
        self._count_label.setText(f"({len(functions)})")

        lines = []
        for name, address in functions:
            lines.append(f"0x{address:08X}  {name}")

        self._list_widget.setPlainText("\n".join(lines))


class XRefPanel(QFrame):
    """Panel showing cross-references to/from an address.

    Displays incoming and outgoing references for navigation.
    """

    xref_selected = pyqtSignal(int)

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the xref panel.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent)
        self._setup_ui()

    def _setup_ui(self) -> None:
        """Set up the xref panel UI."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        header = QFrame()
        header.setFixedHeight(32)
        header.setObjectName("panel_header")
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(8, 0, 8, 0)

        title = QLabel("Cross References")
        title.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
        title.setObjectName("panel_title")
        header_layout.addWidget(title)
        header_layout.addStretch()

        layout.addWidget(header)

        self._xref_display = QPlainTextEdit()
        self._xref_display.setReadOnly(True)
        self._xref_display.setFont(QFont("JetBrains Mono", 9))
        self._xref_display.setObjectName("xref_display")
        layout.addWidget(self._xref_display)

        self.setObjectName("xref_panel")

    def set_xrefs(
        self,
        incoming: list[tuple[int, str]],
        outgoing: list[tuple[int, str]],
    ) -> None:
        """Set the cross-reference data.

        Args:
            incoming: List of (address, description) for refs to this location.
            outgoing: List of (address, description) for refs from this location.
        """
        lines = []

        if incoming:
            lines.append("=== References TO ===")
            for addr, desc in incoming:
                lines.append(f"  0x{addr:08X}  {desc}")
            lines.append("")

        if outgoing:
            lines.append("=== References FROM ===")
            for addr, desc in outgoing:
                lines.append(f"  0x{addr:08X}  {desc}")

        self._xref_display.setPlainText("\n".join(lines))


class ToolOutputPanel(QFrame):
    """Main tool output panel widget.

    Contains tabbed interface for different tool outputs including
    decompiled code, disassembly, strings, and cross-references.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the tool output panel.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent)
        self._tabs: dict[str, ToolTab] = {}
        self._setup_ui()

    def _setup_ui(self) -> None:
        """Set up the tool output panel UI."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        header = QFrame()
        header.setFixedHeight(40)
        header.setObjectName("panel_header")
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(12, 0, 12, 0)

        title = QLabel("Analysis Output")
        title.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        title.setObjectName("panel_title")
        header_layout.addWidget(title)
        header_layout.addStretch()

        self._address_label = QLabel()
        self._address_label.setFont(QFont("JetBrains Mono", 10))
        self._address_label.setObjectName("code_label")
        header_layout.addWidget(self._address_label)

        layout.addWidget(header)

        self._main_splitter = QSplitter(Qt.Orientation.Horizontal)

        left_panel = QFrame()
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(0)

        self._tab_widget = QTabWidget()
        self._tab_widget.setObjectName("analysis_tabs")

        ghidra_tab = ToolTab("Ghidra", "c")
        self._tabs["ghidra"] = ghidra_tab
        self._tab_widget.addTab(ghidra_tab, "Ghidra")

        frida_tab = ToolTab("Frida", "javascript")
        self._tabs["frida"] = frida_tab
        self._tab_widget.addTab(frida_tab, "Frida")

        r2_tab = ToolTab("radare2", "asm")
        self._tabs["radare2"] = r2_tab
        self._tab_widget.addTab(r2_tab, "radare2")

        x64dbg_tab = ToolTab("x64dbg", "asm")
        self._tabs["x64dbg"] = x64dbg_tab
        self._tab_widget.addTab(x64dbg_tab, "x64dbg")

        log_tab = ToolTab("Log", "python")
        self._tabs["log"] = log_tab
        self._tab_widget.addTab(log_tab, "Log")

        left_layout.addWidget(self._tab_widget)
        self._main_splitter.addWidget(left_panel)

        right_panel = QFrame()
        right_panel.setMaximumWidth(250)
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(0)

        self._func_list = FunctionListPanel()
        right_layout.addWidget(self._func_list)

        self._xref_panel = XRefPanel()
        right_layout.addWidget(self._xref_panel)

        self._main_splitter.addWidget(right_panel)
        self._main_splitter.setSizes([600, 200])

        layout.addWidget(self._main_splitter)

        self.setObjectName("analysis_panel")

    def set_tab_content(self, tab_name: str, content: str) -> None:
        """Set content for a specific tab.

        Args:
            tab_name: Name of the tab (ghidra, frida, radare2, x64dbg, log).
            content: Text content to display.
        """
        tab = self._tabs.get(tab_name.lower())
        if tab:
            tab.set_content(content)

    def set_tab_info(self, tab_name: str, header: str, content: str) -> None:
        """Set info panel content for a specific tab.

        Args:
            tab_name: Name of the tab.
            header: Info header text.
            content: Info content text.
        """
        tab = self._tabs.get(tab_name.lower())
        if tab:
            tab.set_info(header, content)

    def append_tab_content(self, tab_name: str, content: str) -> None:
        """Append content to a specific tab.

        Args:
            tab_name: Name of the tab.
            content: Text content to append.
        """
        tab = self._tabs.get(tab_name.lower())
        if tab:
            tab.append_content(content)

    def set_current_address(self, address: int) -> None:
        """Set the currently displayed address.

        Args:
            address: Memory address.
        """
        self._address_label.setText(f"0x{address:08X}")

    def set_functions(self, functions: list[tuple[str, int]]) -> None:
        """Set the function list.

        Args:
            functions: List of (name, address) tuples.
        """
        self._func_list.set_functions(functions)

    def set_xrefs(
        self,
        incoming: list[tuple[int, str]],
        outgoing: list[tuple[int, str]],
    ) -> None:
        """Set the cross-reference data.

        Args:
            incoming: List of (address, description) for refs to this location.
            outgoing: List of (address, description) for refs from this location.
        """
        self._xref_panel.set_xrefs(incoming, outgoing)

    def activate_tab(self, tab_name: str) -> None:
        """Activate a specific tab.

        Args:
            tab_name: Name of the tab to activate.
        """
        tab = self._tabs.get(tab_name.lower())
        if tab:
            index = self._tab_widget.indexOf(tab)
            if index >= 0:
                self._tab_widget.setCurrentIndex(index)

    def log(self, message: str) -> None:
        """Append a message to the log tab.

        Args:
            message: Message to log.
        """
        self.append_tab_content("log", message)

    def clear_tab(self, tab_name: str) -> None:
        """Clear content of a specific tab.

        Args:
            tab_name: Name of the tab to clear.
        """
        tab = self._tabs.get(tab_name.lower())
        if tab:
            tab.set_content("")

    def clear_all(self) -> None:
        """Clear all tab contents."""
        for tab in self._tabs.values():
            tab.set_content("")
        self._func_list.set_functions([])
        self._xref_panel.set_xrefs([], [])
        self._address_label.setText("")

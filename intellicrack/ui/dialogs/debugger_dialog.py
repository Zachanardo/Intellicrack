"""Plugin Debugger Dialog for Intellicrack.

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

from __future__ import annotations

import logging
import os
import queue
from typing import Any, cast

from intellicrack.handlers.pyqt6_handler import (
    QAction,
    QCloseEvent,
    QColor,
    QDialog,
    QFileDialog,
    QFont,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMenu,
    QMessageBox,
    QMouseEvent,
    QPaintEvent,
    QPlainTextEdit,
    QPoint,
    QPushButton,
    QRect,
    QResizeEvent,
    QSize,
    QSplitter,
    Qt,
    QTabWidget,
    QTextCursor,
    QTextEdit,
    QTextFormat,
    QThread,
    QToolBar,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
    pyqtSignal,
)

from ...tools.plugin_debugger import DebuggerState, DebuggerThread, PluginDebugger


class DebuggerOutputThread(QThread):
    """Thread for handling debugger output."""

    output_received = pyqtSignal(str, object)

    def __init__(self, output_queue: queue.Queue[tuple[str, Any]]) -> None:
        """Initialize the DebuggerOutputThread with default values."""
        super().__init__()
        self.output_queue = output_queue
        self.running = True
        self._logger = logging.getLogger(__name__)

    def run(self) -> None:
        """Process debugger output."""
        while self.running:
            try:
                msg_type, data = self.output_queue.get(timeout=0.1)
                self.output_received.emit(msg_type, data)
            except queue.Empty:
                continue
            except Exception as e:
                self._logger.error("Exception in debugger_dialog: %s", e)
                print(f"Debugger output error: {e}")

    def stop(self) -> None:
        """Stop the thread."""
        self.running = False


class DebuggerDialog(QDialog):
    """Advanced debugger dialog with breakpoint support."""

    def __init__(self, parent: QWidget | None = None, plugin_path: str | None = None) -> None:
        """Initialize the DebuggerDialog with default values.

        Args:
            parent: Parent widget, defaults to None.
            plugin_path: Path to the plugin file to debug, defaults to None.

        """
        super().__init__(parent)
        self.plugin_path = plugin_path
        self.debugger: PluginDebugger = PluginDebugger()
        self.debugger_thread: DebuggerThread | None = None
        self.output_thread: DebuggerOutputThread | None = None
        self.breakpoint_lines: dict[str, int] = {}
        self.current_line: int | None = None

        self.run_action: QAction | None = None
        self.pause_action: QAction | None = None
        self.stop_action: QAction | None = None
        self.step_over_action: QAction | None = None
        self.step_into_action: QAction | None = None
        self.step_out_action: QAction | None = None

        self.file_label: QLabel
        self.code_editor: CodeEditorWidget
        self.debug_tabs: QTabWidget
        self.variables_tree: QTreeWidget
        self.stack_list: QListWidget
        self.breakpoint_list: QListWidget
        self.watch_tree: QTreeWidget
        self.watch_input: QLineEdit
        self.console: QTextEdit
        self.repl_input: QLineEdit

        self.setWindowTitle("Plugin Debugger")
        self.setMinimumSize(1200, 800)
        self.setup_ui()

        if plugin_path:
            self.load_plugin(plugin_path)

    def setup_ui(self) -> None:
        """Set up the dialog UI."""
        layout = QVBoxLayout(self)

        toolbar = self.create_toolbar()
        layout.addWidget(toolbar)

        main_splitter = QSplitter(Qt.Orientation.Horizontal)

        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)

        file_layout = QHBoxLayout()
        file_layout.addWidget(QLabel("Plugin:"))
        self.file_label = QLabel("No file loaded")
        self.file_label.setStyleSheet("font-weight: bold;")
        file_layout.addWidget(self.file_label)
        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(self.browse_plugin)
        file_layout.addWidget(browse_btn)
        file_layout.addStretch()
        left_layout.addLayout(file_layout)

        self.code_editor = CodeEditorWidget()
        self.code_editor.breakpoint_toggled.connect(self.toggle_breakpoint)
        left_layout.addWidget(self.code_editor)

        main_splitter.addWidget(left_widget)

        right_splitter = QSplitter(Qt.Orientation.Vertical)

        self.debug_tabs = QTabWidget()

        self.variables_tree = QTreeWidget()
        self.variables_tree.setHeaderLabels(["Name", "Value", "Type"])
        self.debug_tabs.addTab(self.variables_tree, "Variables")

        self.stack_list = QListWidget()
        self.stack_list.itemClicked.connect(self.on_stack_frame_clicked)
        self.debug_tabs.addTab(self.stack_list, "Call Stack")

        self.breakpoint_list = QListWidget()
        breakpoints_widget = self.create_breakpoints_widget()
        self.debug_tabs.addTab(breakpoints_widget, "Breakpoints")

        watch_widget = self.create_watch_widget()
        self.debug_tabs.addTab(watch_widget, "Watch")

        right_splitter.addWidget(self.debug_tabs)

        console_widget = QWidget()
        console_layout = QVBoxLayout(console_widget)
        console_layout.addWidget(QLabel("Debug Console:"))

        self.console = QTextEdit()
        self.console.setReadOnly(True)
        self.console.setFont(QFont("Consolas", 9))
        console_layout.addWidget(self.console)

        repl_layout = QHBoxLayout()
        self.repl_input = QLineEdit()
        self.repl_input.setToolTip("Enter expression to evaluate in the current debug context")
        self.repl_input.returnPressed.connect(self.evaluate_expression)
        repl_layout.addWidget(self.repl_input)

        eval_btn = QPushButton("Evaluate")
        eval_btn.clicked.connect(self.evaluate_expression)
        repl_layout.addWidget(eval_btn)

        console_layout.addLayout(repl_layout)

        right_splitter.addWidget(console_widget)

        main_splitter.addWidget(right_splitter)
        main_splitter.setSizes([700, 500])

        layout.addWidget(main_splitter)

    def create_toolbar(self) -> QToolBar:
        """Create debugger toolbar."""
        toolbar = QToolBar()

        self.run_action = toolbar.addAction("Run")
        if self.run_action is not None:
            self.run_action.triggered.connect(self.run_continue)

        self.pause_action = toolbar.addAction("Pause")
        if self.pause_action is not None:
            self.pause_action.triggered.connect(self.pause_execution)
            self.pause_action.setEnabled(False)

        self.stop_action = toolbar.addAction("Stop")
        if self.stop_action is not None:
            self.stop_action.triggered.connect(self.stop_debugging)
            self.stop_action.setEnabled(False)

        toolbar.addSeparator()

        self.step_over_action = toolbar.addAction("Step Over")
        if self.step_over_action is not None:
            self.step_over_action.triggered.connect(self.step_over)
            self.step_over_action.setEnabled(False)

        self.step_into_action = toolbar.addAction("Step Into")
        if self.step_into_action is not None:
            self.step_into_action.triggered.connect(self.step_into)
            self.step_into_action.setEnabled(False)

        self.step_out_action = toolbar.addAction("Step Out")
        if self.step_out_action is not None:
            self.step_out_action.triggered.connect(self.step_out)
            self.step_out_action.setEnabled(False)

        toolbar.addSeparator()

        toggle_bp_action = toolbar.addAction("Toggle Breakpoint")
        if toggle_bp_action is not None:
            toggle_bp_action.triggered.connect(self.toggle_current_line_breakpoint)

        clear_bp_action = toolbar.addAction("Clear All Breakpoints")
        if clear_bp_action is not None:
            clear_bp_action.triggered.connect(self.clear_all_breakpoints)

        return toolbar

    def create_breakpoints_widget(self) -> QWidget:
        """Create breakpoints management widget."""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        self.breakpoint_list = QListWidget()
        self.breakpoint_list.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.breakpoint_list.customContextMenuRequested.connect(self.show_breakpoint_menu)
        layout.addWidget(self.breakpoint_list)

        btn_layout = QHBoxLayout()

        add_btn = QPushButton("Add...")
        add_btn.clicked.connect(self.add_breakpoint_dialog)
        btn_layout.addWidget(add_btn)

        remove_btn = QPushButton("Remove")
        remove_btn.clicked.connect(self.remove_selected_breakpoint)
        btn_layout.addWidget(remove_btn)

        btn_layout.addStretch()
        layout.addLayout(btn_layout)

        return widget

    def create_watch_widget(self) -> QWidget:
        """Create watch expressions widget."""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        self.watch_tree = QTreeWidget()
        self.watch_tree.setHeaderLabels(["Expression", "Value"])
        layout.addWidget(self.watch_tree)

        add_layout = QHBoxLayout()
        self.watch_input = QLineEdit()
        self.watch_input.setToolTip("Enter expression to watch during execution")
        add_layout.addWidget(self.watch_input)

        add_watch_btn = QPushButton("Add Watch")
        add_watch_btn.clicked.connect(self.add_watch)
        add_layout.addWidget(add_watch_btn)

        layout.addLayout(add_layout)

        return widget

    def browse_plugin(self) -> None:
        """Browse for plugin file."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Plugin",
            "",
            "Python Files (*.py);;All Files (*.*)",
        )

        if file_path:
            self.load_plugin(file_path)

    def load_plugin(self, path: str) -> None:
        """Load a plugin for debugging."""
        self.plugin_path = path
        self.file_label.setText(os.path.basename(path))

        with open(path, encoding="utf-8") as f:
            code = f.read()

        self.code_editor.set_code(code)
        self.code_editor.file_path = path

        if self.run_action is not None:
            self.run_action.setEnabled(True)

        self.clear_debug_info()

    def clear_debug_info(self) -> None:
        """Clear all debug information."""
        self.variables_tree.clear()
        self.stack_list.clear()
        self.watch_tree.clear()
        self.console.clear()
        self.current_line = None
        self.code_editor.highlight_line(None)

    def toggle_breakpoint(self, line: int) -> None:
        """Toggle breakpoint at line."""
        if not self.plugin_path:
            return

        for bp_id, bp in self.debugger.breakpoints.items():
            if bp.file == self.plugin_path and bp.line == line:
                self.debugger.remove_breakpoint(bp_id)
                self.update_breakpoint_display()
                return

        self.debugger.add_breakpoint(self.plugin_path, line=line)
        self.update_breakpoint_display()

    def toggle_current_line_breakpoint(self) -> None:
        """Toggle breakpoint at current line."""
        cursor = self.code_editor.textCursor()
        line = cursor.blockNumber() + 1
        self.toggle_breakpoint(line)

    def clear_all_breakpoints(self) -> None:
        """Clear all breakpoints."""
        self.debugger.breakpoints.clear()
        self.update_breakpoint_display()

    def update_breakpoint_display(self) -> None:
        """Update breakpoint display."""
        self.code_editor.clear_breakpoints()

        for bp in self.debugger.breakpoints.values():
            if bp.file == self.plugin_path and bp.line is not None:
                self.code_editor.add_breakpoint(bp.line)

        self.breakpoint_list.clear()

        for bp in self.debugger.breakpoints.values():
            text = f"{os.path.basename(bp.file)}:{bp.line}"
            if bp.condition:
                text += f" [if {bp.condition}]"
            if not bp.enabled:
                text += " (disabled)"

            item = QListWidgetItem(text)
            item.setData(Qt.ItemDataRole.UserRole, bp.id)
            self.breakpoint_list.addItem(item)

    def show_breakpoint_menu(self, pos: QPoint) -> None:
        """Show breakpoint context menu.

        Args:
            pos: Position where the context menu was requested.

        """
        item = self.breakpoint_list.itemAt(pos)
        if not item:
            return

        bp_id = item.data(Qt.ItemDataRole.UserRole)
        if not isinstance(bp_id, int):
            return

        bp = self.debugger.breakpoints.get(bp_id)
        if not bp:
            return

        menu = QMenu(self)

        if bp.enabled:
            disable_action = menu.addAction("Disable")
            if disable_action is not None:
                disable_action.triggered.connect(lambda: self.disable_breakpoint(bp_id))
        else:
            enable_action = menu.addAction("Enable")
            if enable_action is not None:
                enable_action.triggered.connect(lambda: self.enable_breakpoint(bp_id))

        remove_action = menu.addAction("Remove")
        if remove_action is not None:
            remove_action.triggered.connect(lambda: self.remove_breakpoint(bp_id))

        menu.exec(self.breakpoint_list.mapToGlobal(pos))

    def disable_breakpoint(self, bp_id: int) -> None:
        """Disable breakpoint."""
        self.debugger.disable_breakpoint(bp_id)
        self.update_breakpoint_display()

    def enable_breakpoint(self, bp_id: int) -> None:
        """Enable breakpoint."""
        self.debugger.enable_breakpoint(bp_id)
        self.update_breakpoint_display()

    def remove_breakpoint(self, bp_id: int) -> None:
        """Remove breakpoint."""
        self.debugger.remove_breakpoint(bp_id)
        self.update_breakpoint_display()

    def remove_selected_breakpoint(self) -> None:
        """Remove selected breakpoint."""
        item = self.breakpoint_list.currentItem()
        if item is not None:
            bp_id = item.data(Qt.ItemDataRole.UserRole)
            if isinstance(bp_id, int):
                self.remove_breakpoint(bp_id)

    def add_breakpoint_dialog(self) -> None:
        """Show add breakpoint dialog."""
        self.toggle_current_line_breakpoint()

    def run_continue(self) -> None:
        """Run or continue execution."""
        if self.debugger.state == DebuggerState.IDLE:
            self.start_debugging()
        else:
            self.debugger.command_queue.put({"type": "continue"})
            self.update_ui_state("running")

    def start_debugging(self) -> None:
        """Start debugging session."""
        if not self.plugin_path:
            return

        self.console.clear()
        self.console.append("Starting debug session...\n")

        self.output_thread = DebuggerOutputThread(self.debugger.output_queue)
        self.output_thread.output_received.connect(self.handle_debugger_output)
        self.output_thread.start()

        from ...core.app_context import get_app_context

        app_context = get_app_context()
        current_binary = getattr(app_context, "current_binary_path", None)

        if not current_binary:
            import tempfile

            with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as test_temp_file:
                test_binary = test_temp_file.name

            with open(test_binary, "wb") as f:
                f.write(b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00")
                f.write(b"\xb8\x00\x00\x00\x00" * 200)
            current_binary = test_binary

        self.debugger_thread = DebuggerThread(
            self.debugger,
            self.plugin_path,
            binary_path=current_binary,
            options={},
        )
        self.debugger_thread.start()

        self.update_ui_state("running")

    def pause_execution(self) -> None:
        """Pause execution."""
        self.debugger.command_queue.put({"type": "pause"})

    def stop_debugging(self) -> None:
        """Stop debugging session."""
        self.debugger.command_queue.put({"type": "terminate"})

        if self.debugger_thread:
            self.debugger_thread.join(timeout=2)

        if self.output_thread:
            self.output_thread.stop()
            self.output_thread.wait()

        self.clear_debug_info()

        self.update_ui_state("idle")

        self.console.append("\nDebug session terminated.")

    def step_over(self) -> None:
        """Step over."""
        self.debugger.command_queue.put({"type": "step_over"})
        self.update_ui_state("running")

    def step_into(self) -> None:
        """Step into."""
        self.debugger.command_queue.put({"type": "step_into"})
        self.update_ui_state("running")

    def step_out(self) -> None:
        """Step out."""
        self.debugger.command_queue.put({"type": "step_out"})
        self.update_ui_state("running")

    def update_ui_state(self, state: str) -> None:
        """Update UI based on debugger state."""
        if state == "idle":
            if self.run_action is not None:
                self.run_action.setEnabled(True)
                self.run_action.setText("Run")
            if self.pause_action is not None:
                self.pause_action.setEnabled(False)
            if self.stop_action is not None:
                self.stop_action.setEnabled(False)
            if self.step_over_action is not None:
                self.step_over_action.setEnabled(False)
            if self.step_into_action is not None:
                self.step_into_action.setEnabled(False)
            if self.step_out_action is not None:
                self.step_out_action.setEnabled(False)

        elif state == "running":
            if self.run_action is not None:
                self.run_action.setEnabled(False)
            if self.pause_action is not None:
                self.pause_action.setEnabled(True)
            if self.stop_action is not None:
                self.stop_action.setEnabled(True)
            if self.step_over_action is not None:
                self.step_over_action.setEnabled(False)
            if self.step_into_action is not None:
                self.step_into_action.setEnabled(False)
            if self.step_out_action is not None:
                self.step_out_action.setEnabled(False)

        elif state == "paused":
            if self.run_action is not None:
                self.run_action.setEnabled(True)
                self.run_action.setText("Continue")
            if self.pause_action is not None:
                self.pause_action.setEnabled(False)
            if self.stop_action is not None:
                self.stop_action.setEnabled(True)
            if self.step_over_action is not None:
                self.step_over_action.setEnabled(True)
            if self.step_into_action is not None:
                self.step_into_action.setEnabled(True)
            if self.step_out_action is not None:
                self.step_out_action.setEnabled(True)

    def handle_debugger_output(self, msg_type: str, data: object) -> None:
        """Handle debugger output messages.

        Args:
            msg_type: Type of debugger message (e.g., 'paused', 'breakpoint', 'stack').
            data: Message data payload, varies by message type.

        """
        if msg_type == "paused":
            self.update_ui_state("paused")
            if isinstance(data, dict):
                self.current_line = cast("int", data.get("line"))
                self.code_editor.highlight_line(self.current_line)
                file_name = data.get("file", "unknown")
                line_num = data.get("line", 0)
                func_name = data.get("function", "unknown")
                self.console.append(f"Paused at {file_name}:{line_num} in {func_name}")

        elif msg_type == "breakpoint":
            if isinstance(data, dict):
                file_name = data.get("file", "unknown")
                line_num = data.get("line", 0)
                hit_count = data.get("hit_count", 0)
                self.console.append(f"Breakpoint hit: {file_name}:{line_num} (hit count: {hit_count})")

        elif msg_type == "stack":
            if isinstance(data, list):
                self.update_stack_display(cast("list[dict[str, Any]]", data))

        elif msg_type == "watches":
            if isinstance(data, dict):
                self.update_watch_display(cast("dict[str, Any]", data))

        elif msg_type == "eval_result":
            if isinstance(data, dict):
                if "error" in data:
                    self.console.append(f"Error evaluating '{data.get('expression', '')}': {data.get('error', '')}")
                else:
                    self.console.append(f"{data.get('expression', '')} = {data.get('value', '')}")

        elif msg_type == "exception_break":
            if isinstance(data, dict):
                self.console.append(f"Exception: {data.get('type', '')}: {data.get('message', '')}")
                traceback_str = data.get("traceback", "")
                if traceback_str:
                    self.console.append(str(traceback_str))

        elif msg_type == "result":
            self.console.append(f"\nPlugin returned: {data}")

        elif msg_type == "error":
            self.console.append(f"Error: {data}")

    def update_stack_display(self, stack_frames: list[dict[str, Any]]) -> None:
        """Update call stack display."""
        self.stack_list.clear()

        for i, frame in enumerate(stack_frames):
            func_name = frame.get("function", "unknown")
            filename = frame.get("filename", "unknown")
            lineno = frame.get("lineno", 0)
            text = f"{func_name} at {os.path.basename(filename)}:{lineno}"
            item = QListWidgetItem(text)
            item.setData(Qt.ItemDataRole.UserRole, i)

            if i == 0:
                font = QFont()
                font.setWeight(QFont.Weight.Bold)
                item.setFont(font)

            self.stack_list.addItem(item)

        if stack_frames:
            self.update_variables_display(0)

    def on_stack_frame_clicked(self, item: QListWidgetItem) -> None:
        """Handle stack frame selection."""
        frame_index = item.data(Qt.ItemDataRole.UserRole)
        if isinstance(frame_index, int):
            self.update_variables_display(frame_index)

    def update_variables_display(self, frame_index: int = 0) -> None:
        """Update variables display."""
        variables = self.debugger.get_variables(frame_index)

        self.variables_tree.clear()

        local_root = QTreeWidgetItem(self.variables_tree, ["Local Variables", "", ""])
        global_root = QTreeWidgetItem(self.variables_tree, ["Global Variables", "", ""])

        for name, info in sorted(variables.items()):
            if isinstance(info, dict):
                scope = info.get("scope", "local")
                parent = local_root if scope == "local" else global_root

                value = info.get("value")
                type_name = info.get("type", "unknown")

                item = QTreeWidgetItem(
                    parent,
                    [
                        name,
                        str(value),
                        str(type_name),
                    ],
                )

                if isinstance(value, dict):
                    for k, v in value.items():
                        QTreeWidgetItem(item, [str(k), str(v), type(v).__name__])
                elif isinstance(value, list):
                    for idx, v in enumerate(value):
                        QTreeWidgetItem(item, [f"[{idx}]", str(v), type(v).__name__])

        local_root.setExpanded(True)

    def update_watch_display(self, watches: dict[str, Any]) -> None:
        """Update watch expressions display."""
        for i in range(self.watch_tree.topLevelItemCount()):
            item = self.watch_tree.topLevelItem(i)
            if item is not None:
                expr = item.text(0)
                if expr in watches:
                    item.setText(1, str(watches[expr]))

    def add_watch(self) -> None:
        """Add watch expression."""
        expr = self.watch_input.text().strip()
        if not expr:
            return

        self.debugger.command_queue.put(
            {
                "type": "watch",
                "expression": expr,
            },
        )

        QTreeWidgetItem(self.watch_tree, [expr, "<not evaluated>"])

        self.watch_input.clear()

    def evaluate_expression(self) -> None:
        """Evaluate expression in debug context."""
        expr = self.repl_input.text().strip()
        if not expr:
            return

        self.console.append(f"\n>>> {expr}")

        self.debugger.command_queue.put(
            {
                "type": "evaluate",
                "expression": expr,
            },
        )

        self.repl_input.clear()

    def closeEvent(self, event: QCloseEvent | None) -> None:
        """Handle dialog close event.

        Args:
            event: The close event that triggered this handler.

        """
        if event is None:
            return

        if self.debugger.state != DebuggerState.IDLE:
            reply = QMessageBox.question(
                self,
                "Debugging Active",
                "Debugging session is active. Stop debugging and close?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )

            if reply == QMessageBox.StandardButton.Yes:
                self.stop_debugging()
                event.accept()
            else:
                event.ignore()
        else:
            event.accept()


class CodeEditorWidget(QPlainTextEdit):
    """Code editor with line numbers and breakpoint support."""

    breakpoint_toggled = pyqtSignal(int)

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the CodeEditorWidget with default values.

        Args:
            parent: Parent widget, defaults to None.

        """
        super().__init__(parent)
        self.file_path: str | None = None
        self.breakpoint_lines: set[int] = set()
        self.current_line: int | None = None

        font = QFont("Consolas", 10)
        self.setFont(font)

        self.line_number_area = LineNumberArea(self)

        self.blockCountChanged.connect(self.update_line_number_area_width)
        self.updateRequest.connect(self.update_line_number_area)
        self.cursorPositionChanged.connect(self.highlight_current_line)

        self.update_line_number_area_width(0)
        self.highlight_current_line()

    def line_number_area_width(self) -> int:
        """Calculate line number area width.

        Returns:
            Width in pixels required for the line number area.

        """
        digits = 1
        max_num = max(1, self.blockCount())
        while max_num >= 10:
            max_num //= 10
            digits += 1

        return 3 + self.fontMetrics().horizontalAdvance("9") * (digits + 1)

    def update_line_number_area_width(self, new_block_count: int) -> None:
        """Update line number area width.

        Args:
            new_block_count: Number of blocks (lines) in the document.

        """
        _ = new_block_count
        self.setViewportMargins(self.line_number_area_width(), 0, 0, 0)

    def update_line_number_area(self, rect: QRect, dy: int) -> None:
        """Update line number area.

        Args:
            rect: Rectangle containing the area to update.
            dy: Vertical scroll distance in pixels.

        """
        if dy:
            self.line_number_area.scroll(0, dy)
        else:
            self.line_number_area.update(0, rect.y(), self.line_number_area.width(), rect.height())

        viewport = self.viewport()
        if viewport is not None and rect.contains(viewport.rect()):
            self.update_line_number_area_width(0)

    def resizeEvent(self, event: QResizeEvent | None) -> None:
        """Handle resize event.

        Args:
            event: The resize event.

        """
        super().resizeEvent(event)

        cr = self.contentsRect()
        self.line_number_area.setGeometry(cr.left(), cr.top(), self.line_number_area_width(), cr.height())

    def line_number_area_paint_event(self, event: QPaintEvent) -> None:
        """Paint line numbers.

        Args:
            event: The paint event containing the area to paint.

        """
        from intellicrack.handlers.pyqt6_handler import QPainter

        painter = QPainter(self.line_number_area)
        painter.fillRect(event.rect(), Qt.GlobalColor.lightGray)

        block = self.firstVisibleBlock()
        block_number = block.blockNumber()
        top = int(self.blockBoundingGeometry(block).translated(self.contentOffset()).top())
        bottom = top + int(self.blockBoundingRect(block).height())

        while block.isValid() and top <= event.rect().bottom():
            if block.isVisible() and bottom >= event.rect().top():
                number = str(block_number + 1)

                if block_number + 1 in self.breakpoint_lines:
                    painter.fillRect(
                        0,
                        top,
                        self.line_number_area.width(),
                        self.fontMetrics().height(),
                        QColor(255, 0, 0, 50),
                    )
                    painter.setPen(Qt.GlobalColor.red)
                else:
                    painter.setPen(Qt.GlobalColor.black)

                painter.drawText(
                    0,
                    top,
                    self.line_number_area.width() - 3,
                    self.fontMetrics().height(),
                    int(Qt.AlignmentFlag.AlignRight),
                    number,
                )

            block = block.next()
            top = bottom
            bottom = top + int(self.blockBoundingRect(block).height())
            block_number += 1

        painter.end()

    def line_number_area_mouse_press(self, event: QMouseEvent) -> None:
        """Handle mouse press in line number area.

        Args:
            event: The mouse event.

        """
        if event.button() == Qt.MouseButton.LeftButton:
            cursor = self.cursorForPosition(event.pos())
            line = cursor.blockNumber() + 1
            self.breakpoint_toggled.emit(line)

    def highlight_current_line(self) -> None:
        """Highlight current line."""
        extra_selections: list[QTextEdit.ExtraSelection] = []

        if not self.isReadOnly():
            selection = QTextEdit.ExtraSelection()

            line_color = QColor(Qt.GlobalColor.yellow).lighter(160)

            selection.format.setBackground(line_color)
            selection.format.setProperty(int(QTextFormat.Property.FullWidthSelection), True)
            selection.cursor = self.textCursor()
            selection.cursor.clearSelection()
            extra_selections.append(selection)

        self.setExtraSelections(extra_selections)

    def highlight_line(self, line: int | None) -> None:
        """Highlight execution line."""
        if line is None:
            self.current_line = None
            self.highlight_current_line()
            return

        self.current_line = line

        cursor = QTextCursor(self.document())
        cursor.movePosition(QTextCursor.MoveOperation.Start)
        cursor.movePosition(QTextCursor.MoveOperation.NextBlock, QTextCursor.MoveMode.MoveAnchor, line - 1)
        self.setTextCursor(cursor)

        selection = QTextEdit.ExtraSelection()
        line_color = QColor(Qt.GlobalColor.green).lighter(160)
        selection.format.setBackground(line_color)
        selection.format.setProperty(int(QTextFormat.Property.FullWidthSelection), True)
        selection.cursor = cursor
        selection.cursor.clearSelection()
        extra_selections = [selection]
        self.setExtraSelections(extra_selections)

    def set_code(self, code: str) -> None:
        """Set code content."""
        self.setPlainText(code)

    def add_breakpoint(self, line: int) -> None:
        """Add breakpoint."""
        self.breakpoint_lines.add(line)
        self.line_number_area.update()

    def remove_breakpoint(self, line: int) -> None:
        """Remove breakpoint."""
        self.breakpoint_lines.discard(line)
        self.line_number_area.update()

    def clear_breakpoints(self) -> None:
        """Clear all breakpoints."""
        self.breakpoint_lines.clear()
        self.line_number_area.update()


class LineNumberArea(QWidget):
    """Line number area widget."""

    def __init__(self, editor: CodeEditorWidget) -> None:
        """Initialize the LineNumberArea with default values.

        Args:
            editor: The code editor widget this area is associated with.

        """
        super().__init__(editor)
        self.code_editor: CodeEditorWidget = editor

    def sizeHint(self) -> QSize:
        """Return size hint.

        Returns:
            Size hint for the line number area.

        """
        return QSize(self.code_editor.line_number_area_width(), 0)

    def paintEvent(self, event: QPaintEvent | None) -> None:
        """Paint event.

        Args:
            event: The paint event.

        """
        if event is not None:
            self.code_editor.line_number_area_paint_event(event)

    def mousePressEvent(self, event: QMouseEvent | None) -> None:
        """Mouse press event.

        Args:
            event: The mouse event.

        """
        if event is not None:
            self.code_editor.line_number_area_mouse_press(event)

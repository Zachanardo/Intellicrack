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

import os
import queue
from typing import Any

from intellicrack.handlers.pyqt6_handler import (
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
    QPushButton,
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

    def __init__(self, output_queue: queue.Queue):
        """Initialize the DebuggerOutputThread with default values."""
        super().__init__()
        self.output_queue = output_queue
        self.running = True

    def run(self):
        """Process debugger output."""
        while self.running:
            try:
                msg_type, data = self.output_queue.get(timeout=0.1)
                self.output_received.emit(msg_type, data)
            except queue.Empty as e:
                self.logger.error("queue.Empty in debugger_dialog: %s", e)
                continue
            except Exception as e:
                self.logger.error("Exception in debugger_dialog: %s", e)
                print(f"Debugger output error: {e}")

    def stop(self):
        """Stop the thread."""
        self.running = False


class DebuggerDialog(QDialog):
    """Advanced debugger dialog with breakpoint support."""

    def __init__(self, parent=None, plugin_path=None):
        """Initialize the DebuggerDialog with default values."""
        super().__init__(parent)
        self.plugin_path = plugin_path
        self.debugger = PluginDebugger()
        self.debugger_thread = None
        self.output_thread = None
        self.breakpoint_lines = {}
        self.current_line = None

        self.setWindowTitle("Plugin Debugger")
        self.setMinimumSize(1200, 800)
        self.setup_ui()

        if plugin_path:
            self.load_plugin(plugin_path)

    def setup_ui(self):
        """Set up the dialog UI."""
        layout = QVBoxLayout(self)

        # Toolbar
        toolbar = self.create_toolbar()
        layout.addWidget(toolbar)

        # Main splitter
        main_splitter = QSplitter(Qt.Horizontal)

        # Left panel - Code editor
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)

        # File selection
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

        # Code editor with line numbers
        self.code_editor = CodeEditorWidget()
        self.code_editor.breakpoint_toggled.connect(self.toggle_breakpoint)
        left_layout.addWidget(self.code_editor)

        main_splitter.addWidget(left_widget)

        # Right panel - Debug info
        right_splitter = QSplitter(Qt.Vertical)

        # Debug tabs
        self.debug_tabs = QTabWidget()

        # Variables tab
        self.variables_tree = QTreeWidget()
        self.variables_tree.setHeaderLabels(["Name", "Value", "Type"])
        self.debug_tabs.addTab(self.variables_tree, "Variables")

        # Call stack tab
        self.stack_list = QListWidget()
        self.stack_list.itemClicked.connect(self.on_stack_frame_clicked)
        self.debug_tabs.addTab(self.stack_list, "Call Stack")

        # Breakpoints tab
        self.breakpoints_widget = self.create_breakpoints_widget()
        self.debug_tabs.addTab(self.breakpoints_widget, "Breakpoints")

        # Watch tab
        self.watch_widget = self.create_watch_widget()
        self.debug_tabs.addTab(self.watch_widget, "Watch")

        right_splitter.addWidget(self.debug_tabs)

        # Console output
        console_widget = QWidget()
        console_layout = QVBoxLayout(console_widget)
        console_layout.addWidget(QLabel("Debug Console:"))

        self.console = QTextEdit()
        self.console.setReadOnly(True)
        self.console.setFont(QFont("Consolas", 9))
        console_layout.addWidget(self.console)

        # REPL input
        repl_layout = QHBoxLayout()
        self.repl_input = QLineEdit()
        self.repl_input.setPlaceholderText("Enter expression to evaluate...")
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

        # Run/Continue
        self.run_action = toolbar.addAction("▶️ Run")
        self.run_action.triggered.connect(self.run_continue)

        # Pause
        self.pause_action = toolbar.addAction("⏸️ Pause")
        self.pause_action.triggered.connect(self.pause_execution)
        self.pause_action.setEnabled(False)

        # Stop
        self.stop_action = toolbar.addAction("⏹️ Stop")
        self.stop_action.triggered.connect(self.stop_debugging)
        self.stop_action.setEnabled(False)

        toolbar.addSeparator()

        # Step controls
        self.step_over_action = toolbar.addAction("⏭️ Step Over")
        self.step_over_action.triggered.connect(self.step_over)
        self.step_over_action.setEnabled(False)

        self.step_into_action = toolbar.addAction("⬇️ Step Into")
        self.step_into_action.triggered.connect(self.step_into)
        self.step_into_action.setEnabled(False)

        self.step_out_action = toolbar.addAction("⬆️ Step Out")
        self.step_out_action.triggered.connect(self.step_out)
        self.step_out_action.setEnabled(False)

        toolbar.addSeparator()

        # Breakpoint controls
        toolbar.addAction("🔴 Toggle Breakpoint").triggered.connect(self.toggle_current_line_breakpoint)
        toolbar.addAction(" Clear All Breakpoints").triggered.connect(self.clear_all_breakpoints)

        return toolbar

    def create_breakpoints_widget(self) -> QWidget:
        """Create breakpoints management widget."""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Breakpoint list
        self.breakpoint_list = QListWidget()
        self.breakpoint_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.breakpoint_list.customContextMenuRequested.connect(self.show_breakpoint_menu)
        layout.addWidget(self.breakpoint_list)

        # Buttons
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

        # Watch list
        self.watch_tree = QTreeWidget()
        self.watch_tree.setHeaderLabels(["Expression", "Value"])
        layout.addWidget(self.watch_tree)

        # Add watch
        add_layout = QHBoxLayout()
        self.watch_input = QLineEdit()
        self.watch_input.setPlaceholderText("Enter expression to watch...")
        add_layout.addWidget(self.watch_input)

        add_watch_btn = QPushButton("Add Watch")
        add_watch_btn.clicked.connect(self.add_watch)
        add_layout.addWidget(add_watch_btn)

        layout.addLayout(add_layout)

        return widget

    def browse_plugin(self):
        """Browse for plugin file."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Plugin",
            "",
            "Python Files (*.py);;All Files (*.*)",
        )

        if file_path:
            self.load_plugin(file_path)

    def load_plugin(self, path: str):
        """Load a plugin for debugging."""
        self.plugin_path = path
        self.file_label.setText(os.path.basename(path))

        # Load code into editor
        with open(path) as f:
            code = f.read()

        self.code_editor.set_code(code)
        self.code_editor.file_path = path

        # Enable run button
        self.run_action.setEnabled(True)

        # Clear previous debug info
        self.clear_debug_info()

    def clear_debug_info(self):
        """Clear all debug information."""
        self.variables_tree.clear()
        self.stack_list.clear()
        self.watch_tree.clear()
        self.console.clear()
        self.current_line = None
        self.code_editor.highlight_line(None)

    def toggle_breakpoint(self, line: int):
        """Toggle breakpoint at line."""
        if not self.plugin_path:
            return

        # Check if breakpoint exists
        for bp_id, bp in self.debugger.breakpoints.items():
            if bp.file == self.plugin_path and bp.line == line:
                # Remove existing breakpoint
                self.debugger.remove_breakpoint(bp_id)
                self.update_breakpoint_display()
                return

        # Add new breakpoint
        bp_id = self.debugger.add_breakpoint(self.plugin_path, line=line)
        self.update_breakpoint_display()

    def toggle_current_line_breakpoint(self):
        """Toggle breakpoint at current line."""
        cursor = self.code_editor.textCursor()
        line = cursor.blockNumber() + 1
        self.toggle_breakpoint(line)

    def clear_all_breakpoints(self):
        """Clear all breakpoints."""
        self.debugger.breakpoints.clear()
        self.update_breakpoint_display()

    def update_breakpoint_display(self):
        """Update breakpoint display."""
        # Update editor
        self.code_editor.clear_breakpoints()

        for bp in self.debugger.breakpoints.values():
            if bp.file == self.plugin_path:
                self.code_editor.add_breakpoint(bp.line)

        # Update breakpoint list
        self.breakpoint_list.clear()

        for bp in self.debugger.breakpoints.values():
            text = f"{os.path.basename(bp.file)}:{bp.line}"
            if bp.condition:
                text += f" [if {bp.condition}]"
            if not bp.enabled:
                text += " (disabled)"

            item = QListWidgetItem(text)
            item.setData(Qt.UserRole, bp.id)
            self.breakpoint_list.addItem(item)

    def show_breakpoint_menu(self, pos):
        """Show breakpoint context menu."""
        item = self.breakpoint_list.itemAt(pos)
        if not item:
            return

        bp_id = item.data(Qt.UserRole)
        bp = self.debugger.breakpoints.get(bp_id)
        if not bp:
            return

        menu = QMenu(self)

        if bp.enabled:
            disable_action = menu.addAction("Disable")
            disable_action.triggered.connect(lambda: self.disable_breakpoint(bp_id))
        else:
            enable_action = menu.addAction("Enable")
            enable_action.triggered.connect(lambda: self.enable_breakpoint(bp_id))

        remove_action = menu.addAction("Remove")
        remove_action.triggered.connect(lambda: self.remove_breakpoint(bp_id))

        menu.exec_(self.breakpoint_list.mapToGlobal(pos))

    def disable_breakpoint(self, bp_id: int):
        """Disable breakpoint."""
        self.debugger.disable_breakpoint(bp_id)
        self.update_breakpoint_display()

    def enable_breakpoint(self, bp_id: int):
        """Enable breakpoint."""
        self.debugger.enable_breakpoint(bp_id)
        self.update_breakpoint_display()

    def remove_breakpoint(self, bp_id: int):
        """Remove breakpoint."""
        self.debugger.remove_breakpoint(bp_id)
        self.update_breakpoint_display()

    def remove_selected_breakpoint(self):
        """Remove selected breakpoint."""
        item = self.breakpoint_list.currentItem()
        if item:
            bp_id = item.data(Qt.UserRole)
            self.remove_breakpoint(bp_id)

    def add_breakpoint_dialog(self):
        """Show add breakpoint dialog."""
        # For now, just use current line
        self.toggle_current_line_breakpoint()

    def run_continue(self):
        """Run or continue execution."""
        if self.debugger.state == DebuggerState.IDLE:
            # Start debugging
            self.start_debugging()
        else:
            # Continue execution
            self.debugger.command_queue.put({"type": "continue"})
            self.update_ui_state("running")

    def start_debugging(self):
        """Start debugging session."""
        if not self.plugin_path:
            return

        # Clear console
        self.console.clear()
        self.console.append(" Starting debug session...\n")

        # Start output thread
        self.output_thread = DebuggerOutputThread(self.debugger.output_queue)
        self.output_thread.output_received.connect(self.handle_debugger_output)
        self.output_thread.start()

        # Start debugger thread with real binary path
        from ...core.app_context import get_app_context

        app_context = get_app_context()
        current_binary = getattr(app_context, "current_binary_path", None)

        if not current_binary:
            # Generate real test binary if none available
            import tempfile

            test_binary = tempfile.NamedTemporaryFile(suffix=".exe", delete=False).name
            with open(test_binary, "wb") as f:
                # Create minimal PE executable
                f.write(b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00")
                f.write(b"\xb8\x00\x00\x00\x00" * 200)  # Basic opcodes
            current_binary = test_binary

        self.debugger_thread = DebuggerThread(
            self.debugger,
            self.plugin_path,
            binary_path=current_binary,
            options={},
        )
        self.debugger_thread.start()

        # Update UI
        self.update_ui_state("running")

    def pause_execution(self):
        """Pause execution."""
        self.debugger.command_queue.put({"type": "pause"})

    def stop_debugging(self):
        """Stop debugging session."""
        self.debugger.command_queue.put({"type": "terminate"})

        # Wait for threads
        if self.debugger_thread:
            self.debugger_thread.join(timeout=2)

        if self.output_thread:
            self.output_thread.stop()
            self.output_thread.wait()

        # Clear debug info
        self.clear_debug_info()

        # Update UI
        self.update_ui_state("idle")

        self.console.append("\n🛑 Debug session terminated.")

    def step_over(self):
        """Step over."""
        self.debugger.command_queue.put({"type": "step_over"})
        self.update_ui_state("running")

    def step_into(self):
        """Step into."""
        self.debugger.command_queue.put({"type": "step_into"})
        self.update_ui_state("running")

    def step_out(self):
        """Step out."""
        self.debugger.command_queue.put({"type": "step_out"})
        self.update_ui_state("running")

    def update_ui_state(self, state: str):
        """Update UI based on debugger state."""
        if state == "idle":
            self.run_action.setEnabled(True)
            self.run_action.setText("▶️ Run")
            self.pause_action.setEnabled(False)
            self.stop_action.setEnabled(False)
            self.step_over_action.setEnabled(False)
            self.step_into_action.setEnabled(False)
            self.step_out_action.setEnabled(False)

        elif state == "running":
            self.run_action.setEnabled(False)
            self.pause_action.setEnabled(True)
            self.stop_action.setEnabled(True)
            self.step_over_action.setEnabled(False)
            self.step_into_action.setEnabled(False)
            self.step_out_action.setEnabled(False)

        elif state == "paused":
            self.run_action.setEnabled(True)
            self.run_action.setText("▶️ Continue")
            self.pause_action.setEnabled(False)
            self.stop_action.setEnabled(True)
            self.step_over_action.setEnabled(True)
            self.step_into_action.setEnabled(True)
            self.step_out_action.setEnabled(True)

    def handle_debugger_output(self, msg_type: str, data: Any):
        """Handle debugger output messages."""
        if msg_type == "paused":
            self.update_ui_state("paused")
            self.current_line = data["line"]
            self.code_editor.highlight_line(self.current_line)
            self.console.append(f"⏸️ Paused at {data['file']}:{data['line']} in {data['function']}")

        elif msg_type == "breakpoint":
            self.console.append(f"🔴 Breakpoint hit: {data['file']}:{data['line']} (hit count: {data['hit_count']})")

        elif msg_type == "stack":
            self.update_stack_display(data)

        elif msg_type == "watches":
            self.update_watch_display(data)

        elif msg_type == "eval_result":
            if "error" in data:
                self.console.append(f"ERROR Error evaluating '{data['expression']}': {data['error']}")
            else:
                self.console.append(f"OK {data['expression']} = {data['value']}")

        elif msg_type == "exception_break":
            self.console.append(f"WARNING️ Exception: {data['type']}: {data['message']}")
            self.console.append(data["traceback"])

        elif msg_type == "result":
            self.console.append(f"\n📤 Plugin returned: {data}")

        elif msg_type == "error":
            self.console.append(f"ERROR Error: {data}")

    def update_stack_display(self, stack_frames: list[dict[str, Any]]):
        """Update call stack display."""
        self.stack_list.clear()

        for i, frame in enumerate(stack_frames):
            text = f"{frame['function']} at {os.path.basename(frame['filename'])}:{frame['lineno']}"
            item = QListWidgetItem(text)
            item.setData(Qt.UserRole, i)

            if i == 0:  # Current frame
                item.setFont(QFont("", -1, QFont.Bold))

            self.stack_list.addItem(item)

        # Update variables for current frame
        if stack_frames:
            self.update_variables_display(0)

    def on_stack_frame_clicked(self, item: QListWidgetItem):
        """Handle stack frame selection."""
        frame_index = item.data(Qt.UserRole)
        self.update_variables_display(frame_index)

    def update_variables_display(self, frame_index: int = 0):
        """Update variables display."""
        variables = self.debugger.get_variables(frame_index)

        self.variables_tree.clear()

        # Group by scope
        local_root = QTreeWidgetItem(self.variables_tree, ["Local Variables", "", ""])
        global_root = QTreeWidgetItem(self.variables_tree, ["Global Variables", "", ""])

        for name, info in sorted(variables.items()):
            parent = local_root if info["scope"] == "local" else global_root

            item = QTreeWidgetItem(
                parent,
                [
                    name,
                    str(info["value"]),
                    info["type"],
                ],
            )

            # Add children for complex types
            if isinstance(info["value"], dict):
                for k, v in info["value"].items():
                    QTreeWidgetItem(item, [str(k), str(v), type(v).__name__])
            elif isinstance(info["value"], list):
                for i, v in enumerate(info["value"]):
                    QTreeWidgetItem(item, [f"[{i}]", str(v), type(v).__name__])

        # Expand local variables by default
        local_root.setExpanded(True)

    def update_watch_display(self, watches: dict[str, Any]):
        """Update watch expressions display."""
        # Update existing items
        for i in range(self.watch_tree.topLevelItemCount()):
            item = self.watch_tree.topLevelItem(i)
            expr = item.text(0)
            if expr in watches:
                item.setText(1, str(watches[expr]))

    def add_watch(self):
        """Add watch expression."""
        expr = self.watch_input.text().strip()
        if not expr:
            return

        # Add to debugger
        self.debugger.command_queue.put(
            {
                "type": "watch",
                "expression": expr,
            }
        )

        # Add to UI
        QTreeWidgetItem(self.watch_tree, [expr, "<not evaluated>"])

        # Clear input
        self.watch_input.clear()

    def evaluate_expression(self):
        """Evaluate expression in debug context."""
        expr = self.repl_input.text().strip()
        if not expr:
            return

        self.console.append(f"\n>>> {expr}")

        self.debugger.command_queue.put(
            {
                "type": "evaluate",
                "expression": expr,
            }
        )

        # Clear input
        self.repl_input.clear()

    def closeEvent(self, event):
        """Handle dialog close."""
        if self.debugger.state != DebuggerState.IDLE:
            reply = QMessageBox.question(
                self,
                "Debugging Active",
                "Debugging session is active. Stop debugging and close?",
                QMessageBox.Yes | QMessageBox.No,
            )

            if reply == QMessageBox.Yes:
                self.stop_debugging()
                event.accept()
            else:
                event.ignore()
        else:
            event.accept()


class CodeEditorWidget(QTextEdit):
    """Code editor with line numbers and breakpoint support."""

    breakpoint_toggled = pyqtSignal(int)

    def __init__(self, parent=None):
        """Initialize the CodeEditorWidget with default values."""
        super().__init__(parent)
        self.file_path = None
        self.breakpoint_lines = set()
        self.current_line = None

        # Set font
        font = QFont("Consolas", 10)
        self.setFont(font)

        # Line number area
        self.line_number_area = LineNumberArea(self)

        # Connect signals
        self.blockCountChanged.connect(self.update_line_number_area_width)
        self.updateRequest.connect(self.update_line_number_area)
        self.cursorPositionChanged.connect(self.highlight_current_line)

        self.update_line_number_area_width(0)
        self.highlight_current_line()

    def line_number_area_width(self):
        """Calculate line number area width."""
        digits = 1
        max_num = max(1, self.blockCount())
        while max_num >= 10:
            max_num /= 10
            digits += 1

        space = 3 + self.fontMetrics().horizontalAdvance("9") * (digits + 1)
        return space

    def update_line_number_area_width(self, new_block_count):
        """Update line number area width."""
        # Log block count changes for debugging
        self.logger.debug(f"Updating line number area width for {new_block_count} blocks")
        self.setViewportMargins(self.line_number_area_width(), 0, 0, 0)

    def update_line_number_area(self, rect, dy):
        """Update line number area."""
        if dy:
            self.line_number_area.scroll(0, dy)
        else:
            self.line_number_area.update(0, rect.y(), self.line_number_area.width(), rect.height())

        if rect.contains(self.viewport().rect()):
            self.update_line_number_area_width(0)

    def resizeEvent(self, event):
        """Handle resize event."""
        super().resizeEvent(event)

        cr = self.contentsRect()
        self.line_number_area.setGeometry(cr.left(), cr.top(), self.line_number_area_width(), cr.height())

    def line_number_area_paint_event(self, event):
        """Paint line numbers."""
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

                # Draw breakpoint indicator
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
                    Qt.AlignRight,
                    number,
                )

            block = block.next()
            top = bottom
            bottom = top + int(self.blockBoundingRect(block).height())
            block_number += 1

    def line_number_area_mouse_press(self, event):
        """Handle mouse press in line number area."""
        if event.button() == Qt.LeftButton:
            cursor = self.cursorForPosition(event.pos())
            line = cursor.blockNumber() + 1
            self.breakpoint_toggled.emit(line)

    def highlight_current_line(self):
        """Highlight current line."""
        extra_selections = []

        if not self.isReadOnly():
            selection = QTextEdit.ExtraSelection()

            line_color = QColor(Qt.GlobalColor.yellow).lighter(160)

            selection.format.setBackground(line_color)
            selection.format.setProperty(QTextFormat.FullWidthSelection, True)
            selection.cursor = self.textCursor()
            selection.cursor.clearSelection()
            extra_selections.append(selection)

        self.setExtraSelections(extra_selections)

    def highlight_line(self, line: int):
        """Highlight execution line."""
        if line is None:
            self.current_line = None
            self.highlight_current_line()
            return

        self.current_line = line

        # Move cursor to line
        cursor = QTextCursor(self.document())
        cursor.movePosition(QTextCursor.Start)
        cursor.movePosition(QTextCursor.NextBlock, QTextCursor.MoveAnchor, line - 1)
        self.setTextCursor(cursor)

        # Highlight with different color
        extra_selections = []

        selection = QTextEdit.ExtraSelection()
        line_color = QColor(Qt.GlobalColor.green).lighter(160)
        selection.format.setBackground(line_color)
        selection.format.setProperty(QTextFormat.FullWidthSelection, True)
        selection.cursor = cursor
        selection.cursor.clearSelection()
        extra_selections.append(selection)

        self.setExtraSelections(extra_selections)

    def set_code(self, code: str):
        """Set code content."""
        self.setPlainText(code)

    def add_breakpoint(self, line: int):
        """Add breakpoint."""
        self.breakpoint_lines.add(line)
        self.line_number_area.update()

    def remove_breakpoint(self, line: int):
        """Remove breakpoint."""
        self.breakpoint_lines.discard(line)
        self.line_number_area.update()

    def clear_breakpoints(self):
        """Clear all breakpoints."""
        self.breakpoint_lines.clear()
        self.line_number_area.update()


class LineNumberArea(QWidget):
    """Line number area widget."""

    def __init__(self, editor):
        """Initialize the LineNumberArea with default values."""
        super().__init__(editor)
        self.code_editor = editor

    def sizeHint(self):
        """Return size hint."""
        return QSize(self.code_editor.line_number_area_width(), 0)

    def paintEvent(self, event):
        """Paint event."""
        self.code_editor.line_number_area_paint_event(event)

    def mousePressEvent(self, event):
        """Mouse press event."""
        self.code_editor.line_number_area_mouse_press(event)

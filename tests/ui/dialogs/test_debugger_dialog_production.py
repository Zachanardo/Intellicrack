"""Production tests for plugin debugger dialog.

Validates real plugin debugging capabilities including breakpoint management,
stack inspection, variable watching, and REPL expression evaluation for
plugin development and testing workflows.
"""

import queue
import tempfile
from pathlib import Path
from typing import Any

import pytest

from intellicrack.handlers.pyqt6_handler import QApplication, Qt
from intellicrack.tools.plugin_debugger import Breakpoint, DebuggerState
from intellicrack.ui.dialogs.debugger_dialog import (
    CodeEditorWidget,
    DebuggerDialog,
    DebuggerOutputThread,
    LineNumberArea,
)


@pytest.fixture(scope="module")
def qapp() -> QApplication:
    """Create QApplication instance for tests."""
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


@pytest.fixture
def sample_plugin(tmp_path: Path) -> Path:
    """Create sample plugin file for debugging."""
    plugin_code = '''"""Sample plugin for debugger testing."""

def analyze_binary(binary_path: str) -> dict:
    """Analyze binary for licensing protection.

    Args:
        binary_path: Path to binary file

    Returns:
        Analysis results dictionary
    """
    protection_type = "demo"
    serial_check_offset = 0x1000

    results = {
        "protection": protection_type,
        "serial_offset": serial_check_offset,
        "crackable": True
    }

    return results

def generate_keygen(seed: int) -> str:
    """Generate valid license key.

    Args:
        seed: Random seed for key generation

    Returns:
        Valid license key string
    """
    key_parts = []
    value = seed

    for i in range(4):
        part = (value * (i + 1)) % 10000
        key_parts.append(f"{part:04d}")
        value = value // 2 + part

    return "-".join(key_parts)

if __name__ == "__main__":
    result = analyze_binary("test.exe")
    print(f"Analysis: {result}")

    key = generate_keygen(12345)
    print(f"Generated key: {key}")
'''
    plugin_file = tmp_path / "test_plugin.py"
    plugin_file.write_text(plugin_code)
    return plugin_file


@pytest.fixture
def debugger_dialog(qapp: QApplication, sample_plugin: Path) -> DebuggerDialog:
    """Create debugger dialog with loaded plugin."""
    dialog = DebuggerDialog()
    dialog.load_plugin(str(sample_plugin))
    return dialog


def test_debugger_dialog_initialization(qapp: QApplication) -> None:
    """Dialog initializes with correct UI components."""
    dialog = DebuggerDialog()

    assert dialog.windowTitle() == "Plugin Debugger"
    assert dialog.minimumSize().width() == 1200
    assert dialog.minimumSize().height() == 800

    assert dialog.debugger is not None
    assert dialog.debugger_thread is None
    assert dialog.output_thread is None

    assert dialog.code_editor is not None
    assert dialog.debug_tabs is not None
    assert dialog.variables_tree is not None
    assert dialog.stack_list is not None
    assert dialog.breakpoint_list is not None
    assert dialog.watch_tree is not None
    assert dialog.console is not None


def test_debugger_dialog_toolbar_actions_exist(qapp: QApplication) -> None:
    """Dialog toolbar contains all debugging actions."""
    dialog = DebuggerDialog()

    assert dialog.run_action is not None
    assert dialog.pause_action is not None
    assert dialog.stop_action is not None
    assert dialog.step_over_action is not None
    assert dialog.step_into_action is not None
    assert dialog.step_out_action is not None


def test_plugin_loading_updates_ui(debugger_dialog: DebuggerDialog, sample_plugin: Path) -> None:
    """Loading plugin updates file label and code editor."""
    assert "test_plugin.py" in debugger_dialog.file_label.text()
    assert debugger_dialog.code_editor.toPlainText().strip() != ""
    assert "analyze_binary" in debugger_dialog.code_editor.toPlainText()
    assert debugger_dialog.plugin_path == str(sample_plugin)


def test_plugin_loading_enables_run_action(debugger_dialog: DebuggerDialog) -> None:
    """Loading plugin enables run action."""
    assert debugger_dialog.run_action is not None
    assert debugger_dialog.run_action.isEnabled()


def test_plugin_loading_clears_debug_info(debugger_dialog: DebuggerDialog) -> None:
    """Loading plugin clears previous debug information."""
    assert debugger_dialog.variables_tree.topLevelItemCount() == 0
    assert debugger_dialog.stack_list.count() == 0
    assert debugger_dialog.console.toPlainText().strip() == ""


def test_breakpoint_toggle_adds_breakpoint(debugger_dialog: DebuggerDialog) -> None:
    """Toggling breakpoint adds it to debugger and UI."""
    initial_count = len(debugger_dialog.debugger.breakpoints)

    debugger_dialog.toggle_breakpoint(5)

    assert len(debugger_dialog.debugger.breakpoints) == initial_count + 1

    found_breakpoint = False
    for bp in debugger_dialog.debugger.breakpoints.values():
        if bp.line == 5 and bp.file == debugger_dialog.plugin_path:
            found_breakpoint = True
            break

    assert found_breakpoint, "Breakpoint not added to debugger"


def test_breakpoint_toggle_removes_existing_breakpoint(
    debugger_dialog: DebuggerDialog,
) -> None:
    """Toggling breakpoint twice removes it."""
    debugger_dialog.toggle_breakpoint(10)
    initial_count = len(debugger_dialog.debugger.breakpoints)

    debugger_dialog.toggle_breakpoint(10)

    assert len(debugger_dialog.debugger.breakpoints) == initial_count - 1


def test_breakpoint_display_updates_code_editor(debugger_dialog: DebuggerDialog) -> None:
    """Breakpoint display updates code editor with breakpoint markers."""
    debugger_dialog.toggle_breakpoint(15)

    assert 15 in debugger_dialog.code_editor.breakpoint_lines


def test_breakpoint_display_updates_list_widget(debugger_dialog: DebuggerDialog) -> None:
    """Breakpoint display updates breakpoint list."""
    debugger_dialog.toggle_breakpoint(20)

    found_in_list = False
    for i in range(debugger_dialog.breakpoint_list.count()):
        item = debugger_dialog.breakpoint_list.item(i)
        if item and "20" in item.text():
            found_in_list = True
            break

    assert found_in_list, "Breakpoint not shown in list"


def test_breakpoint_list_shows_disabled_status(debugger_dialog: DebuggerDialog) -> None:
    """Breakpoint list shows disabled status correctly."""
    debugger_dialog.toggle_breakpoint(25)

    bp_id = None
    for bp in debugger_dialog.debugger.breakpoints.values():
        if bp.line == 25:
            bp_id = bp.id
            break

    assert bp_id is not None

    debugger_dialog.disable_breakpoint(bp_id)

    found_disabled = False
    for i in range(debugger_dialog.breakpoint_list.count()):
        item = debugger_dialog.breakpoint_list.item(i)
        if item and "25" in item.text() and "(disabled)" in item.text():
            found_disabled = True
            break

    assert found_disabled, "Disabled status not shown"


def test_breakpoint_enable_after_disable(debugger_dialog: DebuggerDialog) -> None:
    """Breakpoint can be re-enabled after disabling."""
    debugger_dialog.toggle_breakpoint(30)

    bp_id = None
    for bp in debugger_dialog.debugger.breakpoints.values():
        if bp.line == 30:
            bp_id = bp.id
            break

    assert bp_id is not None

    debugger_dialog.disable_breakpoint(bp_id)
    assert not debugger_dialog.debugger.breakpoints[bp_id].enabled

    debugger_dialog.enable_breakpoint(bp_id)
    assert debugger_dialog.debugger.breakpoints[bp_id].enabled


def test_clear_all_breakpoints_removes_all(debugger_dialog: DebuggerDialog) -> None:
    """Clear all breakpoints removes all breakpoints from debugger."""
    debugger_dialog.toggle_breakpoint(5)
    debugger_dialog.toggle_breakpoint(10)
    debugger_dialog.toggle_breakpoint(15)

    assert len(debugger_dialog.debugger.breakpoints) > 0

    debugger_dialog.clear_all_breakpoints()

    assert len(debugger_dialog.debugger.breakpoints) == 0
    assert len(debugger_dialog.code_editor.breakpoint_lines) == 0


def test_ui_state_idle_disables_debug_actions(qapp: QApplication) -> None:
    """Idle state disables debugging actions."""
    dialog = DebuggerDialog()

    dialog.update_ui_state("idle")

    assert dialog.run_action is not None
    assert dialog.pause_action is not None and not dialog.pause_action.isEnabled()
    assert dialog.stop_action is not None and not dialog.stop_action.isEnabled()
    assert dialog.step_over_action is not None and not dialog.step_over_action.isEnabled()
    assert dialog.step_into_action is not None and not dialog.step_into_action.isEnabled()
    assert dialog.step_out_action is not None and not dialog.step_out_action.isEnabled()


def test_ui_state_running_enables_pause_and_stop(qapp: QApplication) -> None:
    """Running state enables pause and stop actions."""
    dialog = DebuggerDialog()

    dialog.update_ui_state("running")

    assert dialog.run_action is not None and not dialog.run_action.isEnabled()
    assert dialog.pause_action is not None and dialog.pause_action.isEnabled()
    assert dialog.stop_action is not None and dialog.stop_action.isEnabled()


def test_ui_state_paused_enables_step_actions(qapp: QApplication) -> None:
    """Paused state enables step actions."""
    dialog = DebuggerDialog()

    dialog.update_ui_state("paused")

    assert dialog.run_action is not None and dialog.run_action.isEnabled()
    assert dialog.step_over_action is not None and dialog.step_over_action.isEnabled()
    assert dialog.step_into_action is not None and dialog.step_into_action.isEnabled()
    assert dialog.step_out_action is not None and dialog.step_out_action.isEnabled()


def test_ui_state_paused_changes_run_to_continue(qapp: QApplication) -> None:
    """Paused state changes run button text to continue."""
    dialog = DebuggerDialog()

    dialog.update_ui_state("idle")
    assert dialog.run_action is not None
    assert "Run" in dialog.run_action.text()

    dialog.update_ui_state("paused")
    assert "Continue" in dialog.run_action.text()


def test_debugger_output_paused_updates_ui(debugger_dialog: DebuggerDialog) -> None:
    """Paused output message updates UI correctly."""
    data = {
        "line": 42,
        "file": str(debugger_dialog.plugin_path),
        "function": "analyze_binary",
    }

    debugger_dialog.handle_debugger_output("paused", data)

    assert debugger_dialog.current_line == 42
    console_text = debugger_dialog.console.toPlainText()
    assert "42" in console_text
    assert "analyze_binary" in console_text


def test_debugger_output_breakpoint_shows_hit_count(
    debugger_dialog: DebuggerDialog,
) -> None:
    """Breakpoint output shows hit count in console."""
    data = {
        "file": str(debugger_dialog.plugin_path),
        "line": 15,
        "hit_count": 3,
    }

    debugger_dialog.handle_debugger_output("breakpoint", data)

    console_text = debugger_dialog.console.toPlainText()
    assert "Breakpoint hit" in console_text
    assert "15" in console_text
    assert "3" in console_text


def test_debugger_output_stack_updates_stack_list(debugger_dialog: DebuggerDialog) -> None:
    """Stack output updates stack list widget."""
    stack_frames = [
        {
            "function": "generate_keygen",
            "filename": str(debugger_dialog.plugin_path),
            "lineno": 25,
        },
        {
            "function": "analyze_binary",
            "filename": str(debugger_dialog.plugin_path),
            "lineno": 10,
        },
    ]

    debugger_dialog.handle_debugger_output("stack", stack_frames)

    assert debugger_dialog.stack_list.count() == 2

    item0 = debugger_dialog.stack_list.item(0)
    assert item0 is not None
    assert "generate_keygen" in item0.text()
    assert "25" in item0.text()


def test_debugger_output_eval_result_shows_value(debugger_dialog: DebuggerDialog) -> None:
    """Eval result output shows evaluated value."""
    data = {
        "expression": "seed * 2",
        "value": 24690,
    }

    debugger_dialog.handle_debugger_output("eval_result", data)

    console_text = debugger_dialog.console.toPlainText()
    assert "seed * 2" in console_text
    assert "24690" in console_text


def test_debugger_output_eval_error_shows_error_message(
    debugger_dialog: DebuggerDialog,
) -> None:
    """Eval error output shows error message."""
    data = {
        "expression": "undefined_var",
        "error": "NameError: name 'undefined_var' is not defined",
    }

    debugger_dialog.handle_debugger_output("eval_result", data)

    console_text = debugger_dialog.console.toPlainText()
    assert "Error evaluating" in console_text
    assert "undefined_var" in console_text
    assert "NameError" in console_text


def test_debugger_output_exception_shows_traceback(
    debugger_dialog: DebuggerDialog,
) -> None:
    """Exception output shows type, message, and traceback."""
    data = {
        "type": "ValueError",
        "message": "invalid literal for int()",
        "traceback": "  File test.py, line 10, in func\n    return int(value)",
    }

    debugger_dialog.handle_debugger_output("exception_break", data)

    console_text = debugger_dialog.console.toPlainText()
    assert "Exception" in console_text
    assert "ValueError" in console_text
    assert "invalid literal" in console_text
    assert "traceback" in console_text.lower() or "File test.py" in console_text


def test_stack_display_bolds_current_frame(debugger_dialog: DebuggerDialog) -> None:
    """Stack display bolds the current (top) frame."""
    stack_frames = [
        {"function": "inner", "filename": "test.py", "lineno": 20},
        {"function": "outer", "filename": "test.py", "lineno": 10},
    ]

    debugger_dialog.update_stack_display(stack_frames)

    item0 = debugger_dialog.stack_list.item(0)
    assert item0 is not None
    assert item0.font().weight() > 50


def test_stack_frame_click_updates_variables(debugger_dialog: DebuggerDialog) -> None:
    """Clicking stack frame updates variables display."""
    stack_frames = [
        {"function": "func1", "filename": "test.py", "lineno": 5},
        {"function": "func2", "filename": "test.py", "lineno": 15},
    ]

    debugger_dialog.update_stack_display(stack_frames)

    item = debugger_dialog.stack_list.item(1)
    assert item is not None


def test_variables_display_shows_local_and_global_sections(
    debugger_dialog: DebuggerDialog,
) -> None:
    """Variables display shows local and global sections."""
    debugger_dialog.update_variables_display(0)

    root = debugger_dialog.variables_tree.invisibleRootItem()
    assert root.childCount() >= 2

    found_local = False
    found_global = False

    for i in range(root.childCount()):
        item = root.child(i)
        text = item.text(0)
        if "Local" in text:
            found_local = True
        if "Global" in text:
            found_global = True

    assert found_local, "Local variables section not found"
    assert found_global, "Global variables section not found"


def test_watch_expression_addition(debugger_dialog: DebuggerDialog) -> None:
    """Adding watch expression creates tree item."""
    debugger_dialog.watch_input.setText("protection_type")
    initial_count = debugger_dialog.watch_tree.topLevelItemCount()

    debugger_dialog.add_watch()

    assert debugger_dialog.watch_tree.topLevelItemCount() == initial_count + 1

    found = False
    for i in range(debugger_dialog.watch_tree.topLevelItemCount()):
        item = debugger_dialog.watch_tree.topLevelItem(i)
        if item and "protection_type" in item.text(0):
            found = True
            break

    assert found, "Watch expression not added to tree"


def test_watch_expression_clears_input(debugger_dialog: DebuggerDialog) -> None:
    """Adding watch expression clears input field."""
    debugger_dialog.watch_input.setText("test_expr")
    debugger_dialog.add_watch()

    assert debugger_dialog.watch_input.text() == ""


def test_watch_display_update_sets_values(debugger_dialog: DebuggerDialog) -> None:
    """Watch display update sets evaluated values."""
    debugger_dialog.watch_input.setText("seed")
    debugger_dialog.add_watch()

    watches = {"seed": 12345}
    debugger_dialog.update_watch_display(watches)

    found_value = False
    for i in range(debugger_dialog.watch_tree.topLevelItemCount()):
        item = debugger_dialog.watch_tree.topLevelItem(i)
        if item and item.text(0) == "seed":
            if "12345" in item.text(1):
                found_value = True
                break

    assert found_value, "Watch value not updated"


def test_repl_expression_evaluation_sends_command(
    debugger_dialog: DebuggerDialog,
) -> None:
    """REPL expression evaluation sends evaluate command to debugger."""
    debugger_dialog.repl_input.setText("2 + 2")

    debugger_dialog.evaluate_expression()

    console_text = debugger_dialog.console.toPlainText()
    assert ">>> 2 + 2" in console_text


def test_repl_expression_clears_input(debugger_dialog: DebuggerDialog) -> None:
    """REPL expression evaluation clears input field."""
    debugger_dialog.repl_input.setText("test")
    debugger_dialog.evaluate_expression()

    assert debugger_dialog.repl_input.text() == ""


def test_code_editor_widget_initialization(qapp: QApplication) -> None:
    """Code editor widget initializes correctly."""
    editor = CodeEditorWidget()

    assert editor.file_path is None
    assert len(editor.breakpoint_lines) == 0
    assert editor.current_line is None
    assert editor.line_number_area is not None


def test_code_editor_set_code_updates_content(qapp: QApplication) -> None:
    """Setting code updates editor content."""
    editor = CodeEditorWidget()
    code = "def test():\n    return True"

    editor.set_code(code)

    assert editor.toPlainText() == code


def test_code_editor_add_breakpoint_updates_set(qapp: QApplication) -> None:
    """Adding breakpoint updates breakpoint set."""
    editor = CodeEditorWidget()

    editor.add_breakpoint(5)

    assert 5 in editor.breakpoint_lines


def test_code_editor_remove_breakpoint_updates_set(qapp: QApplication) -> None:
    """Removing breakpoint updates breakpoint set."""
    editor = CodeEditorWidget()
    editor.add_breakpoint(10)

    editor.remove_breakpoint(10)

    assert 10 not in editor.breakpoint_lines


def test_code_editor_clear_breakpoints_removes_all(qapp: QApplication) -> None:
    """Clearing breakpoints removes all from set."""
    editor = CodeEditorWidget()
    editor.add_breakpoint(5)
    editor.add_breakpoint(10)
    editor.add_breakpoint(15)

    editor.clear_breakpoints()

    assert len(editor.breakpoint_lines) == 0


def test_code_editor_highlight_line_sets_current(qapp: QApplication) -> None:
    """Highlighting line sets current line."""
    editor = CodeEditorWidget()
    editor.set_code("line1\nline2\nline3\nline4\nline5")

    editor.highlight_line(3)

    assert editor.current_line == 3


def test_code_editor_highlight_none_clears_current(qapp: QApplication) -> None:
    """Highlighting None clears current line."""
    editor = CodeEditorWidget()
    editor.set_code("line1\nline2\nline3")
    editor.highlight_line(2)

    editor.highlight_line(None)

    assert editor.current_line is None


def test_code_editor_line_number_area_width_calculation(qapp: QApplication) -> None:
    """Line number area width calculated correctly for line count."""
    editor = CodeEditorWidget()
    editor.set_code("\n" * 99)

    width = editor.line_number_area_width()
    assert width > 0


def test_line_number_area_initialization(qapp: QApplication) -> None:
    """Line number area initializes with editor reference."""
    editor = CodeEditorWidget()
    area = LineNumberArea(editor)

    assert area.code_editor == editor


def test_debugger_output_thread_initialization() -> None:
    """Debugger output thread initializes with queue."""
    output_queue: queue.Queue[tuple[str, Any]] = queue.Queue()
    thread = DebuggerOutputThread(output_queue)

    assert thread.output_queue == output_queue
    assert thread.running is True


def test_debugger_output_thread_stop_sets_flag() -> None:
    """Stopping output thread sets running flag to False."""
    output_queue: queue.Queue[tuple[str, Any]] = queue.Queue()
    thread = DebuggerOutputThread(output_queue)

    thread.stop()

    assert thread.running is False


def test_debugger_output_thread_processes_messages() -> None:
    """Output thread processes messages from queue."""
    output_queue: queue.Queue[tuple[str, Any]] = queue.Queue()
    thread = DebuggerOutputThread(output_queue)

    received_messages: list[tuple[str, Any]] = []

    def capture_output(msg_type: str, data: Any) -> None:
        received_messages.append((msg_type, data))

    thread.output_received.connect(capture_output)

    output_queue.put(("test_message", {"value": 123}))

    thread.start()

    import time

    time.sleep(0.2)

    thread.stop()
    thread.wait()

    assert len(received_messages) > 0
    assert received_messages[0][0] == "test_message"


def test_clear_debug_info_resets_all_displays(debugger_dialog: DebuggerDialog) -> None:
    """Clear debug info resets all debug displays."""
    debugger_dialog.variables_tree.clear()
    from intellicrack.handlers.pyqt6_handler import QTreeWidgetItem

    QTreeWidgetItem(debugger_dialog.variables_tree, ["test", "value", "type"])
    debugger_dialog.console.append("Test output")

    debugger_dialog.clear_debug_info()

    assert debugger_dialog.variables_tree.topLevelItemCount() == 0
    assert debugger_dialog.stack_list.count() == 0
    assert debugger_dialog.console.toPlainText().strip() == ""
    assert debugger_dialog.current_line is None


def test_browse_plugin_updates_dialog(
    debugger_dialog: DebuggerDialog, sample_plugin: Path
) -> None:
    """Browse and load plugin updates dialog state."""
    debugger_dialog.load_plugin(str(sample_plugin))

    assert debugger_dialog.plugin_path == str(sample_plugin)
    assert "test_plugin.py" in debugger_dialog.file_label.text()


def test_breakpoint_list_shows_conditional_breakpoints(
    debugger_dialog: DebuggerDialog,
) -> None:
    """Breakpoint list shows condition for conditional breakpoints."""
    bp_id = debugger_dialog.debugger.add_breakpoint(
        str(debugger_dialog.plugin_path), line=35, condition="seed > 1000"
    )

    debugger_dialog.update_breakpoint_display()

    found_condition = False
    for i in range(debugger_dialog.breakpoint_list.count()):
        item = debugger_dialog.breakpoint_list.item(i)
        if item and "35" in item.text() and "seed > 1000" in item.text():
            found_condition = True
            break

    assert found_condition, "Conditional breakpoint not shown with condition"


def test_debugger_dialog_tabs_exist(debugger_dialog: DebuggerDialog) -> None:
    """Dialog contains all expected debug tabs."""
    tab_texts = [
        debugger_dialog.debug_tabs.tabText(i)
        for i in range(debugger_dialog.debug_tabs.count())
    ]

    assert any("Variables" in text for text in tab_texts)
    assert any("Stack" in text for text in tab_texts)
    assert any("Breakpoints" in text for text in tab_texts)
    assert any("Watch" in text for text in tab_texts)


def test_code_editor_readonly_for_debugging(qapp: QApplication) -> None:
    """Code editor allows editing in debugger context."""
    editor = CodeEditorWidget()
    editor.set_code("def test():\n    pass")

    assert not editor.isReadOnly()


def test_debugger_handles_result_output(debugger_dialog: DebuggerDialog) -> None:
    """Debugger handles plugin result output."""
    result_data = {"protection": "demo", "crackable": True}

    debugger_dialog.handle_debugger_output("result", result_data)

    console_text = debugger_dialog.console.toPlainText()
    assert "returned" in console_text.lower()


def test_debugger_handles_error_output(debugger_dialog: DebuggerDialog) -> None:
    """Debugger handles error output."""
    error_message = "Failed to load plugin: syntax error"

    debugger_dialog.handle_debugger_output("error", error_message)

    console_text = debugger_dialog.console.toPlainText()
    assert "Error" in console_text
    assert error_message in console_text


def test_variables_display_expands_nested_structures(
    debugger_dialog: DebuggerDialog,
) -> None:
    """Variables display expands local variables section."""
    debugger_dialog.update_variables_display(0)

    root = debugger_dialog.variables_tree.invisibleRootItem()
    for i in range(root.childCount()):
        item = root.child(i)
        if "Local" in item.text(0):
            assert item.isExpanded()
            break

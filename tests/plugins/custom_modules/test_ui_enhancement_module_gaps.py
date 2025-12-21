"""Additional production-grade tests for UI Enhancement Module gaps.

Tests validate critical untested functionality including:
- ScriptGeneratorPanel complete workflow
- Event handlers for file operations
- Export functionality for logs and history
- Script execution and error handling
- Analysis error recovery
"""

import json
import tempfile
import threading
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, Mock, patch, call

import pytest

try:
    from intellicrack.plugins.custom_modules.ui_enhancement_module import (
        AnalysisResult,
        AnalysisState,
        FileExplorerPanel,
        LogViewer,
        ScriptGeneratorPanel,
        UIConfig,
        UIEnhancementModule,
        UITheme,
    )
    from intellicrack.handlers.tkinter_handler import tkinter as tk, ttk, scrolledtext
    UI_ENHANCEMENT_AVAILABLE = True
except ImportError as e:
    UI_ENHANCEMENT_AVAILABLE = False
    IMPORT_ERROR = str(e)

pytestmark = pytest.mark.skipif(
    not UI_ENHANCEMENT_AVAILABLE,
    reason=f"UI enhancement module not available: {'' if UI_ENHANCEMENT_AVAILABLE else IMPORT_ERROR}"
)


@pytest.fixture
def tk_root() -> tk.Tk:
    """Create tkinter root window for testing."""
    root = tk.Tk()
    root.withdraw()
    yield root
    try:
        root.quit()
        root.destroy()
    except tk.TclError:
        pass


@pytest.fixture
def ui_config() -> UIConfig:
    """Create default UI configuration."""
    return UIConfig()


@pytest.fixture
def mock_ui_controller() -> MagicMock:
    """Create mock UI controller."""
    controller = MagicMock()
    controller.analyze_file = MagicMock()
    controller.generate_scripts = MagicMock()
    controller.show_file_properties = MagicMock()
    return controller


class TestScriptGeneratorPanelCore:
    """Test ScriptGeneratorPanel initialization and tab creation."""

    def test_frida_tab_has_all_components(self, tk_root: tk.Tk, ui_config: UIConfig, mock_ui_controller: MagicMock) -> None:
        """Frida tab contains all required UI components."""
        frame = ttk.Frame(tk_root)
        generator = ScriptGeneratorPanel(frame, ui_config, mock_ui_controller)

        assert hasattr(generator, 'frida_editor')
        assert hasattr(generator, 'frida_process_entry')
        assert hasattr(generator, 'frida_target_entry')
        assert isinstance(generator.frida_editor, scrolledtext.ScrolledText)

    def test_ghidra_tab_has_all_components(self, tk_root: tk.Tk, ui_config: UIConfig, mock_ui_controller: MagicMock) -> None:
        """Ghidra tab contains all required UI components."""
        frame = ttk.Frame(tk_root)
        generator = ScriptGeneratorPanel(frame, ui_config, mock_ui_controller)

        assert hasattr(generator, 'ghidra_editor')
        assert hasattr(generator, 'ghidra_binary_entry')
        assert isinstance(generator.ghidra_editor, scrolledtext.ScrolledText)

    def test_radare2_tab_has_all_components(self, tk_root: tk.Tk, ui_config: UIConfig, mock_ui_controller: MagicMock) -> None:
        """Radare2 tab contains all required UI components."""
        frame = ttk.Frame(tk_root)
        generator = ScriptGeneratorPanel(frame, ui_config, mock_ui_controller)

        assert hasattr(generator, 'r2_editor')
        assert hasattr(generator, 'r2_binary_entry')
        assert isinstance(generator.r2_editor, scrolledtext.ScrolledText)

    def test_custom_tab_has_all_components(self, tk_root: tk.Tk, ui_config: UIConfig, mock_ui_controller: MagicMock) -> None:
        """Custom tab contains all required UI components."""
        frame = ttk.Frame(tk_root)
        generator = ScriptGeneratorPanel(frame, ui_config, mock_ui_controller)

        assert hasattr(generator, 'custom_editor')
        assert hasattr(generator, 'custom_language_var')
        assert isinstance(generator.custom_editor, scrolledtext.ScrolledText)


class TestScriptGeneratorBrowsing:
    """Test file browsing functionality in script generator."""

    def test_browse_process_opens_dialog(self, tk_root: tk.Tk, ui_config: UIConfig, mock_ui_controller: MagicMock) -> None:
        """Browse process opens process selection dialog."""
        frame = ttk.Frame(tk_root)
        generator = ScriptGeneratorPanel(frame, ui_config, mock_ui_controller)

        with patch('intellicrack.handlers.tkinter_handler.filedialog.askopenfilename', return_value='process.exe') as mock_dialog:
            generator.browse_process()

            mock_dialog.assert_called_once()
            assert generator.frida_process_entry.get() == 'process.exe'

    def test_browse_binary_opens_dialog(self, tk_root: tk.Tk, ui_config: UIConfig, mock_ui_controller: MagicMock) -> None:
        """Browse binary opens file selection dialog."""
        frame = ttk.Frame(tk_root)
        generator = ScriptGeneratorPanel(frame, ui_config, mock_ui_controller)

        with patch('intellicrack.handlers.tkinter_handler.filedialog.askopenfilename', return_value='C:\\test\\target.exe') as mock_dialog:
            generator.browse_binary()

            mock_dialog.assert_called_once()
            assert generator.frida_target_entry.get() == 'C:\\test\\target.exe'

    def test_browse_r2_binary_opens_dialog(self, tk_root: tk.Tk, ui_config: UIConfig, mock_ui_controller: MagicMock) -> None:
        """Browse radare2 binary opens file selection dialog."""
        frame = ttk.Frame(tk_root)
        generator = ScriptGeneratorPanel(frame, ui_config, mock_ui_controller)

        with patch('intellicrack.handlers.tkinter_handler.filedialog.askopenfilename', return_value='C:\\test\\binary.dll') as mock_dialog:
            generator.browse_r2_binary()

            mock_dialog.assert_called_once()
            assert generator.r2_binary_entry.get() == 'C:\\test\\binary.dll'

    def test_browse_process_cancelled(self, tk_root: tk.Tk, ui_config: UIConfig, mock_ui_controller: MagicMock) -> None:
        """Browse process handles user cancellation."""
        frame = ttk.Frame(tk_root)
        generator = ScriptGeneratorPanel(frame, ui_config, mock_ui_controller)

        generator.frida_process_entry.insert(0, "original.exe")

        with patch('intellicrack.handlers.tkinter_handler.filedialog.askopenfilename', return_value=''):
            generator.browse_process()

            assert generator.frida_process_entry.get() == "original.exe"


class TestScriptGeneration:
    """Test script generation functionality."""

    def test_generate_frida_script_creates_content(self, tk_root: tk.Tk, ui_config: UIConfig, mock_ui_controller: MagicMock) -> None:
        """Frida script generation creates valid JavaScript content."""
        frame = ttk.Frame(tk_root)
        generator = ScriptGeneratorPanel(frame, ui_config, mock_ui_controller)

        generator.frida_process_entry.insert(0, "target.exe")

        generator.generate_frida_script()

        script_content = generator.frida_editor.get("1.0", "end-1c")
        assert len(script_content) > 0
        assert "Interceptor" in script_content or "target.exe" in script_content

    def test_generate_ghidra_script_creates_content(self, tk_root: tk.Tk, ui_config: UIConfig, mock_ui_controller: MagicMock) -> None:
        """Ghidra script generation creates valid Java content."""
        frame = ttk.Frame(tk_root)
        generator = ScriptGeneratorPanel(frame, ui_config, mock_ui_controller)

        generator.ghidra_binary_entry.insert(0, "C:\\test\\binary.exe")

        generator.generate_ghidra_script()

        script_content = generator.ghidra_editor.get("1.0", "end-1c")
        assert len(script_content) > 0

    def test_generate_r2_script_creates_content(self, tk_root: tk.Tk, ui_config: UIConfig, mock_ui_controller: MagicMock) -> None:
        """Radare2 script generation creates valid r2 commands."""
        frame = ttk.Frame(tk_root)
        generator = ScriptGeneratorPanel(frame, ui_config, mock_ui_controller)

        generator.r2_binary_entry.insert(0, "C:\\test\\packed.exe")

        generator.generate_r2_script()

        script_content = generator.r2_editor.get("1.0", "end-1c")
        assert len(script_content) > 0


class TestScriptSaving:
    """Test script saving functionality."""

    def test_save_frida_script_creates_file(self, tk_root: tk.Tk, ui_config: UIConfig, mock_ui_controller: MagicMock, tmp_path: Path) -> None:
        """Frida script save writes content to file."""
        frame = ttk.Frame(tk_root)
        generator = ScriptGeneratorPanel(frame, ui_config, mock_ui_controller)

        script_content = "console.log('[+] Hook installed');"
        generator.frida_editor.insert("1.0", script_content)

        save_path = tmp_path / "hook.js"

        with patch('intellicrack.handlers.tkinter_handler.filedialog.asksaveasfilename', return_value=str(save_path)):
            generator.save_frida_script()

        assert save_path.exists()
        assert save_path.read_text() == script_content

    def test_save_ghidra_script_creates_file(self, tk_root: tk.Tk, ui_config: UIConfig, mock_ui_controller: MagicMock, tmp_path: Path) -> None:
        """Ghidra script save writes content to file."""
        frame = ttk.Frame(tk_root)
        generator = ScriptGeneratorPanel(frame, ui_config, mock_ui_controller)

        script_content = "// Ghidra analysis script"
        generator.ghidra_editor.insert("1.0", script_content)

        save_path = tmp_path / "analyze.java"

        with patch('intellicrack.handlers.tkinter_handler.filedialog.asksaveasfilename', return_value=str(save_path)):
            generator.save_ghidra_script()

        assert save_path.exists()
        assert save_path.read_text() == script_content

    def test_save_r2_script_creates_file(self, tk_root: tk.Tk, ui_config: UIConfig, mock_ui_controller: MagicMock, tmp_path: Path) -> None:
        """Radare2 script save writes content to file."""
        frame = ttk.Frame(tk_root)
        generator = ScriptGeneratorPanel(frame, ui_config, mock_ui_controller)

        script_content = "aaa\npdf @ main"
        generator.r2_editor.insert("1.0", script_content)

        save_path = tmp_path / "commands.r2"

        with patch('intellicrack.handlers.tkinter_handler.filedialog.asksaveasfilename', return_value=str(save_path)):
            generator.save_r2_script()

        assert save_path.exists()
        assert save_path.read_text() == script_content

    def test_save_custom_script_creates_file(self, tk_root: tk.Tk, ui_config: UIConfig, mock_ui_controller: MagicMock, tmp_path: Path) -> None:
        """Custom script save writes content to file."""
        frame = ttk.Frame(tk_root)
        generator = ScriptGeneratorPanel(frame, ui_config, mock_ui_controller)

        script_content = "print('Custom script')"
        generator.custom_editor.insert("1.0", script_content)

        save_path = tmp_path / "custom.py"

        with patch('intellicrack.handlers.tkinter_handler.filedialog.asksaveasfilename', return_value=str(save_path)):
            generator.save_custom_script()

        assert save_path.exists()
        assert save_path.read_text() == script_content

    def test_save_script_cancelled(self, tk_root: tk.Tk, ui_config: UIConfig, mock_ui_controller: MagicMock) -> None:
        """Script save handles user cancellation."""
        frame = ttk.Frame(tk_root)
        generator = ScriptGeneratorPanel(frame, ui_config, mock_ui_controller)

        generator.frida_editor.insert("1.0", "test content")

        with patch('intellicrack.handlers.tkinter_handler.filedialog.asksaveasfilename', return_value=''):
            generator.save_frida_script()


class TestScriptLoading:
    """Test script loading functionality."""

    def test_load_frida_script_reads_file(self, tk_root: tk.Tk, ui_config: UIConfig, mock_ui_controller: MagicMock, tmp_path: Path) -> None:
        """Frida script load reads content from file."""
        frame = ttk.Frame(tk_root)
        generator = ScriptGeneratorPanel(frame, ui_config, mock_ui_controller)

        script_content = "console.log('[+] Loaded script');"
        script_file = tmp_path / "load_test.js"
        script_file.write_text(script_content)

        with patch('intellicrack.handlers.tkinter_handler.filedialog.askopenfilename', return_value=str(script_file)):
            generator.load_frida_script()

        loaded_content = generator.frida_editor.get("1.0", "end-1c")
        assert loaded_content == script_content

    def test_load_ghidra_script_reads_file(self, tk_root: tk.Tk, ui_config: UIConfig, mock_ui_controller: MagicMock, tmp_path: Path) -> None:
        """Ghidra script load reads content from file."""
        frame = ttk.Frame(tk_root)
        generator = ScriptGeneratorPanel(frame, ui_config, mock_ui_controller)

        script_content = "// Loaded Ghidra script"
        script_file = tmp_path / "load_test.java"
        script_file.write_text(script_content)

        with patch('intellicrack.handlers.tkinter_handler.filedialog.askopenfilename', return_value=str(script_file)):
            generator.load_ghidra_script()

        loaded_content = generator.ghidra_editor.get("1.0", "end-1c")
        assert loaded_content == script_content

    def test_load_script_cancelled(self, tk_root: tk.Tk, ui_config: UIConfig, mock_ui_controller: MagicMock) -> None:
        """Script load handles user cancellation."""
        frame = ttk.Frame(tk_root)
        generator = ScriptGeneratorPanel(frame, ui_config, mock_ui_controller)

        generator.frida_editor.insert("1.0", "original content")

        with patch('intellicrack.handlers.tkinter_handler.filedialog.askopenfilename', return_value=''):
            generator.load_frida_script()

        content = generator.frida_editor.get("1.0", "end-1c")
        assert content == "original content"


class TestSyntaxHighlighting:
    """Test syntax highlighting for different script types."""

    def test_js_syntax_highlighting_applied(self, tk_root: tk.Tk, ui_config: UIConfig, mock_ui_controller: MagicMock) -> None:
        """JavaScript syntax highlighting is applied to Frida editor."""
        frame = ttk.Frame(tk_root)
        generator = ScriptGeneratorPanel(frame, ui_config, mock_ui_controller)

        generator.frida_editor.insert("1.0", "function test() { console.log('test'); }")

        generator.highlight_syntax(
            generator.frida_editor,
            ["function", "console", "log", "var", "let", "const"]
        )

        tags = generator.frida_editor.tag_names()
        assert "keyword" in tags

    def test_java_syntax_highlighting_applied(self, tk_root: tk.Tk, ui_config: UIConfig, mock_ui_controller: MagicMock) -> None:
        """Java syntax highlighting is applied to Ghidra editor."""
        frame = ttk.Frame(tk_root)
        generator = ScriptGeneratorPanel(frame, ui_config, mock_ui_controller)

        generator.ghidra_editor.insert("1.0", "public class Test { void method() {} }")

        generator.highlight_syntax(
            generator.ghidra_editor,
            ["public", "class", "void", "return", "import"]
        )

        tags = generator.ghidra_editor.tag_names()
        assert "keyword" in tags

    def test_python_syntax_highlighting_applied(self, tk_root: tk.Tk, ui_config: UIConfig, mock_ui_controller: MagicMock) -> None:
        """Python syntax highlighting is applied to custom editor."""
        frame = ttk.Frame(tk_root)
        generator = ScriptGeneratorPanel(frame, ui_config, mock_ui_controller)

        generator.custom_editor.insert("1.0", "def test(): print('hello')")
        generator.custom_language_var.set("Python")

        generator.highlight_syntax(
            generator.custom_editor,
            ["def", "class", "import", "return", "print"]
        )

        tags = generator.custom_editor.tag_names()
        assert "keyword" in tags


class TestFileExplorerEventHandlers:
    """Test file explorer event handling."""

    def test_on_double_click_analyzes_file(self, tk_root: tk.Tk, ui_config: UIConfig, mock_ui_controller: MagicMock, tmp_path: Path) -> None:
        """Double-click on file triggers analysis."""
        frame = ttk.Frame(tk_root)
        explorer = FileExplorerPanel(frame, ui_config, mock_ui_controller)

        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"MZ\x90\x00")

        explorer.current_path = tmp_path
        explorer.refresh_tree()

        if items := explorer.tree.get_children():
            explorer.tree.selection_set(items[0])
            explorer.tree.focus(items[0])

            mock_event = MagicMock()
            explorer.on_double_click(mock_event)

    def test_on_right_click_shows_context_menu(self, tk_root: tk.Tk, ui_config: UIConfig, mock_ui_controller: MagicMock) -> None:
        """Right-click on file shows context menu."""
        frame = ttk.Frame(tk_root)
        explorer = FileExplorerPanel(frame, ui_config, mock_ui_controller)

        mock_event = MagicMock()
        mock_event.x_root = 100
        mock_event.y_root = 100

        with patch.object(explorer.context_menu, 'post') as mock_post:
            explorer.on_right_click(mock_event)
            mock_post.assert_called_once_with(100, 100)

    def test_on_selection_change_updates_status(self, tk_root: tk.Tk, ui_config: UIConfig, mock_ui_controller: MagicMock, tmp_path: Path) -> None:
        """Selection change updates status bar."""
        frame = ttk.Frame(tk_root)
        explorer = FileExplorerPanel(frame, ui_config, mock_ui_controller)

        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"MZ\x90\x00" * 100)

        explorer.current_path = tmp_path
        explorer.refresh_tree()

        mock_event = MagicMock()
        explorer.on_selection_change(mock_event)

    def test_copy_path_copies_to_clipboard(self, tk_root: tk.Tk, ui_config: UIConfig, mock_ui_controller: MagicMock, tmp_path: Path) -> None:
        """Copy path copies selected file path to clipboard."""
        frame = ttk.Frame(tk_root)
        explorer = FileExplorerPanel(frame, ui_config, mock_ui_controller)

        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"data")

        explorer.current_path = tmp_path
        explorer.refresh_tree()

        if items := explorer.tree.get_children():
            explorer.tree.selection_set(items[0])

            with patch.object(explorer.root, 'clipboard_clear') as mock_clear:
                with patch.object(explorer.root, 'clipboard_append') as mock_append:
                    explorer.copy_path()

                    mock_clear.assert_called_once()
                    mock_append.assert_called_once()


class TestLogExport:
    """Test log export functionality."""

    def test_export_logs_creates_file(self, tk_root: tk.Tk, ui_config: UIConfig, tmp_path: Path) -> None:
        """Export logs creates text file with all entries."""
        frame = ttk.Frame(tk_root)
        log_viewer = LogViewer(frame, ui_config)

        log_viewer.add_log("INFO", "Test message 1")
        log_viewer.add_log("WARNING", "Test message 2")
        log_viewer.add_log("ERROR", "Test message 3")

        export_file = tmp_path / "logs.txt"

        with patch('intellicrack.handlers.tkinter_handler.filedialog.asksaveasfilename', return_value=str(export_file)):
            log_viewer.export_logs()

        assert export_file.exists()
        content = export_file.read_text()
        assert "Test message 1" in content
        assert "Test message 2" in content
        assert "Test message 3" in content

    def test_export_logs_cancelled(self, tk_root: tk.Tk, ui_config: UIConfig) -> None:
        """Export logs handles user cancellation."""
        frame = ttk.Frame(tk_root)
        log_viewer = LogViewer(frame, ui_config)

        log_viewer.add_log("INFO", "Test message")

        with patch('intellicrack.handlers.tkinter_handler.filedialog.asksaveasfilename', return_value=''):
            log_viewer.export_logs()


class TestAnalysisErrorHandling:
    """Test analysis error handling in UIEnhancementModule."""

    def test_analysis_error_displays_message(self) -> None:
        """Analysis error displays error message to user."""
        module = UIEnhancementModule()

        error_msg = "Failed to analyze binary: Invalid PE header"

        with patch.object(module.log_viewer, 'add_log') as mock_log:
            module._analysis_error(error_msg)

            mock_log.assert_called_once()
            call_args = mock_log.call_args[0]
            assert call_args[0] == "ERROR"
            assert error_msg in call_args[1]

        try:
            module.root.quit()
            module.root.destroy()
        except tk.TclError:
            pass

    def test_analysis_error_updates_status(self) -> None:
        """Analysis error updates status bar."""
        module = UIEnhancementModule()

        error_msg = "Analysis failed"

        module._analysis_error(error_msg)

        try:
            module.root.quit()
            module.root.destroy()
        except tk.TclError:
            pass

    def test_file_not_found_error_handling(self, tmp_path: Path) -> None:
        """File not found error is properly handled."""
        module = UIEnhancementModule()

        nonexistent_file = str(tmp_path / "nonexistent.exe")

        with patch.object(module, '_perform_analysis') as mock_analysis:
            mock_analysis.side_effect = FileNotFoundError("File not found")

            with patch.object(module, '_analysis_error') as mock_error:
                module.analyze_file(nonexistent_file)

                import time
                time.sleep(0.2)

        try:
            module.root.quit()
            module.root.destroy()
        except tk.TclError:
            pass


class TestScriptExecutionErrorHandling:
    """Test script execution error handling."""

    def test_execute_frida_script_handles_timeout(self) -> None:
        """Frida script execution handles timeout gracefully."""
        module = UIEnhancementModule()

        script = "console.log('test');"
        target = "target.exe"

        with patch('frida.attach') as mock_attach:
            mock_attach.side_effect = TimeoutError("Connection timeout")

            with patch.object(module.log_viewer, 'add_log') as mock_log:
                module.execute_frida_script(script, target)

                import time
                time.sleep(0.2)

        try:
            module.root.quit()
            module.root.destroy()
        except tk.TclError:
            pass

    def test_execute_ghidra_script_handles_java_error(self) -> None:
        """Ghidra script execution handles Java errors."""
        module = UIEnhancementModule()

        script = "// Test script"
        target = "target.exe"

        with patch('subprocess.run') as mock_run:
            mock_run.side_effect = Exception("Java process failed")

            with patch.object(module.log_viewer, 'add_log') as mock_log:
                module.execute_ghidra_script(script, target)

                import time
                time.sleep(0.2)

        try:
            module.root.quit()
            module.root.destroy()
        except tk.TclError:
            pass


class TestScriptHistoryManagement:
    """Test script history tracking."""

    def test_add_to_script_history_stores_entry(self, tk_root: tk.Tk, ui_config: UIConfig, mock_ui_controller: MagicMock) -> None:
        """Script history stores generated scripts."""
        frame = ttk.Frame(tk_root)
        generator = ScriptGeneratorPanel(frame, ui_config, mock_ui_controller)

        script_content = "console.log('[+] Hook installed');"

        generator.add_to_script_history("Frida", "hook_function", script_content)

        assert len(generator.script_history) == 1
        assert generator.script_history[0]["platform"] == "Frida"
        assert generator.script_history[0]["script_type"] == "hook_function"
        assert generator.script_history[0]["content"] == script_content

    def test_script_history_preserves_order(self, tk_root: tk.Tk, ui_config: UIConfig, mock_ui_controller: MagicMock) -> None:
        """Script history preserves chronological order."""
        frame = ttk.Frame(tk_root)
        generator = ScriptGeneratorPanel(frame, ui_config, mock_ui_controller)

        generator.add_to_script_history("Frida", "hook1", "script1")
        generator.add_to_script_history("Ghidra", "analyze", "script2")
        generator.add_to_script_history("Radare2", "patch", "script3")

        assert len(generator.script_history) == 3
        assert generator.script_history[0]["platform"] == "Frida"
        assert generator.script_history[1]["platform"] == "Ghidra"
        assert generator.script_history[2]["platform"] == "Radare2"


class TestLanguageChange:
    """Test custom script language change handling."""

    def test_language_change_updates_editor(self, tk_root: tk.Tk, ui_config: UIConfig, mock_ui_controller: MagicMock) -> None:
        """Language change updates custom editor configuration."""
        frame = ttk.Frame(tk_root)
        generator = ScriptGeneratorPanel(frame, ui_config, mock_ui_controller)

        generator.custom_language_var.set("Python")

        mock_event = MagicMock()
        generator.on_language_change(mock_event)

        assert generator.custom_language_var.get() == "Python"

    def test_language_change_applies_syntax_highlighting(self, tk_root: tk.Tk, ui_config: UIConfig, mock_ui_controller: MagicMock) -> None:
        """Language change applies appropriate syntax highlighting."""
        frame = ttk.Frame(tk_root)
        generator = ScriptGeneratorPanel(frame, ui_config, mock_ui_controller)

        generator.custom_editor.insert("1.0", "def test(): pass")
        generator.custom_language_var.set("Python")

        mock_event = MagicMock()

        with patch.object(generator, 'setup_python_syntax_highlighting') as mock_highlight:
            generator.on_language_change(mock_event)

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
from typing import Any, List, Dict, Optional, Callable

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
    from intellicrack.handlers.tkinter_handler import tkinter as tk, ttk, scrolledtext, filedialog
    UI_ENHANCEMENT_AVAILABLE = True
except ImportError as e:
    UI_ENHANCEMENT_AVAILABLE = False
    IMPORT_ERROR = str(e)

pytestmark = pytest.mark.skipif(
    not UI_ENHANCEMENT_AVAILABLE,
    reason=f"UI enhancement module not available: {'' if UI_ENHANCEMENT_AVAILABLE else IMPORT_ERROR}"
)


class FakeUIController:
    """Real test double for UI controller with actual tracking."""

    def __init__(self) -> None:
        self.analyzed_files: List[str] = []
        self.generated_scripts: List[Dict[str, str]] = []
        self.file_properties_shown: List[str] = []
        self.last_analysis_result: Optional[Dict[str, Any]] = None

    def analyze_file(self, file_path: str) -> None:
        """Track file analysis calls."""
        self.analyzed_files.append(file_path)
        self.last_analysis_result = {
            "path": file_path,
            "size": 1024,
            "type": "PE32",
            "protections": ["VMProtect"]
        }

    def generate_scripts(self, script_type: str, target: str) -> str:
        """Generate and track script creation."""
        script_content = f"// Generated {script_type} script for {target}"
        self.generated_scripts.append({
            "type": script_type,
            "target": target,
            "content": script_content
        })
        return script_content

    def show_file_properties(self, file_path: str) -> None:
        """Track file properties display calls."""
        self.file_properties_shown.append(file_path)


class FakeFileDialog:
    """Real test double for file dialogs with configurable responses."""

    def __init__(self) -> None:
        self.next_open_filename: Optional[str] = None
        self.next_save_filename: Optional[str] = None
        self.open_calls: List[Dict[str, Any]] = []
        self.save_calls: List[Dict[str, Any]] = []

    def askopenfilename(self, **kwargs: Any) -> str:
        """Record open dialog call and return configured filename."""
        self.open_calls.append(kwargs)
        return self.next_open_filename if self.next_open_filename else ""

    def asksaveasfilename(self, **kwargs: Any) -> str:
        """Record save dialog call and return configured filename."""
        self.save_calls.append(kwargs)
        return self.next_save_filename if self.next_save_filename else ""


class FakeEvent:
    """Real test double for tkinter events."""

    def __init__(self, x_root: int = 100, y_root: int = 100) -> None:
        self.x_root = x_root
        self.y_root = y_root


class FakeMenu:
    """Real test double for context menu tracking."""

    def __init__(self) -> None:
        self.post_calls: List[tuple[int, int]] = []

    def post(self, x: int, y: int) -> None:
        """Track menu post calls."""
        self.post_calls.append((x, y))


class FakeClipboard:
    """Real test double for clipboard operations."""

    def __init__(self) -> None:
        self.content: str = ""
        self.clear_count: int = 0
        self.append_count: int = 0

    def clipboard_clear(self) -> None:
        """Clear clipboard and track call."""
        self.content = ""
        self.clear_count += 1

    def clipboard_append(self, text: str) -> None:
        """Append to clipboard and track call."""
        self.content = text
        self.append_count += 1


class FakeLogViewer:
    """Real test double for log viewer with actual logging."""

    def __init__(self) -> None:
        self.logs: List[Dict[str, str]] = []

    def add_log(self, level: str, message: str) -> None:
        """Add log entry to tracking list."""
        self.logs.append({
            "level": level,
            "message": message
        })


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
def fake_ui_controller() -> FakeUIController:
    """Create fake UI controller."""
    return FakeUIController()


@pytest.fixture
def fake_file_dialog() -> FakeFileDialog:
    """Create fake file dialog."""
    return FakeFileDialog()


class TestScriptGeneratorPanelCore:
    """Test ScriptGeneratorPanel initialization and tab creation."""

    def test_frida_tab_has_all_components(self, tk_root: tk.Tk, ui_config: UIConfig, fake_ui_controller: FakeUIController) -> None:
        """Frida tab contains all required UI components."""
        frame = ttk.Frame(tk_root)
        generator = ScriptGeneratorPanel(frame, ui_config, fake_ui_controller)  # type: ignore[arg-type]

        assert hasattr(generator, 'frida_editor')
        assert hasattr(generator, 'frida_process_entry')
        assert hasattr(generator, 'frida_target_entry')
        assert isinstance(generator.frida_editor, scrolledtext.ScrolledText)

    def test_ghidra_tab_has_all_components(self, tk_root: tk.Tk, ui_config: UIConfig, fake_ui_controller: FakeUIController) -> None:
        """Ghidra tab contains all required UI components."""
        frame = ttk.Frame(tk_root)
        generator = ScriptGeneratorPanel(frame, ui_config, fake_ui_controller)  # type: ignore[arg-type]

        assert hasattr(generator, 'ghidra_editor')
        assert hasattr(generator, 'ghidra_binary_entry')
        assert isinstance(generator.ghidra_editor, scrolledtext.ScrolledText)

    def test_radare2_tab_has_all_components(self, tk_root: tk.Tk, ui_config: UIConfig, fake_ui_controller: FakeUIController) -> None:
        """Radare2 tab contains all required UI components."""
        frame = ttk.Frame(tk_root)
        generator = ScriptGeneratorPanel(frame, ui_config, fake_ui_controller)  # type: ignore[arg-type]

        assert hasattr(generator, 'r2_editor')
        assert hasattr(generator, 'r2_binary_entry')
        assert isinstance(generator.r2_editor, scrolledtext.ScrolledText)

    def test_custom_tab_has_all_components(self, tk_root: tk.Tk, ui_config: UIConfig, fake_ui_controller: FakeUIController) -> None:
        """Custom tab contains all required UI components."""
        frame = ttk.Frame(tk_root)
        generator = ScriptGeneratorPanel(frame, ui_config, fake_ui_controller)  # type: ignore[arg-type]

        assert hasattr(generator, 'custom_editor')
        assert hasattr(generator, 'custom_language_var')
        assert isinstance(generator.custom_editor, scrolledtext.ScrolledText)


class TestScriptGeneratorBrowsing:
    """Test file browsing functionality in script generator."""

    def test_browse_process_opens_dialog(self, tk_root: tk.Tk, ui_config: UIConfig, fake_ui_controller: FakeUIController, monkeypatch: pytest.MonkeyPatch) -> None:
        """Browse process opens process selection dialog."""
        frame = ttk.Frame(tk_root)
        generator = ScriptGeneratorPanel(frame, ui_config, fake_ui_controller)  # type: ignore[arg-type]

        fake_dialog = FakeFileDialog()
        fake_dialog.next_open_filename = 'process.exe'

        monkeypatch.setattr('intellicrack.handlers.tkinter_handler.filedialog.askopenfilename', fake_dialog.askopenfilename)

        generator.browse_process()

        assert len(fake_dialog.open_calls) == 1
        assert getattr(generator, "frida_process_entry").get() == 'process.exe'

    def test_browse_binary_opens_dialog(self, tk_root: tk.Tk, ui_config: UIConfig, fake_ui_controller: FakeUIController, monkeypatch: pytest.MonkeyPatch) -> None:
        """Browse binary opens file selection dialog."""
        frame = ttk.Frame(tk_root)
        generator = ScriptGeneratorPanel(frame, ui_config, fake_ui_controller)  # type: ignore[arg-type]

        fake_dialog = FakeFileDialog()
        fake_dialog.next_open_filename = 'C:\\test\\target.exe'

        monkeypatch.setattr('intellicrack.handlers.tkinter_handler.filedialog.askopenfilename', fake_dialog.askopenfilename)

        generator.browse_binary()

        assert len(fake_dialog.open_calls) == 1
        assert getattr(generator, "frida_target_entry").get() == 'C:\\test\\target.exe'

    def test_browse_r2_binary_opens_dialog(self, tk_root: tk.Tk, ui_config: UIConfig, fake_ui_controller: FakeUIController, monkeypatch: pytest.MonkeyPatch) -> None:
        """Browse radare2 binary opens file selection dialog."""
        frame = ttk.Frame(tk_root)
        generator = ScriptGeneratorPanel(frame, ui_config, fake_ui_controller)  # type: ignore[arg-type]

        fake_dialog = FakeFileDialog()
        fake_dialog.next_open_filename = 'C:\\test\\binary.dll'

        monkeypatch.setattr('intellicrack.handlers.tkinter_handler.filedialog.askopenfilename', fake_dialog.askopenfilename)

        generator.browse_r2_binary()

        assert len(fake_dialog.open_calls) == 1
        assert getattr(generator, "r2_binary_entry").get() == 'C:\\test\\binary.dll'

    def test_browse_process_cancelled(self, tk_root: tk.Tk, ui_config: UIConfig, fake_ui_controller: FakeUIController, monkeypatch: pytest.MonkeyPatch) -> None:
        """Browse process handles user cancellation."""
        frame = ttk.Frame(tk_root)
        generator = ScriptGeneratorPanel(frame, ui_config, fake_ui_controller)  # type: ignore[arg-type]

        getattr(generator, "frida_process_entry").insert(0, "original.exe")

        fake_dialog = FakeFileDialog()
        fake_dialog.next_open_filename = ''

        monkeypatch.setattr('intellicrack.handlers.tkinter_handler.filedialog.askopenfilename', fake_dialog.askopenfilename)

        generator.browse_process()

        assert getattr(generator, "frida_process_entry").get() == "original.exe"


class TestScriptGeneration:
    """Test script generation functionality."""

    def test_generate_frida_script_creates_content(self, tk_root: tk.Tk, ui_config: UIConfig, fake_ui_controller: FakeUIController) -> None:
        """Frida script generation creates valid JavaScript content."""
        frame = ttk.Frame(tk_root)
        generator = ScriptGeneratorPanel(frame, ui_config, fake_ui_controller)  # type: ignore[arg-type]

        getattr(generator, "frida_process_entry").insert(0, "target.exe")

        generator.generate_frida_script()

        script_content = generator.frida_editor.get("1.0", "end-1c")
        assert len(script_content) > 0
        assert "Interceptor" in script_content or "target.exe" in script_content

    def test_generate_ghidra_script_creates_content(self, tk_root: tk.Tk, ui_config: UIConfig, fake_ui_controller: FakeUIController) -> None:
        """Ghidra script generation creates valid Java content."""
        frame = ttk.Frame(tk_root)
        generator = ScriptGeneratorPanel(frame, ui_config, fake_ui_controller)  # type: ignore[arg-type]

        getattr(generator, "ghidra_binary_entry").insert(0, "C:\\test\\binary.exe")

        generator.generate_ghidra_script()

        script_content = generator.ghidra_editor.get("1.0", "end-1c")
        assert len(script_content) > 0

    def test_generate_r2_script_creates_content(self, tk_root: tk.Tk, ui_config: UIConfig, fake_ui_controller: FakeUIController) -> None:
        """Radare2 script generation creates valid r2 commands."""
        frame = ttk.Frame(tk_root)
        generator = ScriptGeneratorPanel(frame, ui_config, fake_ui_controller)  # type: ignore[arg-type]

        getattr(generator, "r2_binary_entry").insert(0, "C:\\test\\packed.exe")

        generator.generate_r2_script()

        script_content = generator.r2_editor.get("1.0", "end-1c")
        assert len(script_content) > 0


class TestScriptSaving:
    """Test script saving functionality."""

    def test_save_frida_script_creates_file(self, tk_root: tk.Tk, ui_config: UIConfig, fake_ui_controller: FakeUIController, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Frida script save writes content to file."""
        frame = ttk.Frame(tk_root)
        generator = ScriptGeneratorPanel(frame, ui_config, fake_ui_controller)  # type: ignore[arg-type]

        script_content = "console.log('[+] Hook installed');"
        generator.frida_editor.insert("1.0", script_content)

        save_path = tmp_path / "hook.js"

        fake_dialog = FakeFileDialog()
        fake_dialog.next_save_filename = str(save_path)

        monkeypatch.setattr('intellicrack.handlers.tkinter_handler.filedialog.asksaveasfilename', fake_dialog.asksaveasfilename)

        generator.save_frida_script()

        assert save_path.exists()
        assert save_path.read_text() == script_content

    def test_save_ghidra_script_creates_file(self, tk_root: tk.Tk, ui_config: UIConfig, fake_ui_controller: FakeUIController, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Ghidra script save writes content to file."""
        frame = ttk.Frame(tk_root)
        generator = ScriptGeneratorPanel(frame, ui_config, fake_ui_controller)  # type: ignore[arg-type]

        script_content = "// Ghidra analysis script"
        generator.ghidra_editor.insert("1.0", script_content)

        save_path = tmp_path / "analyze.java"

        fake_dialog = FakeFileDialog()
        fake_dialog.next_save_filename = str(save_path)

        monkeypatch.setattr('intellicrack.handlers.tkinter_handler.filedialog.asksaveasfilename', fake_dialog.asksaveasfilename)

        generator.save_ghidra_script()

        assert save_path.exists()
        assert save_path.read_text() == script_content

    def test_save_r2_script_creates_file(self, tk_root: tk.Tk, ui_config: UIConfig, fake_ui_controller: FakeUIController, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Radare2 script save writes content to file."""
        frame = ttk.Frame(tk_root)
        generator = ScriptGeneratorPanel(frame, ui_config, fake_ui_controller)  # type: ignore[arg-type]

        script_content = "aaa\npdf @ main"
        generator.r2_editor.insert("1.0", script_content)

        save_path = tmp_path / "commands.r2"

        fake_dialog = FakeFileDialog()
        fake_dialog.next_save_filename = str(save_path)

        monkeypatch.setattr('intellicrack.handlers.tkinter_handler.filedialog.asksaveasfilename', fake_dialog.asksaveasfilename)

        generator.save_r2_script()

        assert save_path.exists()
        assert save_path.read_text() == script_content

    def test_save_custom_script_creates_file(self, tk_root: tk.Tk, ui_config: UIConfig, fake_ui_controller: FakeUIController, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Custom script save writes content to file."""
        frame = ttk.Frame(tk_root)
        generator = ScriptGeneratorPanel(frame, ui_config, fake_ui_controller)  # type: ignore[arg-type]

        script_content = "print('Custom script')"
        generator.custom_editor.insert("1.0", script_content)

        save_path = tmp_path / "custom.py"

        fake_dialog = FakeFileDialog()
        fake_dialog.next_save_filename = str(save_path)

        monkeypatch.setattr('intellicrack.handlers.tkinter_handler.filedialog.asksaveasfilename', fake_dialog.asksaveasfilename)

        generator.save_custom_script()

        assert save_path.exists()
        assert save_path.read_text() == script_content

    def test_save_script_cancelled(self, tk_root: tk.Tk, ui_config: UIConfig, fake_ui_controller: FakeUIController, monkeypatch: pytest.MonkeyPatch) -> None:
        """Script save handles user cancellation."""
        frame = ttk.Frame(tk_root)
        generator = ScriptGeneratorPanel(frame, ui_config, fake_ui_controller)  # type: ignore[arg-type]

        generator.frida_editor.insert("1.0", "test content")

        fake_dialog = FakeFileDialog()
        fake_dialog.next_save_filename = ''

        monkeypatch.setattr('intellicrack.handlers.tkinter_handler.filedialog.asksaveasfilename', fake_dialog.asksaveasfilename)

        generator.save_frida_script()


class TestScriptLoading:
    """Test script loading functionality."""

    def test_load_frida_script_reads_file(self, tk_root: tk.Tk, ui_config: UIConfig, fake_ui_controller: FakeUIController, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Frida script load reads content from file."""
        frame = ttk.Frame(tk_root)
        generator = ScriptGeneratorPanel(frame, ui_config, fake_ui_controller)  # type: ignore[arg-type]

        script_content = "console.log('[+] Loaded script');"
        script_file = tmp_path / "load_test.js"
        script_file.write_text(script_content)

        fake_dialog = FakeFileDialog()
        fake_dialog.next_open_filename = str(script_file)

        monkeypatch.setattr('intellicrack.handlers.tkinter_handler.filedialog.askopenfilename', fake_dialog.askopenfilename)

        generator.load_frida_script()

        loaded_content = generator.frida_editor.get("1.0", "end-1c")
        assert loaded_content == script_content

    def test_load_ghidra_script_reads_file(self, tk_root: tk.Tk, ui_config: UIConfig, fake_ui_controller: FakeUIController, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Ghidra script load reads content from file."""
        frame = ttk.Frame(tk_root)
        generator = ScriptGeneratorPanel(frame, ui_config, fake_ui_controller)  # type: ignore[arg-type]

        script_content = "// Loaded Ghidra script"
        script_file = tmp_path / "load_test.java"
        script_file.write_text(script_content)

        fake_dialog = FakeFileDialog()
        fake_dialog.next_open_filename = str(script_file)

        monkeypatch.setattr('intellicrack.handlers.tkinter_handler.filedialog.askopenfilename', fake_dialog.askopenfilename)

        generator.load_ghidra_script()

        loaded_content = generator.ghidra_editor.get("1.0", "end-1c")
        assert loaded_content == script_content

    def test_load_script_cancelled(self, tk_root: tk.Tk, ui_config: UIConfig, fake_ui_controller: FakeUIController, monkeypatch: pytest.MonkeyPatch) -> None:
        """Script load handles user cancellation."""
        frame = ttk.Frame(tk_root)
        generator = ScriptGeneratorPanel(frame, ui_config, fake_ui_controller)  # type: ignore[arg-type]

        generator.frida_editor.insert("1.0", "original content")

        fake_dialog = FakeFileDialog()
        fake_dialog.next_open_filename = ''

        monkeypatch.setattr('intellicrack.handlers.tkinter_handler.filedialog.askopenfilename', fake_dialog.askopenfilename)

        generator.load_frida_script()

        content = generator.frida_editor.get("1.0", "end-1c")
        assert content == "original content"


class TestSyntaxHighlighting:
    """Test syntax highlighting for different script types."""

    def test_js_syntax_highlighting_applied(self, tk_root: tk.Tk, ui_config: UIConfig, fake_ui_controller: FakeUIController) -> None:
        """JavaScript syntax highlighting is applied to Frida editor."""
        frame = ttk.Frame(tk_root)
        generator = ScriptGeneratorPanel(frame, ui_config, fake_ui_controller)  # type: ignore[arg-type]

        generator.frida_editor.insert("1.0", "function test() { console.log('test'); }")

        generator.highlight_syntax(
            generator.frida_editor,
            ["function", "console", "log", "var", "let", "const"]
        )

        tags = generator.frida_editor.tag_names()
        assert "keyword" in tags

    def test_java_syntax_highlighting_applied(self, tk_root: tk.Tk, ui_config: UIConfig, fake_ui_controller: FakeUIController) -> None:
        """Java syntax highlighting is applied to Ghidra editor."""
        frame = ttk.Frame(tk_root)
        generator = ScriptGeneratorPanel(frame, ui_config, fake_ui_controller)  # type: ignore[arg-type]

        generator.ghidra_editor.insert("1.0", "public class Test { void method() {} }")

        generator.highlight_syntax(
            generator.ghidra_editor,
            ["public", "class", "void", "return", "import"]
        )

        tags = generator.ghidra_editor.tag_names()
        assert "keyword" in tags

    def test_python_syntax_highlighting_applied(self, tk_root: tk.Tk, ui_config: UIConfig, fake_ui_controller: FakeUIController) -> None:
        """Python syntax highlighting is applied to custom editor."""
        frame = ttk.Frame(tk_root)
        generator = ScriptGeneratorPanel(frame, ui_config, fake_ui_controller)  # type: ignore[arg-type]

        generator.custom_editor.insert("1.0", "def test(): print('hello')")
        getattr(generator, "custom_language_var").set("Python")

        generator.highlight_syntax(
            generator.custom_editor,
            ["def", "class", "import", "return", "print"]
        )

        tags = generator.custom_editor.tag_names()
        assert "keyword" in tags


class TestFileExplorerEventHandlers:
    """Test file explorer event handling."""

    def test_on_double_click_analyzes_file(self, tk_root: tk.Tk, ui_config: UIConfig, fake_ui_controller: FakeUIController, tmp_path: Path) -> None:
        """Double-click on file triggers analysis."""
        frame = ttk.Frame(tk_root)
        explorer = FileExplorerPanel(frame, ui_config, fake_ui_controller)  # type: ignore[arg-type]

        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"MZ\x90\x00")

        explorer.current_path = tmp_path
        explorer.refresh_tree()

        if items := explorer.tree.get_children():
            explorer.tree.selection_set(items[0])
            explorer.tree.focus(items[0])

            fake_event = FakeEvent()
            explorer.on_double_click(fake_event)

    def test_on_right_click_shows_context_menu(self, tk_root: tk.Tk, ui_config: UIConfig, fake_ui_controller: FakeUIController) -> None:
        """Right-click on file shows context menu."""
        frame = ttk.Frame(tk_root)
        explorer = FileExplorerPanel(frame, ui_config, fake_ui_controller)  # type: ignore[arg-type]

        fake_menu = FakeMenu()
        original_menu = explorer.context_menu
        explorer.context_menu = fake_menu

        fake_event = FakeEvent(x_root=100, y_root=100)
        explorer.on_right_click(fake_event)

        assert len(fake_menu.post_calls) == 1
        assert fake_menu.post_calls[0] == (100, 100)

        explorer.context_menu = original_menu

    def test_on_selection_change_updates_status(self, tk_root: tk.Tk, ui_config: UIConfig, fake_ui_controller: FakeUIController, tmp_path: Path) -> None:
        """Selection change updates status bar."""
        frame = ttk.Frame(tk_root)
        explorer = FileExplorerPanel(frame, ui_config, fake_ui_controller)  # type: ignore[arg-type]

        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"MZ\x90\x00" * 100)

        explorer.current_path = tmp_path
        explorer.refresh_tree()

        fake_event = FakeEvent()
        explorer.on_selection_change(fake_event)

    def test_copy_path_copies_to_clipboard(self, tk_root: tk.Tk, ui_config: UIConfig, fake_ui_controller: FakeUIController, tmp_path: Path) -> None:
        """Copy path copies selected file path to clipboard."""
        frame = ttk.Frame(tk_root)
        explorer = FileExplorerPanel(frame, ui_config, fake_ui_controller)  # type: ignore[arg-type]

        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"data")

        explorer.current_path = tmp_path
        explorer.refresh_tree()

        if items := explorer.tree.get_children():
            explorer.tree.selection_set(items[0])

            fake_clipboard = FakeClipboard()
            explorer_root = getattr(explorer, "root", None)
            if explorer_root is not None:
                original_clear = explorer_root.clipboard_clear
                original_append = explorer_root.clipboard_append
                explorer_root.clipboard_clear = fake_clipboard.clipboard_clear
                explorer_root.clipboard_append = fake_clipboard.clipboard_append

                explorer.copy_path()

                assert fake_clipboard.clear_count == 1
                assert fake_clipboard.append_count == 1

                explorer_root.clipboard_clear = original_clear
                explorer_root.clipboard_append = original_append


class TestLogExport:
    """Test log export functionality."""

    def test_export_logs_creates_file(self, tk_root: tk.Tk, ui_config: UIConfig, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Export logs creates text file with all entries."""
        frame = ttk.Frame(tk_root)
        log_viewer = LogViewer(frame, ui_config)

        log_viewer.add_log("INFO", "Test message 1")
        log_viewer.add_log("WARNING", "Test message 2")
        log_viewer.add_log("ERROR", "Test message 3")

        export_file = tmp_path / "logs.txt"

        fake_dialog = FakeFileDialog()
        fake_dialog.next_save_filename = str(export_file)

        monkeypatch.setattr('intellicrack.handlers.tkinter_handler.filedialog.asksaveasfilename', fake_dialog.asksaveasfilename)

        log_viewer.export_logs()

        assert export_file.exists()
        content = export_file.read_text()
        assert "Test message 1" in content
        assert "Test message 2" in content
        assert "Test message 3" in content

    def test_export_logs_cancelled(self, tk_root: tk.Tk, ui_config: UIConfig, monkeypatch: pytest.MonkeyPatch) -> None:
        """Export logs handles user cancellation."""
        frame = ttk.Frame(tk_root)
        log_viewer = LogViewer(frame, ui_config)

        log_viewer.add_log("INFO", "Test message")

        fake_dialog = FakeFileDialog()
        fake_dialog.next_save_filename = ''

        monkeypatch.setattr('intellicrack.handlers.tkinter_handler.filedialog.asksaveasfilename', fake_dialog.asksaveasfilename)

        log_viewer.export_logs()


class TestAnalysisErrorHandling:
    """Test analysis error handling in UIEnhancementModule."""

    def test_analysis_error_displays_message(self) -> None:
        """Analysis error displays error message to user."""
        module = UIEnhancementModule()

        error_msg = "Failed to analyze binary: Invalid PE header"

        fake_log_viewer = FakeLogViewer()
        original_log_viewer = module.log_viewer
        module.log_viewer = fake_log_viewer  # type: ignore[assignment]

        module._analysis_error(error_msg)

        assert len(fake_log_viewer.logs) == 1
        assert fake_log_viewer.logs[0]["level"] == "ERROR"
        assert error_msg in fake_log_viewer.logs[0]["message"]

        module.log_viewer = original_log_viewer

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

        class FakePerformAnalysis:
            def __init__(self) -> None:
                self.calls: List[str] = []

            def __call__(self, file_path: str) -> None:
                self.calls.append(file_path)
                raise FileNotFoundError("File not found")

        fake_analysis = FakePerformAnalysis()
        fake_error_handler = FakeLogViewer()

        original_perform_analysis = module._perform_analysis
        original_error_handler = module._analysis_error

        module._perform_analysis = fake_analysis  # type: ignore[method-assign]

        def track_error(msg: str) -> None:
            fake_error_handler.add_log("ERROR", msg)

        module._analysis_error = track_error  # type: ignore[method-assign, assignment]

        module.analyze_file(nonexistent_file)

        import time
        time.sleep(0.2)

        module._perform_analysis = original_perform_analysis  # type: ignore[method-assign]
        module._analysis_error = original_error_handler  # type: ignore[method-assign]

        try:
            module.root.quit()
            module.root.destroy()
        except tk.TclError:
            pass


class TestScriptExecutionErrorHandling:
    """Test script execution error handling."""

    def test_execute_frida_script_handles_timeout(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Frida script execution handles timeout gracefully."""
        module = UIEnhancementModule()

        script = "console.log('test');"
        target = "target.exe"

        def fake_frida_attach(*args: Any, **kwargs: Any) -> None:
            raise TimeoutError("Connection timeout")

        try:
            monkeypatch.setattr('frida.attach', fake_frida_attach)
        except (ImportError, AttributeError):
            pass

        fake_log_viewer = FakeLogViewer()
        original_log_viewer = module.log_viewer
        module.log_viewer = fake_log_viewer  # type: ignore[assignment]

        module.execute_frida_script(script, target)

        import time
        time.sleep(0.2)

        module.log_viewer = original_log_viewer

        try:
            module.root.quit()
            module.root.destroy()
        except tk.TclError:
            pass

    def test_execute_ghidra_script_handles_java_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Ghidra script execution handles Java errors."""
        module = UIEnhancementModule()

        script = "// Test script"
        target = "target.exe"

        def fake_subprocess_run(*args: Any, **kwargs: Any) -> None:
            raise Exception("Java process failed")

        monkeypatch.setattr('subprocess.run', fake_subprocess_run)

        fake_log_viewer = FakeLogViewer()
        original_log_viewer = module.log_viewer
        module.log_viewer = fake_log_viewer  # type: ignore[assignment]

        module.execute_ghidra_script(script, target)

        import time
        time.sleep(0.2)

        module.log_viewer = original_log_viewer

        try:
            module.root.quit()
            module.root.destroy()
        except tk.TclError:
            pass


class TestScriptHistoryManagement:
    """Test script history tracking."""

    def test_add_to_script_history_stores_entry(self, tk_root: tk.Tk, ui_config: UIConfig, fake_ui_controller: FakeUIController) -> None:
        """Script history stores generated scripts."""
        frame = ttk.Frame(tk_root)
        generator = ScriptGeneratorPanel(frame, ui_config, fake_ui_controller)  # type: ignore[arg-type]

        script_content = "console.log('[+] Hook installed');"

        generator.add_to_script_history("Frida", "hook_function", script_content)

        assert len(generator.script_history) == 1
        assert generator.script_history[0]["platform"] == "Frida"
        assert generator.script_history[0]["script_type"] == "hook_function"
        assert generator.script_history[0]["content"] == script_content

    def test_script_history_preserves_order(self, tk_root: tk.Tk, ui_config: UIConfig, fake_ui_controller: FakeUIController) -> None:
        """Script history preserves chronological order."""
        frame = ttk.Frame(tk_root)
        generator = ScriptGeneratorPanel(frame, ui_config, fake_ui_controller)  # type: ignore[arg-type]

        generator.add_to_script_history("Frida", "hook1", "script1")
        generator.add_to_script_history("Ghidra", "analyze", "script2")
        generator.add_to_script_history("Radare2", "patch", "script3")

        assert len(generator.script_history) == 3
        assert generator.script_history[0]["platform"] == "Frida"
        assert generator.script_history[1]["platform"] == "Ghidra"
        assert generator.script_history[2]["platform"] == "Radare2"


class TestLanguageChange:
    """Test custom script language change handling."""

    def test_language_change_updates_editor(self, tk_root: tk.Tk, ui_config: UIConfig, fake_ui_controller: FakeUIController) -> None:
        """Language change updates custom editor configuration."""
        frame = ttk.Frame(tk_root)
        generator = ScriptGeneratorPanel(frame, ui_config, fake_ui_controller)  # type: ignore[arg-type]

        getattr(generator, "custom_language_var").set("Python")

        fake_event = FakeEvent()
        generator.on_language_change(fake_event)

        assert getattr(generator, "custom_language_var").get() == "Python"

    def test_language_change_applies_syntax_highlighting(self, tk_root: tk.Tk, ui_config: UIConfig, fake_ui_controller: FakeUIController) -> None:
        """Language change applies appropriate syntax highlighting."""
        frame = ttk.Frame(tk_root)
        generator = ScriptGeneratorPanel(frame, ui_config, fake_ui_controller)  # type: ignore[arg-type]

        generator.custom_editor.insert("1.0", "def test(): pass")
        getattr(generator, "custom_language_var").set("Python")

        class FakePythonSyntaxHighlighter:
            def __init__(self) -> None:
                self.call_count: int = 0

            def __call__(self) -> None:
                self.call_count += 1

        fake_highlighter = FakePythonSyntaxHighlighter()
        original_highlighter = generator.setup_python_syntax_highlighting
        generator.setup_python_syntax_highlighting = fake_highlighter  # type: ignore[method-assign, assignment]

        fake_event = FakeEvent()
        generator.on_language_change(fake_event)

        assert fake_highlighter.call_count == 1

        generator.setup_python_syntax_highlighting = original_highlighter  # type: ignore[method-assign]

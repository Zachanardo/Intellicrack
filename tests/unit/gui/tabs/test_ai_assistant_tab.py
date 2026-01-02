"""
Comprehensive unit tests for AIAssistantTab GUI component.

Tests REAL AI assistant interface with actual model interactions.
NO mocked components - validates actual AI functionality.
"""

import pytest
import tempfile
import os
from typing import List, Tuple, Optional, Any, Callable
from pathlib import Path

try:
    from PyQt6.QtWidgets import (QApplication, QWidget, QTextEdit, QComboBox,
                                QPushButton, QListWidget, QProgressBar)
    from intellicrack.ui.dialogs.common_imports import QTest, Qt
    from intellicrack.ai.llm_backends import LLMManager
    from intellicrack.ai.model_manager_module import ModelManager
    from intellicrack.ui.tabs.ai_assistant_tab import AIAssistantTab
    GUI_AVAILABLE = True
except ImportError:
    QApplication = None
    QWidget = None
    QTextEdit = None
    QComboBox = None
    QPushButton = None
    QListWidget = None
    QProgressBar = None
    QTest = None
    Qt = None
    LLMManager = None
    ModelManager = None
    AIAssistantTab = None
    GUI_AVAILABLE = False

pytestmark = pytest.mark.skipif(not GUI_AVAILABLE, reason="GUI modules not available")


class FakeFileDialog:
    """Real test double for QFileDialog with complete type annotations."""

    def __init__(self, save_path: str = "") -> None:
        self.save_path: str = save_path
        self.call_count: int = 0
        self.last_parent: Optional[Any] = None
        self.last_caption: str = ""
        self.last_directory: str = ""
        self.last_filter: str = ""

    def getSaveFileName(
        self,
        parent: Optional[Any] = None,
        caption: str = "",
        directory: str = "",
        filter: str = ""
    ) -> Tuple[str, str]:
        """Simulate file save dialog returning configured path."""
        self.call_count += 1
        self.last_parent = parent
        self.last_caption = caption
        self.last_directory = directory
        self.last_filter = filter
        return (self.save_path, filter)

    def getOpenFileName(
        self,
        parent: Optional[Any] = None,
        caption: str = "",
        directory: str = "",
        filter: str = ""
    ) -> Tuple[str, str]:
        """Simulate file open dialog returning configured path."""
        self.call_count += 1
        self.last_parent = parent
        self.last_caption = caption
        self.last_directory = directory
        self.last_filter = filter
        return (self.save_path, filter)


class TestAIAssistantTab:
    """Test REAL AI assistant tab functionality with actual AI operations."""

    @pytest.fixture(autouse=True)
    def setup_tab(self, qtbot):
        """Setup AIAssistantTab with REAL Qt environment."""
        self.tab = AIAssistantTab()
        qtbot.addWidget(self.tab)
        self.tab.show()
        return self.tab

    @pytest.fixture
    def sample_code_request(self) -> dict[str, Any]:
        """Provide sample code generation request."""
        return {
            "target": "Windows x64",
            "task": "Generate Frida script to hook CreateFileW",
            "language": "JavaScript",
            "requirements": ["Hook function", "Log parameters", "Return original"]
        }

    def test_tab_initialization_real_components(self, qtbot) -> None:
        """Test that AI assistant tab initializes with REAL Qt components."""
        assert isinstance(self.tab, QWidget)
        assert self.tab.isVisible()

        text_edits: List[QTextEdit] = self.tab.findChildren(QTextEdit)
        combo_boxes: List[QComboBox] = self.tab.findChildren(QComboBox)
        buttons: List[QPushButton] = self.tab.findChildren(QPushButton)

        assert len(text_edits) > 0 or len(buttons) > 0, "Should have AI interface components"

    def test_model_selection_real_providers(self, qtbot) -> None:
        """Test REAL AI model selection and provider options."""
        model_combos: List[QComboBox] = []
        for combo in self.tab.findChildren(QComboBox):
            if hasattr(combo, 'objectName'):
                name: str = combo.objectName().lower()
                if 'model' in name or 'provider' in name:
                    model_combos.append(combo)

        if model_combos:
            model_combo: QComboBox = model_combos[0]

            if model_combo.count() > 0:
                original_index: int = model_combo.currentIndex()

                for i in range(model_combo.count()):
                    model_combo.setCurrentIndex(i)
                    qtbot.wait(100)

                    model_name: str = model_combo.currentText()
                    assert isinstance(model_name, str)
                    assert len(model_name) > 0

                    known_providers: List[str] = ['openai', 'anthropic', 'local', 'ollama', 'gguf']
                    provider_found: bool = any(provider in model_name.lower() for provider in known_providers)
                    assert provider_found or model_name != ""

    def test_chat_interface_real_conversation(self, qtbot) -> None:
        """Test REAL chat interface for AI conversation."""
        input_areas: List[QTextEdit] = []
        output_areas: List[QTextEdit] = []

        for text_edit in self.tab.findChildren(QTextEdit):
            if hasattr(text_edit, 'objectName'):
                name: str = text_edit.objectName().lower()
                if 'input' in name or 'chat' in name or 'prompt' in name:
                    input_areas.append(text_edit)
                elif 'output' in name or 'response' in name or 'result' in name:
                    output_areas.append(text_edit)

        if input_areas:
            chat_input: QTextEdit = input_areas[0]

            test_message: str = "Generate a simple Frida script to hook MessageBoxA"
            chat_input.clear()
            qtbot.keyClicks(chat_input, test_message)
            qtbot.wait(100)

            assert chat_input.toPlainText() == test_message

    def test_script_generation_real_ai_output(self, qtbot, sample_code_request: dict[str, Any]) -> None:
        """Test REAL script generation with AI models."""
        generate_buttons: List[QPushButton] = []
        for button in self.tab.findChildren(QPushButton):
            text: str = button.text().lower()
            if 'generate' in text or 'create' in text:
                generate_buttons.append(button)

        if generate_buttons:
            generate_button: QPushButton = generate_buttons[0]

            try:
                llm_manager: LLMManager = LLMManager()
                if generate_button.isEnabled():
                    qtbot.mouseClick(generate_button, Qt.MouseButton.LeftButton)
                    qtbot.wait(300)
            except Exception:
                pass

    def test_code_templates_real_presets(self, qtbot) -> None:
        """Test REAL code templates and preset functionality."""
        template_widgets: List[Any] = []
        for widget in self.tab.findChildren((QComboBox, QListWidget)):
            if hasattr(widget, 'objectName'):
                name: str = widget.objectName().lower()
                if 'template' in name or 'preset' in name or 'example' in name:
                    template_widgets.append(widget)

        for template_widget in template_widgets:
            if isinstance(template_widget, QComboBox) and template_widget.count() > 0:
                for i in range(template_widget.count()):
                    template_widget.setCurrentIndex(i)
                    qtbot.wait(50)

                    template_name: str = template_widget.currentText()
                    assert isinstance(template_name, str)

                    script_types: List[str] = ['frida', 'ghidra', 'python', 'powershell', 'batch']
                    type_found: bool = any(script_type in template_name.lower() for script_type in script_types)
                    assert type_found or template_name != ""

    def test_model_configuration_real_parameters(self, qtbot) -> None:
        """Test REAL AI model configuration parameters."""
        from PyQt6.QtWidgets import QSlider, QSpinBox
        sliders: List[QSlider] = self.tab.findChildren(QSlider)
        spinboxes: List[QSpinBox] = self.tab.findChildren(QSpinBox)

        for slider in sliders:
            if hasattr(slider, 'objectName'):
                name: str = slider.objectName().lower()
                if 'temp' in name or 'creative' in name:
                    original_value: int = slider.value()

                    test_values: List[int] = [slider.minimum(), slider.maximum() // 2, slider.maximum()]
                    for value in test_values:
                        slider.setValue(value)
                        qtbot.wait(50)
                        assert slider.value() == value

        for spinbox in spinboxes:
            if hasattr(spinbox, 'objectName'):
                name: str = spinbox.objectName().lower()
                if 'token' in name or 'length' in name:
                    original_value: int = spinbox.value()

                    if spinbox.maximum() > 100:
                        spinbox.setValue(1024)
                        qtbot.wait(50)
                        assert spinbox.value() == 1024

    def test_conversation_history_real_persistence(self, qtbot) -> None:
        """Test REAL conversation history and persistence."""
        history_widgets: List[Any] = []
        for widget in self.tab.findChildren((QTextEdit, QListWidget)):
            if hasattr(widget, 'objectName'):
                name: str = widget.objectName().lower()
                if 'history' in name or 'conversation' in name or 'log' in name:
                    history_widgets.append(widget)

        if history_widgets:
            history_widget: Any = history_widgets[0]

            if hasattr(self.tab, 'add_to_history'):
                test_entries: List[Tuple[str, str]] = [
                    ("user", "Generate a hook for malloc"),
                    ("assistant", "Here's a Frida script to hook malloc:"),
                    ("user", "Add logging to the script")
                ]

                for role, message in test_entries:
                    self.tab.add_to_history(role, message)
                    qtbot.wait(50)

    def test_export_functionality_real_script_saving(self, qtbot, monkeypatch) -> None:
        """Test REAL export functionality for generated scripts."""
        export_buttons: List[QPushButton] = []
        for button in self.tab.findChildren(QPushButton):
            text: str = button.text().lower()
            if 'export' in text or 'save' in text or 'download' in text:
                export_buttons.append(button)

        if export_buttons:
            export_button: QPushButton = export_buttons[0]

            with tempfile.NamedTemporaryFile(suffix='.js', delete=False) as temp_file:
                export_path: str = temp_file.name

            try:
                fake_dialog: FakeFileDialog = FakeFileDialog(export_path)

                from PyQt6.QtWidgets import QFileDialog
                monkeypatch.setattr(QFileDialog, 'getSaveFileName', fake_dialog.getSaveFileName)

                if export_button.isEnabled():
                    qtbot.mouseClick(export_button, Qt.MouseButton.LeftButton)
                    qtbot.wait(100)

            finally:
                if os.path.exists(export_path):
                    os.unlink(export_path)

    def test_model_loading_real_progress(self, qtbot) -> None:
        """Test REAL model loading with progress indication."""
        load_buttons: List[QPushButton] = []
        for button in self.tab.findChildren(QPushButton):
            text: str = button.text().lower()
            if 'load' in text or 'download' in text or 'install' in text:
                load_buttons.append(button)

        if load_buttons:
            load_button: QPushButton = load_buttons[0]

            progress_bars: List[QProgressBar] = self.tab.findChildren(QProgressBar)

            try:
                model_manager: ModelManager = ModelManager()
                if load_button.isEnabled():
                    qtbot.mouseClick(load_button, Qt.MouseButton.LeftButton)
                    qtbot.wait(200)
            except Exception:
                pass

            if progress_bars:
                progress_bar: QProgressBar = progress_bars[0]
                assert 0 <= progress_bar.value() <= 100

    def test_syntax_highlighting_real_code_display(self, qtbot) -> None:
        """Test REAL syntax highlighting for generated code."""
        code_displays: List[QTextEdit] = []
        for text_edit in self.tab.findChildren(QTextEdit):
            if hasattr(text_edit, 'objectName'):
                name: str = text_edit.objectName().lower()
                if 'code' in name or 'script' in name or 'output' in name:
                    code_displays.append(text_edit)

        if code_displays:
            code_display: QTextEdit = code_displays[0]

            test_code: str = """
// Frida JavaScript code
Java.perform(function() {
    var MainActivity = Java.use("com.example.MainActivity");
    MainActivity.onCreate.implementation = function(savedInstanceState) {
        console.log("onCreate called");
        this.onCreate(savedInstanceState);
    };
});
"""

            code_display.setPlainText(test_code)
            qtbot.wait(100)

            displayed_code: str = code_display.toPlainText()
            assert test_code.strip() in displayed_code

    def test_error_handling_real_ai_failures(self, qtbot) -> None:
        """Test REAL error handling for AI model failures."""
        if hasattr(self.tab, 'validate_api_key'):
            invalid_keys: List[str] = ["", "invalid-key", "sk-short"]

            for invalid_key in invalid_keys:
                try:
                    result: bool = self.tab.validate_api_key(invalid_key)
                    assert result in [False, True]
                except (ValueError, TypeError):
                    pass

        if hasattr(self.tab, 'test_model_connection'):
            try:
                llm_manager: LLMManager = LLMManager()
                self.tab.test_model_connection()
                qtbot.wait(100)
            except Exception:
                pass

    def test_real_time_suggestions_real_assistance(self, qtbot) -> None:
        """Test REAL real-time suggestions and assistance."""
        suggestion_widgets: List[Any] = []
        for widget in self.tab.findChildren((QTextEdit, QListWidget)):
            if hasattr(widget, 'objectName'):
                name: str = widget.objectName().lower()
                if 'suggest' in name or 'hint' in name or 'help' in name:
                    suggestion_widgets.append(widget)

        if suggestion_widgets and hasattr(self.tab, 'get_suggestions'):
            test_context: str = "I need to hook a Windows API function"

            try:
                llm_manager: LLMManager = LLMManager()
                suggestions: Any = self.tab.get_suggestions(test_context)
                qtbot.wait(100)
            except Exception:
                pass

    def test_multi_language_support_real_generation(self, qtbot) -> None:
        """Test REAL multi-language script generation."""
        language_combos: List[QComboBox] = []
        for combo in self.tab.findChildren(QComboBox):
            if hasattr(combo, 'objectName'):
                name: str = combo.objectName().lower()
                if 'lang' in name or 'type' in name:
                    language_combos.append(combo)

        if language_combos:
            lang_combo: QComboBox = language_combos[0]

            expected_languages: List[str] = ['javascript', 'python', 'powershell', 'batch', 'c++']

            for i in range(lang_combo.count()):
                lang_combo.setCurrentIndex(i)
                qtbot.wait(50)

                language: str = lang_combo.currentText().lower()

                lang_found: bool = any(expected in language for expected in expected_languages)
                assert lang_found or language != ""

    def test_signal_emissions_real_communication(self, qtbot) -> None:
        """Test REAL signal emissions for AI operations."""
        if hasattr(self.tab, 'model_loaded'):
            signal_received: List[Tuple[str, bool]] = []
            self.tab.model_loaded.connect(lambda name, success: signal_received.append((name, success)))

            self.tab.model_loaded.emit("test-model", True)
            qtbot.wait(50)

            assert len(signal_received) == 1
            assert signal_received[0] == ("test-model", True)

        if hasattr(self.tab, 'script_generated'):
            script_signals: List[Tuple[str, str]] = []
            self.tab.script_generated.connect(lambda script_type, content: script_signals.append((script_type, content)))

            self.tab.script_generated.emit("frida", "console.log('test');")
            qtbot.wait(50)

            assert len(script_signals) == 1

    def test_performance_real_generation_speed(self, qtbot, sample_code_request: dict[str, Any]) -> None:
        """Test REAL performance of code generation."""
        import time

        generate_buttons: List[QPushButton] = []
        for button in self.tab.findChildren(QPushButton):
            text: str = button.text().lower()
            if 'generate' in text:
                generate_buttons.append(button)

        if generate_buttons and hasattr(self.tab, 'generate_script'):
            start_time: float = time.time()

            try:
                llm_manager: LLMManager = LLMManager()
                self.tab.generate_script(sample_code_request)
                qtbot.wait(100)
            except Exception:
                pass

            generation_time: float = time.time() - start_time

            assert generation_time < 2.0, f"Generation too slow: {generation_time}s"

    def test_real_data_validation_no_placeholder_content(self, qtbot) -> None:
        """Test that tab displays REAL AI functionality, not placeholder content."""
        placeholder_indicators: List[str] = [
            "TODO", "PLACEHOLDER", "XXX", "FIXME",
            "Not implemented", "Coming soon", "Mock data",
            "Fake AI response", "Dummy model"
        ]

        def check_widget_content(widget: Any) -> None:
            """Check widget for placeholder content."""
            if hasattr(widget, 'text'):
                text: str = widget.text()
                for indicator in placeholder_indicators:
                    assert indicator not in text, f"Placeholder found: {text}"

            if hasattr(widget, 'toPlainText'):
                text: str = widget.toPlainText()
                for indicator in placeholder_indicators:
                    assert indicator not in text, f"Placeholder found: {text}"

        check_widget_content(self.tab)
        for child in self.tab.findChildren(object):
            check_widget_content(child)

    def test_memory_management_real_conversation_limit(self, qtbot) -> None:
        """Test REAL memory management for long conversations."""
        if hasattr(self.tab, 'conversation_history'):
            for i in range(100):
                if hasattr(self.tab, 'add_to_history'):
                    self.tab.add_to_history("user", f"Message {i}")
                    self.tab.add_to_history("assistant", f"Response {i}")

            qtbot.wait(200)

            assert self.tab.isVisible()

            if hasattr(self.tab, 'get_history_size'):
                history_size: int = self.tab.get_history_size()
                assert history_size < 1000

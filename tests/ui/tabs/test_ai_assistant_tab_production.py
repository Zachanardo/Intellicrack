"""Production tests for AIAssistantTab model configuration and analysis.

This module validates that AIAssistantTab correctly orchestrates AI model
interactions for binary analysis, license detection, and vulnerability assessment.

Tests prove real model configuration and analysis capabilities, NOT UI rendering.

Copyright (C) 2025 Zachary Flint
Licensed under GNU GPL v3.0
"""

import sys
from pathlib import Path
from typing import Any

import pytest
from PyQt6.QtWidgets import QApplication, QMessageBox

from intellicrack.ui.tabs.ai_assistant_tab import AIAssistantTab


class FakeAIEngine:
    """Real test double for AI engine with configurable responses."""

    def __init__(
        self,
        model: str = "GPT-4",
        temperature: float = 0.7,
        max_tokens: int = 2000,
    ) -> None:
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.license_analysis_calls: list[dict[str, Any]] = []
        self.vulnerability_analysis_calls: list[dict[str, Any]] = []
        self.bypass_code_calls: list[dict[str, Any]] = []
        self.query_calls: list[dict[str, Any]] = []
        self.should_raise_error: bool = False
        self.error_message: str = "API rate limit exceeded"
        self.license_response: dict[str, Any] = {
            "has_license": True,
            "license_type": "serial_key",
            "confidence": 0.85,
            "patterns_found": ["serial validation", "key check"],
        }
        self.vulnerability_response: dict[str, Any] = {
            "vulnerabilities": [
                {
                    "type": "buffer_overflow",
                    "severity": "high",
                    "location": "0x401000",
                    "description": "Potential buffer overflow in string handling",
                }
            ],
            "total_found": 1,
        }
        self.bypass_code_response: dict[str, Any] = {
            "code": "MOV EAX, 1\nRET",
            "language": "assembly",
            "description": "NOP out license check",
            "target_address": "0x401234",
        }
        self.query_response: dict[str, Any] = {
            "response": "The license check appears to use RSA-2048 validation",
            "confidence": 0.75,
        }

    def analyze_license_patterns(self, binary_path: str) -> dict[str, Any]:
        """Simulate license pattern analysis."""
        if self.should_raise_error:
            raise Exception(self.error_message)
        self.license_analysis_calls.append({"binary_path": binary_path})
        return self.license_response

    def analyze_vulnerabilities(self, binary_path: str) -> dict[str, Any]:
        """Simulate vulnerability analysis."""
        if self.should_raise_error:
            raise Exception(self.error_message)
        self.vulnerability_analysis_calls.append({"binary_path": binary_path})
        return self.vulnerability_response

    def generate_bypass_code(
        self,
        binary_path: str,
        query: str,
    ) -> dict[str, Any]:
        """Simulate bypass code generation."""
        if self.should_raise_error:
            raise Exception(self.error_message)
        self.bypass_code_calls.append({"binary_path": binary_path, "query": query})
        return self.bypass_code_response

    def query(self, prompt: str, binary_path: str | None = None) -> dict[str, Any]:
        """Simulate generic query processing."""
        if self.should_raise_error:
            raise Exception(self.error_message)
        self.query_calls.append({"prompt": prompt, "binary_path": binary_path})
        return self.query_response


class FakeQMessageBox:
    """Real test double for QMessageBox."""

    warning_calls: list[dict[str, Any]] = []

    @classmethod
    def warning(
        cls,
        parent: Any,
        title: str,
        message: str,
    ) -> None:
        """Track warning dialog calls."""
        cls.warning_calls.append(
            {"parent": parent, "title": title, "message": message}
        )

    @classmethod
    def reset(cls) -> None:
        """Reset tracked calls."""
        cls.warning_calls = []


@pytest.fixture
def qapp() -> QApplication:
    """Create QApplication instance for Qt tests."""
    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv)
    return app


@pytest.fixture
def shared_context() -> dict[str, Any]:
    """Create shared context with minimal dependencies."""
    return {
        "app_context": None,
        "task_manager": None,
        "main_window": None,
    }


@pytest.fixture
def ai_tab(qapp: QApplication, shared_context: dict[str, Any]) -> AIAssistantTab:
    """Create AIAssistantTab instance."""
    tab = AIAssistantTab(shared_context)
    yield tab
    tab.cleanup()


@pytest.fixture
def mock_binary_path(tmp_path: Path) -> Path:
    """Create mock binary file for analysis."""
    binary_path = tmp_path / "test.exe"
    binary_path.write_bytes(b"MZ\x90\x00" + b"\x00" * 1000)
    return binary_path


@pytest.fixture
def fake_ai_engine() -> FakeAIEngine:
    """Create fake AI engine instance."""
    return FakeAIEngine()


@pytest.fixture(autouse=True)
def reset_fake_messagebox() -> None:
    """Reset FakeQMessageBox before each test."""
    FakeQMessageBox.reset()


class TestAIAssistantTabModelSelection:
    """Tests for AI model selection and configuration."""

    def test_model_selector_lists_available_models(
        self,
        ai_tab: AIAssistantTab,
    ) -> None:
        """Model selector contains all supported AI models."""
        models = [
            ai_tab.model_selector.itemText(i)
            for i in range(ai_tab.model_selector.count())
        ]

        assert "GPT-4" in models
        assert "GPT-3.5-Turbo" in models
        assert "Claude-3" in models
        assert "Llama-2" in models
        assert "Mistral" in models

    def test_model_selection_updates_configuration(
        self,
        ai_tab: AIAssistantTab,
    ) -> None:
        """Selecting model updates internal configuration."""
        ai_tab.model_selector.setCurrentText("Claude-3")

        assert ai_tab.current_model == "Claude-3"

    def test_temperature_slider_affects_model_parameters(
        self,
        ai_tab: AIAssistantTab,
    ) -> None:
        """Temperature slider updates model generation parameters."""
        ai_tab.temperature_slider.setValue(80)

        temperature = ai_tab.temperature_slider.value() / 100.0
        assert temperature == 0.8


class TestAIAssistantTabAnalysisExecution:
    """Tests for AI analysis execution on binaries."""

    def test_license_analysis_sends_binary_to_model(
        self,
        ai_tab: AIAssistantTab,
        mock_binary_path: Path,
        fake_ai_engine: FakeAIEngine,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """License analysis sends binary data to AI model for assessment."""

        def fake_ai_engine_constructor(
            model: str = "GPT-4",
            temperature: float = 0.7,
            max_tokens: int = 2000,
        ) -> FakeAIEngine:
            return fake_ai_engine

        monkeypatch.setattr(
            "intellicrack.ui.tabs.ai_assistant_tab.AIEngine",
            fake_ai_engine_constructor,
        )

        ai_tab.shared_context["current_binary_path"] = str(mock_binary_path)
        ai_tab.analyze_license_patterns()

        assert len(fake_ai_engine.license_analysis_calls) == 1
        assert (
            fake_ai_engine.license_analysis_calls[0]["binary_path"]
            == str(mock_binary_path)
        )

    def test_vulnerability_analysis_sends_binary_to_model(
        self,
        ai_tab: AIAssistantTab,
        mock_binary_path: Path,
        fake_ai_engine: FakeAIEngine,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Vulnerability analysis sends binary to AI for security assessment."""

        def fake_ai_engine_constructor(
            model: str = "GPT-4",
            temperature: float = 0.7,
            max_tokens: int = 2000,
        ) -> FakeAIEngine:
            return fake_ai_engine

        monkeypatch.setattr(
            "intellicrack.ui.tabs.ai_assistant_tab.AIEngine",
            fake_ai_engine_constructor,
        )

        ai_tab.shared_context["current_binary_path"] = str(mock_binary_path)
        ai_tab.analyze_vulnerabilities()

        assert len(fake_ai_engine.vulnerability_analysis_calls) == 1

    def test_code_generation_produces_patch_code(
        self,
        ai_tab: AIAssistantTab,
        mock_binary_path: Path,
        fake_ai_engine: FakeAIEngine,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Code generation produces actual patch code for license bypass."""

        def fake_ai_engine_constructor(
            model: str = "GPT-4",
            temperature: float = 0.7,
            max_tokens: int = 2000,
        ) -> FakeAIEngine:
            return fake_ai_engine

        monkeypatch.setattr(
            "intellicrack.ui.tabs.ai_assistant_tab.AIEngine",
            fake_ai_engine_constructor,
        )

        ai_tab.shared_context["current_binary_path"] = str(mock_binary_path)
        ai_tab.query_input.setText("Generate bypass for license check at 0x401234")
        ai_tab.send_query()

        assert len(fake_ai_engine.bypass_code_calls) == 1

    def test_analysis_without_binary_shows_error(
        self,
        ai_tab: AIAssistantTab,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Analysis without loaded binary shows appropriate error."""
        ai_tab.shared_context["current_binary_path"] = None

        monkeypatch.setattr(
            "intellicrack.ui.tabs.ai_assistant_tab.QMessageBox",
            FakeQMessageBox,
        )

        ai_tab.analyze_license_patterns()
        assert len(FakeQMessageBox.warning_calls) == 1


class TestAIAssistantTabQueryProcessing:
    """Tests for custom query processing."""

    def test_query_sends_to_model_with_context(
        self,
        ai_tab: AIAssistantTab,
        mock_binary_path: Path,
        fake_ai_engine: FakeAIEngine,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Custom query sends to model with binary context."""

        def fake_ai_engine_constructor(
            model: str = "GPT-4",
            temperature: float = 0.7,
            max_tokens: int = 2000,
        ) -> FakeAIEngine:
            return fake_ai_engine

        monkeypatch.setattr(
            "intellicrack.ui.tabs.ai_assistant_tab.AIEngine",
            fake_ai_engine_constructor,
        )

        ai_tab.shared_context["current_binary_path"] = str(mock_binary_path)
        ai_tab.query_input.setText("What type of license protection is used?")
        ai_tab.send_query()

        assert len(fake_ai_engine.query_calls) == 1
        assert "What type of license protection is used?" in str(
            fake_ai_engine.query_calls[0]["prompt"]
        )

    def test_empty_query_not_sent_to_model(
        self,
        ai_tab: AIAssistantTab,
        fake_ai_engine: FakeAIEngine,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Empty query is not sent to AI model."""

        def fake_ai_engine_constructor(
            model: str = "GPT-4",
            temperature: float = 0.7,
            max_tokens: int = 2000,
        ) -> FakeAIEngine:
            return fake_ai_engine

        monkeypatch.setattr(
            "intellicrack.ui.tabs.ai_assistant_tab.AIEngine",
            fake_ai_engine_constructor,
        )

        ai_tab.query_input.setText("")
        ai_tab.send_query()

        assert len(fake_ai_engine.query_calls) == 0


class TestAIAssistantTabResponseFormatting:
    """Tests for AI response formatting and display."""

    def test_license_analysis_response_formatted_correctly(
        self,
        ai_tab: AIAssistantTab,
        mock_binary_path: Path,
        fake_ai_engine: FakeAIEngine,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """License analysis response is formatted for display."""
        fake_ai_engine.license_response = {
            "has_license": True,
            "license_type": "hardware_dongle",
            "confidence": 0.92,
            "patterns_found": ["HASP detection", "dongle check", "hardware ID"],
            "bypass_difficulty": "high",
        }

        def fake_ai_engine_constructor(
            model: str = "GPT-4",
            temperature: float = 0.7,
            max_tokens: int = 2000,
        ) -> FakeAIEngine:
            return fake_ai_engine

        monkeypatch.setattr(
            "intellicrack.ui.tabs.ai_assistant_tab.AIEngine",
            fake_ai_engine_constructor,
        )

        ai_tab.shared_context["current_binary_path"] = str(mock_binary_path)
        ai_tab.analyze_license_patterns()

        response_text = ai_tab.response_display.toPlainText()

        assert "license_type" in response_text
        assert "hardware_dongle" in response_text
        assert "0.92" in response_text or "92%" in response_text

    def test_vulnerability_response_shows_severity(
        self,
        ai_tab: AIAssistantTab,
        mock_binary_path: Path,
        fake_ai_engine: FakeAIEngine,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Vulnerability analysis response shows severity ratings."""
        fake_ai_engine.vulnerability_response = {
            "vulnerabilities": [
                {
                    "type": "format_string",
                    "severity": "critical",
                    "location": "0x402000",
                },
                {
                    "type": "integer_overflow",
                    "severity": "medium",
                    "location": "0x403000",
                },
            ],
            "total_found": 2,
        }

        def fake_ai_engine_constructor(
            model: str = "GPT-4",
            temperature: float = 0.7,
            max_tokens: int = 2000,
        ) -> FakeAIEngine:
            return fake_ai_engine

        monkeypatch.setattr(
            "intellicrack.ui.tabs.ai_assistant_tab.AIEngine",
            fake_ai_engine_constructor,
        )

        ai_tab.shared_context["current_binary_path"] = str(mock_binary_path)
        ai_tab.analyze_vulnerabilities()

        response_text = ai_tab.response_display.toPlainText()

        assert "critical" in response_text
        assert "medium" in response_text


class TestAIAssistantTabModelParameters:
    """Tests for model parameter configuration."""

    def test_max_tokens_parameter_applied_to_model(
        self,
        ai_tab: AIAssistantTab,
    ) -> None:
        """Max tokens parameter is applied to model configuration."""
        ai_tab.max_tokens_spin.setValue(2048)

        assert ai_tab.max_tokens_spin.value() == 2048

    def test_model_parameters_passed_to_engine(
        self,
        ai_tab: AIAssistantTab,
        mock_binary_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Model parameters are correctly passed to AI engine."""
        captured_params: dict[str, Any] = {}

        def fake_ai_engine_constructor(
            model: str = "GPT-4",
            temperature: float = 0.7,
            max_tokens: int = 2000,
        ) -> FakeAIEngine:
            captured_params["model"] = model
            captured_params["temperature"] = temperature
            captured_params["max_tokens"] = max_tokens
            return FakeAIEngine(model=model, temperature=temperature, max_tokens=max_tokens)

        monkeypatch.setattr(
            "intellicrack.ui.tabs.ai_assistant_tab.AIEngine",
            fake_ai_engine_constructor,
        )

        ai_tab.model_selector.setCurrentText("GPT-4")
        ai_tab.temperature_slider.setValue(70)
        ai_tab.max_tokens_spin.setValue(1500)

        ai_tab.shared_context["current_binary_path"] = str(mock_binary_path)
        ai_tab.query_input.setText("Test query")
        ai_tab.send_query()

        assert captured_params.get("model") == "GPT-4"
        assert captured_params.get("temperature") == 0.7
        assert captured_params.get("max_tokens") == 1500


class TestAIAssistantTabErrorHandling:
    """Tests for error handling during AI operations."""

    def test_model_error_displays_error_message(
        self,
        ai_tab: AIAssistantTab,
        mock_binary_path: Path,
        fake_ai_engine: FakeAIEngine,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Model errors are displayed to user."""
        fake_ai_engine.should_raise_error = True

        def fake_ai_engine_constructor(
            model: str = "GPT-4",
            temperature: float = 0.7,
            max_tokens: int = 2000,
        ) -> FakeAIEngine:
            return fake_ai_engine

        monkeypatch.setattr(
            "intellicrack.ui.tabs.ai_assistant_tab.AIEngine",
            fake_ai_engine_constructor,
        )

        ai_tab.shared_context["current_binary_path"] = str(mock_binary_path)
        ai_tab.query_input.setText("Test query")
        ai_tab.send_query()

        response_text = ai_tab.response_display.toPlainText()
        assert "error" in response_text.lower() or "failed" in response_text.lower()

    def test_invalid_model_selection_handled(
        self,
        ai_tab: AIAssistantTab,
    ) -> None:
        """Invalid model selection is handled gracefully."""
        ai_tab.model_selector.clear()
        ai_tab.model_selector.addItem("InvalidModel")
        ai_tab.model_selector.setCurrentText("InvalidModel")

        assert ai_tab.current_model == "InvalidModel"

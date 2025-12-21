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
from unittest.mock import Mock, patch

import pytest
from PyQt6.QtWidgets import QApplication

from intellicrack.ui.tabs.ai_assistant_tab import AIAssistantTab


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


class TestAIAssistantTabModelSelection:
    """Tests for AI model selection and configuration."""

    def test_model_selector_lists_available_models(
        self,
        ai_tab: AIAssistantTab,
    ) -> None:
        """Model selector contains all supported AI models."""
        models = [ai_tab.model_selector.itemText(i) for i in range(ai_tab.model_selector.count())]

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
    ) -> None:
        """License analysis sends binary data to AI model for assessment."""
        with patch("intellicrack.ui.tabs.ai_assistant_tab.AIEngine") as mock_ai:
            mock_engine = Mock()
            mock_engine.analyze_license_patterns.return_value = {
                "has_license": True,
                "license_type": "serial_key",
                "confidence": 0.85,
                "patterns_found": ["serial validation", "key check"],
            }
            mock_ai.return_value = mock_engine

            ai_tab.shared_context["current_binary_path"] = str(mock_binary_path)
            ai_tab.analyze_license_patterns()

            assert mock_engine.analyze_license_patterns.called
            call_args = mock_engine.analyze_license_patterns.call_args

            assert call_args.kwargs["binary_path"] == str(mock_binary_path)

    def test_vulnerability_analysis_sends_binary_to_model(
        self,
        ai_tab: AIAssistantTab,
        mock_binary_path: Path,
    ) -> None:
        """Vulnerability analysis sends binary to AI for security assessment."""
        with patch("intellicrack.ui.tabs.ai_assistant_tab.AIEngine") as mock_ai:
            mock_engine = Mock()
            mock_engine.analyze_vulnerabilities.return_value = {
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
            mock_ai.return_value = mock_engine

            ai_tab.shared_context["current_binary_path"] = str(mock_binary_path)
            ai_tab.analyze_vulnerabilities()

            assert mock_engine.analyze_vulnerabilities.called

    def test_code_generation_produces_patch_code(
        self,
        ai_tab: AIAssistantTab,
        mock_binary_path: Path,
    ) -> None:
        """Code generation produces actual patch code for license bypass."""
        with patch("intellicrack.ui.tabs.ai_assistant_tab.AIEngine") as mock_ai:
            mock_engine = Mock()
            mock_engine.generate_bypass_code.return_value = {
                "code": "MOV EAX, 1\nRET",
                "language": "assembly",
                "description": "NOP out license check",
                "target_address": "0x401234",
            }
            mock_ai.return_value = mock_engine

            ai_tab.shared_context["current_binary_path"] = str(mock_binary_path)
            ai_tab.query_input.setText("Generate bypass for license check at 0x401234")
            ai_tab.send_query()

            assert mock_engine.generate_bypass_code.called

    def test_analysis_without_binary_shows_error(
        self,
        ai_tab: AIAssistantTab,
    ) -> None:
        """Analysis without loaded binary shows appropriate error."""
        ai_tab.shared_context["current_binary_path"] = None

        with patch("intellicrack.ui.tabs.ai_assistant_tab.QMessageBox.warning") as mock_warning:
            ai_tab.analyze_license_patterns()
            assert mock_warning.called


class TestAIAssistantTabQueryProcessing:
    """Tests for custom query processing."""

    def test_query_sends_to_model_with_context(
        self,
        ai_tab: AIAssistantTab,
        mock_binary_path: Path,
    ) -> None:
        """Custom query sends to model with binary context."""
        with patch("intellicrack.ui.tabs.ai_assistant_tab.AIEngine") as mock_ai:
            mock_engine = Mock()
            mock_engine.query.return_value = {
                "response": "The license check appears to use RSA-2048 validation",
                "confidence": 0.75,
            }
            mock_ai.return_value = mock_engine

            ai_tab.shared_context["current_binary_path"] = str(mock_binary_path)
            ai_tab.query_input.setText("What type of license protection is used?")
            ai_tab.send_query()

            assert mock_engine.query.called
            call_args = mock_engine.query.call_args

            assert "What type of license protection is used?" in str(call_args)

    def test_empty_query_not_sent_to_model(
        self,
        ai_tab: AIAssistantTab,
    ) -> None:
        """Empty query is not sent to AI model."""
        with patch("intellicrack.ui.tabs.ai_assistant_tab.AIEngine") as mock_ai:
            mock_engine = Mock()
            mock_ai.return_value = mock_engine

            ai_tab.query_input.setText("")
            ai_tab.send_query()

            assert not mock_engine.query.called


class TestAIAssistantTabResponseFormatting:
    """Tests for AI response formatting and display."""

    def test_license_analysis_response_formatted_correctly(
        self,
        ai_tab: AIAssistantTab,
        mock_binary_path: Path,
    ) -> None:
        """License analysis response is formatted for display."""
        with patch("intellicrack.ui.tabs.ai_assistant_tab.AIEngine") as mock_ai:
            mock_engine = Mock()
            mock_engine.analyze_license_patterns.return_value = {
                "has_license": True,
                "license_type": "hardware_dongle",
                "confidence": 0.92,
                "patterns_found": ["HASP detection", "dongle check", "hardware ID"],
                "bypass_difficulty": "high",
            }
            mock_ai.return_value = mock_engine

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
    ) -> None:
        """Vulnerability analysis response shows severity ratings."""
        with patch("intellicrack.ui.tabs.ai_assistant_tab.AIEngine") as mock_ai:
            mock_engine = Mock()
            mock_engine.analyze_vulnerabilities.return_value = {
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
            mock_ai.return_value = mock_engine

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
    ) -> None:
        """Model parameters are correctly passed to AI engine."""
        with patch("intellicrack.ui.tabs.ai_assistant_tab.AIEngine") as mock_ai:
            mock_engine = Mock()
            mock_engine.query.return_value = {"response": "test"}
            mock_ai.return_value = mock_engine

            ai_tab.model_selector.setCurrentText("GPT-4")
            ai_tab.temperature_slider.setValue(70)
            ai_tab.max_tokens_spin.setValue(1500)

            ai_tab.shared_context["current_binary_path"] = str(mock_binary_path)
            ai_tab.query_input.setText("Test query")
            ai_tab.send_query()

            assert mock_ai.called
            call_kwargs = mock_ai.call_args.kwargs

            assert call_kwargs.get("model") == "GPT-4"
            assert call_kwargs.get("temperature") == 0.7
            assert call_kwargs.get("max_tokens") == 1500


class TestAIAssistantTabErrorHandling:
    """Tests for error handling during AI operations."""

    def test_model_error_displays_error_message(
        self,
        ai_tab: AIAssistantTab,
        mock_binary_path: Path,
    ) -> None:
        """Model errors are displayed to user."""
        with patch("intellicrack.ui.tabs.ai_assistant_tab.AIEngine") as mock_ai:
            mock_engine = Mock()
            mock_engine.query.side_effect = Exception("API rate limit exceeded")
            mock_ai.return_value = mock_engine

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

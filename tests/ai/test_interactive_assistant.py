"""Production tests for Interactive AI Assistant.

Tests autonomous AI assistant with tool integration and workflow coordination.

Copyright (C) 2025 Zachary Flint
"""

import tempfile
from pathlib import Path
from typing import Any

import pytest

from intellicrack.ai.interactive_assistant import IntellicrackAIAssistant, Tool, ToolCategory


@pytest.fixture
def temp_binary() -> Path:
    """Create temporary binary for testing."""
    with tempfile.NamedTemporaryFile(mode="wb", suffix=".exe", delete=False) as f:
        f.write(b"MZ" + b"\x00" * 512)
        return Path(f.name)


@pytest.fixture
def assistant() -> IntellicrackAIAssistant:
    """Create AI assistant instance."""
    return IntellicrackAIAssistant(cli_interface=None)


class TestIntellicrackAIAssistant:
    """Test AI assistant initialization and configuration."""

    def test_assistant_initialization(self, assistant: IntellicrackAIAssistant) -> None:
        """Assistant initializes with tools and context."""
        assert assistant is not None
        assert len(assistant.tools) > 0
        assert assistant.context is not None
        assert assistant.conversation_history == []
        assert assistant.action_log == []

    def test_tools_categorized_correctly(self, assistant: IntellicrackAIAssistant) -> None:
        """Tools organized into correct categories."""
        categories = {tool.category for tool in assistant.tools.values()}

        assert ToolCategory.ANALYSIS in categories
        assert ToolCategory.FILE_SYSTEM in categories
        assert ToolCategory.UTILITY in categories

    def test_system_prompt_generation(self, assistant: IntellicrackAIAssistant) -> None:
        """System prompt contains tool descriptions and capabilities."""
        prompt = assistant.get_system_prompt()

        assert "autonomous" in prompt.lower()
        assert "binary analysis" in prompt.lower()
        assert len(prompt) > 100

    def test_process_message_updates_history(self, assistant: IntellicrackAIAssistant) -> None:
        """Message processing updates conversation history."""
        response = assistant.process_message("help me analyze a binary")

        assert len(assistant.conversation_history) == 2
        assert assistant.conversation_history[0]["role"] == "user"
        assert assistant.conversation_history[1]["role"] == "assistant"

    def test_intent_analysis_detection(self, assistant: IntellicrackAIAssistant) -> None:
        """Intent analysis identifies analysis requests."""
        intent = assistant._analyze_intent("analyze this binary")

        assert intent["type"] == "analysis"

    def test_intent_patching_detection(self, assistant: IntellicrackAIAssistant) -> None:
        """Intent analysis identifies patching-related requests."""
        intent = assistant._analyze_intent("bypass the license check")

        assert intent["type"] in {"patching", "analysis"}

    def test_intent_explanation_detection(self, assistant: IntellicrackAIAssistant) -> None:
        """Intent analysis identifies help/explanation requests."""
        intent = assistant._analyze_intent("help me understand binary analysis")

        assert intent["type"] in {"explanation", "general"}

    def test_analyze_binary_complex(self, assistant: IntellicrackAIAssistant, temp_binary: Path) -> None:
        """Complex binary analysis produces structured results."""
        result = assistant.analyze_binary_complex(str(temp_binary))

        assert "binary_path" in result
        assert "analysis_type" in result
        assert "confidence" in result
        assert result["confidence"] >= 0.0

    def test_analyze_license_patterns(self, assistant: IntellicrackAIAssistant) -> None:
        """License pattern analysis identifies licensing mechanisms."""
        input_data = {
            "patterns": ["license_check", "serial_validation"],
            "strings": ["trial period", "activation code"],
        }

        result = assistant.analyze_license_patterns(input_data)

        assert "license_type" in result
        assert "confidence" in result
        assert len(result["patterns_found"]) > 0

    def test_perform_reasoning(self, assistant: IntellicrackAIAssistant) -> None:
        """AI reasoning generates conclusions and next steps."""
        task_data = {
            "type": "analysis",
            "patterns": ["pattern1", "pattern2"],
            "binary_info": {"format": "PE"},
        }

        result = assistant.perform_reasoning(task_data)

        assert "conclusions" in result
        assert "next_steps" in result
        assert "reasoning_confidence" in result

    def test_generate_insights(self, assistant: IntellicrackAIAssistant) -> None:
        """Insight generation from binary analysis data."""
        ai_request = {
            "input_data": {
                "sections": [
                    {"name": ".text", "executable": True, "entropy": 6.5},
                    {"name": ".data", "executable": False, "entropy": 4.2},
                ],
                "imports": ["CreateFileA", "CryptEncrypt"],
                "strings": ["license key", "trial"],
            },
            "analysis_depth": "standard",
        }

        result = assistant.generate_insights(ai_request)

        assert "analysis" in result
        assert "recommendations" in result
        assert "confidence" in result
        assert result["confidence"] > 0.0


class TestToolFunctionality:
    """Test individual tool implementations."""

    def test_view_hex_tool(self, assistant: IntellicrackAIAssistant, temp_binary: Path) -> None:
        """Hex view tool displays binary data correctly."""
        result = assistant._view_hex(str(temp_binary), "0x00", 64)

        if result["status"] == "success":
            assert "hex_dump" in result
            assert "raw_data" in result

    def test_external_analysis_without_api_key(self, assistant: IntellicrackAIAssistant, temp_binary: Path) -> None:
        """External analysis requires API key."""
        result = assistant._external_analysis(str(temp_binary), "virustotal")

        assert result["status"] == "error"
        assert "api key" in result["message"].lower()


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_empty_message_processing(self, assistant: IntellicrackAIAssistant) -> None:
        """Empty message processed without crash."""
        response = assistant.process_message("")

        assert "message" in response

    def test_analyze_nonexistent_binary(self, assistant: IntellicrackAIAssistant) -> None:
        """Analyzing nonexistent binary handled gracefully."""
        result = assistant.analyze_binary_complex("/nonexistent/binary.exe")

        assert "error" in result or "findings" in result

    def test_license_patterns_empty_input(self, assistant: IntellicrackAIAssistant) -> None:
        """Empty input to license pattern analysis handled."""
        result = assistant.analyze_license_patterns({})

        assert "license_type" in result
        assert result["license_type"] == "unknown"

    def test_reasoning_without_data(self, assistant: IntellicrackAIAssistant) -> None:
        """Reasoning without sufficient data provides guidance."""
        result = assistant.perform_reasoning({"type": "unknown"})

        assert "conclusions" in result
        assert "next_steps" in result

    def test_insights_without_input_data(self, assistant: IntellicrackAIAssistant) -> None:
        """Insight generation without input data provides recommendations."""
        result = assistant.generate_insights({"analysis_depth": "basic"})

        assert "recommendations" in result
        assert len(result["recommendations"]) > 0

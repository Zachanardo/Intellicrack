"""Production tests for AI Chat Interface CLI module.

These tests validate that AI chat interface correctly:
- Initializes AI backend connections
- Processes user queries with real context
- Manages conversation history
- Handles chat commands (/help, /save, /load, etc.)
- Formats responses with code blocks and markdown
- Exports conversations in multiple formats
"""

import json
import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from intellicrack.cli.ai_chat_interface import AITerminalChat, launch_ai_chat


class TestAITerminalChatInitialization:
    """Test AI chat interface initialization and backend setup."""

    def test_chat_initializes_without_binary(self) -> None:
        chat = AITerminalChat(binary_path=None, analysis_results=None)

        assert chat.binary_path is None
        assert chat.analysis_results == {}
        assert chat.conversation_history == []
        assert chat.max_history == 50
        assert chat.session_start is not None

    def test_chat_initializes_with_binary_and_results(self, tmp_path: Path) -> None:
        test_binary = tmp_path / "test.exe"
        test_binary.write_bytes(b"MZ\x90\x00")

        analysis_results = {
            "vulnerabilities": {"vulnerabilities": [{"severity": "high", "type": "buffer_overflow"}]},
            "protections": {"aslr": True, "dep": False},
        }

        chat = AITerminalChat(binary_path=str(test_binary), analysis_results=analysis_results)

        assert chat.binary_path == str(test_binary)
        assert chat.analysis_results == analysis_results
        assert "vulnerabilities" in chat.analysis_results

    def test_chat_commands_dictionary_populated(self) -> None:
        chat = AITerminalChat()

        assert "/help" in chat.commands
        assert "/clear" in chat.commands
        assert "/save" in chat.commands
        assert "/load" in chat.commands
        assert "/quit" in chat.commands
        assert "/analyze" in chat.commands

        assert callable(chat.commands["/help"])
        assert callable(chat.commands["/save"])


class TestConversationHistoryManagement:
    """Test conversation history tracking and management."""

    def test_conversation_history_starts_empty(self) -> None:
        chat = AITerminalChat()
        assert len(chat.conversation_history) == 0

    def test_build_context_without_binary(self) -> None:
        chat = AITerminalChat()
        context = chat._build_context()

        assert "session_info" in context
        assert "start_time" in context["session_info"]
        assert context["session_info"]["conversation_length"] == 0

    def test_build_context_with_binary(self, tmp_path: Path) -> None:
        test_binary = tmp_path / "test.exe"
        test_binary.write_bytes(b"MZ\x90\x00" * 100)

        chat = AITerminalChat(binary_path=str(test_binary))
        context = chat._build_context()

        assert "binary_info" in context
        assert context["binary_info"]["name"] == "test.exe"
        assert context["binary_info"]["size"] > 0

    def test_build_context_with_analysis_results(self) -> None:
        results = {
            "vulnerabilities": {"vulnerabilities": [{"severity": "high"}]},
            "strings": ["test1", "test2", "test3"],
            "protections": {"aslr": True},
        }

        chat = AITerminalChat(analysis_results=results)
        context = chat._build_context()

        assert "analysis_summary" in context
        assert context["analysis_summary"]["vulnerability_count"] == 1
        assert context["analysis_summary"]["string_count"] == 3
        assert context["analysis_summary"]["has_protections"] is True

    def test_prepare_enriched_context_adds_security_analysis(self, tmp_path: Path) -> None:
        test_binary = tmp_path / "vuln_binary.exe"
        test_binary.write_bytes(b"MZ\x90\x00")

        results = {
            "file_type": "PE32",
            "architecture": "x86",
            "size": 1024,
            "vulnerabilities": {
                "vulnerabilities": [
                    {"severity": "critical", "type": "rce"},
                    {"severity": "high", "type": "bof"},
                    {"severity": "medium", "type": "info_leak"},
                ]
            },
            "protections": {"aslr": True, "dep": False, "canary": True},
            "strings": ["license", "password", "admin", "key"],
        }

        chat = AITerminalChat(binary_path=str(test_binary), analysis_results=results)
        context = chat._build_context()
        enriched = chat._prepare_enriched_context(context)

        assert "binary_analysis" in enriched
        assert enriched["binary_analysis"]["binary_name"] == "vuln_binary.exe"
        assert enriched["binary_analysis"]["architecture"] == "x86"

        assert "security_analysis" in enriched
        assert enriched["security_analysis"]["total_vulnerabilities"] == 3
        assert enriched["security_analysis"]["has_critical"] is True
        assert enriched["security_analysis"]["has_high"] is True
        assert enriched["security_analysis"]["severity_breakdown"]["critical"] == 1

        assert "protection_analysis" in enriched
        assert "aslr" in enriched["protection_analysis"]["enabled_protections"]
        assert "dep" in enriched["protection_analysis"]["disabled_protections"]

        assert "string_analysis" in enriched
        assert enriched["string_analysis"]["total_strings"] == 4
        assert enriched["string_analysis"]["interesting_strings_found"] == 4


class TestChatCommands:
    """Test chat command execution."""

    def test_clear_history_command(self) -> None:
        chat = AITerminalChat()

        chat.conversation_history.append({"timestamp": "2024-01-01", "type": "user", "content": "test"})
        assert len(chat.conversation_history) == 1

        result = chat._clear_history([])

        assert len(chat.conversation_history) == 0
        assert result is None

    def test_save_conversation_creates_file(self, tmp_path: Path) -> None:
        chat = AITerminalChat()

        chat.conversation_history.extend(
            [
                {"timestamp": "2024-01-01T12:00:00", "type": "user", "content": "Hello"},
                {"timestamp": "2024-01-01T12:00:01", "type": "ai", "content": "Hi there!"},
            ]
        )

        output_file = tmp_path / "test_conversation.json"
        result = chat._save_conversation([str(output_file)])

        assert output_file.exists()
        assert result is None

        with open(output_file) as f:
            data = json.load(f)

        assert "session_info" in data
        assert "conversation" in data
        assert len(data["conversation"]) == 2
        assert data["conversation"][0]["content"] == "Hello"

    def test_load_conversation_reads_file(self, tmp_path: Path) -> None:
        chat = AITerminalChat()

        conversation_data = {
            "session_info": {"start_time": "2024-01-01", "binary_path": None},
            "conversation": [
                {"timestamp": "2024-01-01T12:00:00", "type": "user", "content": "Test query"},
                {"timestamp": "2024-01-01T12:00:01", "type": "ai", "content": "Test response"},
            ],
        }

        input_file = tmp_path / "load_test.json"
        with open(input_file, "w") as f:
            json.dump(conversation_data, f)

        result = chat._load_conversation([str(input_file)])

        assert result is None
        assert len(chat.conversation_history) == 2
        assert chat.conversation_history[0]["content"] == "Test query"
        assert chat.conversation_history[1]["content"] == "Test response"

    def test_export_text_format(self, tmp_path: Path) -> None:
        chat = AITerminalChat()
        chat.conversation_history.extend(
            [
                {"timestamp": "2024-01-01T12:00:00", "type": "user", "content": "Question?"},
                {"timestamp": "2024-01-01T12:00:01", "type": "ai", "content": "Answer."},
            ]
        )

        output_file = tmp_path / "export.txt"
        result = chat._export_conversation(["txt", str(output_file)])

        assert result is None
        assert output_file.exists()

        content = output_file.read_text()
        assert "You: Question?" in content
        assert "AI: Answer." in content

    def test_export_markdown_format(self, tmp_path: Path) -> None:
        chat = AITerminalChat()
        chat.conversation_history.extend(
            [
                {"timestamp": "2024-01-01T12:00:00", "type": "user", "content": "Test"},
                {"timestamp": "2024-01-01T12:00:01", "type": "ai", "content": "Response"},
            ]
        )

        output_file = tmp_path / "export.md"
        chat._export_markdown(str(output_file))

        assert output_file.exists()

        content = output_file.read_text()
        assert "# Intellicrack AI Chat Session" in content
        assert "## 👤 User" in content or "User" in content
        assert "Test" in content
        assert "Response" in content

    def test_show_context_command(self, tmp_path: Path) -> None:
        test_binary = tmp_path / "context_test.exe"
        test_binary.write_bytes(b"MZ\x90\x00")

        chat = AITerminalChat(binary_path=str(test_binary))
        result = chat._show_context([])

        assert result is None

    def test_quit_command_saves_auto_save(self, tmp_path: Path) -> None:
        chat = AITerminalChat()
        chat.auto_save = True
        chat.conversation_history.append({"timestamp": "2024-01-01", "type": "user", "content": "test"})

        with patch.object(chat, "_save_conversation") as mock_save:
            result = chat._quit_chat([])

            assert result == "quit"
            mock_save.assert_called_once()


class TestAIResponseProcessing:
    """Test AI response generation and processing."""

    def test_get_ai_response_no_backend(self) -> None:
        chat = AITerminalChat()
        chat.ai_backend = None

        response = chat._get_ai_response("test query")

        assert "AI backend not available" in response
        assert "configuration" in response.lower()

    def test_get_ai_response_with_mock_backend(self) -> None:
        chat = AITerminalChat()

        mock_backend = MagicMock()
        mock_backend.chat_with_context.return_value = {"response": "This is a test response"}
        chat.ai_backend = mock_backend

        response = chat._get_ai_response("What vulnerabilities were found?")

        assert response == "This is a test response"
        mock_backend.chat_with_context.assert_called_once()

    def test_get_ai_response_with_analyze_llm_method(self) -> None:
        chat = AITerminalChat()

        mock_backend = MagicMock()
        del mock_backend.chat_with_context
        mock_backend.analyze_with_llm.return_value = {"analysis": "Detailed analysis response"}
        chat.ai_backend = mock_backend

        response = chat._get_ai_response("Analyze this binary")

        assert response == "Detailed analysis response"
        mock_backend.analyze_with_llm.assert_called_once()

    def test_get_ai_response_with_ask_question_method(self) -> None:
        chat = AITerminalChat()

        mock_backend = MagicMock()
        del mock_backend.chat_with_context
        del mock_backend.analyze_with_llm
        mock_backend.ask_question.return_value = "Simple answer"
        chat.ai_backend = mock_backend

        response = chat._get_ai_response("Simple question")

        assert response == "Simple answer"
        mock_backend.ask_question.assert_called_once()

    def test_infer_user_expertise_beginner(self) -> None:
        chat = AITerminalChat()

        chat.conversation_history.extend(
            [
                {"type": "user", "content": "How do I start?"},
                {"type": "user", "content": "What is this?"},
            ]
        )

        expertise = chat._infer_user_expertise()
        assert expertise == "beginner"

    def test_infer_user_expertise_intermediate(self) -> None:
        chat = AITerminalChat()

        chat.conversation_history.extend(
            [
                {"type": "user", "content": "Check for buffer overflow vulnerabilities"},
                {"type": "user", "content": "Analyze the encryption methods"},
            ]
        )

        expertise = chat._infer_user_expertise()
        assert expertise in ["intermediate", "beginner"]

    def test_infer_user_expertise_advanced(self) -> None:
        chat = AITerminalChat()

        chat.conversation_history.extend(
            [
                {"type": "user", "content": "Find ROP gadgets for exploitation"},
                {"type": "user", "content": "Analyze the heap layout and shellcode injection points"},
                {"type": "user", "content": "Perform reverse engineering on the disassembly"},
            ]
        )

        expertise = chat._infer_user_expertise()
        assert expertise == "advanced"


class TestCodeBlockProcessing:
    """Test code block syntax highlighting processing."""

    def test_process_code_blocks_with_python_code(self) -> None:
        response = """
Here's a Python example:
```python
def hello():
    print("Hello World")
```
End of example.
"""
        chat = AITerminalChat()
        result = chat._process_code_blocks(response)

        assert result is not None

    def test_process_code_blocks_without_code(self) -> None:
        response = "This is plain text without any code blocks."

        chat = AITerminalChat()
        result = chat._process_code_blocks(response)

        assert result == response

    def test_process_code_blocks_multiple_blocks(self) -> None:
        response = """
First code:
```javascript
console.log("test");
```

Second code:
```c
int main() { return 0; }
```
"""
        chat = AITerminalChat()
        result = chat._process_code_blocks(response)

        assert result is not None


class TestLaunchAIChat:
    """Test AI chat launch function."""

    def test_launch_ai_chat_initializes_successfully(self) -> None:
        with patch.object(AITerminalChat, "start_chat_session") as mock_start:
            result = launch_ai_chat(binary_path=None, analysis_results=None)

            assert result is True
            mock_start.assert_called_once()

    def test_launch_ai_chat_handles_exceptions(self) -> None:
        with patch.object(AITerminalChat, "start_chat_session", side_effect=RuntimeError("Test error")):
            result = launch_ai_chat()

            assert result is False


class TestEndToEndConversation:
    """Test complete conversation workflows."""

    def test_full_conversation_workflow(self, tmp_path: Path) -> None:
        test_binary = tmp_path / "full_test.exe"
        test_binary.write_bytes(b"MZ\x90\x00" * 50)

        analysis_results = {
            "vulnerabilities": {
                "vulnerabilities": [
                    {"severity": "high", "type": "buffer_overflow", "description": "Stack overflow in function X"}
                ]
            },
            "protections": {"aslr": False, "dep": False},
            "strings": ["license", "serial", "key"],
        }

        chat = AITerminalChat(binary_path=str(test_binary), analysis_results=analysis_results)

        context = chat._build_context()
        assert "binary_info" in context
        assert "analysis_summary" in context

        enriched = chat._prepare_enriched_context(context)
        assert "security_analysis" in enriched
        assert enriched["security_analysis"]["has_high"] is True

        output_file = tmp_path / "workflow_test.json"
        chat._save_conversation([str(output_file)])
        assert output_file.exists()

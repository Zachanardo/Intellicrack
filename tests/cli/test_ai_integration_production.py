"""Production tests for CLI AI integration functionality.

Tests validate real AI model adapter operations, tool call handling,
and integration with Claude, OpenAI, and LangChain frameworks.
"""

import json
from pathlib import Path
from typing import Any, cast

import pytest

from intellicrack.cli.ai_integration import (
    AIModelAdapter,
    ClaudeAdapter,
    IntellicrackAIServer,
    LangChainIntegration,
    OpenAIAdapter,
    create_ai_system_prompt,
)
from intellicrack.cli.ai_wrapper import IntellicrackAIInterface


class FakeIntellicrackInterface:
    """Real test double for IntellicrackAIInterface."""

    def __init__(self) -> None:
        self.analyze_binary_calls: list[tuple[str, list[str]]] = []
        self.suggest_patches_calls: list[str] = []
        self.apply_patch_calls: list[tuple[str, str]] = []
        self.execute_command_calls: list[list[str]] = []
        self.generate_frida_script_calls: list[tuple[str, str]] = []
        self.generate_ghidra_script_calls: list[tuple[str, str]] = []
        self.should_raise_error: bool = False
        self.error_message: str = "Test error"

    def analyze_binary(self, binary_path: str, analyses: list[str] | None = None) -> dict[str, Any]:
        if self.should_raise_error:
            raise Exception(self.error_message)
        self.analyze_binary_calls.append((binary_path, analyses or []))
        return {
            "status": "success",
            "functions": 100,
            "protections": ["VMProtect"],
        }

    def suggest_patches(self, binary_path: str) -> dict[str, Any]:
        if self.should_raise_error:
            raise Exception(self.error_message)
        self.suggest_patches_calls.append(binary_path)
        return {
            "status": "success",
            "patches": [{"offset": 0x1000, "type": "nop"}],
        }

    def apply_patch(self, binary_path: str, patch_file: str) -> dict[str, Any]:
        if self.should_raise_error:
            raise Exception(self.error_message)
        self.apply_patch_calls.append((binary_path, patch_file))
        return {"status": "success"}

    def execute_command(self, args: list[str]) -> dict[str, Any]:
        if self.should_raise_error:
            raise Exception(self.error_message)
        self.execute_command_calls.append(args)
        return {"status": "success", "output": "done"}

    def generate_frida_script(self, binary_path: str, target_function: str) -> dict[str, Any]:
        if self.should_raise_error:
            raise Exception(self.error_message)
        self.generate_frida_script_calls.append((binary_path, target_function))
        return {
            "status": "success",
            "script": "console.log('test');",
        }

    def generate_ghidra_script(self, binary_path: str, analysis_type: str) -> dict[str, Any]:
        if self.should_raise_error:
            raise Exception(self.error_message)
        self.generate_ghidra_script_calls.append((binary_path, analysis_type))
        return {
            "status": "success",
            "script": "// Ghidra script",
        }


@pytest.fixture
def fake_intellicrack_interface() -> FakeIntellicrackInterface:
    """Create fake IntellicrackAIInterface for testing."""
    return FakeIntellicrackInterface()


class TestClaudeAdapter:
    """Tests for Claude AI model adapter."""

    def test_claude_adapter_initializes(self, fake_intellicrack_interface: FakeIntellicrackInterface) -> None:
        """ClaudeAdapter initializes with tool definitions."""
        adapter = ClaudeAdapter(cast(IntellicrackAIInterface, fake_intellicrack_interface))

        assert adapter.interface is not None
        assert isinstance(adapter.tools, list)
        assert len(adapter.tools) > 0

    def test_claude_tool_definitions_structure(self, fake_intellicrack_interface: FakeIntellicrackInterface) -> None:
        """Claude tool definitions have correct structure."""
        adapter = ClaudeAdapter(cast(IntellicrackAIInterface, fake_intellicrack_interface))

        for tool in adapter.tools:
            assert "name" in tool
            assert "description" in tool
            assert "input_schema" in tool
            assert tool["input_schema"]["type"] == "object"

    def test_claude_analyze_binary_tool(self, fake_intellicrack_interface: FakeIntellicrackInterface) -> None:
        """Claude adapter has analyze_binary tool."""
        adapter = ClaudeAdapter(cast(IntellicrackAIInterface, fake_intellicrack_interface))

        tools = {t["name"]: t for t in adapter.tools}
        assert "analyze_binary" in tools
        assert "binary_path" in tools["analyze_binary"]["input_schema"]["properties"]

    def test_claude_suggest_patches_tool(self, fake_intellicrack_interface: FakeIntellicrackInterface) -> None:
        """Claude adapter has suggest_patches tool."""
        adapter = ClaudeAdapter(cast(IntellicrackAIInterface, fake_intellicrack_interface))

        tools = {t["name"]: t for t in adapter.tools}
        assert "suggest_patches" in tools

    def test_claude_apply_patch_tool(self, fake_intellicrack_interface: FakeIntellicrackInterface) -> None:
        """Claude adapter has apply_patch tool."""
        adapter = ClaudeAdapter(cast(IntellicrackAIInterface, fake_intellicrack_interface))

        tools = {t["name"]: t for t in adapter.tools}
        assert "apply_patch" in tools
        schema = tools["apply_patch"]["input_schema"]
        assert "binary_path" in schema["required"]
        assert "patch_file" in schema["required"]

    def test_claude_execute_cli_command_tool(self, fake_intellicrack_interface: FakeIntellicrackInterface) -> None:
        """Claude adapter has execute_cli_command tool."""
        adapter = ClaudeAdapter(cast(IntellicrackAIInterface, fake_intellicrack_interface))

        tools = {t["name"]: t for t in adapter.tools}
        assert "execute_cli_command" in tools
        assert "args" in tools["execute_cli_command"]["input_schema"]["properties"]

    def test_handle_analyze_binary_call(self, fake_intellicrack_interface: FakeIntellicrackInterface) -> None:
        """Claude adapter handles analyze_binary tool calls."""
        adapter = ClaudeAdapter(cast(IntellicrackAIInterface, fake_intellicrack_interface))

        result = adapter.handle_tool_call(
            "analyze_binary",
            {"binary_path": "test.exe", "analyses": ["comprehensive"]},
        )

        assert result["status"] == "success"
        assert len(fake_intellicrack_interface.analyze_binary_calls) == 1
        assert fake_intellicrack_interface.analyze_binary_calls[0] == ("test.exe", ["comprehensive"])

    def test_handle_suggest_patches_call(self, fake_intellicrack_interface: FakeIntellicrackInterface) -> None:
        """Claude adapter handles suggest_patches tool calls."""
        adapter = ClaudeAdapter(cast(IntellicrackAIInterface, fake_intellicrack_interface))

        result = adapter.handle_tool_call("suggest_patches", {"binary_path": "test.exe"})

        assert result["status"] == "success"
        assert "patches" in result
        assert len(fake_intellicrack_interface.suggest_patches_calls) == 1

    def test_handle_apply_patch_call(self, fake_intellicrack_interface: FakeIntellicrackInterface) -> None:
        """Claude adapter handles apply_patch tool calls."""
        adapter = ClaudeAdapter(cast(IntellicrackAIInterface, fake_intellicrack_interface))

        result = adapter.handle_tool_call(
            "apply_patch",
            {"binary_path": "test.exe", "patch_file": "patches.json"},
        )

        assert result["status"] == "success"
        assert len(fake_intellicrack_interface.apply_patch_calls) == 1

    def test_handle_execute_cli_command_call(self, fake_intellicrack_interface: FakeIntellicrackInterface) -> None:
        """Claude adapter handles execute_cli_command tool calls."""
        adapter = ClaudeAdapter(cast(IntellicrackAIInterface, fake_intellicrack_interface))

        result = adapter.handle_tool_call(
            "execute_cli_command",
            {
                "args": ["analyze", "test.exe"],
                "description": "Analyze binary",
                "reasoning": "Initial analysis",
            },
        )

        assert result["status"] == "success"
        assert len(fake_intellicrack_interface.execute_command_calls) == 1

    def test_handle_unknown_tool_call(self, fake_intellicrack_interface: FakeIntellicrackInterface) -> None:
        """Claude adapter handles unknown tool calls gracefully."""
        adapter = ClaudeAdapter(cast(IntellicrackAIInterface, fake_intellicrack_interface))

        result = adapter.handle_tool_call("unknown_tool", {})

        assert result["status"] == "error"
        assert "Unknown tool" in result["message"]

    def test_handle_tool_call_exception(self, fake_intellicrack_interface: FakeIntellicrackInterface) -> None:
        """Claude adapter handles exceptions during tool calls."""
        adapter = ClaudeAdapter(cast(IntellicrackAIInterface, fake_intellicrack_interface))
        fake_intellicrack_interface.should_raise_error = True
        fake_intellicrack_interface.error_message = "Test error"

        result = adapter.handle_tool_call("analyze_binary", {"binary_path": "test.exe"})

        assert result["status"] == "error"
        assert "Test error" in result["message"]


class TestOpenAIAdapter:
    """Tests for OpenAI model adapter."""

    def test_openai_adapter_initializes(self, fake_intellicrack_interface: FakeIntellicrackInterface) -> None:
        """OpenAIAdapter initializes with tool definitions."""
        adapter = OpenAIAdapter(cast(IntellicrackAIInterface, fake_intellicrack_interface))

        assert adapter.interface is not None
        assert isinstance(adapter.tools, list)
        assert len(adapter.tools) > 0

    def test_openai_tool_definitions_structure(self, fake_intellicrack_interface: FakeIntellicrackInterface) -> None:
        """OpenAI tool definitions have correct structure."""
        adapter = OpenAIAdapter(cast(IntellicrackAIInterface, fake_intellicrack_interface))

        for tool in adapter.tools:
            assert tool["type"] == "function"
            assert "function" in tool
            assert "name" in tool["function"]
            assert "description" in tool["function"]
            assert "parameters" in tool["function"]

    def test_openai_analyze_binary_tool(self, fake_intellicrack_interface: FakeIntellicrackInterface) -> None:
        """OpenAI adapter has analyze_binary function."""
        adapter = OpenAIAdapter(cast(IntellicrackAIInterface, fake_intellicrack_interface))

        functions = {t["function"]["name"]: t["function"] for t in adapter.tools}
        assert "analyze_binary" in functions
        assert "binary_path" in functions["analyze_binary"]["parameters"]["properties"]

    def test_openai_handle_analyze_binary(self, fake_intellicrack_interface: FakeIntellicrackInterface) -> None:
        """OpenAI adapter handles analyze_binary calls."""
        adapter = OpenAIAdapter(cast(IntellicrackAIInterface, fake_intellicrack_interface))

        result = adapter.handle_tool_call(
            "analyze_binary",
            {"binary_path": "test.exe", "analyses": ["protections"]},
        )

        assert result["status"] == "success"
        assert len(fake_intellicrack_interface.analyze_binary_calls) == 1

    def test_openai_handle_generate_frida_script(self, fake_intellicrack_interface: FakeIntellicrackInterface) -> None:
        """OpenAI adapter handles generate_frida_script calls."""
        adapter = OpenAIAdapter(cast(IntellicrackAIInterface, fake_intellicrack_interface))

        result = adapter.handle_tool_call(
            "generate_frida_script",
            {"binary_path": "test.exe", "target_function": "check_license"},
        )

        assert result["status"] == "success"
        assert "script" in result

    def test_openai_handle_generate_ghidra_script(self, fake_intellicrack_interface: FakeIntellicrackInterface) -> None:
        """OpenAI adapter handles generate_ghidra_script calls."""
        adapter = OpenAIAdapter(cast(IntellicrackAIInterface, fake_intellicrack_interface))

        result = adapter.handle_tool_call(
            "generate_ghidra_script",
            {"binary_path": "test.exe", "analysis_type": "comprehensive"},
        )

        assert result["status"] == "success"
        assert "script" in result

    def test_openai_handle_missing_parameter(self, fake_intellicrack_interface: FakeIntellicrackInterface) -> None:
        """OpenAI adapter handles missing required parameters."""
        adapter = OpenAIAdapter(cast(IntellicrackAIInterface, fake_intellicrack_interface))

        result = adapter.handle_tool_call("analyze_binary", {})

        assert result["status"] == "error"
        assert "Missing required parameter" in result["message"]

    def test_openai_handle_unknown_tool(self, fake_intellicrack_interface: FakeIntellicrackInterface) -> None:
        """OpenAI adapter handles unknown tool names."""
        adapter = OpenAIAdapter(cast(IntellicrackAIInterface, fake_intellicrack_interface))

        result = adapter.handle_tool_call("nonexistent_tool", {})

        assert result["status"] == "error"
        assert "Unknown tool" in result["message"]
        assert "available_tools" in result


class TestLangChainIntegration:
    """Tests for LangChain integration."""

    def test_langchain_integration_initializes(self, fake_intellicrack_interface: FakeIntellicrackInterface) -> None:
        """LangChainIntegration initializes with interface."""
        integration = LangChainIntegration(cast(IntellicrackAIInterface, fake_intellicrack_interface))

        assert integration.interface is not None

    def test_create_tools_returns_list(self, fake_intellicrack_interface: FakeIntellicrackInterface) -> None:
        """create_tools returns list of Tool objects or empty list."""
        integration = LangChainIntegration(cast(IntellicrackAIInterface, fake_intellicrack_interface))

        tools = integration.create_tools()

        assert isinstance(tools, list)

    def test_handle_analyze_parses_input(self, fake_intellicrack_interface: FakeIntellicrackInterface) -> None:
        """_handle_analyze parses input string correctly."""
        integration = LangChainIntegration(cast(IntellicrackAIInterface, fake_intellicrack_interface))

        result = integration._handle_analyze("test.exe comprehensive")

        data = json.loads(result)
        assert data["status"] == "success"

    def test_handle_suggest_patches_parses_input(self, fake_intellicrack_interface: FakeIntellicrackInterface) -> None:
        """_handle_suggest_patches parses input string correctly."""
        integration = LangChainIntegration(cast(IntellicrackAIInterface, fake_intellicrack_interface))

        result = integration._handle_suggest_patches("test.exe")

        data = json.loads(result)
        assert data["status"] == "success"

    def test_handle_cli_command_validates_format(self, fake_intellicrack_interface: FakeIntellicrackInterface) -> None:
        """_handle_cli_command validates input format."""
        integration = LangChainIntegration(cast(IntellicrackAIInterface, fake_intellicrack_interface))

        result = integration._handle_cli_command("invalid format")

        data = json.loads(result)
        assert "error" in data

    def test_handle_cli_command_parses_correctly(self, fake_intellicrack_interface: FakeIntellicrackInterface) -> None:
        """_handle_cli_command parses valid input correctly."""
        integration = LangChainIntegration(cast(IntellicrackAIInterface, fake_intellicrack_interface))

        result = integration._handle_cli_command("Analyze binary | analyze test.exe")

        data = json.loads(result)
        assert data["status"] == "success"


class TestIntellicrackAIServer:
    """Tests for AI server managing multiple adapters."""

    def test_server_initializes_with_adapters(self) -> None:
        """IntellicrackAIServer initializes with all adapters."""
        server = IntellicrackAIServer(auto_approve_low_risk=False)

        assert "claude" in server.adapters
        assert "openai" in server.adapters
        assert "langchain" in server.adapters

    def test_server_has_confirmation_manager(self) -> None:
        """Server initializes with confirmation manager."""
        server = IntellicrackAIServer(auto_approve_low_risk=True)

        assert server.confirmation_manager is not None
        assert server.confirmation_manager.auto_approve_low_risk is True

    def test_get_adapter_returns_claude(self) -> None:
        """get_adapter returns Claude adapter."""
        server = IntellicrackAIServer()

        adapter = server.get_adapter("claude")

        assert isinstance(adapter, ClaudeAdapter)

    def test_get_adapter_returns_openai(self) -> None:
        """get_adapter returns OpenAI adapter."""
        server = IntellicrackAIServer()

        adapter = server.get_adapter("openai")

        assert isinstance(adapter, OpenAIAdapter)

    def test_get_adapter_returns_langchain(self) -> None:
        """get_adapter returns LangChain integration."""
        server = IntellicrackAIServer()

        adapter = server.get_adapter("langchain")

        assert isinstance(adapter, LangChainIntegration)

    def test_get_adapter_returns_none_for_unknown(self) -> None:
        """get_adapter returns None for unknown model type."""
        server = IntellicrackAIServer()

        adapter = server.get_adapter("unknown_model")

        assert adapter is None

    def test_handle_request_routes_to_claude(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """handle_request routes to Claude adapter."""
        server = IntellicrackAIServer()

        call_record: dict[str, Any] = {"called": False, "tool": None, "params": None}

        def fake_handle(tool: str, parameters: dict[str, Any]) -> dict[str, Any]:
            call_record["called"] = True
            call_record["tool"] = tool
            call_record["params"] = parameters
            return {"status": "success"}

        monkeypatch.setattr(server.adapters["claude"], "handle_tool_call", fake_handle)

        request = {
            "model_type": "claude",
            "tool": "analyze_binary",
            "parameters": {"binary_path": "test.exe"},
        }

        result = server.handle_request(request)

        assert result["status"] == "success"
        assert call_record["called"] is True

    def test_handle_request_routes_to_openai(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """handle_request routes to OpenAI adapter."""
        server = IntellicrackAIServer()

        call_record: dict[str, Any] = {"called": False}

        def fake_handle(tool: str, parameters: dict[str, Any]) -> dict[str, Any]:
            call_record["called"] = True
            return {"status": "success"}

        monkeypatch.setattr(server.adapters["openai"], "handle_tool_call", fake_handle)

        request = {
            "model_type": "openai",
            "tool": "suggest_patches",
            "parameters": {"binary_path": "test.exe"},
        }

        result = server.handle_request(request)

        assert result["status"] == "success"

    def test_handle_request_defaults_to_claude(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """handle_request defaults to Claude if no model_type specified."""
        server = IntellicrackAIServer()

        call_record: dict[str, Any] = {"called": False}

        def fake_handle(tool: str, parameters: dict[str, Any]) -> dict[str, Any]:
            call_record["called"] = True
            return {"status": "success"}

        monkeypatch.setattr(server.adapters["claude"], "handle_tool_call", fake_handle)

        request = {"tool": "analyze_binary", "parameters": {"binary_path": "test.exe"}}

        result = server.handle_request(request)

        assert result["status"] == "success"

    def test_handle_request_unknown_model_type(self) -> None:
        """handle_request handles unknown model type."""
        server = IntellicrackAIServer()

        request = {
            "model_type": "unknown",
            "tool": "test",
            "parameters": {},
        }

        result = server.handle_request(request)

        assert result["status"] == "error"
        assert "Unknown model type" in result["message"]


class TestSystemPromptGeneration:
    """Tests for AI system prompt generation."""

    def test_create_system_prompt_returns_string(self) -> None:
        """create_ai_system_prompt returns a string."""
        prompt = create_ai_system_prompt()

        assert isinstance(prompt, str)
        assert len(prompt) > 0

    def test_system_prompt_includes_tools(self) -> None:
        """System prompt describes available tools."""
        prompt = create_ai_system_prompt()

        assert "analyze_binary" in prompt
        assert "suggest_patches" in prompt
        assert "apply_patch" in prompt
        assert "execute_cli_command" in prompt

    def test_system_prompt_includes_workflow(self) -> None:
        """System prompt includes workflow guidelines."""
        prompt = create_ai_system_prompt()

        assert "workflow" in prompt.lower() or "guidelines" in prompt.lower()

    def test_system_prompt_includes_safety_notes(self) -> None:
        """System prompt includes safety considerations."""
        prompt = create_ai_system_prompt()

        assert "confirmation" in prompt.lower() or "safety" in prompt.lower()


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_adapter_handles_empty_parameters(self, fake_intellicrack_interface: FakeIntellicrackInterface) -> None:
        """Adapters handle empty parameter dictionaries."""
        adapter = ClaudeAdapter(cast(IntellicrackAIInterface, fake_intellicrack_interface))

        result = adapter.handle_tool_call("analyze_binary", {})

        assert "status" in result

    def test_langchain_handle_analyze_with_minimal_input(self, fake_intellicrack_interface: FakeIntellicrackInterface) -> None:
        """LangChain _handle_analyze works with minimal input."""
        integration = LangChainIntegration(cast(IntellicrackAIInterface, fake_intellicrack_interface))

        result = integration._handle_analyze("test.exe")

        data = json.loads(result)
        assert "status" in data

    def test_server_handle_request_with_missing_parameters(self) -> None:
        """Server handles requests with missing parameters."""
        server = IntellicrackAIServer()

        request = {"model_type": "claude"}

        result = server.handle_request(request)

        assert "status" in result


class TestRealWorldScenarios:
    """Tests for real-world usage scenarios."""

    def test_complete_analysis_workflow(self, fake_intellicrack_interface: FakeIntellicrackInterface) -> None:
        """Test complete analysis workflow through adapters."""
        server = IntellicrackAIServer()

        request1 = {
            "model_type": "claude",
            "tool": "analyze_binary",
            "parameters": {"binary_path": "app.exe", "analyses": ["comprehensive"]},
        }
        result1 = server.handle_request(request1)
        assert result1["status"] == "success"

        request2 = {
            "model_type": "claude",
            "tool": "suggest_patches",
            "parameters": {"binary_path": "app.exe"},
        }
        result2 = server.handle_request(request2)
        assert result2["status"] == "success"

        request3 = {
            "model_type": "claude",
            "tool": "apply_patch",
            "parameters": {"binary_path": "app.exe", "patch_file": "patches.json"},
        }
        result3 = server.handle_request(request3)
        assert result3["status"] == "success"

    def test_multi_model_type_switching(self, fake_intellicrack_interface: FakeIntellicrackInterface) -> None:
        """Test switching between different model types."""
        server = IntellicrackAIServer()

        claude_request = {
            "model_type": "claude",
            "tool": "analyze_binary",
            "parameters": {"binary_path": "test.exe"},
        }
        claude_result = server.handle_request(claude_request)

        openai_request = {
            "model_type": "openai",
            "tool": "analyze_binary",
            "parameters": {"binary_path": "test.exe"},
        }
        openai_result = server.handle_request(openai_request)

        assert claude_result["status"] == "success"
        assert openai_result["status"] == "success"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])

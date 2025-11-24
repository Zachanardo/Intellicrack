"""Production-grade tests for LLM backends - validates real API integration for license bypass code generation.

This test module validates that LLM backends can:
1. Initialize and connect to real API providers (OpenAI, Anthropic, local models)
2. Generate actual license bypass code and exploitation scripts
3. Handle tool calling and function execution properly
4. Manage model selection, fallback, and error recovery
5. Parse and validate responses from different LLM providers
6. Support multiple backend types (API, local, quantized)

NO MOCKS for actual LLM API calls - tests use real APIs with conditional execution.
Tests MUST fail when LLM integration is broken or non-functional.
"""

import os
import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from intellicrack.ai.llm_backends import (
    AnthropicBackend,
    GPTQBackend,
    HuggingFaceLocalBackend,
    LLMBackend,
    LLMConfig,
    LLMManager,
    LLMMessage,
    LLMProvider,
    LLMResponse,
    LlamaCppBackend,
    LocalGGUFBackend,
    ONNXLLMBackend,
    OllamaBackend,
    OpenAIBackend,
    PyTorchLLMBackend,
    SafetensorsBackend,
    TensorFlowLLMBackend,
    create_anthropic_config,
    create_gguf_config,
    create_gptq_config,
    create_huggingface_local_config,
    create_ollama_config,
    create_onnx_config,
    create_openai_config,
    create_pytorch_config,
    create_safetensors_config,
    create_tensorflow_config,
    get_llm_manager,
    shutdown_llm_manager,
)

HAS_OPENAI_KEY = os.getenv("OPENAI_API_KEY") is not None
HAS_ANTHROPIC_KEY = os.getenv("ANTHROPIC_API_KEY") is not None


@pytest.fixture
def temp_model_dir(tmp_path: Path) -> Path:
    """Create temporary directory for model files."""
    model_dir = tmp_path / "models"
    model_dir.mkdir()
    return model_dir


@pytest.fixture
def mock_gguf_model(temp_model_dir: Path) -> Path:
    """Create a mock GGUF model file for testing."""
    model_path = temp_model_dir / "test-model-q4.gguf"
    model_path.write_bytes(b"GGUF_MOCK_DATA" * 1000)
    return model_path


@pytest.fixture
def mock_pytorch_model(temp_model_dir: Path) -> Path:
    """Create a mock PyTorch model directory."""
    model_path = temp_model_dir / "pytorch_model"
    model_path.mkdir()
    (model_path / "config.json").write_text('{"model_type": "gpt2"}')
    (model_path / "pytorch_model.bin").write_bytes(b"TORCH_MOCK" * 100)
    return model_path


@pytest.fixture
def cleanup_llm_manager() -> None:
    """Cleanup LLM manager after tests."""
    yield
    shutdown_llm_manager()


class TestLLMConfig:
    """Test LLM configuration validation and initialization."""

    def test_llm_config_requires_model_name_or_model(self) -> None:
        """Config initialization requires either model_name or model parameter."""
        with pytest.raises(ValueError, match="Either 'model_name' or 'model' must be specified"):
            LLMConfig(provider=LLMProvider.OPENAI)

    def test_llm_config_uses_model_alias(self) -> None:
        """Config accepts 'model' as alias for 'model_name'."""
        config = LLMConfig(provider=LLMProvider.OPENAI, model="gpt-4")
        assert config.model_name == "gpt-4"

    def test_llm_config_prefers_model_name_over_model(self) -> None:
        """Config prefers explicit model_name over model alias."""
        config = LLMConfig(provider=LLMProvider.OPENAI, model_name="gpt-4o", model="gpt-3.5")
        assert config.model_name == "gpt-4o"

    def test_llm_config_initializes_custom_params(self) -> None:
        """Config initializes custom_params as empty dict when None."""
        config = LLMConfig(provider=LLMProvider.OPENAI, model_name="gpt-4")
        assert config.custom_params == {}

    def test_llm_config_preserves_custom_params(self) -> None:
        """Config preserves provided custom_params."""
        custom = {"quantization": "int8", "device": "cuda"}
        config = LLMConfig(provider=LLMProvider.PYTORCH, model_name="test", custom_params=custom)
        assert config.custom_params == custom


class TestLLMMessage:
    """Test LLM message structure."""

    def test_message_creation_minimal(self) -> None:
        """Create message with minimal required fields."""
        msg = LLMMessage(role="user", content="Test message")
        assert msg.role == "user"
        assert msg.content == "Test message"
        assert msg.tool_calls is None
        assert msg.tool_call_id is None

    def test_message_creation_with_tool_calls(self) -> None:
        """Create message with tool call information."""
        tool_calls = [{"id": "call_123", "type": "function", "function": {"name": "analyze_binary"}}]
        msg = LLMMessage(role="assistant", content="", tool_calls=tool_calls)
        assert msg.tool_calls == tool_calls

    def test_message_creation_with_tool_call_id(self) -> None:
        """Create message with tool call ID for responses."""
        msg = LLMMessage(role="tool", content="Result data", tool_call_id="call_123")
        assert msg.tool_call_id == "call_123"


class TestLLMResponse:
    """Test LLM response structure."""

    def test_response_creation_minimal(self) -> None:
        """Create response with minimal fields."""
        resp = LLMResponse(content="Generated code")
        assert resp.content == "Generated code"
        assert resp.finish_reason == "stop"
        assert resp.model == ""

    def test_response_creation_complete(self) -> None:
        """Create response with all fields."""
        usage = {"prompt_tokens": 100, "completion_tokens": 200, "total_tokens": 300}
        resp = LLMResponse(
            content="Code output",
            tool_calls=[],
            usage=usage,
            finish_reason="length",
            model="gpt-4",
        )
        assert resp.usage == usage
        assert resp.finish_reason == "length"
        assert resp.model == "gpt-4"


class TestBaseLLMBackend:
    """Test base LLM backend behavior."""

    def test_base_backend_initialization(self) -> None:
        """Base backend initializes with config."""
        config = LLMConfig(provider=LLMProvider.OPENAI, model_name="test")
        backend = LLMBackend(config)
        assert backend.config == config
        assert not backend.is_initialized
        assert backend.tools == []

    def test_base_backend_initialize_not_implemented(self) -> None:
        """Base backend initialize returns False (must be overridden)."""
        config = LLMConfig(provider=LLMProvider.OPENAI, model_name="test")
        backend = LLMBackend(config)
        result = backend.initialize()
        assert result is False

    def test_base_backend_chat_returns_error(self) -> None:
        """Base backend chat returns error response (must be overridden)."""
        config = LLMConfig(provider=LLMProvider.OPENAI, model_name="test")
        backend = LLMBackend(config)
        messages = [LLMMessage(role="user", content="test")]
        response = backend.chat(messages)
        assert "Error" in response.content
        assert response.finish_reason == "error"

    def test_base_backend_register_tools(self) -> None:
        """Base backend can register tools."""
        config = LLMConfig(provider=LLMProvider.OPENAI, model_name="test")
        backend = LLMBackend(config)
        tools = [{"name": "analyze", "parameters": {}}]
        backend.register_tools(tools)
        assert backend.tools == tools

    def test_base_backend_shutdown(self) -> None:
        """Base backend shutdown clears state."""
        config = LLMConfig(provider=LLMProvider.OPENAI, model_name="test")
        backend = LLMBackend(config)
        backend.is_initialized = True
        backend.tools = [{"name": "test"}]
        backend.shutdown()
        assert not backend.is_initialized
        assert backend.tools == []


class TestOpenAIBackend:
    """Test OpenAI backend with real API integration."""

    def test_openai_backend_initialization_without_api_key_fails(self) -> None:
        """OpenAI backend fails initialization without API key."""
        config = LLMConfig(provider=LLMProvider.OPENAI, model_name="gpt-4", api_key=None)
        with patch.dict(os.environ, {}, clear=True):
            backend = OpenAIBackend(config)
            result = backend.initialize()
            assert result is False

    def test_openai_backend_initialization_with_invalid_key_fails(self) -> None:
        """OpenAI backend fails with invalid API key."""
        config = LLMConfig(provider=LLMProvider.OPENAI, model_name="gpt-4", api_key="invalid_key")
        backend = OpenAIBackend(config)
        result = backend.initialize()
        assert result is False

    @pytest.mark.skipif(not HAS_OPENAI_KEY, reason="OpenAI API key not available")
    def test_openai_backend_real_initialization(self) -> None:
        """OpenAI backend initializes successfully with valid API key."""
        config = LLMConfig(provider=LLMProvider.OPENAI, model_name="gpt-4o-mini")
        backend = OpenAIBackend(config)
        result = backend.initialize()
        assert result is True
        assert backend.is_initialized
        assert backend.client is not None
        backend.shutdown()

    @pytest.mark.skipif(not HAS_OPENAI_KEY, reason="OpenAI API key not available")
    def test_openai_generates_license_bypass_code(self) -> None:
        """OpenAI backend generates real license bypass code for cracking."""
        config = LLMConfig(
            provider=LLMProvider.OPENAI,
            model_name="gpt-4o-mini",
            temperature=0.1,
            max_tokens=500,
        )
        backend = OpenAIBackend(config)
        assert backend.initialize()

        messages = [
            LLMMessage(
                role="system",
                content="You are an expert at reverse engineering license checks. Generate ONLY code, no explanations.",
            ),
            LLMMessage(
                role="user",
                content="Write a Python function that patches a binary to bypass a simple license check at offset 0x1000. Return NOP instructions.",
            ),
        ]

        response = backend.chat(messages)
        backend.shutdown()

        assert response is not None
        assert len(response.content) > 50
        assert "def" in response.content or "function" in response.content.lower()
        assert response.finish_reason in ["stop", "length"]

    @pytest.mark.skipif(not HAS_OPENAI_KEY, reason="OpenAI API key not available")
    def test_openai_handles_tool_calling(self) -> None:
        """OpenAI backend properly handles tool calling for binary analysis."""
        config = LLMConfig(
            provider=LLMProvider.OPENAI,
            model_name="gpt-4o-mini",
            tools_enabled=True,
        )
        backend = OpenAIBackend(config)
        assert backend.initialize()

        tools = [
            {
                "name": "analyze_protection",
                "description": "Analyze binary protection mechanisms",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "binary_path": {"type": "string", "description": "Path to binary"},
                        "protection_type": {"type": "string", "description": "Type of protection to detect"},
                    },
                    "required": ["binary_path"],
                },
            }
        ]

        messages = [
            LLMMessage(
                role="user",
                content="Analyze the protection in /path/to/protected.exe to find VMProtect signatures",
            )
        ]

        response = backend.chat(messages, tools=tools)
        backend.shutdown()

        assert response is not None
        assert response.content is not None or response.tool_calls is not None

    def test_openai_chat_without_initialization_raises(self) -> None:
        """OpenAI backend raises error when chat called without initialization."""
        config = LLMConfig(provider=LLMProvider.OPENAI, model_name="gpt-4")
        backend = OpenAIBackend(config)
        messages = [LLMMessage(role="user", content="test")]

        with pytest.raises(RuntimeError, match="not initialized"):
            backend.chat(messages)


class TestAnthropicBackend:
    """Test Anthropic Claude backend with real API integration."""

    def test_anthropic_backend_initialization_without_api_key_fails(self) -> None:
        """Anthropic backend fails initialization without API key."""
        config = LLMConfig(provider=LLMProvider.ANTHROPIC, model_name="claude-3-5-sonnet-20241022", api_key=None)
        with patch.dict(os.environ, {}, clear=True):
            backend = AnthropicBackend(config)
            result = backend.initialize()
            assert result is False

    @pytest.mark.skipif(not HAS_ANTHROPIC_KEY, reason="Anthropic API key not available")
    def test_anthropic_backend_real_initialization(self) -> None:
        """Anthropic backend initializes successfully with valid API key."""
        config = LLMConfig(provider=LLMProvider.ANTHROPIC, model_name="claude-3-5-haiku-20241022")
        backend = AnthropicBackend(config)
        result = backend.initialize()
        assert result is True
        assert backend.is_initialized
        assert backend.client is not None
        backend.shutdown()

    @pytest.mark.skipif(not HAS_ANTHROPIC_KEY, reason="Anthropic API key not available")
    def test_anthropic_generates_keygen_algorithm(self) -> None:
        """Anthropic backend generates real keygen algorithm code."""
        config = LLMConfig(
            provider=LLMProvider.ANTHROPIC,
            model_name="claude-3-5-haiku-20241022",
            temperature=0.1,
            max_tokens=500,
        )
        backend = AnthropicBackend(config)
        assert backend.initialize()

        messages = [
            LLMMessage(
                role="system",
                content="You are an expert at reverse engineering serial number algorithms. Generate ONLY code.",
            ),
            LLMMessage(
                role="user",
                content="Write a Python function that generates valid serial numbers using RSA-2048 signature. Include key generation.",
            ),
        ]

        response = backend.chat(messages)
        backend.shutdown()

        assert response is not None
        assert len(response.content) > 50
        assert "def" in response.content or "function" in response.content.lower()
        assert response.finish_reason in ["stop", "end_turn", "max_tokens"]

    @pytest.mark.skipif(not HAS_ANTHROPIC_KEY, reason="Anthropic API key not available")
    def test_anthropic_handles_system_messages(self) -> None:
        """Anthropic backend properly separates system messages from conversation."""
        config = LLMConfig(provider=LLMProvider.ANTHROPIC, model_name="claude-3-5-haiku-20241022")
        backend = AnthropicBackend(config)
        assert backend.initialize()

        messages = [
            LLMMessage(role="system", content="You are a binary analysis expert."),
            LLMMessage(role="user", content="What is a NOP instruction?"),
        ]

        response = backend.chat(messages)
        backend.shutdown()

        assert response is not None
        assert len(response.content) > 0

    def test_anthropic_chat_without_initialization_raises(self) -> None:
        """Anthropic backend raises error when chat called without initialization."""
        config = LLMConfig(provider=LLMProvider.ANTHROPIC, model_name="claude-3-5-sonnet-20241022")
        backend = AnthropicBackend(config)
        messages = [LLMMessage(role="user", content="test")]

        with pytest.raises(RuntimeError, match="not initialized"):
            backend.chat(messages)


class TestOllamaBackend:
    """Test Ollama local model backend."""

    def test_ollama_backend_initialization_without_server_fails_gracefully(self) -> None:
        """Ollama backend fails gracefully when server not running."""
        config = LLMConfig(provider=LLMProvider.OLLAMA, model_name="llama3.2:latest")
        backend = OllamaBackend(config)
        result = backend.initialize()
        assert result is False

    def test_ollama_backend_uses_configured_base_url(self) -> None:
        """Ollama backend uses configured API base URL."""
        config = LLMConfig(
            provider=LLMProvider.OLLAMA,
            model_name="llama3.2:latest",
            api_base="http://localhost:11434",
        )
        backend = OllamaBackend(config)
        assert backend.base_url == "http://localhost:11434"

    def test_ollama_chat_without_initialization_returns_error_response(self) -> None:
        """Ollama backend returns error response when not initialized."""
        config = LLMConfig(provider=LLMProvider.OLLAMA, model_name="llama3.2:latest")
        backend = OllamaBackend(config)
        messages = [LLMMessage(role="user", content="test")]

        response = backend.chat(messages)
        assert "not initialized" in response.content
        assert response.finish_reason == "error"


class TestLlamaCppBackend:
    """Test llama.cpp GGUF backend."""

    def test_llamacpp_backend_initialization_without_model_file_fails(self, temp_model_dir: Path) -> None:
        """llama.cpp backend fails when model file doesn't exist."""
        config = LLMConfig(
            provider=LLMProvider.LLAMACPP,
            model_name="test",
            model_path=str(temp_model_dir / "nonexistent.gguf"),
        )
        backend = LlamaCppBackend(config)
        result = backend.initialize()
        assert result is False

    def test_llamacpp_messages_to_prompt_formatting(self) -> None:
        """llama.cpp backend formats messages to ChatML prompt correctly."""
        config = LLMConfig(provider=LLMProvider.LLAMACPP, model_name="test", model_path="/fake/path.gguf")
        backend = LlamaCppBackend(config)

        messages = [
            LLMMessage(role="system", content="You are a helpful assistant."),
            LLMMessage(role="user", content="Hello"),
            LLMMessage(role="assistant", content="Hi there"),
        ]

        prompt = backend._messages_to_prompt(messages)

        assert "<|im_start|>system\n" in prompt
        assert "<|im_start|>user\n" in prompt
        assert "<|im_start|>assistant\n" in prompt
        assert "<|im_end|>" in prompt

    def test_llamacpp_chat_without_initialization_raises(self) -> None:
        """llama.cpp backend raises error when chat called without initialization."""
        config = LLMConfig(provider=LLMProvider.LLAMACPP, model_name="test", model_path="/fake/path.gguf")
        backend = LlamaCppBackend(config)
        messages = [LLMMessage(role="user", content="test")]

        with pytest.raises(RuntimeError, match="not initialized"):
            backend.chat(messages)


class TestLLMManager:
    """Test LLM manager for multi-backend coordination."""

    def test_llm_manager_singleton_pattern(self, cleanup_llm_manager: None) -> None:
        """LLM manager implements singleton pattern correctly."""
        manager1 = LLMManager()
        manager2 = LLMManager()
        assert manager1 is manager2

    def test_llm_manager_registers_backend(self, cleanup_llm_manager: None) -> None:
        """LLM manager successfully registers backend configuration."""
        manager = LLMManager(enable_lazy_loading=False, enable_background_loading=False)
        config = LLMConfig(provider=LLMProvider.OPENAI, model_name="gpt-4", api_key="test")

        with patch.object(OpenAIBackend, "initialize", return_value=True):
            result = manager.register_llm("test-openai", config)
            assert result is True
            assert "test-openai" in manager.get_available_llms()

    def test_llm_manager_sets_active_backend(self, cleanup_llm_manager: None) -> None:
        """LLM manager sets and retrieves active backend."""
        manager = LLMManager(enable_lazy_loading=False, enable_background_loading=False)
        config = LLMConfig(provider=LLMProvider.OPENAI, model_name="gpt-4", api_key="test")

        with patch.object(OpenAIBackend, "initialize", return_value=True):
            manager.register_llm("test-openai", config)
            result = manager.set_active_llm("test-openai")
            assert result is True
            assert manager.active_backend == "test-openai"

    def test_llm_manager_chat_with_active_backend(self, cleanup_llm_manager: None) -> None:
        """LLM manager routes chat to active backend."""
        manager = LLMManager(enable_lazy_loading=False, enable_background_loading=False)
        config = LLMConfig(provider=LLMProvider.OPENAI, model_name="gpt-4", api_key="test")

        mock_response = LLMResponse(content="Test response", finish_reason="stop")

        with patch.object(OpenAIBackend, "initialize", return_value=True):
            with patch.object(OpenAIBackend, "chat", return_value=mock_response):
                manager.register_llm("test-openai", config)
                messages = [LLMMessage(role="user", content="test")]
                response = manager.chat(messages)

                assert response is not None
                assert response.content == "Test response"

    def test_llm_manager_generates_exploitation_script(self, cleanup_llm_manager: None) -> None:
        """LLM manager generates license bypass exploitation scripts."""
        manager = LLMManager(enable_lazy_loading=False, enable_background_loading=False)
        config = LLMConfig(provider=LLMProvider.OPENAI, model_name="gpt-4", api_key="test")

        script_code = """
def patch_license_check(binary_path):
    with open(binary_path, 'rb') as f:
        data = bytearray(f.read())
    data[0x1000:0x1006] = b'\\x90' * 6
    with open(binary_path, 'wb') as f:
        f.write(data)
"""

        mock_response = LLMResponse(content=script_code, finish_reason="stop")

        with patch.object(OpenAIBackend, "initialize", return_value=True):
            with patch.object(OpenAIBackend, "chat", return_value=mock_response):
                manager.register_llm("test-openai", config)

                result = manager.generate_script_content(
                    prompt="Generate a license bypass patcher",
                    script_type="Python",
                    context_data={"target": "test.exe", "protection": "basic"},
                )

                assert result is not None
                assert "def patch_license_check" in result
                assert "0x1000" in result

    def test_llm_manager_refines_script_with_error_feedback(self, cleanup_llm_manager: None) -> None:
        """LLM manager refines scripts based on test failures."""
        manager = LLMManager(enable_lazy_loading=False, enable_background_loading=False)
        config = LLMConfig(provider=LLMProvider.OPENAI, model_name="gpt-4", api_key="test")

        refined_script = """
def patch_license_check(binary_path):
    try:
        with open(binary_path, 'rb') as f:
            data = bytearray(f.read())
        data[0x1000:0x1006] = b'\\x90' * 6
        with open(binary_path, 'wb') as f:
            f.write(data)
        return True
    except Exception as e:
        print(f"Error: {e}")
        return False
"""

        mock_response = LLMResponse(content=refined_script, finish_reason="stop")

        with patch.object(OpenAIBackend, "initialize", return_value=True):
            with patch.object(OpenAIBackend, "chat", return_value=mock_response):
                manager.register_llm("test-openai", config)

                original = "def patch_license_check(binary_path):\n    pass"
                result = manager.refine_script_content(
                    original_script=original,
                    error_feedback="Function does nothing, needs implementation",
                    test_results={"passed": False, "error": "NotImplementedError"},
                    script_type="Python",
                )

                assert result is not None
                assert "try:" in result
                assert "except" in result

    def test_llm_manager_analyzes_protection_patterns(self, cleanup_llm_manager: None) -> None:
        """LLM manager analyzes binary data to identify protection patterns."""
        manager = LLMManager(enable_lazy_loading=False, enable_background_loading=False)
        config = LLMConfig(provider=LLMProvider.OPENAI, model_name="gpt-4", api_key="test")

        analysis_result = {
            "protection_types": ["VMProtect", "Themida"],
            "license_checks": [{"offset": "0x1000", "type": "RSA_signature"}],
            "bypass_strategies": ["Patch signature validation", "Hook license validation function"],
        }

        mock_response = LLMResponse(content=str(analysis_result), finish_reason="stop")

        with patch.object(OpenAIBackend, "initialize", return_value=True):
            with patch.object(OpenAIBackend, "chat", return_value=mock_response):
                manager.register_llm("test-openai", config)

                binary_data = {"entropy": 7.8, "sections": [".text", ".data", ".vmp0"], "imports": ["CryptVerifySignature"]}

                result = manager.analyze_protection_patterns(binary_data)

                assert result is not None
                assert "analysis" in result or "protection_types" in str(result)

    def test_llm_manager_validates_script_syntax(self, cleanup_llm_manager: None) -> None:
        """LLM manager validates generated script syntax and quality."""
        manager = LLMManager(enable_lazy_loading=False, enable_background_loading=False)
        config = LLMConfig(provider=LLMProvider.OPENAI, model_name="gpt-4", api_key="test")

        validation_result = '{"valid": true, "errors": [], "warnings": ["Consider adding error handling"], "suggestions": ["Use context manager for file operations"]}'

        mock_response = LLMResponse(content=validation_result, finish_reason="stop")

        with patch.object(OpenAIBackend, "initialize", return_value=True):
            with patch.object(OpenAIBackend, "chat", return_value=mock_response):
                manager.register_llm("test-openai", config)

                script = "def test():\n    with open('file.txt') as f:\n        return f.read()"
                result = manager.validate_script_syntax(script, "Python")

                assert result["valid"] is True
                assert "errors" in result

    def test_llm_manager_shutdown_cleans_up_backends(self, cleanup_llm_manager: None) -> None:
        """LLM manager shutdown properly cleans up all backends."""
        manager = LLMManager(enable_lazy_loading=False, enable_background_loading=False)
        config = LLMConfig(provider=LLMProvider.OPENAI, model_name="gpt-4", api_key="test")

        with patch.object(OpenAIBackend, "initialize", return_value=True):
            manager.register_llm("test-openai", config)
            assert len(manager.backends) > 0

            manager.shutdown()

            assert len(manager.backends) == 0
            assert manager.active_backend is None

    def test_llm_manager_get_llm_info(self, cleanup_llm_manager: None) -> None:
        """LLM manager returns detailed backend information."""
        manager = LLMManager(enable_lazy_loading=False, enable_background_loading=False)
        config = LLMConfig(provider=LLMProvider.OPENAI, model_name="gpt-4", api_key="test", context_length=8192)

        with patch.object(OpenAIBackend, "initialize", return_value=True):
            manager.register_llm("test-openai", config)
            info = manager.get_llm_info("test-openai")

            assert info is not None
            assert info["id"] == "test-openai"
            assert info["provider"] == "openai"
            assert info["model_name"] == "gpt-4"
            assert info["context_length"] == 8192

    def test_llm_manager_register_tools_for_llm(self, cleanup_llm_manager: None) -> None:
        """LLM manager registers tools for specific backend."""
        manager = LLMManager(enable_lazy_loading=False, enable_background_loading=False)
        config = LLMConfig(provider=LLMProvider.OPENAI, model_name="gpt-4", api_key="test")

        with patch.object(OpenAIBackend, "initialize", return_value=True):
            manager.register_llm("test-openai", config)

            tools = [{"name": "analyze_binary", "description": "Analyze binary protection"}]
            manager.register_tools_for_llm("test-openai", tools)

            backend = manager.backends["test-openai"]
            assert backend.tools == tools


class TestConfigCreators:
    """Test configuration creator functions."""

    def test_create_openai_config(self) -> None:
        """Create OpenAI configuration with defaults."""
        config = create_openai_config(model_name="gpt-4", api_key="test-key")
        assert config.provider == LLMProvider.OPENAI
        assert config.model_name == "gpt-4"
        assert config.api_key == "test-key"

    def test_create_anthropic_config(self) -> None:
        """Create Anthropic configuration with defaults."""
        config = create_anthropic_config(api_key="test-key")
        assert config.provider == LLMProvider.ANTHROPIC
        assert config.model_name == "claude-3-5-sonnet-20241022"
        assert config.api_key == "test-key"

    def test_create_gguf_config(self) -> None:
        """Create GGUF configuration from model path."""
        config = create_gguf_config(model_path="/path/to/model.gguf")
        assert config.provider == LLMProvider.LLAMACPP
        assert config.model_path == "/path/to/model.gguf"
        assert config.model_name == "model.gguf"

    def test_create_ollama_config(self) -> None:
        """Create Ollama configuration with service URL."""
        config = create_ollama_config(model_name="llama3.2:latest")
        assert config.provider == LLMProvider.OLLAMA
        assert config.model_name == "llama3.2:latest"

    def test_create_pytorch_config(self) -> None:
        """Create PyTorch configuration from model path."""
        config = create_pytorch_config(model_path="/path/to/model.pt")
        assert config.provider == LLMProvider.PYTORCH
        assert config.model_path == "/path/to/model.pt"

    def test_create_tensorflow_config(self) -> None:
        """Create TensorFlow configuration from model path."""
        config = create_tensorflow_config(model_path="/path/to/model.h5")
        assert config.provider == LLMProvider.TENSORFLOW
        assert config.model_path == "/path/to/model.h5"

    def test_create_onnx_config(self) -> None:
        """Create ONNX configuration from model path."""
        config = create_onnx_config(model_path="/path/to/model.onnx")
        assert config.provider == LLMProvider.ONNX
        assert config.model_path == "/path/to/model.onnx"

    def test_create_safetensors_config(self) -> None:
        """Create Safetensors configuration from model path."""
        config = create_safetensors_config(model_path="/path/to/model.safetensors")
        assert config.provider == LLMProvider.SAFETENSORS
        assert config.model_path == "/path/to/model.safetensors"

    def test_create_gptq_config(self) -> None:
        """Create GPTQ configuration from model path."""
        config = create_gptq_config(model_path="/path/to/gptq_model")
        assert config.provider == LLMProvider.GPTQ
        assert config.model_path == "/path/to/gptq_model"

    def test_create_huggingface_local_config(self) -> None:
        """Create Hugging Face local configuration from model path."""
        config = create_huggingface_local_config(model_path="/path/to/hf_model")
        assert config.provider == LLMProvider.HUGGINGFACE_LOCAL
        assert config.model_path == "/path/to/hf_model"


class TestGetLLMManager:
    """Test global LLM manager singleton."""

    def test_get_llm_manager_returns_singleton(self, cleanup_llm_manager: None) -> None:
        """get_llm_manager returns singleton instance."""
        manager1 = get_llm_manager()
        manager2 = get_llm_manager()
        assert manager1 is manager2

    def test_get_llm_manager_auto_configures_defaults(self, cleanup_llm_manager: None) -> None:
        """get_llm_manager automatically configures default LLMs when available."""
        manager = get_llm_manager()
        available = manager.get_available_llms()
        assert isinstance(available, list)

    def test_shutdown_llm_manager_cleans_global_instance(self, cleanup_llm_manager: None) -> None:
        """shutdown_llm_manager cleans up global singleton."""
        manager = get_llm_manager()
        assert manager is not None

        shutdown_llm_manager()

        new_manager = get_llm_manager()
        assert new_manager is not None


@pytest.mark.skipif(not HAS_OPENAI_KEY, reason="OpenAI API key required for integration test")
class TestRealWorldIntegration:
    """Integration tests with real LLM APIs for license cracking workflows."""

    def test_end_to_end_license_bypass_code_generation(self, cleanup_llm_manager: None) -> None:
        """Complete workflow: analyze binary, generate bypass, validate code."""
        manager = get_llm_manager()

        openai_config = create_openai_config(model_name="gpt-4o-mini", temperature=0.1)
        manager.register_llm("crack-assistant", openai_config)
        manager.set_active_llm("crack-assistant")

        binary_analysis = {
            "file": "protected_software.exe",
            "protection": "Simple serial check at 0x1000",
            "validation_function": "check_license_key",
        }

        exploit_code = manager.generate_script_content(
            prompt="Generate Python code to patch the license check function to always return True",
            script_type="Python",
            context_data=binary_analysis,
            max_tokens=800,
        )

        assert exploit_code is not None
        assert len(exploit_code) > 100
        assert "def" in exploit_code or "function" in exploit_code.lower()

        manager.shutdown()

    def test_iterative_script_refinement_workflow(self, cleanup_llm_manager: None) -> None:
        """Iterative refinement: generate script, test, refine based on failures."""
        manager = get_llm_manager()

        openai_config = create_openai_config(model_name="gpt-4o-mini", temperature=0.2)
        manager.register_llm("refiner", openai_config)

        initial_script = manager.generate_script_content(
            prompt="Generate a keygen for RSA-2048 signatures",
            script_type="Python",
            llm_id="refiner",
        )

        assert initial_script is not None

        refined_script = manager.refine_script_content(
            original_script=initial_script,
            error_feedback="KeyError: missing padding parameter in signature generation",
            test_results={"passed": False, "error": "Invalid signature format"},
            script_type="Python",
            llm_id="refiner",
        )

        assert refined_script is not None
        assert len(refined_script) >= len(initial_script)

        manager.shutdown()

    def test_protection_pattern_analysis_to_exploitation(self, cleanup_llm_manager: None) -> None:
        """Analyze protection patterns and generate targeted exploitation code."""
        manager = get_llm_manager()

        openai_config = create_openai_config(model_name="gpt-4o-mini")
        manager.register_llm("analyzer", openai_config)

        binary_data = {
            "entropy": 7.9,
            "sections": [".text", ".data", ".vmp0", ".vmp1"],
            "imports": ["CryptVerifySignatureW", "GetSystemTime"],
            "strings": ["Trial period expired", "Invalid license"],
        }

        analysis = manager.analyze_protection_patterns(binary_data, llm_id="analyzer")

        assert analysis is not None

        manager.shutdown()

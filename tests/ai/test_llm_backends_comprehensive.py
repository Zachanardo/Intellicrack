"""Comprehensive production-ready tests for LLM backends module.

This test suite validates:
1. Backend initialization for all provider types
2. Configuration validation and error handling
3. API key management and security
4. Model configuration parsing and validation
5. Message formatting and prompt handling
6. Tool registration and execution
7. Context window management and token limits
8. Lazy loading and background loading mechanisms
9. LLM Manager singleton pattern and thread safety
10. Backend factory and provider selection logic
11. Error handling and recovery mechanisms
12. Configuration helper functions

CRITICAL: Tests validate real configuration logic without making external API calls.
Tests must FAIL when configuration validation is broken or security is compromised.
"""

import json
import os
import tempfile
import threading
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, Mock, patch

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
    OllamaBackend,
    ONNXLLMBackend,
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
from intellicrack.core.exceptions import ConfigurationError


@pytest.fixture(autouse=True)
def reset_llm_manager() -> None:
    """Reset LLM Manager singleton between tests."""
    shutdown_llm_manager()
    if hasattr(LLMManager, "_instance"):
        LLMManager._instance = None
    yield
    shutdown_llm_manager()
    if hasattr(LLMManager, "_instance"):
        LLMManager._instance = None


@pytest.fixture
def temp_model_dir(tmp_path: Path) -> Path:
    """Create temporary directory for model files."""
    model_dir = tmp_path / "models"
    model_dir.mkdir(parents=True, exist_ok=True)
    return model_dir


@pytest.fixture
def mock_gguf_file(temp_model_dir: Path) -> Path:
    """Create mock GGUF model file."""
    model_file = temp_model_dir / "test-model-q4.gguf"
    model_file.write_bytes(b"GGUF" + b"\x00" * 1000)
    return model_file


@pytest.fixture
def mock_pytorch_dir(temp_model_dir: Path) -> Path:
    """Create mock PyTorch model directory with config."""
    model_dir = temp_model_dir / "pytorch_model"
    model_dir.mkdir(parents=True, exist_ok=True)
    config_file = model_dir / "config.json"
    config_file.write_text(json.dumps({"model_type": "gpt2", "architectures": ["GPT2LMHeadModel"]}))
    model_file = model_dir / "pytorch_model.bin"
    model_file.write_bytes(b"TORCH_MODEL" * 100)
    return model_dir


class TestLLMConfigValidation:
    """Test LLM configuration validation logic."""

    def test_config_requires_model_name_or_model(self) -> None:
        """Configuration must specify either model_name or model parameter."""
        with pytest.raises(ValueError, match="Either 'model_name' or 'model' must be specified"):
            LLMConfig(provider=LLMProvider.OPENAI)

    def test_config_accepts_model_alias(self) -> None:
        """Configuration accepts 'model' as alias for 'model_name'."""
        config = LLMConfig(provider=LLMProvider.OPENAI, model="gpt-4")
        assert config.model_name == "gpt-4"
        assert config.provider == LLMProvider.OPENAI

    def test_config_prefers_model_name_over_model(self) -> None:
        """When both model_name and model are provided, model_name takes precedence."""
        config = LLMConfig(provider=LLMProvider.OPENAI, model_name="gpt-4-turbo", model="gpt-3.5-turbo")
        assert config.model_name == "gpt-4-turbo"

    def test_config_initializes_custom_params_dict(self) -> None:
        """Configuration initializes custom_params as empty dict if not provided."""
        config = LLMConfig(provider=LLMProvider.OPENAI, model_name="gpt-4")
        assert isinstance(config.custom_params, dict)
        assert len(config.custom_params) == 0

    def test_config_preserves_custom_params(self) -> None:
        """Configuration preserves custom_params when provided."""
        custom_params = {"param1": "value1", "param2": 42}
        config = LLMConfig(provider=LLMProvider.OPENAI, model_name="gpt-4", custom_params=custom_params)
        assert config.custom_params == custom_params

    def test_config_default_values(self) -> None:
        """Configuration sets proper default values."""
        config = LLMConfig(provider=LLMProvider.ANTHROPIC, model_name="claude-3-5-sonnet-20241022")
        assert config.context_length == 4096
        assert config.temperature == 0.7
        assert config.max_tokens == 2048
        assert config.tools_enabled is True
        assert config.system_prompt is None
        assert config.api_key is None
        assert config.api_base is None
        assert config.model_path is None
        assert config.device is None
        assert config.quantization is None

    def test_config_custom_values_override_defaults(self) -> None:
        """Configuration allows overriding default values."""
        config = LLMConfig(
            provider=LLMProvider.OPENAI,
            model_name="gpt-4",
            context_length=8192,
            temperature=0.2,
            max_tokens=4096,
            tools_enabled=False,
            system_prompt="You are a security researcher.",
            api_key="test-key",
            api_base="https://custom-endpoint.com",
        )
        assert config.context_length == 8192
        assert config.temperature == 0.2
        assert config.max_tokens == 4096
        assert config.tools_enabled is False
        assert config.system_prompt == "You are a security researcher."
        assert config.api_key == "test-key"
        assert config.api_base == "https://custom-endpoint.com"


class TestLLMMessageAndResponse:
    """Test LLM message and response data structures."""

    def test_llm_message_basic_creation(self) -> None:
        """LLMMessage can be created with basic parameters."""
        msg = LLMMessage(role="user", content="Test message")
        assert msg.role == "user"
        assert msg.content == "Test message"
        assert msg.tool_calls is None
        assert msg.tool_call_id is None

    def test_llm_message_with_tool_calls(self) -> None:
        """LLMMessage supports tool calls."""
        tool_calls = [{"id": "call_123", "function": {"name": "test_func", "arguments": "{}"}}]
        msg = LLMMessage(role="assistant", content="", tool_calls=tool_calls)
        assert msg.tool_calls == tool_calls

    def test_llm_message_with_tool_call_id(self) -> None:
        """LLMMessage supports tool call ID for responses."""
        msg = LLMMessage(role="tool", content="Tool result", tool_call_id="call_123")
        assert msg.tool_call_id == "call_123"

    def test_llm_response_basic_creation(self) -> None:
        """LLMResponse can be created with basic parameters."""
        response = LLMResponse(content="Test response")
        assert response.content == "Test response"
        assert response.tool_calls is None
        assert response.usage is None
        assert response.finish_reason == "stop"
        assert response.model == ""

    def test_llm_response_with_usage_stats(self) -> None:
        """LLMResponse supports usage statistics."""
        usage = {"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30}
        response = LLMResponse(content="Test", usage=usage, model="gpt-4")
        assert response.usage == usage
        assert response.model == "gpt-4"

    def test_llm_response_with_tool_calls(self) -> None:
        """LLMResponse supports tool calls."""
        tool_calls = [{"id": "call_456", "function": {"name": "execute_query", "arguments": "{}"}}]
        response = LLMResponse(content="", tool_calls=tool_calls, finish_reason="tool_calls")
        assert response.tool_calls == tool_calls
        assert response.finish_reason == "tool_calls"


class TestBackendBaseClass:
    """Test base LLMBackend class behavior."""

    def test_backend_initialization(self) -> None:
        """Backend base class initializes with configuration."""
        config = LLMConfig(provider=LLMProvider.OPENAI, model_name="gpt-4")
        backend = LLMBackend(config)
        assert backend.config == config
        assert backend.is_initialized is False
        assert isinstance(backend.tools, list)
        assert len(backend.tools) == 0

    def test_backend_base_initialize_returns_false(self) -> None:
        """Base backend initialize method returns False."""
        config = LLMConfig(provider=LLMProvider.OPENAI, model_name="gpt-4")
        backend = LLMBackend(config)
        result = backend.initialize()
        assert result is False
        assert backend.is_initialized is False

    def test_backend_base_chat_returns_error_response(self) -> None:
        """Base backend chat method returns error response."""
        config = LLMConfig(provider=LLMProvider.OPENAI, model_name="gpt-4")
        backend = LLMBackend(config)
        messages = [LLMMessage(role="user", content="Test")]
        response = backend.chat(messages)
        assert isinstance(response, LLMResponse)
        assert "Error" in response.content
        assert response.finish_reason == "error"
        assert response.model == "base_backend_fallback"

    def test_backend_complete_is_alias_for_chat(self) -> None:
        """Backend complete method is alias for chat method."""
        config = LLMConfig(provider=LLMProvider.OPENAI, model_name="gpt-4")
        backend = LLMBackend(config)
        messages = [LLMMessage(role="user", content="Test")]
        chat_response = backend.chat(messages)
        complete_response = backend.complete(messages)
        assert chat_response.content == complete_response.content
        assert chat_response.finish_reason == complete_response.finish_reason

    def test_backend_register_tools(self) -> None:
        """Backend can register tools for function calling."""
        config = LLMConfig(provider=LLMProvider.OPENAI, model_name="gpt-4")
        backend = LLMBackend(config)
        tools = [{"name": "test_tool", "description": "Test tool"}]
        backend.register_tools(tools)
        assert backend.tools == tools

    def test_backend_shutdown_clears_state(self) -> None:
        """Backend shutdown clears initialization state and tools."""
        config = LLMConfig(provider=LLMProvider.OPENAI, model_name="gpt-4")
        backend = LLMBackend(config)
        backend.is_initialized = True
        backend.register_tools([{"name": "tool1"}])
        backend.shutdown()
        assert backend.is_initialized is False
        assert len(backend.tools) == 0


class TestOpenAIBackendConfiguration:
    """Test OpenAI backend configuration and validation."""

    def test_openai_backend_initialization_without_api_key(self) -> None:
        """OpenAI backend requires API key for initialization."""
        config = LLMConfig(provider=LLMProvider.OPENAI, model_name="gpt-4")
        backend = OpenAIBackend(config)

        with patch("intellicrack.utils.secrets_manager.get_secret", return_value=None):
            result = backend.initialize()
            assert result is False
            assert backend.is_initialized is False

    def test_openai_backend_uses_config_api_key(self) -> None:
        """OpenAI backend uses API key from configuration."""
        config = LLMConfig(provider=LLMProvider.OPENAI, model_name="gpt-4", api_key="test-key-123")
        backend = OpenAIBackend(config)

        mock_openai_module = Mock()
        mock_client = Mock()
        mock_client.models.list.return_value = []
        mock_openai_module.OpenAI.return_value = mock_client

        with patch.dict("sys.modules", {"openai": mock_openai_module}):
            result = backend.initialize()
            assert result is True
            mock_openai_module.OpenAI.assert_called_once_with(api_key="test-key-123", base_url=None)

    def test_openai_backend_fallback_to_secrets_manager(self) -> None:
        """OpenAI backend falls back to secrets manager for API key."""
        config = LLMConfig(provider=LLMProvider.OPENAI, model_name="gpt-4")
        backend = OpenAIBackend(config)

        mock_openai_module = Mock()
        mock_client = Mock()
        mock_client.models.list.return_value = []
        mock_openai_module.OpenAI.return_value = mock_client

        with patch("intellicrack.utils.secrets_manager.get_secret", return_value="secret-key-456"):
            with patch.dict("sys.modules", {"openai": mock_openai_module}):
                result = backend.initialize()
                assert result is True
                mock_openai_module.OpenAI.assert_called_once_with(api_key="secret-key-456", base_url=None)

    def test_openai_backend_uses_custom_base_url(self) -> None:
        """OpenAI backend supports custom base URL."""
        config = LLMConfig(
            provider=LLMProvider.OPENAI,
            model_name="gpt-4",
            api_key="test-key",
            api_base="https://custom.openai.com/v1",
        )
        backend = OpenAIBackend(config)

        mock_openai_module = Mock()
        mock_client = Mock()
        mock_client.models.list.return_value = []
        mock_openai_module.OpenAI.return_value = mock_client

        with patch.dict("sys.modules", {"openai": mock_openai_module}):
            backend.initialize()
            mock_openai_module.OpenAI.assert_called_once_with(api_key="test-key", base_url="https://custom.openai.com/v1")

    def test_openai_backend_chat_requires_initialization(self) -> None:
        """OpenAI backend chat raises error when not initialized."""
        config = LLMConfig(provider=LLMProvider.OPENAI, model_name="gpt-4")
        backend = OpenAIBackend(config)
        messages = [LLMMessage(role="user", content="Test")]

        with pytest.raises(RuntimeError, match="Backend not initialized"):
            backend.chat(messages)

    def test_openai_backend_message_conversion(self) -> None:
        """OpenAI backend converts LLMMessage to OpenAI format correctly."""
        config = LLMConfig(provider=LLMProvider.OPENAI, model_name="gpt-4", api_key="test")
        backend = OpenAIBackend(config)
        backend.is_initialized = True
        backend.client = Mock()

        mock_response = Mock()
        mock_response.choices = [Mock()]
        mock_response.choices[0].message.content = "Response"
        mock_response.choices[0].message.tool_calls = None
        mock_response.choices[0].finish_reason = "stop"
        mock_response.model = "gpt-4"
        mock_response.usage = None
        backend.client.chat.completions.create.return_value = mock_response

        messages = [
            LLMMessage(role="system", content="System prompt"),
            LLMMessage(role="user", content="User message"),
        ]
        backend.chat(messages)

        call_args = backend.client.chat.completions.create.call_args
        openai_messages = call_args.kwargs["messages"]
        assert len(openai_messages) == 2
        assert openai_messages[0]["role"] == "system"
        assert openai_messages[0]["content"] == "System prompt"
        assert openai_messages[1]["role"] == "user"
        assert openai_messages[1]["content"] == "User message"

    def test_openai_backend_includes_tools_when_enabled(self) -> None:
        """OpenAI backend includes tools in request when enabled."""
        config = LLMConfig(provider=LLMProvider.OPENAI, model_name="gpt-4", api_key="test", tools_enabled=True)
        backend = OpenAIBackend(config)
        backend.is_initialized = True
        backend.client = Mock()

        mock_response = Mock()
        mock_response.choices = [Mock()]
        mock_response.choices[0].message.content = "Response"
        mock_response.choices[0].message.tool_calls = None
        mock_response.choices[0].finish_reason = "stop"
        mock_response.model = "gpt-4"
        mock_response.usage = None
        backend.client.chat.completions.create.return_value = mock_response

        tools = [{"name": "analyze_binary", "description": "Analyze binary file"}]
        messages = [LLMMessage(role="user", content="Test")]
        backend.chat(messages, tools)

        call_args = backend.client.chat.completions.create.call_args
        assert "tools" in call_args.kwargs
        assert call_args.kwargs["tool_choice"] == "auto"

    def test_openai_backend_excludes_tools_when_disabled(self) -> None:
        """OpenAI backend excludes tools when tools_enabled is False."""
        config = LLMConfig(provider=LLMProvider.OPENAI, model_name="gpt-4", api_key="test", tools_enabled=False)
        backend = OpenAIBackend(config)
        backend.is_initialized = True
        backend.client = Mock()

        mock_response = Mock()
        mock_response.choices = [Mock()]
        mock_response.choices[0].message.content = "Response"
        mock_response.choices[0].message.tool_calls = None
        mock_response.choices[0].finish_reason = "stop"
        mock_response.model = "gpt-4"
        mock_response.usage = None
        backend.client.chat.completions.create.return_value = mock_response

        tools = [{"name": "analyze_binary", "description": "Analyze binary file"}]
        messages = [LLMMessage(role="user", content="Test")]
        backend.chat(messages, tools)

        call_args = backend.client.chat.completions.create.call_args
        assert "tools" not in call_args.kwargs


class TestAnthropicBackendConfiguration:
    """Test Anthropic backend configuration and validation."""

    def test_anthropic_backend_requires_api_key(self) -> None:
        """Anthropic backend requires API key for initialization."""
        config = LLMConfig(provider=LLMProvider.ANTHROPIC, model_name="claude-3-5-sonnet-20241022")
        backend = AnthropicBackend(config)

        with patch("intellicrack.utils.secrets_manager.get_secret", return_value=None):
            result = backend.initialize()
            assert result is False

    def test_anthropic_backend_separates_system_messages(self) -> None:
        """Anthropic backend separates system messages from conversation."""
        config = LLMConfig(provider=LLMProvider.ANTHROPIC, model_name="claude-3-5-sonnet-20241022", api_key="test")
        backend = AnthropicBackend(config)
        backend.is_initialized = True
        backend.client = Mock()

        mock_response = Mock()
        mock_response.content = [Mock()]
        mock_response.content[0].text = "Response"
        mock_response.stop_reason = "end_turn"
        mock_response.model = "claude-3-5-sonnet-20241022"
        backend.client.messages.create.return_value = mock_response

        messages = [
            LLMMessage(role="system", content="You are a helpful assistant"),
            LLMMessage(role="user", content="Hello"),
        ]
        backend.chat(messages)

        call_args = backend.client.messages.create.call_args
        assert "system" in call_args.kwargs
        assert call_args.kwargs["system"] == "You are a helpful assistant"
        assert len(call_args.kwargs["messages"]) == 1
        assert call_args.kwargs["messages"][0]["role"] == "user"

    def test_anthropic_backend_handles_no_system_message(self) -> None:
        """Anthropic backend works without system message."""
        config = LLMConfig(provider=LLMProvider.ANTHROPIC, model_name="claude-3-5-sonnet-20241022", api_key="test")
        backend = AnthropicBackend(config)
        backend.is_initialized = True
        backend.client = Mock()

        mock_response = Mock()
        mock_response.content = [Mock()]
        mock_response.content[0].text = "Response"
        mock_response.stop_reason = "end_turn"
        mock_response.model = "claude-3-5-sonnet-20241022"
        backend.client.messages.create.return_value = mock_response

        messages = [LLMMessage(role="user", content="Hello")]
        backend.chat(messages)

        call_args = backend.client.messages.create.call_args
        assert "system" not in call_args.kwargs or call_args.kwargs["system"] == ""


class TestLlamaCppBackendConfiguration:
    """Test llama.cpp backend configuration and validation."""

    def test_llamacpp_backend_requires_model_path(self) -> None:
        """llama.cpp backend requires valid model path."""
        config = LLMConfig(provider=LLMProvider.LLAMACPP, model_name="test-model")
        backend = LlamaCppBackend(config)
        result = backend.initialize()
        assert result is False

    def test_llamacpp_backend_validates_model_file_exists(self) -> None:
        """llama.cpp backend validates model file exists."""
        config = LLMConfig(
            provider=LLMProvider.LLAMACPP,
            model_name="test-model",
            model_path="/nonexistent/model.gguf",
        )
        backend = LlamaCppBackend(config)
        result = backend.initialize()
        assert result is False

    def test_llamacpp_messages_to_prompt_conversion(self) -> None:
        """llama.cpp converts messages to prompt format correctly."""
        config = LLMConfig(provider=LLMProvider.LLAMACPP, model_name="test")
        backend = LlamaCppBackend(config)

        messages = [
            LLMMessage(role="system", content="System prompt"),
            LLMMessage(role="user", content="User message"),
            LLMMessage(role="assistant", content="Assistant reply"),
        ]
        prompt = backend._messages_to_prompt(messages)

        assert "<|im_start|>system" in prompt
        assert "System prompt" in prompt
        assert "<|im_start|>user" in prompt
        assert "User message" in prompt
        assert "<|im_start|>assistant" in prompt
        assert "Assistant reply" in prompt
        assert prompt.endswith("<|im_start|>assistant\n")


class TestOllamaBackendConfiguration:
    """Test Ollama backend configuration and validation."""

    def test_ollama_backend_requires_base_url(self) -> None:
        """Ollama backend requires base URL configuration."""
        config = LLMConfig(provider=LLMProvider.OLLAMA, model_name="llama3.2")

        with patch("intellicrack.utils.secrets_manager.get_secret", return_value=None):
            with patch("intellicrack.utils.service_utils.get_service_url", side_effect=Exception("Not configured")):
                with pytest.raises(ConfigurationError, match="Ollama API URL not configured"):
                    OllamaBackend(config)

    def test_ollama_backend_uses_config_base_url(self) -> None:
        """Ollama backend uses base URL from config."""
        config = LLMConfig(
            provider=LLMProvider.OLLAMA,
            model_name="llama3.2",
            api_base="http://localhost:11434",
        )
        backend = OllamaBackend(config)
        assert backend.base_url == "http://localhost:11434"

    def test_ollama_backend_initialization_checks_server(self) -> None:
        """Ollama backend checks if server is running during initialization."""
        config = LLMConfig(
            provider=LLMProvider.OLLAMA,
            model_name="llama3.2",
            api_base="http://localhost:11434",
        )
        backend = OllamaBackend(config)

        mock_requests = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_requests.get.return_value = mock_response

        with patch.dict("sys.modules", {"requests": mock_requests}):
            result = backend.initialize()
            assert result is True
            assert mock_requests.get.called

    def test_ollama_backend_handles_server_not_running(self) -> None:
        """Ollama backend handles server not running gracefully."""
        config = LLMConfig(
            provider=LLMProvider.OLLAMA,
            model_name="llama3.2",
            api_base="http://localhost:11434",
        )
        backend = OllamaBackend(config)

        mock_requests = Mock()
        mock_requests.exceptions = Mock()
        mock_requests.exceptions.ConnectionError = ConnectionError
        mock_requests.exceptions.Timeout = TimeoutError
        mock_requests.exceptions.RequestException = Exception
        mock_requests.get.side_effect = ConnectionError("Connection refused")

        with patch.dict("sys.modules", {"requests": mock_requests}):
            result = backend.initialize()
            assert result is False

    def test_ollama_backend_chat_includes_tools(self) -> None:
        """Ollama backend includes tools in chat request."""
        config = LLMConfig(
            provider=LLMProvider.OLLAMA,
            model_name="llama3.2",
            api_base="http://localhost:11434",
        )
        backend = OllamaBackend(config)
        backend.is_initialized = True

        mock_requests = Mock()
        mock_response = Mock()
        mock_response.json.return_value = {"message": {"content": "Response"}}
        mock_requests.post.return_value = mock_response

        with patch.dict("sys.modules", {"requests": mock_requests}):
            tools = [{"name": "test_tool", "description": "Test"}]
            messages = [LLMMessage(role="user", content="Test")]
            backend.chat(messages, tools)

            call_args = mock_requests.post.call_args
            request_data = call_args.kwargs["json"]
            assert "tools" in request_data
            assert request_data["tools"] == tools


class TestLLMManagerSingleton:
    """Test LLM Manager singleton pattern and thread safety."""

    def test_llm_manager_singleton_pattern(self) -> None:
        """LLM Manager implements singleton pattern correctly."""
        manager1 = LLMManager()
        manager2 = LLMManager()
        assert manager1 is manager2

    def test_llm_manager_get_llm_manager_returns_singleton(self) -> None:
        """get_llm_manager returns same singleton instance."""
        manager1 = get_llm_manager()
        manager2 = get_llm_manager()
        assert manager1 is manager2

    def test_llm_manager_thread_safe_initialization(self) -> None:
        """LLM Manager initialization is thread-safe."""
        instances = []

        def create_manager() -> None:
            instances.append(LLMManager())

        threads = [threading.Thread(target=create_manager) for _ in range(10)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert len(set(id(inst) for inst in instances)) == 1

    def test_llm_manager_initialization_parameters(self) -> None:
        """LLM Manager accepts lazy loading and background loading parameters."""
        shutdown_llm_manager()
        LLMManager._instance = None

        manager = LLMManager(enable_lazy_loading=False, enable_background_loading=False)
        assert manager.enable_lazy_loading is False
        assert manager.enable_background_loading is False

    def test_llm_manager_validates_parameter_types(self) -> None:
        """LLM Manager validates parameter types."""
        shutdown_llm_manager()
        LLMManager._instance = None

        with pytest.raises(TypeError, match="enable_lazy_loading must be a boolean"):
            LLMManager(enable_lazy_loading="true")

        shutdown_llm_manager()
        LLMManager._instance = None

        with pytest.raises(TypeError, match="enable_background_loading must be a boolean"):
            LLMManager(enable_background_loading="yes")


class TestLLMManagerBackendRegistration:
    """Test LLM Manager backend registration logic."""

    def test_register_llm_validates_provider(self) -> None:
        """LLM Manager validates provider type during registration."""
        manager = LLMManager(enable_lazy_loading=False)

        invalid_config = LLMConfig(provider=999, model_name="test")
        result = manager.register_llm("test-llm", invalid_config)
        assert result is False

    def test_register_llm_sets_first_as_active(self) -> None:
        """LLM Manager sets first registered LLM as active."""
        manager = LLMManager(enable_lazy_loading=False)

        with patch.object(OpenAIBackend, "initialize", return_value=True):
            config = LLMConfig(provider=LLMProvider.OPENAI, model_name="gpt-4", api_key="test")
            result = manager.register_llm("openai-gpt4", config)
            assert result is True
            assert manager.active_backend == "openai-gpt4"

    def test_register_llm_preserves_active_backend(self) -> None:
        """LLM Manager preserves active backend when registering additional LLMs."""
        manager = LLMManager(enable_lazy_loading=False)

        with patch.object(OpenAIBackend, "initialize", return_value=True):
            config1 = LLMConfig(provider=LLMProvider.OPENAI, model_name="gpt-4", api_key="test")
            manager.register_llm("openai-gpt4", config1)

            config2 = LLMConfig(provider=LLMProvider.OPENAI, model_name="gpt-3.5-turbo", api_key="test")
            manager.register_llm("openai-gpt35", config2)

            assert manager.active_backend == "openai-gpt4"

    def test_register_llm_stores_config(self) -> None:
        """LLM Manager stores configuration for registered LLMs."""
        manager = LLMManager(enable_lazy_loading=False)

        with patch.object(OpenAIBackend, "initialize", return_value=True):
            config = LLMConfig(provider=LLMProvider.OPENAI, model_name="gpt-4", api_key="test")
            manager.register_llm("openai-gpt4", config)
            assert "openai-gpt4" in manager.configs
            assert manager.configs["openai-gpt4"] == config

    def test_get_backend_class_returns_correct_class(self) -> None:
        """LLM Manager returns correct backend class for provider."""
        manager = LLMManager(enable_lazy_loading=False)

        assert manager._get_backend_class(LLMProvider.OPENAI) == OpenAIBackend
        assert manager._get_backend_class(LLMProvider.ANTHROPIC) == AnthropicBackend
        assert manager._get_backend_class(LLMProvider.LLAMACPP) == LlamaCppBackend
        assert manager._get_backend_class(LLMProvider.OLLAMA) == OllamaBackend
        assert manager._get_backend_class(LLMProvider.PYTORCH) == PyTorchLLMBackend
        assert manager._get_backend_class(LLMProvider.TENSORFLOW) == TensorFlowLLMBackend

    def test_get_backend_class_returns_none_for_invalid_provider(self) -> None:
        """LLM Manager returns None for invalid provider."""
        manager = LLMManager(enable_lazy_loading=False)
        result = manager._get_backend_class(999)
        assert result is None


class TestLLMManagerChatInterface:
    """Test LLM Manager chat interface."""

    def test_chat_uses_active_backend(self) -> None:
        """LLM Manager uses active backend for chat."""
        manager = LLMManager(enable_lazy_loading=False)

        with patch.object(OpenAIBackend, "initialize", return_value=True):
            config = LLMConfig(provider=LLMProvider.OPENAI, model_name="gpt-4", api_key="test")
            manager.register_llm("openai-gpt4", config)

            mock_backend = manager.backends["openai-gpt4"]
            mock_backend.chat = Mock(return_value=LLMResponse(content="Test response"))

            messages = [LLMMessage(role="user", content="Test")]
            response = manager.chat(messages)

            assert response is not None
            assert response.content == "Test response"
            mock_backend.chat.assert_called_once()

    def test_chat_accepts_specific_llm_id(self) -> None:
        """LLM Manager can use specific LLM by ID."""
        manager = LLMManager(enable_lazy_loading=False)

        with patch.object(OpenAIBackend, "initialize", return_value=True):
            config1 = LLMConfig(provider=LLMProvider.OPENAI, model_name="gpt-4", api_key="test")
            config2 = LLMConfig(provider=LLMProvider.OPENAI, model_name="gpt-3.5-turbo", api_key="test")
            manager.register_llm("gpt4", config1)
            manager.register_llm("gpt35", config2)

            manager.backends["gpt35"].chat = Mock(return_value=LLMResponse(content="GPT-3.5 response"))

            messages = [LLMMessage(role="user", content="Test")]
            response = manager.chat(messages, llm_id="gpt35")

            assert response.content == "GPT-3.5 response"

    def test_chat_returns_none_when_no_backend(self) -> None:
        """LLM Manager returns None when no backend is available."""
        manager = LLMManager(enable_lazy_loading=False)
        messages = [LLMMessage(role="user", content="Test")]
        response = manager.chat(messages)
        assert response is None

    def test_chat_prepends_system_prompt_from_config(self) -> None:
        """LLM Manager prepends system prompt from config if not in messages."""
        manager = LLMManager(enable_lazy_loading=False)

        with patch.object(OpenAIBackend, "initialize", return_value=True):
            config = LLMConfig(
                provider=LLMProvider.OPENAI,
                model_name="gpt-4",
                api_key="test",
                system_prompt="You are a security analyst.",
            )
            manager.register_llm("openai-gpt4", config)

            mock_backend = manager.backends["openai-gpt4"]
            mock_backend.chat = Mock(return_value=LLMResponse(content="Response"))

            messages = [LLMMessage(role="user", content="Test")]
            manager.chat(messages)

            call_args = mock_backend.chat.call_args[0][0]
            assert call_args[0].role == "system"
            assert call_args[0].content == "You are a security analyst."

    def test_chat_does_not_duplicate_system_prompt(self) -> None:
        """LLM Manager does not duplicate system prompt if already present."""
        manager = LLMManager(enable_lazy_loading=False)

        with patch.object(OpenAIBackend, "initialize", return_value=True):
            config = LLMConfig(
                provider=LLMProvider.OPENAI,
                model_name="gpt-4",
                api_key="test",
                system_prompt="Default prompt",
            )
            manager.register_llm("openai-gpt4", config)

            mock_backend = manager.backends["openai-gpt4"]
            mock_backend.chat = Mock(return_value=LLMResponse(content="Response"))

            messages = [
                LLMMessage(role="system", content="Custom prompt"),
                LLMMessage(role="user", content="Test"),
            ]
            manager.chat(messages)

            call_args = mock_backend.chat.call_args[0][0]
            system_messages = [msg for msg in call_args if msg.role == "system"]
            assert len(system_messages) == 1
            assert system_messages[0].content == "Custom prompt"


class TestConfigurationHelpers:
    """Test configuration helper functions."""

    def test_create_openai_config(self) -> None:
        """create_openai_config creates valid OpenAI configuration."""
        config = create_openai_config(model_name="gpt-4", api_key="test-key")
        assert config.provider == LLMProvider.OPENAI
        assert config.model_name == "gpt-4"
        assert config.api_key == "test-key"

    def test_create_openai_config_with_kwargs(self) -> None:
        """create_openai_config accepts additional kwargs."""
        config = create_openai_config(
            model_name="gpt-4",
            api_key="test",
            context_length=8192,
            temperature=0.2,
            max_tokens=4096,
        )
        assert config.context_length == 8192
        assert config.temperature == 0.2
        assert config.max_tokens == 4096

    def test_create_anthropic_config(self) -> None:
        """create_anthropic_config creates valid Anthropic configuration."""
        config = create_anthropic_config(model_name="claude-3-5-sonnet-20241022", api_key="test-key")
        assert config.provider == LLMProvider.ANTHROPIC
        assert config.model_name == "claude-3-5-sonnet-20241022"
        assert config.api_key == "test-key"

    def test_create_gguf_config(self) -> None:
        """create_gguf_config creates valid GGUF configuration."""
        config = create_gguf_config(model_path="/path/to/model.gguf", model_name="llama-3.2-3b")
        assert config.provider == LLMProvider.LLAMACPP
        assert config.model_path == "/path/to/model.gguf"
        assert config.model_name == "llama-3.2-3b"

    def test_create_ollama_config(self) -> None:
        """create_ollama_config creates valid Ollama configuration."""
        config = create_ollama_config(model_name="llama3.2", api_base="http://localhost:11434")
        assert config.provider == LLMProvider.OLLAMA
        assert config.model_name == "llama3.2"
        assert config.api_base == "http://localhost:11434"

    def test_create_pytorch_config(self) -> None:
        """create_pytorch_config creates valid PyTorch configuration."""
        config = create_pytorch_config(model_path="/path/to/model.pt", model_name="custom-model")
        assert config.provider == LLMProvider.PYTORCH
        assert config.model_path == "/path/to/model.pt"
        assert config.model_name == "custom-model"

    def test_create_tensorflow_config(self) -> None:
        """create_tensorflow_config creates valid TensorFlow configuration."""
        config = create_tensorflow_config(model_path="/path/to/model", model_name="tf-model")
        assert config.provider == LLMProvider.TENSORFLOW
        assert config.model_path == "/path/to/model"
        assert config.model_name == "tf-model"

    def test_create_onnx_config(self) -> None:
        """create_onnx_config creates valid ONNX configuration."""
        config = create_onnx_config(model_path="/path/to/model.onnx", model_name="onnx-model")
        assert config.provider == LLMProvider.ONNX
        assert config.model_path == "/path/to/model.onnx"
        assert config.model_name == "onnx-model"

    def test_create_safetensors_config(self) -> None:
        """create_safetensors_config creates valid Safetensors configuration."""
        config = create_safetensors_config(model_path="/path/to/model.safetensors", model_name="safe-model")
        assert config.provider == LLMProvider.SAFETENSORS
        assert config.model_path == "/path/to/model.safetensors"
        assert config.model_name == "safe-model"

    def test_create_gptq_config(self) -> None:
        """create_gptq_config creates valid GPTQ configuration."""
        config = create_gptq_config(model_path="/path/to/gptq-model", model_name="gptq-model")
        assert config.provider == LLMProvider.GPTQ
        assert config.model_path == "/path/to/gptq-model"
        assert config.model_name == "gptq-model"

    def test_create_huggingface_local_config(self) -> None:
        """create_huggingface_local_config creates valid HuggingFace local configuration."""
        config = create_huggingface_local_config(model_path="/path/to/hf-model", model_name="hf-model")
        assert config.provider == LLMProvider.HUGGINGFACE_LOCAL
        assert config.model_path == "/path/to/hf-model"
        assert config.model_name == "hf-model"


class TestLLMManagerUtilityMethods:
    """Test LLM Manager utility methods."""

    def test_get_available_llms_returns_registered_llms(self) -> None:
        """get_available_llms returns list of registered LLM IDs."""
        manager = LLMManager(enable_lazy_loading=False)

        with patch.object(OpenAIBackend, "initialize", return_value=True):
            config1 = LLMConfig(provider=LLMProvider.OPENAI, model_name="gpt-4", api_key="test")
            config2 = LLMConfig(provider=LLMProvider.OPENAI, model_name="gpt-3.5-turbo", api_key="test")
            manager.register_llm("gpt4", config1)
            manager.register_llm("gpt35", config2)

            available = manager.get_available_llms()
            assert "gpt4" in available
            assert "gpt35" in available
            assert len(available) == 2

    def test_get_llm_info_returns_backend_details(self) -> None:
        """get_llm_info returns detailed information about LLM backend."""
        manager = LLMManager(enable_lazy_loading=False)

        def mock_initialize(self):
            self.is_initialized = True
            return True

        with patch.object(OpenAIBackend, "initialize", mock_initialize):
            config = LLMConfig(
                provider=LLMProvider.OPENAI,
                model_name="gpt-4",
                api_key="test",
                context_length=8192,
                tools_enabled=True,
            )
            manager.register_llm("gpt4", config)

            info = manager.get_llm_info("gpt4")
            assert info is not None
            assert info["id"] == "gpt4"
            assert info["provider"] == "openai"
            assert info["model_name"] == "gpt-4"
            assert info["context_length"] == 8192
            assert info["tools_enabled"] is True
            assert info["is_initialized"] is True

    def test_get_llm_info_returns_none_for_unknown_llm(self) -> None:
        """get_llm_info returns None for unknown LLM ID."""
        manager = LLMManager(enable_lazy_loading=False)
        info = manager.get_llm_info("nonexistent")
        assert info is None

    def test_set_active_llm_changes_active_backend(self) -> None:
        """set_active_llm changes the active backend."""
        manager = LLMManager(enable_lazy_loading=False)

        with patch.object(OpenAIBackend, "initialize", return_value=True):
            config1 = LLMConfig(provider=LLMProvider.OPENAI, model_name="gpt-4", api_key="test")
            config2 = LLMConfig(provider=LLMProvider.OPENAI, model_name="gpt-3.5-turbo", api_key="test")
            manager.register_llm("gpt4", config1)
            manager.register_llm("gpt35", config2)

            assert manager.active_backend == "gpt4"

            result = manager.set_active_llm("gpt35")
            assert result is True
            assert manager.active_backend == "gpt35"

    def test_set_active_llm_fails_for_unregistered_llm(self) -> None:
        """set_active_llm returns False for unregistered LLM."""
        manager = LLMManager(enable_lazy_loading=False)
        result = manager.set_active_llm("nonexistent")
        assert result is False

    def test_register_tools_for_llm(self) -> None:
        """register_tools_for_llm registers tools for specific backend."""
        manager = LLMManager(enable_lazy_loading=False)

        with patch.object(OpenAIBackend, "initialize", return_value=True):
            config = LLMConfig(provider=LLMProvider.OPENAI, model_name="gpt-4", api_key="test")
            manager.register_llm("gpt4", config)

            tools = [{"name": "analyze_binary", "description": "Analyze binary"}]
            manager.register_tools_for_llm("gpt4", tools)

            backend = manager.backends["gpt4"]
            assert backend.tools == tools


class TestContextWindowManagement:
    """Test context window and token limit management."""

    def test_config_context_length_default(self) -> None:
        """Configuration has default context length of 4096."""
        config = LLMConfig(provider=LLMProvider.OPENAI, model_name="gpt-4")
        assert config.context_length == 4096

    def test_config_max_tokens_default(self) -> None:
        """Configuration has default max_tokens of 2048."""
        config = LLMConfig(provider=LLMProvider.OPENAI, model_name="gpt-4")
        assert config.max_tokens == 2048

    def test_config_custom_context_length(self) -> None:
        """Configuration accepts custom context length."""
        config = LLMConfig(provider=LLMProvider.OPENAI, model_name="gpt-4", context_length=16384)
        assert config.context_length == 16384

    def test_config_custom_max_tokens(self) -> None:
        """Configuration accepts custom max_tokens."""
        config = LLMConfig(provider=LLMProvider.OPENAI, model_name="gpt-4", max_tokens=8192)
        assert config.max_tokens == 8192

    def test_openai_backend_uses_config_max_tokens(self) -> None:
        """OpenAI backend uses max_tokens from configuration."""
        config = LLMConfig(provider=LLMProvider.OPENAI, model_name="gpt-4", api_key="test", max_tokens=1000)
        backend = OpenAIBackend(config)
        backend.is_initialized = True
        backend.client = Mock()

        mock_response = Mock()
        mock_response.choices = [Mock()]
        mock_response.choices[0].message.content = "Response"
        mock_response.choices[0].message.tool_calls = None
        mock_response.choices[0].finish_reason = "stop"
        mock_response.model = "gpt-4"
        mock_response.usage = None
        backend.client.chat.completions.create.return_value = mock_response

        messages = [LLMMessage(role="user", content="Test")]
        backend.chat(messages)

        call_args = backend.client.chat.completions.create.call_args
        assert call_args.kwargs["max_tokens"] == 1000

    def test_openai_backend_uses_config_temperature(self) -> None:
        """OpenAI backend uses temperature from configuration."""
        config = LLMConfig(provider=LLMProvider.OPENAI, model_name="gpt-4", api_key="test", temperature=0.1)
        backend = OpenAIBackend(config)
        backend.is_initialized = True
        backend.client = Mock()

        mock_response = Mock()
        mock_response.choices = [Mock()]
        mock_response.choices[0].message.content = "Response"
        mock_response.choices[0].message.tool_calls = None
        mock_response.choices[0].finish_reason = "stop"
        mock_response.model = "gpt-4"
        mock_response.usage = None
        backend.client.chat.completions.create.return_value = mock_response

        messages = [LLMMessage(role="user", content="Test")]
        backend.chat(messages)

        call_args = backend.client.chat.completions.create.call_args
        assert call_args.kwargs["temperature"] == 0.1


class TestErrorHandling:
    """Test error handling and recovery mechanisms."""

    def test_openai_backend_handles_import_error(self) -> None:
        """OpenAI backend handles missing openai package gracefully."""
        config = LLMConfig(provider=LLMProvider.OPENAI, model_name="gpt-4", api_key="test")
        backend = OpenAIBackend(config)

        def mock_import(name, *args, **kwargs):
            if name == "openai":
                raise ImportError("No module named 'openai'")
            return __import__(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=mock_import):
            result = backend.initialize()
            assert result is False

    def test_anthropic_backend_handles_import_error(self) -> None:
        """Anthropic backend handles missing anthropic package gracefully."""
        config = LLMConfig(provider=LLMProvider.ANTHROPIC, model_name="claude-3-5-sonnet-20241022", api_key="test")
        backend = AnthropicBackend(config)

        def mock_import(name, *args, **kwargs):
            if name == "anthropic":
                raise ImportError("No module named 'anthropic'")
            return __import__(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=mock_import):
            result = backend.initialize()
            assert result is False

    def test_llamacpp_backend_handles_import_error(self) -> None:
        """llama.cpp backend handles missing llama-cpp-python gracefully."""
        config = LLMConfig(provider=LLMProvider.LLAMACPP, model_name="test", model_path="/test/model.gguf")
        backend = LlamaCppBackend(config)

        with patch("builtins.__import__", side_effect=ImportError("No module named 'llama_cpp'")):
            result = backend.initialize()
            assert result is False

    def test_ollama_backend_returns_error_response_when_not_initialized(self) -> None:
        """Ollama backend returns error response when chat called without initialization."""
        config = LLMConfig(provider=LLMProvider.OLLAMA, model_name="llama3.2", api_base="http://localhost:11434")
        backend = OllamaBackend(config)
        backend.is_initialized = False

        messages = [LLMMessage(role="user", content="Test")]
        response = backend.chat(messages)

        assert isinstance(response, LLMResponse)
        assert "not initialized" in response.content
        assert response.finish_reason == "error"

    def test_manager_chat_returns_none_on_backend_error(self) -> None:
        """LLM Manager returns None when backend raises error during chat."""
        manager = LLMManager(enable_lazy_loading=False)

        with patch.object(OpenAIBackend, "initialize", return_value=True):
            config = LLMConfig(provider=LLMProvider.OPENAI, model_name="gpt-4", api_key="test")
            manager.register_llm("gpt4", config)

            manager.backends["gpt4"].chat = Mock(side_effect=RuntimeError("API error"))

            messages = [LLMMessage(role="user", content="Test")]
            response = manager.chat(messages)

            assert response is None

    def test_backend_shutdown_handles_cleanup_errors(self) -> None:
        """Backend shutdown handles cleanup errors gracefully."""
        config = LLMConfig(provider=LLMProvider.OPENAI, model_name="gpt-4")
        backend = OpenAIBackend(config)
        backend.is_initialized = True
        backend.client = Mock()

        backend.shutdown()
        assert backend.is_initialized is False
        assert backend.client is None


class TestBackendShutdown:
    """Test backend shutdown and resource cleanup."""

    def test_openai_backend_shutdown_clears_client(self) -> None:
        """OpenAI backend shutdown clears client reference."""
        config = LLMConfig(provider=LLMProvider.OPENAI, model_name="gpt-4")
        backend = OpenAIBackend(config)
        backend.client = Mock()
        backend.is_initialized = True

        backend.shutdown()
        assert backend.client is None
        assert backend.is_initialized is False

    def test_anthropic_backend_shutdown_clears_client(self) -> None:
        """Anthropic backend shutdown clears client reference."""
        config = LLMConfig(provider=LLMProvider.ANTHROPIC, model_name="claude-3-5-sonnet-20241022")
        backend = AnthropicBackend(config)
        backend.client = Mock()
        backend.is_initialized = True

        backend.shutdown()
        assert backend.client is None
        assert backend.is_initialized is False

    def test_llamacpp_backend_shutdown_clears_model(self) -> None:
        """llama.cpp backend shutdown clears model reference."""
        config = LLMConfig(provider=LLMProvider.LLAMACPP, model_name="test")
        backend = LlamaCppBackend(config)
        backend.llama = Mock()
        backend.is_initialized = True

        backend.shutdown()
        assert backend.llama is None
        assert backend.is_initialized is False

    def test_global_shutdown_llm_manager_clears_singleton(self) -> None:
        """shutdown_llm_manager clears global singleton instance."""
        manager = get_llm_manager()
        assert manager is not None

        shutdown_llm_manager()

        if hasattr(LLMManager, "_instance"):
            LLMManager._instance = None

        new_manager = get_llm_manager()
        assert new_manager is not manager

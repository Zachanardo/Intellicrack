"""
Unit tests for LLM Backends

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellicrack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack.  If not, see <https://www.gnu.org/licenses/>.
"""

import json
import os
import pytest
from unittest.mock import Mock, patch

from intellicrack.ai.llm_backends import (
    LLMManager,
    LLMConfig,
    LLMMessage,
    LLMResponse,
    LLMProvider,
    OpenAIBackend,
    AnthropicBackend,
    LlamaCppBackend,
    OllamaBackend,
    create_openai_config,
    create_anthropic_config,
    create_gguf_config,
    create_ollama_config
)


class TestLLMConfig:
    """Test cases for LLM configuration."""

    def test_config_creation(self):
        """Test LLM configuration creation."""
        config = LLMConfig(
            provider=LLMProvider.OPENAI,
            model_name="gpt-4",
            api_key="test_key",
            context_length=8192,
            temperature=0.7
        )

        assert config.provider == LLMProvider.OPENAI
        assert config.model_name == "gpt-4"
        assert config.api_key == "test_key"
        assert config.context_length == 8192
        assert config.temperature == 0.7

    def test_convenience_functions(self):
        """Test convenience functions for creating configs."""
        # OpenAI config
        openai_config = create_openai_config("gpt-3.5-turbo", "key123")
        assert openai_config.provider == LLMProvider.OPENAI
        assert openai_config.model_name == "gpt-3.5-turbo"
        assert openai_config.api_key == "key123"

        # Anthropic config
        anthropic_config = create_anthropic_config("claude-3-sonnet", "anthrop_key")
        assert anthropic_config.provider == LLMProvider.ANTHROPIC
        assert anthropic_config.model_name == "claude-3-sonnet"
        assert anthropic_config.api_key == "anthrop_key"

        # GGUF config
        gguf_config = create_gguf_config("/path/to/model.gguf")
        assert gguf_config.provider == LLMProvider.LLAMACPP
        assert gguf_config.model_path == "/path/to/model.gguf"

        # Ollama config
        ollama_config = create_ollama_config("llama2")
        assert ollama_config.provider == LLMProvider.OLLAMA
        assert ollama_config.model_name == "llama2"


class TestLLMMessage:
    """Test cases for LLM messages."""

    def test_message_creation(self):
        """Test LLM message creation."""
        message = LLMMessage(
            role="user",
            content="Generate a Frida script",
            tool_calls=[{"name": "analyze_binary"}]
        )

        assert message.role == "user"
        assert message.content == "Generate a Frida script"
        assert len(message.tool_calls) == 1

    def test_message_types(self):
        """Test different message types."""
        system_msg = LLMMessage(role="system", content="You are an expert")
        user_msg = LLMMessage(role="user", content="Help me")
        assistant_msg = LLMMessage(role="assistant", content="I'll help")
        tool_msg = LLMMessage(role="tool", content="Result", tool_call_id="call_123")

        assert system_msg.role == "system"
        assert user_msg.role == "user"
        assert assistant_msg.role == "assistant"
        assert tool_msg.role == "tool"
        assert tool_msg.tool_call_id == "call_123"


class TestLLMResponse:
    """Test cases for LLM responses."""

    def test_response_creation(self):
        """Test LLM response creation."""
        response = LLMResponse(
            content="Generated script content",
            finish_reason="stop",
            model="gpt-4",
            usage={"prompt_tokens": 100, "completion_tokens": 200}
        )

        assert response.content == "Generated script content"
        assert response.finish_reason == "stop"
        assert response.model == "gpt-4"
        assert response.usage["prompt_tokens"] == 100

    def test_response_with_tool_calls(self):
        """Test response with tool calls."""
        tool_calls = [
            {
                "id": "call_123",
                "type": "function",
                "function": {
                    "name": "analyze_binary",
                    "arguments": json.dumps({"path": "/path/to/binary"})
                }
            }
        ]

        response = LLMResponse(
            content="I'll analyze the binary",
            tool_calls=tool_calls,
            finish_reason="tool_calls"
        )

        assert len(response.tool_calls) == 1
        assert response.tool_calls[0]["function"]["name"] == "analyze_binary"
        assert response.finish_reason == "tool_calls"


class TestOpenAIBackend:
    """Test cases for OpenAI backend."""

    def setup_method(self):
        """Set up test fixtures."""
        self.config = LLMConfig(
            provider=LLMProvider.OPENAI,
            model_name="gpt-4",
            api_key="test_key"
        )
        self.backend = OpenAIBackend(self.config)

    @patch('intellicrack.ai.llm_backends.openai')
    def test_initialization_success(self, mock_openai):
        """Test successful initialization."""
        mock_client = Mock()
        mock_openai.OpenAI.return_value = mock_client
        mock_client.models.list.return_value = []

        result = self.backend.initialize()

        assert result is True
        assert self.backend.is_initialized is True
        mock_openai.OpenAI.assert_called_once_with(api_key="test_key", base_url=None)

    @patch('intellicrack.ai.llm_backends.openai')
    def test_initialization_no_api_key(self, mock_openai):
        """Test initialization without API key."""
        config = LLMConfig(provider=LLMProvider.OPENAI, model_name="gpt-4")
        backend = OpenAIBackend(config)

        with patch.dict(os.environ, {}, clear=True):
            result = backend.initialize()

        assert result is False
        assert backend.is_initialized is False

    @patch('intellicrack.ai.llm_backends.openai')
    def test_chat_success(self, mock_openai):
        """Test successful chat completion."""
        # Setup mock client
        mock_client = Mock()
        mock_openai.OpenAI.return_value = mock_client
        mock_client.models.list.return_value = []

        # Setup mock response
        mock_choice = Mock()
        mock_choice.message.content = "Generated script content"
        mock_choice.message.tool_calls = None
        mock_choice.finish_reason = "stop"

        mock_response = Mock()
        mock_response.choices = [mock_choice]
        mock_response.model = "gpt-4"
        mock_response.usage = None

        mock_client.chat.completions.create.return_value = mock_response

        # Initialize and test
        self.backend.initialize()

        messages = [LLMMessage(role="user", content="Generate a script")]
        response = self.backend.chat(messages)

        assert response.content == "Generated script content"
        assert response.finish_reason == "stop"
        assert response.model == "gpt-4"

    def test_chat_not_initialized(self):
        """Test chat when backend not initialized."""
        messages = [LLMMessage(role="user", content="Test")]

        with pytest.raises(RuntimeError, match="Backend not initialized"):
            self.backend.chat(messages)


class TestAnthropicBackend:
    """Test cases for Anthropic backend."""

    def setup_method(self):
        """Set up test fixtures."""
        self.config = LLMConfig(
            provider=LLMProvider.ANTHROPIC,
            model_name="claude-3-sonnet",
            api_key="test_key"
        )
        self.backend = AnthropicBackend(self.config)

    @patch('intellicrack.ai.llm_backends.anthropic')
    def test_initialization_success(self, mock_anthropic):
        """Test successful initialization."""
        mock_client = Mock()
        mock_anthropic.Anthropic.return_value = mock_client

        result = self.backend.initialize()

        assert result is True
        assert self.backend.is_initialized is True
        mock_anthropic.Anthropic.assert_called_once_with(api_key="test_key")

    @patch('intellicrack.ai.llm_backends.anthropic')
    def test_chat_with_system_message(self, mock_anthropic):
        """Test chat with system message handling."""
        mock_client = Mock()
        mock_anthropic.Anthropic.return_value = mock_client

        # Setup mock response
        mock_content = Mock()
        mock_content.text = "Generated response"

        mock_response = Mock()
        mock_response.content = [mock_content]
        mock_response.stop_reason = "end_turn"
        mock_response.model = "claude-3-sonnet"

        mock_client.messages.create.return_value = mock_response

        # Initialize and test
        self.backend.initialize()

        messages = [
            LLMMessage(role="system", content="You are an expert"),
            LLMMessage(role="user", content="Generate a script")
        ]

        response = self.backend.chat(messages)

        # Verify system message was passed separately
        call_args = mock_client.messages.create.call_args[1]
        assert "system" in call_args
        assert call_args["system"] == "You are an expert"
        assert len(call_args["messages"]) == 1  # Only user message

        assert response.content == "Generated response"


class TestLlamaCppBackend:
    """Test cases for llama.cpp backend."""

    def setup_method(self):
        """Set up test fixtures."""
        self.config = LLMConfig(
            provider=LLMProvider.LLAMACPP,
            model_name="test_model",
            model_path="/path/to/model.gguf"
        )
        self.backend = LlamaCppBackend(self.config)

    def test_initialization_no_model_path(self):
        """Test initialization without model path."""
        config = LLMConfig(provider=LLMProvider.LLAMACPP, model_name="test")
        backend = LlamaCppBackend(config)

        result = backend.initialize()

        assert result is False
        assert backend.is_initialized is False

    @patch('intellicrack.ai.llm_backends.Llama')
    @patch('os.path.exists')
    def test_initialization_success(self, mock_exists, mock_llama):
        """Test successful initialization."""
        mock_exists.return_value = True
        mock_llama_instance = Mock()
        mock_llama.return_value = mock_llama_instance

        result = self.backend.initialize()

        assert result is True
        assert self.backend.is_initialized is True
        mock_llama.assert_called_once_with(
            model_path="/path/to/model.gguf",
            n_ctx=4096,
            verbose=False,
            n_threads=4
        )

    @patch('intellicrack.ai.llm_backends.Llama')
    @patch('os.path.exists')
    def test_chat_success(self, mock_exists, mock_llama):
        """Test successful chat completion."""
        mock_exists.return_value = True
        mock_llama_instance = Mock()
        mock_llama.return_value = mock_llama_instance

        # Setup mock response
        mock_response = {
            'choices': [{
                'text': 'Generated response text',
                'finish_reason': 'stop'
            }]
        }
        mock_llama_instance.return_value = mock_response

        # Initialize and test
        self.backend.initialize()

        messages = [LLMMessage(role="user", content="Generate a script")]
        response = self.backend.chat(messages)

        assert response.content == "Generated response text"
        assert response.finish_reason == "stop"
        assert response.model == "test_model"

    def test_messages_to_prompt(self):
        """Test message to prompt conversion."""
        messages = [
            LLMMessage(role="system", content="You are an expert"),
            LLMMessage(role="user", content="Help me"),
            LLMMessage(role="assistant", content="Sure!")
        ]

        prompt = self.backend._messages_to_prompt(messages)

        assert "<|im_start|>system" in prompt
        assert "You are an expert" in prompt
        assert "<|im_start|>user" in prompt
        assert "Help me" in prompt
        assert "<|im_start|>assistant" in prompt
        assert "Sure!" in prompt
        assert prompt.endswith("<|im_start|>assistant\n")


class TestOllamaBackend:
    """Test cases for Ollama backend."""

    def setup_method(self):
        """Set up test fixtures."""
        self.config = LLMConfig(
            provider=LLMProvider.OLLAMA,
            model_name="llama2",
            api_base="http://localhost:11434"
        )
        self.backend = OllamaBackend(self.config)

    @patch('intellicrack.ai.llm_backends.requests')
    def test_initialization_success(self, mock_requests):
        """Test successful initialization."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_requests.get.return_value = mock_response

        result = self.backend.initialize()

        assert result is True
        assert self.backend.is_initialized is True
        mock_requests.get.assert_called_once_with(
            "http://localhost:11434/api/tags",
            timeout=5
        )

    @patch('intellicrack.ai.llm_backends.requests')
    def test_initialization_failure(self, mock_requests):
        """Test initialization failure."""
        mock_response = Mock()
        mock_response.status_code = 404
        mock_requests.get.return_value = mock_response

        result = self.backend.initialize()

        assert result is False
        assert self.backend.is_initialized is False

    @patch('intellicrack.ai.llm_backends.requests')
    def test_chat_success(self, mock_requests):
        """Test successful chat completion."""
        # Mock initialization
        init_response = Mock()
        init_response.status_code = 200

        # Mock chat response
        chat_response = Mock()
        chat_response.status_code = 200
        chat_response.json.return_value = {
            "message": {
                "content": "Generated response"
            }
        }

        mock_requests.get.return_value = init_response
        mock_requests.post.return_value = chat_response

        # Initialize and test
        self.backend.initialize()

        messages = [LLMMessage(role="user", content="Generate a script")]
        response = self.backend.chat(messages)

        assert response.content == "Generated response"
        assert response.finish_reason == "stop"
        assert response.model == "llama2"


class TestLLMManager:
    """Test cases for LLM Manager."""

    def setup_method(self):
        """Set up test fixtures."""
        self.manager = LLMManager()

    def test_manager_initialization(self):
        """Test LLM manager initialization."""
        assert len(self.manager.backends) == 0
        assert len(self.manager.configs) == 0
        assert self.manager.active_backend is None

    @patch.object(OpenAIBackend, 'initialize')
    def test_register_llm_success(self, mock_init):
        """Test successful LLM registration."""
        mock_init.return_value = True

        config = create_openai_config("gpt-4", "test_key")
        result = self.manager.register_llm("openai_gpt4", config)

        assert result is True
        assert "openai_gpt4" in self.manager.backends
        assert "openai_gpt4" in self.manager.configs
        assert self.manager.active_backend == "openai_gpt4"

    @patch.object(OpenAIBackend, 'initialize')
    def test_register_llm_failure(self, mock_init):
        """Test LLM registration failure."""
        mock_init.return_value = False

        config = create_openai_config("gpt-4", "invalid_key")
        result = self.manager.register_llm("openai_fail", config)

        assert result is False
        assert "openai_fail" not in self.manager.backends

    @patch.object(OpenAIBackend, 'initialize')
    @patch.object(OpenAIBackend, 'chat')
    def test_chat_success(self, mock_chat, mock_init):
        """Test successful chat through manager."""
        mock_init.return_value = True
        mock_response = LLMResponse(content="Generated script", finish_reason="stop")
        mock_chat.return_value = mock_response

        # Register backend
        config = create_openai_config("gpt-4", "test_key")
        self.manager.register_llm("test_llm", config)

        # Test chat
        messages = [LLMMessage(role="user", content="Generate script")]
        response = self.manager.chat(messages)

        assert response is not None
        assert response.content == "Generated script"
        mock_chat.assert_called_once_with(messages, None)

    def test_chat_no_backend(self):
        """Test chat with no registered backend."""
        messages = [LLMMessage(role="user", content="Test")]
        response = self.manager.chat(messages)

        assert response is None

    @patch.object(OpenAIBackend, 'initialize')
    def test_set_active_llm(self, mock_init):
        """Test setting active LLM."""
        mock_init.return_value = True

        # Register two LLMs
        config1 = create_openai_config("gpt-4", "key1")
        config2 = create_openai_config("gpt-3.5-turbo", "key2")

        self.manager.register_llm("llm1", config1)
        self.manager.register_llm("llm2", config2)

        # Test setting active
        result = self.manager.set_active_llm("llm2")
        assert result is True
        assert self.manager.active_backend == "llm2"

        # Test setting non-existent LLM
        result = self.manager.set_active_llm("nonexistent")
        assert result is False
        assert self.manager.active_backend == "llm2"  # Unchanged

    @patch.object(OpenAIBackend, 'initialize')
    def test_get_llm_info(self, mock_init):
        """Test getting LLM information."""
        mock_init.return_value = True

        config = create_openai_config("gpt-4", "test_key")
        self.manager.register_llm("test_llm", config)

        info = self.manager.get_llm_info("test_llm")

        assert info is not None
        assert info["id"] == "test_llm"
        assert info["provider"] == "openai"
        assert info["model_name"] == "gpt-4"
        assert info["is_initialized"] is True

    @patch.object(OpenAIBackend, 'initialize')
    @patch.object(OpenAIBackend, 'chat')
    def test_generate_script_content(self, mock_chat, mock_init):
        """Test script content generation."""
        mock_init.return_value = True
        mock_response = LLMResponse(content="Generated Frida script", finish_reason="stop")
        mock_chat.return_value = mock_response

        # Register backend
        config = create_openai_config("gpt-4", "test_key")
        self.manager.register_llm("test_llm", config)

        # Test script generation
        result = self.manager.generate_script_content(
            prompt="Generate a license bypass script",
            script_type="frida",
            context_data={"binary_name": "test.exe"}
        )

        assert result == "Generated Frida script"

        # Verify the call included context
        call_args = mock_chat.call_args[0]
        messages = call_args[0]
        assert len(messages) == 2  # system + user
        assert "frida" in messages[0].content.lower()
        assert "test.exe" in messages[0].content

    @patch.object(OpenAIBackend, 'initialize')
    @patch.object(OpenAIBackend, 'chat')
    def test_refine_script_content(self, mock_chat, mock_init):
        """Test script content refinement."""
        mock_init.return_value = True
        mock_response = LLMResponse(content="Refined script", finish_reason="stop")
        mock_chat.return_value = mock_response

        # Register backend
        config = create_openai_config("gpt-4", "test_key")
        self.manager.register_llm("test_llm", config)

        # Test script refinement
        result = self.manager.refine_script_content(
            original_script="broken script",
            error_feedback="Syntax error",
            test_results={"success": False},
            script_type="frida"
        )

        assert result == "Refined script"

        # Verify the refinement prompt was used
        call_args = mock_chat.call_args[0]
        messages = call_args[0]
        user_message = messages[1].content
        assert "broken script" in user_message
        assert "Syntax error" in user_message

    @patch.object(OpenAIBackend, 'initialize')
    @patch.object(OpenAIBackend, 'chat')
    def test_validate_script_syntax(self, mock_chat, mock_init):
        """Test script syntax validation."""
        mock_init.return_value = True
        validation_result = {
            "valid": True,
            "errors": [],
            "warnings": ["Consider adding error handling"]
        }
        mock_response = LLMResponse(content=json.dumps(validation_result), finish_reason="stop")
        mock_chat.return_value = mock_response

        # Register backend
        config = create_openai_config("gpt-4", "test_key")
        self.manager.register_llm("test_llm", config)

        # Test validation
        result = self.manager.validate_script_syntax(
            script_content="console.log('test');",
            script_type="javascript"
        )

        assert result["valid"] is True
        assert len(result["errors"]) == 0
        assert len(result["warnings"]) == 1

    @patch.object(OpenAIBackend, 'shutdown')
    @patch.object(OpenAIBackend, 'initialize')
    def test_shutdown(self, mock_init, mock_shutdown):
        """Test manager shutdown."""
        mock_init.return_value = True

        # Register backend
        config = create_openai_config("gpt-4", "test_key")
        self.manager.register_llm("test_llm", config)

        # Shutdown
        self.manager.shutdown()

        assert len(self.manager.backends) == 0
        assert len(self.manager.configs) == 0
        assert self.manager.active_backend is None
        mock_shutdown.assert_called_once()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
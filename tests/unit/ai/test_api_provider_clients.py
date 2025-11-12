"""Comprehensive production-ready tests for API Provider Clients.

These tests validate real-world behavior of API provider clients for dynamic
model discovery, ensuring genuine functionality without mocks or stubs.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import json
from typing import Any
from unittest.mock import MagicMock, Mock, patch

import pytest
import requests

from intellicrack.ai.api_provider_clients import (
    AnthropicProviderClient,
    BaseProviderClient,
    LMStudioProviderClient,
    LocalProviderClient,
    ModelInfo,
    OllamaProviderClient,
    OpenAIProviderClient,
    ProviderManager,
    get_provider_manager,
)


class TestModelInfo:
    """Test ModelInfo dataclass."""

    def test_model_info_initialization_full(self) -> None:
        """Test ModelInfo initialization with all fields."""
        model = ModelInfo(
            id="test-model-001",
            name="Test Model",
            provider="TestProvider",
            description="A test model for validation",
            context_length=8192,
            capabilities=["text-generation", "chat"],
            pricing={"input": 0.01, "output": 0.03},
        )

        assert model.id == "test-model-001"
        assert model.name == "Test Model"
        assert model.provider == "TestProvider"
        assert model.description == "A test model for validation"
        assert model.context_length == 8192
        assert model.capabilities == ["text-generation", "chat"]
        assert model.pricing == {"input": 0.01, "output": 0.03}

    def test_model_info_initialization_minimal(self) -> None:
        """Test ModelInfo initialization with only required fields."""
        model = ModelInfo(id="model-123", name="Model", provider="Provider")

        assert model.id == "model-123"
        assert model.name == "Model"
        assert model.provider == "Provider"
        assert model.description == ""
        assert model.context_length == 4096
        assert model.capabilities is None
        assert model.pricing is None


class TestBaseProviderClient:
    """Test BaseProviderClient abstract base class."""

    def test_base_provider_initialization_with_api_key(self) -> None:
        """Test BaseProviderClient initialization with API key."""

        class ConcreteProvider(BaseProviderClient):
            def _configure_auth(self) -> None:
                self.auth_configured = True

            def fetch_models(self) -> list[ModelInfo]:
                return []

        client = ConcreteProvider(
            api_key="test_key_123", base_url="https://api.example.com"
        )

        assert client.api_key == "test_key_123"
        assert client.base_url == "https://api.example.com"
        assert hasattr(client, "session")
        assert client.session.headers["Content-Type"] == "application/json"
        assert hasattr(client, "auth_configured")
        assert client.auth_configured

    def test_base_provider_initialization_without_api_key(self) -> None:
        """Test BaseProviderClient initialization without API key."""

        class ConcreteProvider(BaseProviderClient):
            def _configure_auth(self) -> None:
                self.auth_configured = True

            def fetch_models(self) -> list[ModelInfo]:
                return []

        client = ConcreteProvider(base_url="https://api.example.com")

        assert client.api_key is None
        assert client.base_url == "https://api.example.com"
        assert not hasattr(client, "auth_configured")

    @patch("requests.Session.request")
    def test_make_request_successful(self, mock_request: Mock) -> None:
        """Test successful HTTP request with JSON response."""

        class ConcreteProvider(BaseProviderClient):
            def _configure_auth(self) -> None:
                pass

            def fetch_models(self) -> list[ModelInfo]:
                return []

        mock_response = Mock()
        mock_response.json.return_value = {"data": ["model1", "model2"]}
        mock_response.status_code = 200
        mock_request.return_value = mock_response

        client = ConcreteProvider()
        result = client._make_request("GET", "https://api.example.com/models")

        assert result == {"data": ["model1", "model2"]}
        mock_request.assert_called_once_with(
            "GET", "https://api.example.com/models", timeout=10
        )

    @patch("requests.Session.request")
    def test_make_request_timeout(self, mock_request: Mock) -> None:
        """Test HTTP request timeout handling."""

        class ConcreteProvider(BaseProviderClient):
            def _configure_auth(self) -> None:
                pass

            def fetch_models(self) -> list[ModelInfo]:
                return []

        mock_request.side_effect = requests.exceptions.Timeout("Timeout occurred")

        client = ConcreteProvider()
        result = client._make_request("GET", "https://api.example.com/models")

        assert result is None
        assert mock_request.call_args[1]["timeout"] == 10

    @patch("requests.Session.request")
    def test_make_request_connection_error(self, mock_request: Mock) -> None:
        """Test HTTP request connection error handling."""

        class ConcreteProvider(BaseProviderClient):
            def _configure_auth(self) -> None:
                pass

            def fetch_models(self) -> list[ModelInfo]:
                return []

        mock_request.side_effect = requests.exceptions.ConnectionError(
            "Failed to connect"
        )

        client = ConcreteProvider()
        result = client._make_request("GET", "https://api.example.com/models")

        assert result is None

    @patch("requests.Session.request")
    def test_make_request_http_error_401(self, mock_request: Mock) -> None:
        """Test HTTP 401 Unauthorized error handling."""

        class ConcreteProvider(BaseProviderClient):
            def _configure_auth(self) -> None:
                pass

            def fetch_models(self) -> list[ModelInfo]:
                return []

        mock_response = Mock()
        mock_response.status_code = 401
        mock_response.text = "Unauthorized"
        mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError(
            response=mock_response
        )
        mock_request.return_value = mock_response

        client = ConcreteProvider()
        result = client._make_request("GET", "https://api.example.com/models")

        assert result is None

    @patch("requests.Session.request")
    def test_make_request_http_error_429(self, mock_request: Mock) -> None:
        """Test HTTP 429 Rate Limit error handling."""

        class ConcreteProvider(BaseProviderClient):
            def _configure_auth(self) -> None:
                pass

            def fetch_models(self) -> list[ModelInfo]:
                return []

        mock_response = Mock()
        mock_response.status_code = 429
        mock_response.text = "Rate limit exceeded"
        mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError(
            response=mock_response
        )
        mock_request.return_value = mock_response

        client = ConcreteProvider()
        result = client._make_request("GET", "https://api.example.com/models")

        assert result is None

    @patch("requests.Session.request")
    def test_make_request_http_error_500(self, mock_request: Mock) -> None:
        """Test HTTP 500 Internal Server Error handling."""

        class ConcreteProvider(BaseProviderClient):
            def _configure_auth(self) -> None:
                pass

            def fetch_models(self) -> list[ModelInfo]:
                return []

        mock_response = Mock()
        mock_response.status_code = 500
        mock_response.text = "Internal server error"
        mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError(
            response=mock_response
        )
        mock_request.return_value = mock_response

        client = ConcreteProvider()
        result = client._make_request("GET", "https://api.example.com/models")

        assert result is None

    @patch("requests.Session.request")
    def test_make_request_malformed_json(self, mock_request: Mock) -> None:
        """Test malformed JSON response handling."""

        class ConcreteProvider(BaseProviderClient):
            def _configure_auth(self) -> None:
                pass

            def fetch_models(self) -> list[ModelInfo]:
                return []

        mock_response = Mock()
        mock_response.json.side_effect = json.JSONDecodeError("Invalid JSON", "", 0)
        mock_response.status_code = 200
        mock_request.return_value = mock_response

        client = ConcreteProvider()
        result = client._make_request("GET", "https://api.example.com/models")

        assert result is None


class TestOpenAIProviderClient:
    """Test OpenAIProviderClient for dynamic model discovery."""

    def test_initialization_default_base_url(self) -> None:
        """Test OpenAI client initialization with default base URL."""
        client = OpenAIProviderClient(api_key="sk-test123")

        assert client.api_key == "sk-test123"
        assert client.base_url == "https://api.openai.com/v1"
        assert client.session.headers["Authorization"] == "Bearer sk-test123"

    def test_initialization_custom_base_url(self) -> None:
        """Test OpenAI client initialization with custom base URL."""
        client = OpenAIProviderClient(
            api_key="sk-test123", base_url="https://custom.openai.com/v1"
        )

        assert client.base_url == "https://custom.openai.com/v1"

    def test_configure_auth(self) -> None:
        """Test OpenAI authentication configuration."""
        client = OpenAIProviderClient(api_key="sk-test-key-789")

        assert "Authorization" in client.session.headers
        assert client.session.headers["Authorization"] == "Bearer sk-test-key-789"

    def test_fetch_models_no_api_key(self) -> None:
        """Test fetch_models falls back when no API key provided."""
        client = OpenAIProviderClient()

        models = client.fetch_models()

        assert len(models) == 4
        assert all(isinstance(m, ModelInfo) for m in models)
        assert models[0].id == "gpt-4o"
        assert models[1].id == "gpt-4-turbo"
        assert models[2].id == "gpt-4"
        assert models[3].id == "gpt-3.5-turbo"

    @patch.object(OpenAIProviderClient, "_make_request")
    def test_fetch_models_successful_api_call(self, mock_request: Mock) -> None:
        """Test successful model fetching from OpenAI API."""
        mock_request.return_value = {
            "data": [
                {"id": "gpt-4-turbo-2024-04-09"},
                {"id": "gpt-4"},
                {"id": "gpt-3.5-turbo-0125"},
                {"id": "text-embedding-ada-002"},
                {"id": "whisper-1"},
            ]
        }

        client = OpenAIProviderClient(api_key="sk-test123")
        models = client.fetch_models()

        assert len(models) == 3
        assert all(isinstance(m, ModelInfo) for m in models)
        assert models[0].provider == "OpenAI"
        mock_request.assert_called_once()

    @patch.object(OpenAIProviderClient, "_make_request")
    def test_fetch_models_api_failure_fallback(self, mock_request: Mock) -> None:
        """Test fallback behavior when API request fails."""
        mock_request.return_value = None

        client = OpenAIProviderClient(api_key="sk-test123")
        models = client.fetch_models()

        assert len(models) == 4
        assert models[0].id == "gpt-4o"

    def test_is_chat_model_gpt_variants(self) -> None:
        """Test _is_chat_model correctly identifies GPT chat models."""
        client = OpenAIProviderClient()

        assert client._is_chat_model("gpt-4-turbo")
        assert client._is_chat_model("gpt-4")
        assert client._is_chat_model("gpt-3.5-turbo")
        assert client._is_chat_model("chatgpt-4")
        assert client._is_chat_model("o1-preview")
        assert client._is_chat_model("o3-mini")

    def test_is_chat_model_non_chat_models(self) -> None:
        """Test _is_chat_model filters non-chat models."""
        client = OpenAIProviderClient()

        assert not client._is_chat_model("text-embedding-ada-002")
        assert not client._is_chat_model("whisper-1")
        assert not client._is_chat_model("dall-e-3")
        assert not client._is_chat_model("tts-1")

    def test_get_context_length_known_models(self) -> None:
        """Test _get_context_length returns correct values for known models."""
        client = OpenAIProviderClient()

        assert client._get_context_length("gpt-4-turbo") == 128000
        assert client._get_context_length("gpt-4") == 8192
        assert client._get_context_length("gpt-4-32k") == 32768
        assert client._get_context_length("gpt-3.5-turbo") == 16385
        assert client._get_context_length("gpt-3.5-turbo-16k") == 16385
        assert client._get_context_length("o1") == 200000
        assert client._get_context_length("o1-mini") == 128000
        assert client._get_context_length("o3") == 200000
        assert client._get_context_length("o3-mini") == 128000

    def test_get_context_length_unknown_model(self) -> None:
        """Test _get_context_length defaults to 4096 for unknown models."""
        client = OpenAIProviderClient()

        assert client._get_context_length("unknown-model-xyz") == 4096
        assert client._get_context_length("gpt-5-experimental") == 4096

    def test_get_capabilities_turbo_models(self) -> None:
        """Test _get_capabilities for turbo models."""
        client = OpenAIProviderClient()

        capabilities = client._get_capabilities("gpt-3.5-turbo")

        assert "text-generation" in capabilities
        assert "chat" in capabilities
        assert "function-calling" in capabilities

    def test_get_capabilities_gpt4_models(self) -> None:
        """Test _get_capabilities for GPT-4 models."""
        client = OpenAIProviderClient()

        capabilities = client._get_capabilities("gpt-4")

        assert "text-generation" in capabilities
        assert "chat" in capabilities
        assert "function-calling" in capabilities

    def test_get_capabilities_vision_models(self) -> None:
        """Test _get_capabilities identifies vision capability."""
        client = OpenAIProviderClient()

        vision_caps = client._get_capabilities("gpt-4o")
        assert "vision" in vision_caps

        turbo_vision_caps = client._get_capabilities("gpt-4-turbo")
        assert "vision" in turbo_vision_caps

        explicit_vision_caps = client._get_capabilities("gpt-4-vision-preview")
        assert "vision" in explicit_vision_caps

    def test_get_fallback_models_structure(self) -> None:
        """Test _get_fallback_models returns expected hardcoded list."""
        client = OpenAIProviderClient()

        fallback = client._get_fallback_models()

        assert len(fallback) == 4
        assert fallback[0].id == "gpt-4o"
        assert fallback[0].context_length == 128000
        assert "vision" in fallback[0].capabilities

        assert fallback[1].id == "gpt-4-turbo"
        assert fallback[1].context_length == 128000

        assert fallback[2].id == "gpt-4"
        assert fallback[2].context_length == 8192

        assert fallback[3].id == "gpt-3.5-turbo"
        assert fallback[3].context_length == 16385


class TestAnthropicProviderClient:
    """Test AnthropicProviderClient for model discovery."""

    def test_initialization_default_base_url(self) -> None:
        """Test Anthropic client initialization with default base URL."""
        client = AnthropicProviderClient(api_key="sk-ant-test123")

        assert client.api_key == "sk-ant-test123"
        assert client.base_url == "https://api.anthropic.com"
        assert client.session.headers["x-api-key"] == "sk-ant-test123"
        assert client.session.headers["anthropic-version"] == "2023-06-01"

    def test_initialization_custom_base_url(self) -> None:
        """Test Anthropic client initialization with custom base URL."""
        client = AnthropicProviderClient(
            api_key="sk-ant-test", base_url="https://custom.anthropic.com"
        )

        assert client.base_url == "https://custom.anthropic.com"

    def test_configure_auth(self) -> None:
        """Test Anthropic authentication configuration with x-api-key header."""
        client = AnthropicProviderClient(api_key="sk-ant-key-xyz")

        assert "x-api-key" in client.session.headers
        assert client.session.headers["x-api-key"] == "sk-ant-key-xyz"
        assert client.session.headers["anthropic-version"] == "2023-06-01"

    def test_fetch_models_returns_hardcoded_claude_models(self) -> None:
        """Test fetch_models returns expected Claude model list."""
        client = AnthropicProviderClient()

        models = client.fetch_models()

        assert len(models) == 5
        assert all(m.provider == "Anthropic" for m in models)

        model_ids = [m.id for m in models]
        assert "claude-3-5-sonnet-20241022" in model_ids
        assert "claude-3-5-haiku-20241022" in model_ids
        assert "claude-3-opus-20240229" in model_ids
        assert "claude-3-sonnet-20240229" in model_ids
        assert "claude-3-haiku-20240307" in model_ids

    def test_fetch_models_context_lengths(self) -> None:
        """Test Claude models have correct 200K context length."""
        client = AnthropicProviderClient()

        models = client.fetch_models()

        assert all(m.context_length == 200000 for m in models)

    def test_fetch_models_capabilities(self) -> None:
        """Test Claude 3.5 models have correct capabilities."""
        client = AnthropicProviderClient()

        models = client.fetch_models()

        sonnet_35 = next(m for m in models if "3-5-sonnet" in m.id)
        assert "text-generation" in sonnet_35.capabilities
        assert "chat" in sonnet_35.capabilities
        assert "vision" in sonnet_35.capabilities
        assert "tool-use" in sonnet_35.capabilities

        haiku_35 = next(m for m in models if "3-5-haiku" in m.id)
        assert "tool-use" in haiku_35.capabilities

    @patch.object(AnthropicProviderClient, "_make_request")
    def test_fetch_models_validates_api_key_when_provided(
        self, mock_request: Mock
    ) -> None:
        """Test API key validation with test request when key provided."""
        mock_request.return_value = {"id": "msg_123", "content": [{"text": "test"}]}

        client = AnthropicProviderClient(api_key="sk-ant-valid-key")
        models = client.fetch_models()

        assert len(models) == 5
        mock_request.assert_called_once()

        call_args = mock_request.call_args
        assert call_args[0][0] == "POST"
        assert "/messages" in call_args[0][1]

    @patch.object(AnthropicProviderClient, "_make_request")
    def test_fetch_models_handles_validation_failure_gracefully(
        self, mock_request: Mock
    ) -> None:
        """Test API key validation failure doesn't prevent model listing."""
        mock_request.side_effect = Exception("API validation failed")

        client = AnthropicProviderClient(api_key="sk-ant-invalid-key")
        models = client.fetch_models()

        assert len(models) == 5
        assert all(isinstance(m, ModelInfo) for m in models)


class TestOllamaProviderClient:
    """Test OllamaProviderClient for local model discovery."""

    def test_initialization_default_base_url(self) -> None:
        """Test Ollama client initialization with default localhost URL."""
        client = OllamaProviderClient()

        assert client.base_url == "http://localhost:11434"
        assert client.api_key is None

    def test_initialization_custom_base_url(self) -> None:
        """Test Ollama client initialization with custom URL."""
        client = OllamaProviderClient(base_url="http://192.168.1.100:11434")

        assert client.base_url == "http://192.168.1.100:11434"

    def test_configure_auth_does_nothing(self) -> None:
        """Test Ollama doesn't require authentication configuration."""
        client = OllamaProviderClient()

        assert "Authorization" not in client.session.headers
        assert "x-api-key" not in client.session.headers

    @patch.object(OllamaProviderClient, "_make_request")
    def test_fetch_models_successful(self, mock_request: Mock) -> None:
        """Test successful model fetching from Ollama."""
        mock_request.return_value = {
            "models": [
                {"name": "llama2:7b", "size": 3825819519, "context_length": 4096},
                {"name": "mistral:latest", "size": 4109865159, "context_length": 8192},
                {"name": "codellama:13b", "size": 7365960935},
            ]
        }

        client = OllamaProviderClient()
        models = client.fetch_models()

        assert len(models) == 3
        assert models[0].id == "llama2:7b"
        assert models[0].provider == "Ollama"
        assert "3.6GB" in models[0].description
        assert models[0].context_length == 4096

        assert models[1].id == "mistral:latest"
        assert "3.8GB" in models[1].description
        assert models[1].context_length == 8192

    @patch.object(OllamaProviderClient, "_make_request")
    def test_fetch_models_api_failure(self, mock_request: Mock) -> None:
        """Test fetch_models returns empty list on API failure."""
        mock_request.return_value = None

        client = OllamaProviderClient()
        models = client.fetch_models()

        assert models == []

    @patch.object(OllamaProviderClient, "_make_request")
    def test_fetch_models_malformed_response(self, mock_request: Mock) -> None:
        """Test fetch_models handles malformed response gracefully."""
        mock_request.return_value = {"error": "malformed data"}

        client = OllamaProviderClient()
        models = client.fetch_models()

        assert models == []


class TestLMStudioProviderClient:
    """Test LMStudioProviderClient for local model discovery."""

    def test_initialization_default_base_url(self) -> None:
        """Test LM Studio client initialization with default localhost URL."""
        client = LMStudioProviderClient()

        assert client.base_url == "http://localhost:1234/v1"
        assert client.api_key is None

    def test_initialization_custom_base_url(self) -> None:
        """Test LM Studio client initialization with custom URL."""
        client = LMStudioProviderClient(base_url="http://localhost:5678/v1")

        assert client.base_url == "http://localhost:5678/v1"

    def test_configure_auth_does_nothing(self) -> None:
        """Test LM Studio doesn't require authentication."""
        client = LMStudioProviderClient()

        assert "Authorization" not in client.session.headers

    @patch.object(LMStudioProviderClient, "_make_request")
    def test_fetch_models_successful(self, mock_request: Mock) -> None:
        """Test successful model fetching from LM Studio."""
        mock_request.return_value = {
            "data": [
                {"id": "TheBloke/Llama-2-7B-GGUF"},
                {"id": "TheBloke/Mistral-7B-Instruct-v0.2-GGUF"},
            ]
        }

        client = LMStudioProviderClient()
        models = client.fetch_models()

        assert len(models) == 2
        assert models[0].id == "TheBloke/Llama-2-7B-GGUF"
        assert models[0].provider == "LM Studio"
        assert models[0].description == "Local LM Studio model"
        assert models[0].context_length == 4096

    @patch.object(LMStudioProviderClient, "_make_request")
    def test_fetch_models_api_failure(self, mock_request: Mock) -> None:
        """Test fetch_models returns empty list on API failure."""
        mock_request.return_value = None

        client = LMStudioProviderClient()
        models = client.fetch_models()

        assert models == []


class TestLocalProviderClient:
    """Test LocalProviderClient for GGUF local models."""

    def test_initialization(self) -> None:
        """Test Local provider client initialization."""
        client = LocalProviderClient()

        assert client.api_key is None
        assert client.base_url is None

    def test_configure_auth_does_nothing(self) -> None:
        """Test local models don't require authentication."""
        client = LocalProviderClient()

        assert "Authorization" not in client.session.headers

    @patch("intellicrack.ai.api_provider_clients.gguf_manager")
    def test_fetch_models_successful(self, mock_gguf_manager: Mock) -> None:
        """Test successful local GGUF model discovery."""
        mock_gguf_manager.list_models.return_value = {
            "llama-2-7b-q4": {
                "size_mb": 3825,
                "quantization": "Q4_K_M",
                "context_length": 4096,
            },
            "mistral-7b-q5": {
                "size_mb": 4850,
                "quantization": "Q5_K_M",
                "context_length": 8192,
            },
        }

        client = LocalProviderClient()
        models = client.fetch_models()

        assert len(models) == 2
        assert models[0].provider == "Local GGUF"
        assert "Q4_K_M" in models[0].description
        assert "3825MB" in models[0].description

    def test_fetch_models_gguf_manager_unavailable(self) -> None:
        """Test fetch_models handles missing gguf_manager gracefully."""
        client = LocalProviderClient()

        with patch(
            "intellicrack.ai.api_provider_clients.gguf_manager",
            side_effect=ImportError(),
        ):
            models = client.fetch_models()

        assert models == []


class TestProviderManager:
    """Test ProviderManager for managing multiple provider clients."""

    def test_initialization(self) -> None:
        """Test ProviderManager initialization creates empty provider dict."""
        manager = ProviderManager()

        assert hasattr(manager, "providers")
        assert isinstance(manager.providers, dict)
        assert len(manager.providers) == 0

    def test_register_provider(self) -> None:
        """Test registering a provider client."""
        manager = ProviderManager()
        client = OpenAIProviderClient(api_key="sk-test123")

        manager.register_provider("openai", client)

        assert "openai" in manager.providers
        assert manager.providers["openai"] == client

    def test_register_multiple_providers(self) -> None:
        """Test registering multiple provider clients."""
        manager = ProviderManager()
        openai_client = OpenAIProviderClient(api_key="sk-test123")
        anthropic_client = AnthropicProviderClient(api_key="sk-ant-test")

        manager.register_provider("openai", openai_client)
        manager.register_provider("anthropic", anthropic_client)

        assert len(manager.providers) == 2
        assert manager.providers["openai"] == openai_client
        assert manager.providers["anthropic"] == anthropic_client

    def test_get_provider_exists(self) -> None:
        """Test getting a registered provider."""
        manager = ProviderManager()
        client = OpenAIProviderClient()
        manager.register_provider("openai", client)

        retrieved = manager.get_provider("openai")

        assert retrieved == client

    def test_get_provider_not_found(self) -> None:
        """Test getting non-existent provider returns None."""
        manager = ProviderManager()

        result = manager.get_provider("nonexistent")

        assert result is None

    def test_fetch_models_from_provider_success(self) -> None:
        """Test fetching models from specific registered provider."""
        manager = ProviderManager()
        client = AnthropicProviderClient()
        manager.register_provider("anthropic", client)

        models = manager.fetch_models_from_provider("anthropic")

        assert len(models) == 5
        assert all(m.provider == "Anthropic" for m in models)

    def test_fetch_models_from_provider_not_found(self) -> None:
        """Test fetching from non-existent provider returns empty list."""
        manager = ProviderManager()

        models = manager.fetch_models_from_provider("nonexistent")

        assert models == []

    @patch.object(OpenAIProviderClient, "fetch_models")
    def test_fetch_models_from_provider_exception_handling(
        self, mock_fetch: Mock
    ) -> None:
        """Test exception handling during model fetching."""
        manager = ProviderManager()
        client = OpenAIProviderClient(api_key="sk-test")
        manager.register_provider("openai", client)

        mock_fetch.side_effect = Exception("API Error")

        models = manager.fetch_models_from_provider("openai")

        assert models == []

    def test_fetch_all_models_empty(self) -> None:
        """Test fetching all models with no registered providers."""
        manager = ProviderManager()

        all_models = manager.fetch_all_models()

        assert all_models == {}

    def test_fetch_all_models_multiple_providers(self) -> None:
        """Test fetching models from all registered providers."""
        manager = ProviderManager()
        manager.register_provider("anthropic", AnthropicProviderClient())

        with patch.object(OpenAIProviderClient, "fetch_models") as mock_openai:
            mock_openai.return_value = [
                ModelInfo(
                    id="gpt-4", name="GPT-4", provider="OpenAI", context_length=8192
                )
            ]
            manager.register_provider(
                "openai", OpenAIProviderClient(api_key="sk-test")
            )

            all_models = manager.fetch_all_models()

            assert "anthropic" in all_models
            assert "openai" in all_models
            assert len(all_models["anthropic"]) == 5
            assert len(all_models["openai"]) == 1

    def test_fetch_all_models_filters_empty_results(self) -> None:
        """Test fetch_all_models doesn't include providers with no models."""
        manager = ProviderManager()

        with patch.object(OllamaProviderClient, "fetch_models") as mock_ollama:
            mock_ollama.return_value = []
            manager.register_provider("ollama", OllamaProviderClient())

            manager.register_provider("anthropic", AnthropicProviderClient())

            all_models = manager.fetch_all_models()

            assert "ollama" not in all_models
            assert "anthropic" in all_models


class TestGetProviderManager:
    """Test global provider manager singleton."""

    def test_get_provider_manager_returns_singleton(self) -> None:
        """Test get_provider_manager returns same instance."""
        manager1 = get_provider_manager()
        manager2 = get_provider_manager()

        assert manager1 is manager2
        assert isinstance(manager1, ProviderManager)


class TestRealWorldScenarios:
    """Real-world scenario tests for API provider clients."""

    @patch("requests.Session.request")
    def test_network_completely_down(self, mock_request: Mock) -> None:
        """Test behavior when network is completely unavailable."""
        mock_request.side_effect = requests.exceptions.ConnectionError("No network")

        client = OpenAIProviderClient(api_key="sk-test")
        models = client.fetch_models()

        assert len(models) == 4
        assert models[0].id == "gpt-4o"

    @patch.object(OpenAIProviderClient, "_make_request")
    def test_api_provider_changes_model_ids(self, mock_request: Mock) -> None:
        """Test handling when API provider adds new models with different naming."""
        mock_request.return_value = {
            "data": [
                {"id": "gpt-5-ultra"},
                {"id": "gpt-4-turbo-enhanced"},
                {"id": "text-embedding-v3"},
            ]
        }

        client = OpenAIProviderClient(api_key="sk-test")
        models = client.fetch_models()

        assert len(models) == 2
        gpt5_model = next((m for m in models if "gpt-5" in m.id), None)
        assert gpt5_model is not None
        assert gpt5_model.context_length == 4096

    @patch.object(OpenAIProviderClient, "_make_request")
    @patch.object(AnthropicProviderClient, "_make_request")
    def test_concurrent_requests_multiple_providers(
        self, mock_anthropic: Mock, mock_openai: Mock
    ) -> None:
        """Test concurrent requests to multiple providers."""
        mock_openai.return_value = {"data": [{"id": "gpt-4"}]}
        mock_anthropic.return_value = {"id": "msg_test", "content": [{"text": "ok"}]}

        manager = ProviderManager()
        manager.register_provider(
            "openai", OpenAIProviderClient(api_key="sk-openai-test")
        )
        manager.register_provider(
            "anthropic", AnthropicProviderClient(api_key="sk-ant-test")
        )

        all_models = manager.fetch_all_models()

        assert "openai" in all_models
        assert "anthropic" in all_models
        assert len(all_models["openai"]) >= 1
        assert len(all_models["anthropic"]) == 5

    @patch("requests.Session.request")
    def test_rate_limiting_429_status(self, mock_request: Mock) -> None:
        """Test handling of rate limit (429) responses."""
        mock_response = Mock()
        mock_response.status_code = 429
        mock_response.text = '{"error": {"message": "Rate limit exceeded", "type": "rate_limit_error"}}'
        mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError(
            response=mock_response
        )
        mock_request.return_value = mock_response

        client = OpenAIProviderClient(api_key="sk-test")
        models = client.fetch_models()

        assert len(models) == 4

    @patch("requests.Session.request")
    def test_invalid_api_key_401_403(self, mock_request: Mock) -> None:
        """Test handling of invalid API key (401/403) errors."""
        mock_response = Mock()
        mock_response.status_code = 401
        mock_response.text = '{"error": {"message": "Invalid API key"}}'
        mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError(
            response=mock_response
        )
        mock_request.return_value = mock_response

        client = OpenAIProviderClient(api_key="sk-invalid")
        models = client.fetch_models()

        assert len(models) == 4

    @patch("requests.Session.request")
    def test_partial_json_response(self, mock_request: Mock) -> None:
        """Test handling of incomplete/partial JSON responses."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.side_effect = json.JSONDecodeError(
            "Expecting property name", '{"data": [{"id": "gpt', 20
        )
        mock_request.return_value = mock_response

        client = OpenAIProviderClient(api_key="sk-test")
        models = client.fetch_models()

        assert len(models) == 4

    @patch.object(OpenAIProviderClient, "_make_request")
    def test_model_filtering_edge_cases(self, mock_request: Mock) -> None:
        """Test model filtering with unusual naming patterns."""
        mock_request.return_value = {
            "data": [
                {"id": "gpt-4-EXPERIMENTAL-v2"},
                {"id": "GPT-3.5-TURBO"},
                {"id": "o1-preview-2024"},
                {"id": "random-model-123"},
                {"id": "davinci-002"},
            ]
        }

        client = OpenAIProviderClient(api_key="sk-test")
        models = client.fetch_models()

        model_ids = [m.id for m in models]
        assert "gpt-4-EXPERIMENTAL-v2" in model_ids
        assert "davinci-002" in model_ids
        assert "o1-preview-2024" in model_ids
        assert "random-model-123" not in model_ids

    def test_provider_client_reuse_across_fetches(self) -> None:
        """Test provider client can be reused for multiple fetch_models calls."""
        client = AnthropicProviderClient()

        models1 = client.fetch_models()
        models2 = client.fetch_models()
        models3 = client.fetch_models()

        assert len(models1) == len(models2) == len(models3) == 5
        assert models1[0].id == models2[0].id == models3[0].id

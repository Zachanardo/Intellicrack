"""Comprehensive production-ready tests for API Provider Clients.

These tests validate real-world behavior of API provider clients for dynamic
model discovery, ensuring genuine functionality without mocks or stubs.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import json
from typing import Any

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


class FakeHTTPResponse:
    """Real HTTP response class for testing."""

    def __init__(
        self,
        json_data: dict[str, Any] | None = None,
        status_code: int = 200,
        text: str = "",
        raise_exception: Exception | None = None,
    ) -> None:
        self._json_data = json_data
        self.status_code = status_code
        self.text = text
        self._raise_exception = raise_exception

    def json(self) -> dict[str, Any]:
        if self._raise_exception:
            raise self._raise_exception
        if self._json_data is None:
            raise json.JSONDecodeError("Invalid JSON", "", 0)
        return self._json_data

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            http_error = requests.exceptions.HTTPError(response=self)
            raise http_error


class FakeHTTPSession:
    """Real HTTP session replacement for testing."""

    def __init__(self) -> None:
        self.headers: dict[str, str] = {}
        self._response_queue: list[FakeHTTPResponse | Exception] = []
        self._request_log: list[tuple[str, str, dict[str, Any]]] = []

    def update(self, headers: dict[str, str]) -> None:
        self.headers.update(headers)

    def set_next_response(self, response: FakeHTTPResponse | Exception) -> None:
        """Configure the next response to return."""
        self._response_queue.append(response)

    def request(
        self, method: str, url: str, timeout: int = 10, **kwargs: Any
    ) -> FakeHTTPResponse:
        """Simulate HTTP request with configured responses."""
        self._request_log.append((method, url, kwargs))

        if not self._response_queue:
            return FakeHTTPResponse(json_data={}, status_code=200)

        response_or_exception = self._response_queue.pop(0)
        if isinstance(response_or_exception, Exception):
            raise response_or_exception
        return response_or_exception

    def get_request_log(self) -> list[tuple[str, str, dict[str, Any]]]:
        """Get log of all requests made."""
        return self._request_log


class TestableProviderClient(BaseProviderClient):
    """Concrete provider client for testing base functionality."""

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str | None = None,
        configure_auth_enabled: bool = True,
    ) -> None:
        self.configure_auth_enabled = configure_auth_enabled
        self.auth_configured = False
        super().__init__(api_key, base_url)

    def _configure_auth(self) -> None:
        if self.configure_auth_enabled:
            self.auth_configured = True

    def fetch_models(self) -> list[ModelInfo]:
        return []


class TestableOpenAIClient(OpenAIProviderClient):
    """OpenAI client with injectable HTTP session for testing."""

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str | None = None,
        fake_session: FakeHTTPSession | None = None,
    ) -> None:
        super().__init__(api_key, base_url)
        if fake_session:
            self.session = fake_session  # type: ignore


class TestableAnthropicClient(AnthropicProviderClient):
    """Anthropic client with injectable HTTP session for testing."""

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str | None = None,
        fake_session: FakeHTTPSession | None = None,
    ) -> None:
        super().__init__(api_key, base_url)
        if fake_session:
            self.session = fake_session  # type: ignore


class TestableOllamaClient(OllamaProviderClient):
    """Ollama client with injectable HTTP session for testing."""

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str | None = None,
        fake_session: FakeHTTPSession | None = None,
    ) -> None:
        super().__init__(api_key, base_url)
        if fake_session:
            self.session = fake_session  # type: ignore


class TestableLMStudioClient(LMStudioProviderClient):
    """LM Studio client with injectable HTTP session for testing."""

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str | None = None,
        fake_session: FakeHTTPSession | None = None,
    ) -> None:
        super().__init__(api_key, base_url)
        if fake_session:
            self.session = fake_session  # type: ignore


class FakeGGUFManager:
    """Real GGUF manager replacement for testing."""

    def __init__(self, models: dict[str, dict[str, Any]]) -> None:
        self._models = models

    def list_models(self) -> dict[str, dict[str, Any]]:
        return self._models


class TestModelInfo:
    """Test ModelInfo dataclass."""

    def test_model_info_initialization_full(self) -> None:
        """ModelInfo initializes correctly with all fields provided."""
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
        """ModelInfo initializes correctly with only required fields."""
        model = ModelInfo(id="model-123", name="Model", provider="Provider")

        assert model.id == "model-123"
        assert model.name == "Model"
        assert model.provider == "Provider"
        assert model.description == ""
        assert model.context_length == 4096
        assert model.capabilities is None
        assert model.pricing is None

    def test_model_info_equality(self) -> None:
        """ModelInfo instances compare correctly."""
        model1 = ModelInfo(id="test", name="Test", provider="Provider")
        model2 = ModelInfo(id="test", name="Test", provider="Provider")

        assert model1 == model2

    def test_model_info_with_complex_capabilities(self) -> None:
        """ModelInfo handles complex capability lists correctly."""
        model = ModelInfo(
            id="advanced-model",
            name="Advanced",
            provider="Provider",
            capabilities=[
                "text-generation",
                "chat",
                "vision",
                "tool-use",
                "function-calling",
            ],
        )

        assert len(model.capabilities) == 5
        assert "vision" in model.capabilities
        assert "tool-use" in model.capabilities


class TestBaseProviderClient:
    """Test BaseProviderClient abstract base class."""

    def test_base_provider_initialization_with_api_key(self) -> None:
        """BaseProviderClient initializes correctly with API key."""
        client = TestableProviderClient(
            api_key="test_key_123", base_url="https://api.example.com"
        )

        assert client.api_key == "test_key_123"
        assert client.base_url == "https://api.example.com"
        assert hasattr(client, "session")
        assert client.session.headers["Content-Type"] == "application/json"
        assert client.auth_configured

    def test_base_provider_initialization_without_api_key(self) -> None:
        """BaseProviderClient initializes correctly without API key."""
        client = TestableProviderClient(base_url="https://api.example.com")

        assert client.api_key is None
        assert client.base_url == "https://api.example.com"
        assert not client.auth_configured

    def test_base_provider_session_headers_configured(self) -> None:
        """BaseProviderClient configures session headers correctly."""
        client = TestableProviderClient()

        assert "Content-Type" in client.session.headers
        assert client.session.headers["Content-Type"] == "application/json"

    def test_make_request_successful_json_response(self) -> None:
        """_make_request returns JSON data on successful response."""
        client = TestableProviderClient()
        fake_session = FakeHTTPSession()
        fake_session.set_next_response(
            FakeHTTPResponse(json_data={"data": ["model1", "model2"]}, status_code=200)
        )
        client.session = fake_session  # type: ignore

        result = client._make_request("GET", "https://api.example.com/models")

        assert result == {"data": ["model1", "model2"]}
        log = fake_session.get_request_log()
        assert len(log) == 1
        assert log[0][0] == "GET"
        assert log[0][1] == "https://api.example.com/models"

    def test_make_request_timeout_returns_none(self) -> None:
        """_make_request returns None on timeout."""
        client = TestableProviderClient()
        fake_session = FakeHTTPSession()
        fake_session.set_next_response(
            requests.exceptions.Timeout("Timeout occurred")
        )
        client.session = fake_session  # type: ignore

        result = client._make_request("GET", "https://api.example.com/models")

        assert result is None

    def test_make_request_connection_error_returns_none(self) -> None:
        """_make_request returns None on connection error."""
        client = TestableProviderClient()
        fake_session = FakeHTTPSession()
        fake_session.set_next_response(
            requests.exceptions.ConnectionError("Failed to connect")
        )
        client.session = fake_session  # type: ignore

        result = client._make_request("GET", "https://api.example.com/models")

        assert result is None

    def test_make_request_http_error_401_returns_none(self) -> None:
        """_make_request returns None on 401 Unauthorized."""
        client = TestableProviderClient()
        fake_session = FakeHTTPSession()
        fake_session.set_next_response(
            FakeHTTPResponse(status_code=401, text="Unauthorized")
        )
        client.session = fake_session  # type: ignore

        result = client._make_request("GET", "https://api.example.com/models")

        assert result is None

    def test_make_request_http_error_429_returns_none(self) -> None:
        """_make_request returns None on 429 Rate Limit."""
        client = TestableProviderClient()
        fake_session = FakeHTTPSession()
        fake_session.set_next_response(
            FakeHTTPResponse(status_code=429, text="Rate limit exceeded")
        )
        client.session = fake_session  # type: ignore

        result = client._make_request("GET", "https://api.example.com/models")

        assert result is None

    def test_make_request_http_error_500_returns_none(self) -> None:
        """_make_request returns None on 500 Internal Server Error."""
        client = TestableProviderClient()
        fake_session = FakeHTTPSession()
        fake_session.set_next_response(
            FakeHTTPResponse(status_code=500, text="Internal server error")
        )
        client.session = fake_session  # type: ignore

        result = client._make_request("GET", "https://api.example.com/models")

        assert result is None

    def test_make_request_malformed_json_returns_none(self) -> None:
        """_make_request returns None on malformed JSON."""
        client = TestableProviderClient()
        fake_session = FakeHTTPSession()
        fake_session.set_next_response(
            FakeHTTPResponse(
                raise_exception=json.JSONDecodeError("Invalid JSON", "", 0),
                status_code=200,
            )
        )
        client.session = fake_session  # type: ignore

        result = client._make_request("GET", "https://api.example.com/models")

        assert result is None

    def test_make_request_includes_timeout_parameter(self) -> None:
        """_make_request includes timeout parameter in request."""
        client = TestableProviderClient()
        fake_session = FakeHTTPSession()
        fake_session.set_next_response(FakeHTTPResponse(json_data={}, status_code=200))
        client.session = fake_session  # type: ignore

        client._make_request("GET", "https://api.example.com/models")

        log = fake_session.get_request_log()
        assert log[0][2].get("timeout") == 10


class TestOpenAIProviderClient:
    """Test OpenAIProviderClient for dynamic model discovery."""

    def test_initialization_default_base_url(self) -> None:
        """OpenAI client initializes with correct default base URL."""
        client = OpenAIProviderClient(api_key="sk-test123")

        assert client.api_key == "sk-test123"
        assert client.base_url == "https://api.openai.com/v1"
        assert client.session.headers["Authorization"] == "Bearer sk-test123"

    def test_initialization_custom_base_url(self) -> None:
        """OpenAI client accepts custom base URL."""
        client = OpenAIProviderClient(
            api_key="sk-test123", base_url="https://custom.openai.com/v1"
        )

        assert client.base_url == "https://custom.openai.com/v1"

    def test_configure_auth_sets_bearer_token(self) -> None:
        """OpenAI client configures Bearer authentication correctly."""
        client = OpenAIProviderClient(api_key="sk-test-key-789")

        assert "Authorization" in client.session.headers
        assert client.session.headers["Authorization"] == "Bearer sk-test-key-789"

    def test_fetch_models_no_api_key_returns_fallback(self) -> None:
        """fetch_models returns fallback models when no API key provided."""
        client = OpenAIProviderClient()

        models = client.fetch_models()

        assert len(models) == 2
        assert all(isinstance(m, ModelInfo) for m in models)
        assert models[0].id == "gpt-4o"
        assert models[1].id == "gpt-4-turbo"

    def test_fetch_models_successful_api_call_filters_chat_models(self) -> None:
        """fetch_models successfully fetches and filters chat models from API."""
        fake_session = FakeHTTPSession()
        fake_session.set_next_response(
            FakeHTTPResponse(
                json_data={
                    "data": [
                        {"id": "gpt-4-turbo-2024-04-09"},
                        {"id": "gpt-4"},
                        {"id": "gpt-3.5-turbo-0125"},
                        {"id": "text-embedding-ada-002"},
                        {"id": "whisper-1"},
                    ]
                }
            )
        )

        client = TestableOpenAIClient(api_key="sk-test123", fake_session=fake_session)
        models = client.fetch_models()

        assert len(models) == 3
        assert all(isinstance(m, ModelInfo) for m in models)
        assert all(m.provider == "OpenAI" for m in models)
        model_ids = [m.id for m in models]
        assert "gpt-4" in model_ids
        assert "gpt-4-turbo-2024-04-09" in model_ids
        assert "gpt-3.5-turbo-0125" in model_ids
        assert "text-embedding-ada-002" not in model_ids
        assert "whisper-1" not in model_ids

    def test_fetch_models_api_failure_uses_fallback(self) -> None:
        """fetch_models uses fallback on API failure."""
        fake_session = FakeHTTPSession()
        fake_session.set_next_response(
            requests.exceptions.ConnectionError("No connection")
        )

        client = TestableOpenAIClient(api_key="sk-test123", fake_session=fake_session)
        models = client.fetch_models()

        assert len(models) == 2
        assert models[0].id == "gpt-4o"

    def test_fetch_models_malformed_response_uses_fallback(self) -> None:
        """fetch_models uses fallback on malformed API response."""
        fake_session = FakeHTTPSession()
        fake_session.set_next_response(
            FakeHTTPResponse(json_data={"error": "invalid"})
        )

        client = TestableOpenAIClient(api_key="sk-test123", fake_session=fake_session)
        models = client.fetch_models()

        assert len(models) == 2

    def test_is_chat_model_identifies_gpt_variants(self) -> None:
        """_is_chat_model correctly identifies GPT chat models."""
        client = OpenAIProviderClient()

        assert client._is_chat_model("gpt-4-turbo")
        assert client._is_chat_model("gpt-4")
        assert client._is_chat_model("gpt-3.5-turbo")
        assert client._is_chat_model("chatgpt-4")
        assert client._is_chat_model("o1-preview")
        assert client._is_chat_model("o3-mini")

    def test_is_chat_model_filters_non_chat_models(self) -> None:
        """_is_chat_model filters non-chat models correctly."""
        client = OpenAIProviderClient()

        assert not client._is_chat_model("text-embedding-ada-002")
        assert not client._is_chat_model("whisper-1")
        assert not client._is_chat_model("dall-e-3")
        assert not client._is_chat_model("tts-1")

    def test_infer_capabilities_turbo_models(self) -> None:
        """_infer_capabilities includes function-calling for turbo models."""
        client = OpenAIProviderClient()

        capabilities = client._infer_capabilities("gpt-3.5-turbo")

        assert "text-generation" in capabilities
        assert "chat" in capabilities
        assert "function-calling" in capabilities

    def test_infer_capabilities_gpt4_models(self) -> None:
        """_infer_capabilities includes function-calling for GPT-4 models."""
        client = OpenAIProviderClient()

        capabilities = client._infer_capabilities("gpt-4")

        assert "text-generation" in capabilities
        assert "chat" in capabilities
        assert "function-calling" in capabilities

    def test_infer_capabilities_vision_models(self) -> None:
        """_infer_capabilities identifies vision capability correctly."""
        client = OpenAIProviderClient()

        vision_caps = client._infer_capabilities("gpt-4o")
        assert "vision" in vision_caps

        turbo_vision_caps = client._infer_capabilities("gpt-4-turbo")
        assert "vision" in turbo_vision_caps

        explicit_vision_caps = client._infer_capabilities("gpt-4-vision-preview")
        assert "vision" in explicit_vision_caps

    def test_get_fallback_models_structure(self) -> None:
        """_get_fallback_models returns expected hardcoded models."""
        client = OpenAIProviderClient()

        fallback = client._get_fallback_models()

        assert len(fallback) == 2
        assert fallback[0].id == "gpt-4o"
        assert fallback[0].context_length == 128000
        assert "vision" in fallback[0].capabilities

        assert fallback[1].id == "gpt-4-turbo"
        assert fallback[1].context_length == 128000

    def test_fetch_models_sorts_results(self) -> None:
        """fetch_models sorts model list by ID."""
        fake_session = FakeHTTPSession()
        fake_session.set_next_response(
            FakeHTTPResponse(
                json_data={
                    "data": [
                        {"id": "gpt-4"},
                        {"id": "gpt-3.5-turbo"},
                        {"id": "gpt-4-turbo"},
                    ]
                }
            )
        )

        client = TestableOpenAIClient(api_key="sk-test", fake_session=fake_session)
        models = client.fetch_models()

        model_ids = [m.id for m in models]
        assert model_ids == sorted(model_ids)


class TestAnthropicProviderClient:
    """Test AnthropicProviderClient for model discovery."""

    def test_initialization_default_base_url(self) -> None:
        """Anthropic client initializes with correct default base URL."""
        client = AnthropicProviderClient(api_key="sk-ant-test123")

        assert client.api_key == "sk-ant-test123"
        assert client.base_url == "https://api.anthropic.com"
        assert client.session.headers["x-api-key"] == "sk-ant-test123"
        assert client.session.headers["anthropic-version"] == "2023-06-01"

    def test_initialization_custom_base_url(self) -> None:
        """Anthropic client accepts custom base URL."""
        client = AnthropicProviderClient(
            api_key="sk-ant-test", base_url="https://custom.anthropic.com"
        )

        assert client.base_url == "https://custom.anthropic.com"

    def test_configure_auth_sets_x_api_key_header(self) -> None:
        """Anthropic client configures x-api-key authentication correctly."""
        client = AnthropicProviderClient(api_key="sk-ant-key-xyz")

        assert "x-api-key" in client.session.headers
        assert client.session.headers["x-api-key"] == "sk-ant-key-xyz"
        assert client.session.headers["anthropic-version"] == "2023-06-01"

    def test_fetch_models_no_api_key_returns_fallback(self) -> None:
        """fetch_models returns fallback models when no API key provided."""
        client = AnthropicProviderClient()

        models = client.fetch_models()

        assert len(models) == 2
        assert all(m.provider == "Anthropic" for m in models)

        model_ids = [m.id for m in models]
        assert "claude-3-5-sonnet-20241022" in model_ids
        assert "claude-3-5-haiku-20241022" in model_ids

    def test_fetch_models_successful_api_call(self) -> None:
        """fetch_models successfully fetches models from API."""
        fake_session = FakeHTTPSession()
        fake_session.set_next_response(
            FakeHTTPResponse(
                json_data={
                    "data": [
                        {
                            "id": "claude-3-5-sonnet-20241022",
                            "display_name": "Claude 3.5 Sonnet",
                        },
                        {
                            "id": "claude-3-opus-20240229",
                            "display_name": "Claude 3 Opus",
                        },
                        {
                            "id": "claude-3-haiku-20240307",
                            "display_name": "Claude 3 Haiku",
                        },
                    ]
                }
            )
        )

        client = TestableAnthropicClient(
            api_key="sk-ant-test", fake_session=fake_session
        )
        models = client.fetch_models()

        assert len(models) == 3
        assert all(isinstance(m, ModelInfo) for m in models)
        assert all(m.provider == "Anthropic" for m in models)
        assert all(m.context_length == 200000 for m in models)

    def test_fetch_models_context_lengths(self) -> None:
        """Claude models have correct 200K context length."""
        client = AnthropicProviderClient()

        models = client.fetch_models()

        assert all(m.context_length == 200000 for m in models)

    def test_fetch_models_capabilities_vision(self) -> None:
        """Claude models have correct vision capabilities."""
        fake_session = FakeHTTPSession()
        fake_session.set_next_response(
            FakeHTTPResponse(
                json_data={
                    "data": [
                        {
                            "id": "claude-3-5-sonnet-20241022",
                            "display_name": "Claude 3.5 Sonnet",
                        }
                    ]
                }
            )
        )

        client = TestableAnthropicClient(
            api_key="sk-ant-test", fake_session=fake_session
        )
        models = client.fetch_models()

        sonnet_35 = models[0]
        assert "text-generation" in sonnet_35.capabilities
        assert "chat" in sonnet_35.capabilities
        assert "vision" in sonnet_35.capabilities
        assert "tool-use" in sonnet_35.capabilities

    def test_fetch_models_api_failure_uses_fallback(self) -> None:
        """fetch_models uses fallback on API failure."""
        fake_session = FakeHTTPSession()
        fake_session.set_next_response(
            requests.exceptions.ConnectionError("Connection failed")
        )

        client = TestableAnthropicClient(
            api_key="sk-ant-test", fake_session=fake_session
        )
        models = client.fetch_models()

        assert len(models) == 2
        assert all(isinstance(m, ModelInfo) for m in models)

    def test_get_fallback_models_structure(self) -> None:
        """_get_fallback_models returns expected Claude models."""
        client = AnthropicProviderClient()

        fallback = client._get_fallback_models()

        assert len(fallback) == 2
        assert fallback[0].id == "claude-3-5-sonnet-20241022"
        assert fallback[0].context_length == 200000
        assert "tool-use" in fallback[0].capabilities

        assert fallback[1].id == "claude-3-5-haiku-20241022"
        assert "tool-use" in fallback[1].capabilities


class TestOllamaProviderClient:
    """Test OllamaProviderClient for local model discovery."""

    def test_initialization_default_base_url(self) -> None:
        """Ollama client initializes with correct default localhost URL."""
        client = OllamaProviderClient()

        assert client.base_url == "http://localhost:11434"
        assert client.api_key is None

    def test_initialization_custom_base_url(self) -> None:
        """Ollama client accepts custom URL."""
        client = OllamaProviderClient(base_url="http://192.168.1.100:11434")

        assert client.base_url == "http://192.168.1.100:11434"

    def test_configure_auth_does_nothing(self) -> None:
        """Ollama doesn't configure authentication headers."""
        client = OllamaProviderClient()

        assert "Authorization" not in client.session.headers
        assert "x-api-key" not in client.session.headers

    def test_fetch_models_successful(self) -> None:
        """fetch_models successfully fetches models from Ollama."""
        fake_session = FakeHTTPSession()
        fake_session.set_next_response(
            FakeHTTPResponse(
                json_data={
                    "models": [
                        {
                            "name": "llama2:7b",
                            "size": 3825819519,
                            "context_length": 4096,
                        },
                        {
                            "name": "mistral:latest",
                            "size": 4109865159,
                            "context_length": 8192,
                        },
                        {"name": "codellama:13b", "size": 7365960935},
                    ]
                }
            )
        )

        client = TestableOllamaClient(fake_session=fake_session)
        models = client.fetch_models()

        assert len(models) == 3
        assert models[0].id == "llama2:7b"
        assert models[0].provider == "Ollama"
        assert "3.6GB" in models[0].description
        assert models[0].context_length == 4096

        assert models[1].id == "mistral:latest"
        assert "3.8GB" in models[1].description
        assert models[1].context_length == 8192

    def test_fetch_models_api_failure_returns_empty_list(self) -> None:
        """fetch_models returns empty list on API failure."""
        fake_session = FakeHTTPSession()
        fake_session.set_next_response(
            requests.exceptions.ConnectionError("Connection failed")
        )

        client = TestableOllamaClient(fake_session=fake_session)
        models = client.fetch_models()

        assert models == []

    def test_fetch_models_malformed_response_returns_empty_list(self) -> None:
        """fetch_models returns empty list on malformed response."""
        fake_session = FakeHTTPSession()
        fake_session.set_next_response(
            FakeHTTPResponse(json_data={"error": "malformed data"})
        )

        client = TestableOllamaClient(fake_session=fake_session)
        models = client.fetch_models()

        assert models == []

    def test_fetch_models_size_calculation_accuracy(self) -> None:
        """fetch_models calculates model sizes accurately."""
        fake_session = FakeHTTPSession()
        fake_session.set_next_response(
            FakeHTTPResponse(
                json_data={
                    "models": [
                        {"name": "tiny:1b", "size": 1073741824},
                        {"name": "large:70b", "size": 75161927680},
                    ]
                }
            )
        )

        client = TestableOllamaClient(fake_session=fake_session)
        models = client.fetch_models()

        assert "1.0GB" in models[0].description
        assert "70.0GB" in models[1].description


class TestLMStudioProviderClient:
    """Test LMStudioProviderClient for local model discovery."""

    def test_initialization_default_base_url(self) -> None:
        """LM Studio client initializes with correct default localhost URL."""
        client = LMStudioProviderClient()

        assert client.base_url == "http://localhost:1234/v1"
        assert client.api_key is None

    def test_initialization_custom_base_url(self) -> None:
        """LM Studio client accepts custom URL."""
        client = LMStudioProviderClient(base_url="http://localhost:5678/v1")

        assert client.base_url == "http://localhost:5678/v1"

    def test_configure_auth_does_nothing(self) -> None:
        """LM Studio doesn't configure authentication."""
        client = LMStudioProviderClient()

        assert "Authorization" not in client.session.headers

    def test_fetch_models_successful(self) -> None:
        """fetch_models successfully fetches models from LM Studio."""
        fake_session = FakeHTTPSession()
        fake_session.set_next_response(
            FakeHTTPResponse(
                json_data={
                    "data": [
                        {"id": "TheBloke/Llama-2-7B-GGUF"},
                        {"id": "TheBloke/Mistral-7B-Instruct-v0.2-GGUF"},
                    ]
                }
            )
        )

        client = TestableLMStudioClient(fake_session=fake_session)
        models = client.fetch_models()

        assert len(models) == 2
        assert models[0].id == "TheBloke/Llama-2-7B-GGUF"
        assert models[0].provider == "LM Studio"
        assert models[0].description == "Local LM Studio model"
        assert models[0].context_length == 4096

    def test_fetch_models_api_failure_returns_empty_list(self) -> None:
        """fetch_models returns empty list on API failure."""
        fake_session = FakeHTTPSession()
        fake_session.set_next_response(
            requests.exceptions.ConnectionError("Connection failed")
        )

        client = TestableLMStudioClient(fake_session=fake_session)
        models = client.fetch_models()

        assert models == []


class TestLocalProviderClient:
    """Test LocalProviderClient for GGUF local models."""

    def test_initialization(self) -> None:
        """Local provider client initializes correctly."""
        client = LocalProviderClient()

        assert client.api_key is None
        assert client.base_url is None

    def test_configure_auth_does_nothing(self) -> None:
        """Local models don't require authentication."""
        client = LocalProviderClient()

        assert "Authorization" not in client.session.headers

    def test_fetch_models_successful(self) -> None:
        """fetch_models successfully discovers local GGUF models."""
        import sys
        from types import ModuleType

        fake_gguf = FakeGGUFManager(
            {
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
        )

        fake_module = ModuleType("intellicrack.ai.local_gguf_server")
        fake_module.gguf_manager = fake_gguf  # type: ignore

        sys.modules["intellicrack.ai.local_gguf_server"] = fake_module

        try:
            client = LocalProviderClient()
            models = client.fetch_models()

            assert len(models) == 2
            assert models[0].provider == "Local GGUF"
            assert "Q4_K_M" in models[0].description
            assert "3825MB" in models[0].description
            assert models[1].context_length == 8192
        finally:
            del sys.modules["intellicrack.ai.local_gguf_server"]

    def test_fetch_models_gguf_manager_unavailable_returns_empty_list(self) -> None:
        """fetch_models returns empty list when gguf_manager unavailable."""
        import sys

        if "intellicrack.ai.local_gguf_server" in sys.modules:
            del sys.modules["intellicrack.ai.local_gguf_server"]

        client = LocalProviderClient()
        models = client.fetch_models()

        assert models == []


class TestProviderManager:
    """Test ProviderManager for managing multiple provider clients."""

    def test_initialization(self) -> None:
        """ProviderManager initializes with empty provider dictionary."""
        manager = ProviderManager()

        assert hasattr(manager, "providers")
        assert isinstance(manager.providers, dict)
        assert len(manager.providers) == 0

    def test_register_provider(self) -> None:
        """register_provider adds provider correctly."""
        manager = ProviderManager()
        client = OpenAIProviderClient(api_key="sk-test123")

        manager.register_provider("openai", client)

        assert "openai" in manager.providers
        assert manager.providers["openai"] == client

    def test_register_multiple_providers(self) -> None:
        """register_provider handles multiple providers correctly."""
        manager = ProviderManager()
        openai_client = OpenAIProviderClient(api_key="sk-test123")
        anthropic_client = AnthropicProviderClient(api_key="sk-ant-test")

        manager.register_provider("openai", openai_client)
        manager.register_provider("anthropic", anthropic_client)

        assert len(manager.providers) == 2
        assert manager.providers["openai"] == openai_client
        assert manager.providers["anthropic"] == anthropic_client

    def test_get_provider_exists(self) -> None:
        """get_provider returns registered provider."""
        manager = ProviderManager()
        client = OpenAIProviderClient()
        manager.register_provider("openai", client)

        retrieved = manager.get_provider("openai")

        assert retrieved == client

    def test_get_provider_not_found_returns_none(self) -> None:
        """get_provider returns None for non-existent provider."""
        manager = ProviderManager()

        result = manager.get_provider("nonexistent")

        assert result is None

    def test_fetch_models_from_provider_success(self) -> None:
        """fetch_models_from_provider fetches models from registered provider."""
        manager = ProviderManager()
        client = AnthropicProviderClient()
        manager.register_provider("anthropic", client)

        models = manager.fetch_models_from_provider("anthropic")

        assert len(models) == 2
        assert all(m.provider == "Anthropic" for m in models)

    def test_fetch_models_from_provider_not_found_returns_empty_list(self) -> None:
        """fetch_models_from_provider returns empty list for non-existent provider."""
        manager = ProviderManager()

        models = manager.fetch_models_from_provider("nonexistent")

        assert models == []

    def test_fetch_models_from_provider_exception_handling(self) -> None:
        """fetch_models_from_provider handles exceptions gracefully."""

        class BrokenClient(BaseProviderClient):
            def _configure_auth(self) -> None:
                pass

            def fetch_models(self) -> list[ModelInfo]:
                raise RuntimeError("API Error")

        manager = ProviderManager()
        client = BrokenClient()
        manager.register_provider("broken", client)

        models = manager.fetch_models_from_provider("broken")

        assert models == []

    def test_fetch_all_models_empty(self) -> None:
        """fetch_all_models returns empty dict with no registered providers."""
        manager = ProviderManager()

        all_models = manager.fetch_all_models()

        assert all_models == {}

    def test_fetch_all_models_multiple_providers(self) -> None:
        """fetch_all_models fetches from all registered providers."""
        manager = ProviderManager()
        manager.register_provider("anthropic", AnthropicProviderClient())
        manager.register_provider("openai", OpenAIProviderClient())

        all_models = manager.fetch_all_models()

        assert "anthropic" in all_models
        assert "openai" in all_models
        assert len(all_models["anthropic"]) == 2
        assert len(all_models["openai"]) == 2

    def test_fetch_all_models_filters_empty_results(self) -> None:
        """fetch_all_models excludes providers with no models."""
        manager = ProviderManager()

        fake_session_ollama = FakeHTTPSession()
        fake_session_ollama.set_next_response(
            requests.exceptions.ConnectionError("No connection")
        )
        manager.register_provider(
            "ollama", TestableOllamaClient(fake_session=fake_session_ollama)
        )

        manager.register_provider("anthropic", AnthropicProviderClient())

        all_models = manager.fetch_all_models()

        assert "ollama" not in all_models
        assert "anthropic" in all_models

    def test_provider_registration_overwrites_existing(self) -> None:
        """Registering same provider name overwrites previous registration."""
        manager = ProviderManager()
        client1 = OpenAIProviderClient(api_key="key1")
        client2 = OpenAIProviderClient(api_key="key2")

        manager.register_provider("openai", client1)
        manager.register_provider("openai", client2)

        assert manager.get_provider("openai") == client2
        assert manager.get_provider("openai") != client1


class TestGetProviderManager:
    """Test global provider manager singleton."""

    def test_get_provider_manager_returns_singleton(self) -> None:
        """get_provider_manager returns same instance across calls."""
        manager1 = get_provider_manager()
        manager2 = get_provider_manager()

        assert manager1 is manager2
        assert isinstance(manager1, ProviderManager)

    def test_get_provider_manager_persistence(self) -> None:
        """get_provider_manager maintains state across calls."""
        manager1 = get_provider_manager()
        client = OpenAIProviderClient()
        manager1.register_provider("test", client)

        manager2 = get_provider_manager()
        retrieved = manager2.get_provider("test")

        assert retrieved == client


class TestRealWorldScenarios:
    """Real-world scenario tests for API provider clients."""

    def test_network_completely_down_uses_fallback(self) -> None:
        """Client uses fallback models when network is unavailable."""
        fake_session = FakeHTTPSession()
        fake_session.set_next_response(
            requests.exceptions.ConnectionError("No network")
        )

        client = TestableOpenAIClient(api_key="sk-test", fake_session=fake_session)
        models = client.fetch_models()

        assert len(models) == 2
        assert models[0].id == "gpt-4o"

    def test_api_provider_adds_new_models(self) -> None:
        """Client handles new models with different naming correctly."""
        fake_session = FakeHTTPSession()
        fake_session.set_next_response(
            FakeHTTPResponse(
                json_data={
                    "data": [
                        {"id": "gpt-5-ultra"},
                        {"id": "gpt-4-turbo-enhanced"},
                        {"id": "text-embedding-v3"},
                    ]
                }
            )
        )

        client = TestableOpenAIClient(api_key="sk-test", fake_session=fake_session)
        models = client.fetch_models()

        assert len(models) == 2
        gpt5_model = next((m for m in models if "gpt-5" in m.id), None)
        assert gpt5_model is not None

    def test_concurrent_requests_multiple_providers(self) -> None:
        """Manager handles concurrent requests to multiple providers."""
        fake_session_openai = FakeHTTPSession()
        fake_session_openai.set_next_response(
            FakeHTTPResponse(json_data={"data": [{"id": "gpt-4"}]})
        )

        fake_session_anthropic = FakeHTTPSession()
        fake_session_anthropic.set_next_response(
            FakeHTTPResponse(
                json_data={
                    "data": [
                        {
                            "id": "claude-3-5-sonnet-20241022",
                            "display_name": "Claude 3.5 Sonnet",
                        }
                    ]
                }
            )
        )

        manager = ProviderManager()
        manager.register_provider(
            "openai",
            TestableOpenAIClient(api_key="sk-openai-test", fake_session=fake_session_openai),
        )
        manager.register_provider(
            "anthropic",
            TestableAnthropicClient(
                api_key="sk-ant-test", fake_session=fake_session_anthropic
            ),
        )

        all_models = manager.fetch_all_models()

        assert "openai" in all_models
        assert "anthropic" in all_models
        assert len(all_models["openai"]) >= 1
        assert len(all_models["anthropic"]) >= 1

    def test_rate_limiting_429_status_uses_fallback(self) -> None:
        """Client handles rate limit (429) responses gracefully."""
        fake_session = FakeHTTPSession()
        fake_session.set_next_response(
            FakeHTTPResponse(
                status_code=429,
                text='{"error": {"message": "Rate limit exceeded", "type": "rate_limit_error"}}',
            )
        )

        client = TestableOpenAIClient(api_key="sk-test", fake_session=fake_session)
        models = client.fetch_models()

        assert len(models) == 2

    def test_invalid_api_key_401_uses_fallback(self) -> None:
        """Client handles invalid API key (401) errors gracefully."""
        fake_session = FakeHTTPSession()
        fake_session.set_next_response(
            FakeHTTPResponse(
                status_code=401, text='{"error": {"message": "Invalid API key"}}'
            )
        )

        client = TestableOpenAIClient(api_key="sk-invalid", fake_session=fake_session)
        models = client.fetch_models()

        assert len(models) == 2

    def test_partial_json_response_uses_fallback(self) -> None:
        """Client handles incomplete/partial JSON responses gracefully."""
        fake_session = FakeHTTPSession()
        fake_session.set_next_response(
            FakeHTTPResponse(
                raise_exception=json.JSONDecodeError(
                    "Expecting property name", '{"data": [{"id": "gpt', 20
                ),
                status_code=200,
            )
        )

        client = TestableOpenAIClient(api_key="sk-test", fake_session=fake_session)
        models = client.fetch_models()

        assert len(models) == 2

    def test_model_filtering_edge_cases(self) -> None:
        """Client filters models with unusual naming patterns correctly."""
        fake_session = FakeHTTPSession()
        fake_session.set_next_response(
            FakeHTTPResponse(
                json_data={
                    "data": [
                        {"id": "gpt-4-EXPERIMENTAL-v2"},
                        {"id": "GPT-3.5-TURBO"},
                        {"id": "o1-preview-2024"},
                        {"id": "random-model-123"},
                        {"id": "davinci-002"},
                    ]
                }
            )
        )

        client = TestableOpenAIClient(api_key="sk-test", fake_session=fake_session)
        models = client.fetch_models()

        model_ids = [m.id for m in models]
        assert "gpt-4-EXPERIMENTAL-v2" in model_ids
        assert "davinci-002" in model_ids
        assert "o1-preview-2024" in model_ids
        assert "random-model-123" not in model_ids

    def test_provider_client_reuse_across_fetches(self) -> None:
        """Provider client can be reused for multiple fetch_models calls."""
        client = AnthropicProviderClient()

        models1 = client.fetch_models()
        models2 = client.fetch_models()
        models3 = client.fetch_models()

        assert len(models1) == len(models2) == len(models3) == 2
        assert models1[0].id == models2[0].id == models3[0].id

    def test_mixed_success_and_failure_in_manager(self) -> None:
        """Manager handles mix of successful and failed provider fetches."""
        fake_session_success = FakeHTTPSession()
        fake_session_success.set_next_response(
            FakeHTTPResponse(json_data={"data": [{"id": "gpt-4"}]})
        )

        fake_session_failure = FakeHTTPSession()
        fake_session_failure.set_next_response(
            requests.exceptions.Timeout("Request timeout")
        )

        manager = ProviderManager()
        manager.register_provider(
            "openai_success",
            TestableOpenAIClient(api_key="sk-test", fake_session=fake_session_success),
        )
        manager.register_provider(
            "openai_failure",
            TestableOpenAIClient(api_key="sk-test", fake_session=fake_session_failure),
        )

        all_models = manager.fetch_all_models()

        assert "openai_success" in all_models
        assert "openai_failure" in all_models
        assert len(all_models["openai_success"]) >= 1
        assert len(all_models["openai_failure"]) == 2

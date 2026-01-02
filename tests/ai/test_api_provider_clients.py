from typing import Any, cast

import pytest

from intellicrack.ai.api_provider_clients import (
    AnthropicProviderClient,
    LMStudioProviderClient,
    LocalProviderClient,
    ModelInfo,
    OllamaProviderClient,
    OpenAIProviderClient,
    ProviderManager,
)


class FakeHTTPResponse:
    """Fake HTTP response for testing without mocks."""

    def __init__(self, json_data: dict[str, Any] | None, status_code: int = 200) -> None:
        self._json_data = json_data
        self.status_code = status_code
        self.text = str(json_data) if json_data else ""

    def json(self) -> dict[str, Any]:
        if self._json_data is None:
            raise ValueError("No JSON data")
        return self._json_data

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise Exception(f"HTTP Error {self.status_code}")


class FakeSession:
    """Fake requests.Session for testing without mocks."""

    def __init__(self, response_data: dict[str, Any] | None = None) -> None:
        self.headers: dict[str, str] = {}
        self._response_data = response_data
        self._should_fail = response_data is None

    def update(self, headers: dict[str, str]) -> None:
        self.headers.update(headers)

    def request(
        self, method: str, url: str, timeout: int = 10, **kwargs: Any
    ) -> FakeHTTPResponse:
        if self._should_fail:
            raise ConnectionError("Failed to connect")
        return FakeHTTPResponse(self._response_data)


class FakeProviderClientWithResponse:
    """Base class for creating fake provider clients with predetermined responses."""

    def __init__(
        self,
        client_class: type,
        response_data: dict[str, Any] | None,
        api_key: str | None = "test-key",
        base_url: str | None = None,
    ) -> None:
        self.client = client_class(api_key=api_key, base_url=base_url)
        self.client.session = FakeSession(response_data)

    def fetch_models(self) -> list[ModelInfo]:
        return cast(list[ModelInfo], self.client.fetch_models())


class FakeGGUFManager:
    """Fake GGUF manager for testing local models."""

    def __init__(self, models: dict[str, dict[str, Any]]) -> None:
        self._models = models

    def list_models(self) -> dict[str, dict[str, Any]]:
        return self._models


@pytest.fixture
def openai_api_response() -> dict[str, Any]:
    return {
        "object": "list",
        "data": [
            {
                "id": "gpt-4o",
                "object": "model",
                "created": 1687882411,
                "owned_by": "openai",
                "context_window": 128000,
            },
            {
                "id": "gpt-4-turbo",
                "object": "model",
                "created": 1687882410,
                "owned_by": "openai",
                "context_window": 128000,
            },
            {
                "id": "gpt-3.5-turbo",
                "object": "model",
                "created": 1687882409,
                "owned_by": "openai",
                "context_window": 16385,
            },
            {
                "id": "whisper-1",
                "object": "model",
                "created": 1687882408,
                "owned_by": "openai",
            },
        ],
    }


@pytest.fixture
def anthropic_api_response() -> dict[str, Any]:
    return {
        "data": [
            {
                "id": "claude-3-5-sonnet-20241022",
                "display_name": "Claude 3.5 Sonnet",
                "created_at": "2024-10-22T00:00:00Z",
                "type": "model",
            },
            {
                "id": "claude-3-5-haiku-20241022",
                "display_name": "Claude 3.5 Haiku",
                "created_at": "2024-10-22T00:00:00Z",
                "type": "model",
            },
            {
                "id": "claude-3-opus-20240229",
                "display_name": "Claude 3 Opus",
                "created_at": "2024-02-29T00:00:00Z",
                "type": "model",
            },
        ],
    }


@pytest.fixture
def ollama_api_response() -> dict[str, Any]:
    return {
        "models": [
            {
                "name": "llama3:latest",
                "modified_at": "2024-01-01T00:00:00Z",
                "size": 4661211808,
                "digest": "sha256:abc123",
                "details": {
                    "format": "gguf",
                    "family": "llama",
                },
            },
            {
                "name": "codellama:13b",
                "modified_at": "2024-01-01T00:00:00Z",
                "size": 7365960384,
                "digest": "sha256:def456",
                "details": {
                    "format": "gguf",
                    "family": "llama",
                },
            },
        ],
    }


@pytest.fixture
def lmstudio_api_response() -> dict[str, Any]:
    return {
        "object": "list",
        "data": [
            {
                "id": "local-model-1",
                "object": "model",
                "created": 1687882411,
                "owned_by": "user",
            },
            {
                "id": "local-model-2",
                "object": "model",
                "created": 1687882410,
                "owned_by": "user",
            },
        ],
    }


class TestOpenAIProviderClient:

    def test_fetch_models_success_extracts_context_window(
        self, openai_api_response: dict[str, Any]
    ) -> None:
        fake_client = FakeProviderClientWithResponse(
            OpenAIProviderClient, openai_api_response
        )

        models = fake_client.fetch_models()

        assert len(models) == 3

        gpt4o = next((m for m in models if m.id == "gpt-4o"), None)
        assert gpt4o is not None
        assert gpt4o.context_length == 128000
        assert gpt4o.capabilities is not None
        assert "vision" in gpt4o.capabilities
        assert "function-calling" in gpt4o.capabilities

        gpt35 = next((m for m in models if m.id == "gpt-3.5-turbo"), None)
        assert gpt35 is not None
        assert gpt35.context_length == 16385

    def test_fetch_models_filters_non_chat_models(
        self, openai_api_response: dict[str, Any]
    ) -> None:
        fake_client = FakeProviderClientWithResponse(
            OpenAIProviderClient, openai_api_response
        )

        models = fake_client.fetch_models()

        model_ids = [m.id for m in models]
        assert "whisper-1" not in model_ids
        assert "gpt-4o" in model_ids

    def test_fetch_models_no_api_key_returns_fallback(self) -> None:
        client = OpenAIProviderClient(api_key=None)

        models = client.fetch_models()

        assert len(models) == 2
        assert models[0].id == "gpt-4o"
        assert models[0].context_length == 128000

    def test_fetch_models_api_failure_returns_fallback(self) -> None:
        fake_client = FakeProviderClientWithResponse(OpenAIProviderClient, None)

        models = fake_client.fetch_models()

        assert len(models) == 2
        assert models[0].id == "gpt-4o"

    def test_fetch_models_empty_data_returns_fallback(self) -> None:
        fake_client = FakeProviderClientWithResponse(
            OpenAIProviderClient, {"data": []}
        )

        models = fake_client.fetch_models()

        assert len(models) == 2
        assert models[0].id == "gpt-4o"

    def test_is_chat_model(self) -> None:
        client = OpenAIProviderClient(api_key="test-key")

        assert client._is_chat_model("gpt-4o") is True
        assert client._is_chat_model("gpt-3.5-turbo") is True
        assert client._is_chat_model("chatgpt-4o-latest") is True
        assert client._is_chat_model("text-davinci-003") is True
        assert client._is_chat_model("o1-preview") is True
        assert client._is_chat_model("whisper-1") is False
        assert client._is_chat_model("dall-e-3") is False

    def test_infer_capabilities(self) -> None:
        client = OpenAIProviderClient(api_key="test-key")

        capabilities = client._infer_capabilities("gpt-4o")
        assert "text-generation" in capabilities
        assert "chat" in capabilities
        assert "function-calling" in capabilities
        assert "vision" in capabilities

        capabilities = client._infer_capabilities("gpt-3.5-turbo")
        assert "text-generation" in capabilities
        assert "chat" in capabilities
        assert "vision" not in capabilities


class TestAnthropicProviderClient:

    def test_fetch_models_success_uses_v1_models_endpoint(
        self, anthropic_api_response: dict[str, Any]
    ) -> None:
        fake_client = FakeProviderClientWithResponse(
            AnthropicProviderClient, anthropic_api_response
        )

        models = fake_client.fetch_models()

        assert len(models) == 3

        sonnet = next((m for m in models if "sonnet" in m.id), None)
        assert sonnet is not None
        assert sonnet.name == "Claude 3.5 Sonnet"
        assert sonnet.provider == "Anthropic"
        assert sonnet.context_length == 200000
        assert sonnet.capabilities is not None
        assert "vision" in sonnet.capabilities
        assert "tool-use" in sonnet.capabilities

    def test_fetch_models_extracts_display_name(
        self, anthropic_api_response: dict[str, Any]
    ) -> None:
        fake_client = FakeProviderClientWithResponse(
            AnthropicProviderClient, anthropic_api_response
        )

        models = fake_client.fetch_models()

        haiku = next((m for m in models if "haiku" in m.id), None)
        assert haiku is not None
        assert haiku.name == "Claude 3.5 Haiku"
        assert haiku.id == "claude-3-5-haiku-20241022"

    def test_fetch_models_infers_capabilities(
        self, anthropic_api_response: dict[str, Any]
    ) -> None:
        fake_client = FakeProviderClientWithResponse(
            AnthropicProviderClient, anthropic_api_response
        )

        models = fake_client.fetch_models()

        opus = next((m for m in models if "opus" in m.id), None)
        assert opus is not None
        assert opus.capabilities is not None
        assert "vision" in opus.capabilities
        assert "chat" in opus.capabilities

    def test_fetch_models_no_api_key_returns_fallback(self) -> None:
        client = AnthropicProviderClient(api_key=None)

        models = client.fetch_models()

        assert len(models) == 2
        assert models[0].id == "claude-3-5-sonnet-20241022"
        assert models[0].context_length == 200000

    def test_fetch_models_api_failure_returns_fallback(self) -> None:
        fake_client = FakeProviderClientWithResponse(AnthropicProviderClient, None)

        models = fake_client.fetch_models()

        assert len(models) == 2
        assert models[0].id == "claude-3-5-sonnet-20241022"

    def test_fetch_models_empty_data_returns_fallback(self) -> None:
        fake_client = FakeProviderClientWithResponse(
            AnthropicProviderClient, {"data": []}
        )

        models = fake_client.fetch_models()

        assert len(models) == 2


class TestOllamaProviderClient:

    def test_fetch_models_success(self, ollama_api_response: dict[str, Any]) -> None:
        fake_client = FakeProviderClientWithResponse(
            OllamaProviderClient, ollama_api_response, api_key=None
        )

        models = fake_client.fetch_models()

        assert len(models) == 2

        llama3 = next((m for m in models if "llama3" in m.id), None)
        assert llama3 is not None
        assert llama3.provider == "Ollama"
        assert "4.3GB" in llama3.description

    def test_fetch_models_calculates_size(
        self, ollama_api_response: dict[str, Any]
    ) -> None:
        fake_client = FakeProviderClientWithResponse(
            OllamaProviderClient, ollama_api_response, api_key=None
        )

        models = fake_client.fetch_models()

        codellama = next((m for m in models if "codellama" in m.id), None)
        assert codellama is not None
        assert "6.9GB" in codellama.description

    def test_fetch_models_api_failure_returns_empty(self) -> None:
        fake_client = FakeProviderClientWithResponse(
            OllamaProviderClient, None, api_key=None
        )

        models = fake_client.fetch_models()

        assert len(models) == 0

    def test_fetch_models_missing_models_key_returns_empty(self) -> None:
        fake_client = FakeProviderClientWithResponse(
            OllamaProviderClient, {"data": []}, api_key=None
        )

        models = fake_client.fetch_models()

        assert len(models) == 0


class TestLMStudioProviderClient:

    def test_fetch_models_success(
        self, lmstudio_api_response: dict[str, Any]
    ) -> None:
        fake_client = FakeProviderClientWithResponse(
            LMStudioProviderClient, lmstudio_api_response, api_key=None
        )

        models = fake_client.fetch_models()

        assert len(models) == 2
        assert models[0].provider == "LM Studio"
        assert models[0].id == "local-model-1"

    def test_fetch_models_api_failure_returns_empty(self) -> None:
        fake_client = FakeProviderClientWithResponse(
            LMStudioProviderClient, None, api_key=None
        )

        models = fake_client.fetch_models()

        assert len(models) == 0


class TestLocalProviderClient:

    def test_fetch_models_success(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake_gguf_manager = FakeGGUFManager(
            {
                "model1.gguf": {
                    "size_mb": 4096,
                    "quantization": "Q4_K_M",
                    "context_length": 8192,
                },
                "model2.gguf": {
                    "size_mb": 7680,
                    "quantization": "Q5_K_M",
                    "context_length": 16384,
                },
            }
        )

        class FakeModule:
            gguf_manager = fake_gguf_manager

        def fake_import(
            name: str, globals: Any = None, locals: Any = None, fromlist: Any = None, level: int = 0
        ) -> Any:
            if name == "intellicrack.ai.local_gguf_server" or (
                fromlist and "gguf_manager" in fromlist
            ):
                return FakeModule()
            return __import__(name, globals, locals, fromlist, level)

        monkeypatch.setattr("builtins.__import__", fake_import)

        client = LocalProviderClient()
        models = client.fetch_models()

        assert len(models) == 2
        assert models[0].provider == "Local GGUF"
        assert "Q4_K_M" in models[0].description or "Q5_K_M" in models[0].description
        assert models[0].context_length in [8192, 16384]

    def test_fetch_models_import_error_returns_empty(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def fake_import_error(
            name: str, globals: Any = None, locals: Any = None, fromlist: Any = None, level: int = 0
        ) -> Any:
            if name == "intellicrack.ai.local_gguf_server" or (
                fromlist and "gguf_manager" in fromlist
            ):
                raise ImportError("Module not found")
            return __import__(name, globals, locals, fromlist, level)

        monkeypatch.setattr("builtins.__import__", fake_import_error)

        client = LocalProviderClient()
        models = client.fetch_models()

        assert len(models) == 0


class TestProviderManager:

    def test_register_and_get_provider(self) -> None:
        manager = ProviderManager()
        client = OpenAIProviderClient(api_key="test-key")

        manager.register_provider("OpenAI", client)

        retrieved = manager.get_provider("OpenAI")
        assert retrieved is client

    def test_get_nonexistent_provider(self) -> None:
        manager = ProviderManager()

        retrieved = manager.get_provider("NonExistent")
        assert retrieved is None

    def test_fetch_models_from_provider(
        self, openai_api_response: dict[str, Any]
    ) -> None:
        manager = ProviderManager()
        fake_client = FakeProviderClientWithResponse(
            OpenAIProviderClient, openai_api_response
        )

        manager.register_provider("OpenAI", fake_client.client)

        models = manager.fetch_models_from_provider("OpenAI")

        assert len(models) > 0
        assert all(isinstance(m, ModelInfo) for m in models)

    def test_fetch_models_from_nonexistent_provider(self) -> None:
        manager = ProviderManager()

        models = manager.fetch_models_from_provider("NonExistent")

        assert len(models) == 0

    def test_fetch_all_models(
        self, openai_api_response: dict[str, Any], anthropic_api_response: dict[str, Any]
    ) -> None:
        manager = ProviderManager()

        openai_fake = FakeProviderClientWithResponse(
            OpenAIProviderClient, openai_api_response
        )
        anthropic_fake = FakeProviderClientWithResponse(
            AnthropicProviderClient, anthropic_api_response
        )

        manager.register_provider("OpenAI", openai_fake.client)
        manager.register_provider("Anthropic", anthropic_fake.client)

        all_models = manager.fetch_all_models()

        assert "OpenAI" in all_models
        assert "Anthropic" in all_models
        assert len(all_models["OpenAI"]) > 0
        assert len(all_models["Anthropic"]) > 0

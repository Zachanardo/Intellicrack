"""Production tests for API provider clients.

Validates real API model discovery from OpenAI, Anthropic, Ollama, LM Studio, and local providers.
Tests authentication, model fetching, fallback handling, and provider management.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import os
from pathlib import Path
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


class TestModelInfo:
    """Tests for ModelInfo dataclass structure."""

    def test_model_info_creation(self) -> None:
        model = ModelInfo(
            id="gpt-4o",
            name="GPT-4 Optimized",
            provider="OpenAI",
            description="Latest GPT-4 model",
            context_length=128000,
            capabilities=["text-generation", "vision"],
            pricing={"input": 0.01, "output": 0.03},
        )

        assert model.id == "gpt-4o"
        assert model.name == "GPT-4 Optimized"
        assert model.provider == "OpenAI"
        assert model.context_length == 128000
        assert model.capabilities is not None
        assert "vision" in model.capabilities
        assert model.pricing is not None
        assert model.pricing["input"] == 0.01

    def test_model_info_defaults(self) -> None:
        model = ModelInfo(id="test-model", name="Test", provider="TestProvider")

        assert model.description == ""
        assert model.context_length == 4096
        assert model.capabilities is None
        assert model.pricing is None


class TestBaseProviderClient:
    """Tests for base provider client functionality."""

    def test_base_provider_initialization(self) -> None:
        class ConcreteProvider(BaseProviderClient):
            def _configure_auth(self) -> None:
                pass

            def fetch_models(self) -> list[ModelInfo]:
                return []

        provider = ConcreteProvider(api_key="test-key", base_url="https://api.test.com")

        assert provider.api_key == "test-key"
        assert provider.base_url == "https://api.test.com"
        assert provider.session.headers["Content-Type"] == "application/json"

    def test_make_request_timeout(self) -> None:
        class ConcreteProvider(BaseProviderClient):
            def _configure_auth(self) -> None:
                pass

            def fetch_models(self) -> list[ModelInfo]:
                return []

        provider = ConcreteProvider()
        result = provider._make_request("GET", "http://127.0.0.1:9999/timeout", timeout=0.1)

        assert result is None

    def test_make_request_connection_error(self) -> None:
        class ConcreteProvider(BaseProviderClient):
            def _configure_auth(self) -> None:
                pass

            def fetch_models(self) -> list[ModelInfo]:
                return []

        provider = ConcreteProvider()
        result = provider._make_request("GET", "http://192.0.2.0:9999/unreachable", timeout=0.1)

        assert result is None


class TestOpenAIProviderClient:
    """Tests for OpenAI provider client."""

    def test_initialization_default_url(self) -> None:
        client = OpenAIProviderClient(api_key="test-key")

        assert client.base_url == "https://api.openai.com/v1"
        assert client.api_key == "test-key"
        assert "Authorization" in client.session.headers

    def test_initialization_custom_url(self) -> None:
        client = OpenAIProviderClient(api_key="test-key", base_url="https://custom.api.com")

        assert client.base_url == "https://custom.api.com"

    def test_configure_auth(self) -> None:
        client = OpenAIProviderClient(api_key="sk-test-key-12345")

        assert client.session.headers["Authorization"] == "Bearer sk-test-key-12345"

    def test_fetch_models_without_api_key(self) -> None:
        client = OpenAIProviderClient()

        models = client.fetch_models()

        assert len(models) > 0
        assert all(isinstance(m, ModelInfo) for m in models)
        assert all(m.provider == "OpenAI" for m in models)

    def test_is_chat_model(self) -> None:
        client = OpenAIProviderClient()

        assert client._is_chat_model("gpt-4o")
        assert client._is_chat_model("gpt-3.5-turbo")
        assert client._is_chat_model("text-davinci-003")
        assert client._is_chat_model("o1-preview")
        assert not client._is_chat_model("whisper-1")
        assert not client._is_chat_model("dall-e-3")

    def test_infer_capabilities(self) -> None:
        client = OpenAIProviderClient()

        gpt4_caps = client._infer_capabilities("gpt-4o")
        assert "vision" in gpt4_caps
        assert "function-calling" in gpt4_caps

        turbo_caps = client._infer_capabilities("gpt-4-turbo")
        assert "vision" in turbo_caps
        assert "function-calling" in turbo_caps

        basic_caps = client._infer_capabilities("gpt-3.5-turbo")
        assert "function-calling" in basic_caps


class TestAnthropicProviderClient:
    """Tests for Anthropic provider client."""

    def test_initialization(self) -> None:
        client = AnthropicProviderClient(api_key="test-key")

        assert client.base_url == "https://api.anthropic.com"
        assert client.api_key == "test-key"
        assert client.session.headers["anthropic-version"] == "2023-06-01"
        assert client.session.headers["x-api-key"] == "test-key"

    def test_fallback_models(self) -> None:
        client = AnthropicProviderClient()

        models = client.fetch_models()

        assert len(models) >= 2
        assert any("sonnet" in m.id for m in models)
        assert any("haiku" in m.id for m in models)


class TestOllamaProviderClient:
    """Tests for Ollama local provider client."""

    def test_initialization_default_url(self) -> None:
        client = OllamaProviderClient()

        assert client.base_url == "http://localhost:11434"

    def test_initialization_custom_url(self) -> None:
        client = OllamaProviderClient(base_url="http://192.168.1.100:11434")

        assert client.base_url == "http://192.168.1.100:11434"

    def test_fetch_models_connection_failure(self) -> None:
        client = OllamaProviderClient(base_url="http://127.0.0.1:9999")

        models = client.fetch_models()

        assert models == []


class TestLMStudioProviderClient:
    """Tests for LM Studio provider client."""

    def test_initialization(self) -> None:
        client = LMStudioProviderClient()

        assert client.base_url == "http://localhost:1234/v1"

    def test_fetch_models_connection_failure(self) -> None:
        client = LMStudioProviderClient(base_url="http://127.0.0.1:9999/v1")

        models = client.fetch_models()

        assert models == []


class TestLocalProviderClient:
    """Tests for local GGUF model provider."""

    def test_initialization(self) -> None:
        client = LocalProviderClient()

        assert client.api_key is None
        assert client.base_url is None

    def test_fetch_models_returns_list(self) -> None:
        client = LocalProviderClient()

        models = client.fetch_models()

        assert isinstance(models, list)


class TestProviderManager:
    """Tests for provider management system."""

    def test_initialization(self) -> None:
        manager = ProviderManager()

        assert len(manager.providers) == 0

    def test_register_provider(self) -> None:
        manager = ProviderManager()
        client = OpenAIProviderClient(api_key="test")

        manager.register_provider("openai", client)

        assert "openai" in manager.providers
        assert manager.providers["openai"] == client

    def test_get_provider(self) -> None:
        manager = ProviderManager()
        client = OpenAIProviderClient(api_key="test")
        manager.register_provider("openai", client)

        retrieved = manager.get_provider("openai")

        assert retrieved == client

    def test_get_nonexistent_provider(self) -> None:
        manager = ProviderManager()

        retrieved = manager.get_provider("nonexistent")

        assert retrieved is None

    def test_fetch_models_from_provider(self) -> None:
        manager = ProviderManager()
        client = OpenAIProviderClient()
        manager.register_provider("openai", client)

        models = manager.fetch_models_from_provider("openai")

        assert isinstance(models, list)
        assert all(isinstance(m, ModelInfo) for m in models)

    def test_fetch_models_from_nonexistent_provider(self) -> None:
        manager = ProviderManager()

        models = manager.fetch_models_from_provider("nonexistent")

        assert models == []

    def test_fetch_all_models(self) -> None:
        manager = ProviderManager()

        openai_client = OpenAIProviderClient()
        anthropic_client = AnthropicProviderClient()

        manager.register_provider("openai", openai_client)
        manager.register_provider("anthropic", anthropic_client)

        all_models = manager.fetch_all_models()

        assert "openai" in all_models
        assert "anthropic" in all_models
        assert len(all_models["openai"]) > 0
        assert len(all_models["anthropic"]) > 0

    def test_fetch_all_models_handles_failures(self) -> None:
        manager = ProviderManager()

        failing_client = OllamaProviderClient(base_url="http://127.0.0.1:9999")
        working_client = AnthropicProviderClient()

        manager.register_provider("failing", failing_client)
        manager.register_provider("working", working_client)

        all_models = manager.fetch_all_models()

        assert "failing" not in all_models or len(all_models["failing"]) == 0
        assert "working" in all_models
        assert len(all_models["working"]) > 0


class TestGlobalProviderManager:
    """Tests for global provider manager singleton."""

    def test_get_provider_manager_returns_singleton(self) -> None:
        manager1 = get_provider_manager()
        manager2 = get_provider_manager()

        assert manager1 is manager2

    def test_get_provider_manager_is_instance(self) -> None:
        manager = get_provider_manager()

        assert isinstance(manager, ProviderManager)


class TestRealAPIIntegration:
    """Integration tests with real API endpoints (requires API keys)."""

    @pytest.mark.skipif(not os.getenv("OPENAI_API_KEY"), reason="Requires OPENAI_API_KEY")
    def test_real_openai_api_call(self) -> None:
        api_key = os.getenv("OPENAI_API_KEY")
        client = OpenAIProviderClient(api_key=api_key)

        models = client.fetch_models()

        assert len(models) > 0
        assert all(isinstance(m, ModelInfo) for m in models)
        assert all(m.provider == "OpenAI" for m in models)

    @pytest.mark.skipif(not os.getenv("ANTHROPIC_API_KEY"), reason="Requires ANTHROPIC_API_KEY")
    def test_real_anthropic_api_call(self) -> None:
        api_key = os.getenv("ANTHROPIC_API_KEY")
        client = AnthropicProviderClient(api_key=api_key)

        models = client.fetch_models()

        assert len(models) > 0
        assert all(isinstance(m, ModelInfo) for m in models)
        assert all(m.provider == "Anthropic" for m in models)


class TestErrorHandling:
    """Tests for robust error handling."""

    def test_invalid_url_handling(self) -> None:
        client = OpenAIProviderClient(api_key="test")

        result = client._make_request("GET", "http://127.0.0.1:9999/models", timeout=0.1)

        assert result is None

    def test_http_error_handling(self) -> None:
        client = OpenAIProviderClient(api_key="invalid-key")

        result = client._make_request("GET", "https://httpbin.org/status/401", timeout=5.0)

        assert result is None


class TestModelSorting:
    """Tests for model sorting and organization."""

    def test_openai_models_sorted_alphabetically(self) -> None:
        client = OpenAIProviderClient()

        models = client.fetch_models()

        model_ids = [m.id for m in models]
        assert model_ids == sorted(model_ids)

    def test_anthropic_models_sorted_reverse(self) -> None:
        client = AnthropicProviderClient()

        models = client.fetch_models()

        if len(models) >= 2:
            model_ids = [m.id for m in models]
            assert model_ids == sorted(model_ids, reverse=True)

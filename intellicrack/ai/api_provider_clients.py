"""API Provider Clients for Dynamic Model Discovery.

This module provides production-ready API clients for fetching available models
from different LLM providers. Each client implements real API communication
to discover models dynamically without hardcoded lists.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

import requests

from intellicrack.utils.logger import get_logger


logger = get_logger(__name__)


@dataclass
class ModelInfo:
    """Information about an available model."""

    id: str
    name: str
    provider: str
    description: str = ""
    context_length: int = 4096
    capabilities: list[str] | None = None
    pricing: dict[str, Any] | None = None


class BaseProviderClient(ABC):
    """Base class for API provider clients."""

    def __init__(self, api_key: str | None = None, base_url: str | None = None) -> None:
        """Initialize base provider client with API key and base URL."""
        self.api_key = api_key
        self.base_url = base_url
        self.session = requests.Session()
        self.session.headers.update({"Content-Type": "application/json"})
        if api_key:
            self._configure_auth()

    @abstractmethod
    def _configure_auth(self) -> None:
        """Configure authentication headers."""

    @abstractmethod
    def fetch_models(self) -> list[ModelInfo]:
        """Fetch available models from the provider."""

    def _make_request(self, method: str, url: str, **kwargs: Any) -> dict[str, Any] | None:
        """Make HTTP request with error handling."""
        try:
            response = self.session.request(method, url, timeout=10, **kwargs)
            response.raise_for_status()
            json_response: dict[str, Any] = response.json()
            return json_response
        except requests.exceptions.Timeout:
            logger.exception("Request to %s timed out", url)
            return None
        except requests.exceptions.ConnectionError:
            logger.exception("Failed to connect to %s", url)
            return None
        except requests.exceptions.HTTPError as e:
            logger.exception("HTTP error %d: %s", e.response.status_code, e.response.text)
            return None
        except Exception as e:
            logger.exception("Unexpected error making request to %s: %s", url, e)
            return None


class OpenAIProviderClient(BaseProviderClient):
    """OpenAI API provider client for dynamic model discovery."""

    def __init__(self, api_key: str | None = None, base_url: str | None = None) -> None:
        """Initialize OpenAI provider client with API key and base URL."""
        if base_url is None:
            base_url = "https://api.openai.com/v1"
        super().__init__(api_key, base_url)

    def _configure_auth(self) -> None:
        """Configure OpenAI authentication."""
        if self.api_key:
            self.session.headers.update({"Authorization": f"Bearer {self.api_key}"})

    def fetch_models(self) -> list[ModelInfo]:
        """Fetch available models from OpenAI API."""
        if not self.api_key:
            logger.warning("No API key provided for OpenAI")
            return self._get_fallback_models()

        logger.info("Fetching models from OpenAI")
        url = f"{self.base_url}/models"
        data = self._make_request("GET", url)

        if not data or "data" not in data:
            logger.warning("Failed to fetch OpenAI models, using fallback list")
            return self._get_fallback_models()

        models: list[ModelInfo] = []
        model_list: list[dict[str, Any]] = data["data"]
        for model_data in model_list:
            model_id: str = model_data.get("id", "")

            if not model_id or not self._is_chat_model(model_id):
                continue

            context_length = model_data.get("context_window", 4096)
            capabilities = self._infer_capabilities(model_id)

            models.append(
                ModelInfo(
                    id=model_id,
                    name=model_id,
                    provider="OpenAI",
                    description=f"OpenAI {model_id} model",
                    context_length=context_length,
                    capabilities=capabilities,
                ),
            )

        if not models:
            return self._get_fallback_models()

        models.sort(key=lambda x: x.id)
        return models

    def _is_chat_model(self, model_id: str) -> bool:
        """Check if model is a chat/completion model."""
        chat_indicators = ["gpt", "chatgpt", "turbo", "davinci", "o1", "o3"]
        return any(indicator in model_id.lower() for indicator in chat_indicators)

    def _infer_capabilities(self, model_id: str) -> list[str]:
        """Infer model capabilities from model ID."""
        capabilities = ["text-generation", "chat"]

        if "turbo" in model_id or "gpt-4" in model_id:
            capabilities.append("function-calling")

        if "vision" in model_id or "gpt-4o" in model_id or "gpt-4-turbo" in model_id:
            capabilities.append("vision")

        return capabilities

    def _get_fallback_models(self) -> list[ModelInfo]:
        """Get minimal fallback model list when API is unavailable."""
        return [
            ModelInfo(
                id="gpt-4o",
                name="gpt-4o",
                provider="OpenAI",
                description="Most capable GPT-4 model",
                context_length=128000,
                capabilities=["text-generation", "chat", "function-calling", "vision"],
            ),
            ModelInfo(
                id="gpt-4-turbo",
                name="gpt-4-turbo",
                provider="OpenAI",
                description="High performance GPT-4 model",
                context_length=128000,
                capabilities=["text-generation", "chat", "function-calling", "vision"],
            ),
        ]


class AnthropicProviderClient(BaseProviderClient):
    """Anthropic API provider client for dynamic model discovery."""

    def __init__(self, api_key: str | None = None, base_url: str | None = None) -> None:
        """Initialize Anthropic provider client with API key and base URL."""
        if base_url is None:
            base_url = "https://api.anthropic.com"
        super().__init__(api_key, base_url)
        self.session.headers.update({"anthropic-version": "2023-06-01"})

    def _configure_auth(self) -> None:
        """Configure Anthropic authentication."""
        if self.api_key:
            self.session.headers.update({"x-api-key": self.api_key})

    def fetch_models(self) -> list[ModelInfo]:
        """Fetch available models from Anthropic /v1/models API endpoint."""
        if not self.api_key:
            logger.warning("No API key provided for Anthropic")
            return self._get_fallback_models()

        logger.info("Fetching models from Anthropic")
        url = f"{self.base_url}/v1/models"
        data = self._make_request("GET", url)

        if not data or "data" not in data:
            logger.warning("Failed to fetch Anthropic models, using fallback list")
            return self._get_fallback_models()

        models: list[ModelInfo] = []
        model_list: list[dict[str, Any]] = data["data"]

        for model_data in model_list:
            model_id: str = model_data.get("id", "")
            display_name: str = model_data.get("display_name", model_id)

            if not model_id:
                continue

            capabilities = ["text-generation", "chat"]

            if "vision" in model_id or "opus" in model_id or "sonnet" in model_id or "haiku" in model_id:
                capabilities.append("vision")

            if "3-5" in model_id or "3.5" in model_id:
                capabilities.append("tool-use")

            models.append(
                ModelInfo(
                    id=model_id,
                    name=display_name,
                    provider="Anthropic",
                    description=f"Claude model: {display_name}",
                    context_length=200000,
                    capabilities=capabilities,
                ),
            )

        if not models:
            return self._get_fallback_models()

        models.sort(key=lambda x: x.id, reverse=True)
        return models

    def _get_fallback_models(self) -> list[ModelInfo]:
        """Get minimal fallback model list when API is unavailable."""
        return [
            ModelInfo(
                id="claude-3-5-sonnet-20241022",
                name="Claude 3.5 Sonnet",
                provider="Anthropic",
                description="Most intelligent Claude model",
                context_length=200000,
                capabilities=["text-generation", "chat", "vision", "tool-use"],
            ),
            ModelInfo(
                id="claude-3-5-haiku-20241022",
                name="Claude 3.5 Haiku",
                provider="Anthropic",
                description="Fastest Claude model",
                context_length=200000,
                capabilities=["text-generation", "chat", "vision", "tool-use"],
            ),
        ]


class OllamaProviderClient(BaseProviderClient):
    """Ollama API provider client for dynamic model discovery."""

    def __init__(self, api_key: str | None = None, base_url: str | None = None) -> None:
        """Initialize Ollama provider client with base URL."""
        if base_url is None:
            base_url = "http://localhost:11434"
        super().__init__(api_key, base_url)

    def _configure_auth(self) -> None:
        """Ollama typically doesn't require authentication."""

    def fetch_models(self) -> list[ModelInfo]:
        """Fetch available models from Ollama."""
        url = f"{self.base_url}/api/tags"
        data = self._make_request("GET", url)

        if not data or "models" not in data:
            logger.warning("Failed to fetch Ollama models")
            return []

        models: list[ModelInfo] = []
        model_list: list[dict[str, Any]] = data["models"]
        for model_data in model_list:
            model_name: str = model_data.get("name", "")
            size: int = model_data.get("size", 0)
            size_gb: float = size / (1024**3) if size > 0 else 0.0

            models.append(
                ModelInfo(
                    id=model_name,
                    name=model_name,
                    provider="Ollama",
                    description=f"Local Ollama model ({size_gb:.1f}GB)",
                    context_length=model_data.get("context_length", 4096),
                    capabilities=["text-generation", "chat"],
                ),
            )

        return models


class LMStudioProviderClient(BaseProviderClient):
    """LM Studio API provider client for dynamic model discovery."""

    def __init__(self, api_key: str | None = None, base_url: str | None = None) -> None:
        """Initialize LM Studio provider client with base URL."""
        if base_url is None:
            base_url = "http://localhost:1234/v1"
        super().__init__(api_key, base_url)

    def _configure_auth(self) -> None:
        """LM Studio typically doesn't require authentication."""

    def fetch_models(self) -> list[ModelInfo]:
        """Fetch available models from LM Studio."""
        url = f"{self.base_url}/models"
        data = self._make_request("GET", url)

        if not data or "data" not in data:
            logger.warning("Failed to fetch LM Studio models")
            return []

        models: list[ModelInfo] = []
        model_list: list[dict[str, Any]] = data["data"]
        for model_data in model_list:
            model_id: str = model_data.get("id", "")

            models.append(
                ModelInfo(
                    id=model_id,
                    name=model_id,
                    provider="LM Studio",
                    description="Local LM Studio model",
                    context_length=4096,
                    capabilities=["text-generation", "chat"],
                ),
            )

        return models


class LocalProviderClient(BaseProviderClient):
    """Local model provider client for GGUF and other local formats."""

    def __init__(self, api_key: str | None = None, base_url: str | None = None) -> None:
        """Initialize local provider client."""
        super().__init__(api_key, base_url)

    def _configure_auth(self) -> None:
        """Local models don't require authentication."""

    def fetch_models(self) -> list[ModelInfo]:
        """Fetch available local models."""
        models: list[ModelInfo] = []

        try:
            from intellicrack.ai.local_gguf_server import gguf_manager

            local_models: dict[str, dict[str, Any]] = gguf_manager.list_models()

            for model_name, model_info in local_models.items():
                size_mb: int = model_info.get("size_mb", 0)
                quantization: str = model_info.get("quantization", "")

                models.append(
                    ModelInfo(
                        id=model_name,
                        name=model_name,
                        provider="Local GGUF",
                        description=f"Local GGUF model - {quantization} ({size_mb}MB)",
                        context_length=model_info.get("context_length", 4096),
                        capabilities=["text-generation", "chat"],
                    ),
                )

        except Exception as e:
            logger.warning("Could not load local GGUF models: %s", e)

        return models


class ProviderManager:
    """Manager for all API provider clients."""

    def __init__(self) -> None:
        """Initialize provider manager with empty provider dictionary."""
        self.providers: dict[str, BaseProviderClient] = {}

    def register_provider(self, provider_name: str, client: BaseProviderClient) -> None:
        """Register a provider client."""
        self.providers[provider_name] = client
        logger.info("Registered provider: %s", provider_name)

    def get_provider(self, provider_name: str) -> BaseProviderClient | None:
        """Get a registered provider client."""
        return self.providers.get(provider_name)

    def fetch_models_from_provider(self, provider_name: str) -> list[ModelInfo]:
        """Fetch models from a specific provider."""
        provider = self.get_provider(provider_name)
        if not provider:
            logger.warning("Provider not found: %s", provider_name)
            return []

        try:
            return provider.fetch_models()
        except Exception as e:
            logger.exception("Error fetching models from %s: %s", provider_name, e)
            return []

    def fetch_all_models(self) -> dict[str, list[ModelInfo]]:
        """Fetch models from all registered providers."""
        all_models: dict[str, list[ModelInfo]] = {}

        for provider_name in self.providers:
            if models := self.fetch_models_from_provider(provider_name):
                all_models[provider_name] = models

        return all_models


_PROVIDER_MANAGER: ProviderManager | None = None


def get_provider_manager() -> ProviderManager:
    """Get the global provider manager instance."""
    global _PROVIDER_MANAGER
    if _PROVIDER_MANAGER is None:
        _PROVIDER_MANAGER = ProviderManager()
    return _PROVIDER_MANAGER

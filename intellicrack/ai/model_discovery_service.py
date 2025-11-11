"""Model Discovery Service for Dynamic API-Based Model Discovery.

This service integrates ProviderManager with LLMConfigManager to discover
available models from API providers dynamically. It queries provider APIs
using configured API keys and returns comprehensive model lists for UI display.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import time
from typing import Any

from intellicrack.utils.logger import get_logger

from .api_provider_clients import (
    AnthropicProviderClient,
    LMStudioProviderClient,
    LocalProviderClient,
    ModelInfo,
    OllamaProviderClient,
    OpenAIProviderClient,
    get_provider_manager,
)
from .llm_config_manager import get_llm_config_manager

logger = get_logger(__name__)


class ModelDiscoveryService:
    """Service for discovering models from API providers with caching."""

    def __init__(self, cache_ttl_seconds: int = 300) -> None:
        """Initialize the model discovery service.

        Args:
            cache_ttl_seconds: Time-to-live for cached models (default 5 minutes)

        """
        self.cache_ttl = cache_ttl_seconds
        self._cached_models: dict[str, list[ModelInfo]] = {}
        self._cache_timestamp = 0
        self._provider_manager = get_provider_manager()
        self._config_manager = get_llm_config_manager()

    def discover_all_models(self, force_refresh: bool = False) -> dict[str, list[ModelInfo]]:
        """Discover models from all configured providers.

        Args:
            force_refresh: Force refresh even if cache is valid

        Returns:
            Dictionary mapping provider names to lists of ModelInfo objects

        """
        current_time = time.time()
        cache_age = current_time - self._cache_timestamp

        if not force_refresh and cache_age < self.cache_ttl and self._cached_models:
            logger.debug(f"Using cached models (age: {cache_age:.1f}s)")
            return self._cached_models.copy()

        logger.info("Discovering models from API providers")
        self._initialize_providers()

        all_models = self._provider_manager.fetch_all_models()

        self._cached_models = all_models
        self._cache_timestamp = current_time

        total_models = sum(len(models) for models in all_models.values())
        logger.info(f"Discovered {total_models} models from {len(all_models)} providers")

        return all_models.copy()

    def discover_provider_models(self, provider_name: str, force_refresh: bool = False) -> list[ModelInfo]:
        """Discover models from a specific provider.

        Args:
            provider_name: Name of the provider (e.g., "OpenAI", "Anthropic")
            force_refresh: Force refresh even if cache is valid

        Returns:
            List of ModelInfo objects for the provider

        """
        all_models = self.discover_all_models(force_refresh=force_refresh)
        return all_models.get(provider_name, [])

    def get_flat_model_list(self, force_refresh: bool = False) -> list[tuple[str, ModelInfo]]:
        """Get a flat list of all models with provider names.

        Args:
            force_refresh: Force refresh even if cache is valid

        Returns:
            List of (display_name, ModelInfo) tuples suitable for UI dropdowns

        """
        all_models = self.discover_all_models(force_refresh=force_refresh)
        flat_list = []

        for provider_name, models in all_models.items():
            for model in models:
                display_name = f"{provider_name}: {model.name}"
                flat_list.append((display_name, model))

        flat_list.sort(key=lambda x: x[0])
        return flat_list

    def get_configured_and_discovered_models(self, force_refresh: bool = False) -> dict[str, dict[str, Any]]:
        """Get both configured models and API-discovered models.

        Returns:
            Dictionary with 'configured' and 'discovered' keys containing model info

        """
        result = {"configured": {}, "discovered": {}}

        configured_models = self._config_manager.list_model_configs()
        result["configured"] = configured_models

        discovered_models = self.discover_all_models(force_refresh=force_refresh)
        result["discovered"] = {
            provider: [
                {
                    "id": model.id,
                    "name": model.name,
                    "provider": model.provider,
                    "description": model.description,
                    "context_length": model.context_length,
                    "capabilities": model.capabilities or [],
                }
                for model in models
            ]
            for provider, models in discovered_models.items()
        }

        return result

    def _initialize_providers(self) -> None:
        """Initialize provider clients with API keys from configuration."""
        configured_models = self._config_manager.list_model_configs()

        api_keys = self._extract_api_keys(configured_models)

        self._provider_manager.providers.clear()

        if "openai" in api_keys:
            openai_client = OpenAIProviderClient(api_key=api_keys["openai"]["api_key"], base_url=api_keys["openai"].get("api_base"))
            self._provider_manager.register_provider("OpenAI", openai_client)
            logger.info("Registered OpenAI provider for model discovery")

        if "anthropic" in api_keys:
            anthropic_client = AnthropicProviderClient(
                api_key=api_keys["anthropic"]["api_key"],
                base_url=api_keys["anthropic"].get("api_base"),
            )
            self._provider_manager.register_provider("Anthropic", anthropic_client)
            logger.info("Registered Anthropic provider for model discovery")

        ollama_client = OllamaProviderClient(base_url=api_keys.get("ollama", {}).get("api_base", "http://localhost:11434"))
        self._provider_manager.register_provider("Ollama", ollama_client)
        logger.debug("Registered Ollama provider for model discovery")

        lmstudio_client = LMStudioProviderClient(base_url=api_keys.get("lmstudio", {}).get("api_base", "http://localhost:1234/v1"))
        self._provider_manager.register_provider("LM Studio", lmstudio_client)
        logger.debug("Registered LM Studio provider for model discovery")

        local_client = LocalProviderClient()
        self._provider_manager.register_provider("Local GGUF", local_client)
        logger.debug("Registered Local GGUF provider for model discovery")

    def _extract_api_keys(self, configured_models: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
        """Extract API keys and base URLs from configured models.

        Args:
            configured_models: Dictionary of model configurations

        Returns:
            Dictionary mapping provider names to API credentials

        """
        api_keys = {}

        for _model_id, config in configured_models.items():
            provider = config.get("provider", "").lower()
            api_key = config.get("api_key")
            api_base = config.get("api_base")

            if not api_key:
                continue

            if provider in ["openai", "anthropic"]:
                if provider not in api_keys:
                    api_keys[provider] = {"api_key": api_key}
                    if api_base:
                        api_keys[provider]["api_base"] = api_base

            elif provider in ["ollama", "local_api", "lmstudio"]:
                provider_key = "ollama" if provider == "ollama" else "lmstudio"
                if provider_key not in api_keys:
                    api_keys[provider_key] = {}
                if api_base:
                    api_keys[provider_key]["api_base"] = api_base

        return api_keys

    def clear_cache(self) -> None:
        """Clear the cached models, forcing fresh discovery on next request."""
        self._cached_models.clear()
        self._cache_timestamp = 0
        logger.info("Model discovery cache cleared")


_DISCOVERY_SERVICE: ModelDiscoveryService | None = None


def get_model_discovery_service() -> ModelDiscoveryService:
    """Get the global model discovery service instance."""
    global _DISCOVERY_SERVICE
    if _DISCOVERY_SERVICE is None:
        _DISCOVERY_SERVICE = ModelDiscoveryService()
    return _DISCOVERY_SERVICE

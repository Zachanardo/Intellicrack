"""Model Discovery Service for Dynamic API-Based Model Discovery.

This service integrates ProviderManager with LLMConfigManager to discover
available models from API providers dynamically. It queries provider APIs
using configured API keys and returns comprehensive model lists for UI display.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import json
import threading
import time
from datetime import UTC, datetime, timezone
from pathlib import Path
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

    def __init__(
        self,
        cache_ttl_seconds: int = 300,
        cache_file: Path | None = None,
        auto_update_interval_hours: int = 6,
    ) -> None:
        """Initialize the model discovery service.

        Args:
            cache_ttl_seconds: Time-to-live for in-memory cache (default 5 minutes)
            cache_file: Path to disk cache file (default: config/model_cache.json)
            auto_update_interval_hours: Hours between automatic background updates (default 6)

        """
        self.cache_ttl = cache_ttl_seconds
        self._cached_models: dict[str, list[ModelInfo]] = {}
        self._cache_timestamp: float = 0.0
        self._provider_manager = get_provider_manager()
        self._config_manager = get_llm_config_manager()

        if cache_file is None:
            cache_file = Path("config/model_cache.json")
        self._cache_file = cache_file
        self._auto_update_interval = auto_update_interval_hours * 3600
        self._update_thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._cache_lock = threading.RLock()

        self._load_cache_from_disk()

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
            logger.debug("Using cached models (age: %.1fs)", cache_age)
            return self._cached_models.copy()

        logger.info("Discovering models from API providers")
        self._initialize_providers()

        all_models = self._provider_manager.fetch_all_models()

        new_models = self._detect_new_models(all_models)
        for provider, model_ids in new_models.items():
            for model_id in model_ids:
                logger.info("New model discovered: %s (%s)", model_id, provider)

        self._cached_models = all_models
        self._cache_timestamp = current_time

        self._save_cache_to_disk(all_models)

        total_models = sum(len(models) for models in all_models.values())
        logger.info("Discovered %d models from %d providers", total_models, len(all_models))

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
        configured_models = self._config_manager.list_model_configs()
        discovered_models = self.discover_all_models(force_refresh=force_refresh)
        discovered_data: dict[str, list[dict[str, Any]]] = {
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

        return {"discovered": discovered_data, "configured": configured_models}

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

        for config in configured_models.values():
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

    def start_background_updater(self) -> None:
        """Start background thread for automatic model cache updates."""
        if self._update_thread and self._update_thread.is_alive():
            logger.warning("Background updater already running")
            return

        self._stop_event.clear()
        self._update_thread = threading.Thread(
            target=self._background_update_loop,
            name="ModelDiscoveryUpdater",
            daemon=True,
        )
        self._update_thread.start()
        logger.info("Started background model discovery updater (interval: %.1fh)", self._auto_update_interval / 3600)

    def stop_background_updater(self) -> None:
        """Stop background update thread gracefully."""
        if not self._update_thread or not self._update_thread.is_alive():
            return

        logger.info("Stopping background model discovery updater")
        self._stop_event.set()
        self._update_thread.join(timeout=5.0)
        self._update_thread = None

    def _background_update_loop(self) -> None:
        """Background thread loop for automatic cache updates."""
        while not self._stop_event.is_set():
            try:
                if self._stop_event.wait(timeout=self._auto_update_interval):
                    break

                logger.info("Background model discovery update triggered")
                self.discover_all_models(force_refresh=True)

            except Exception as e:
                logger.exception("Error in background update loop: %s", e)
                if self._stop_event.wait(timeout=300):
                    break

    def _load_cache_from_disk(self) -> None:
        """Load cached models from disk file."""
        with self._cache_lock:
            if not self._cache_file.exists():
                logger.debug("Disk cache file not found: %s", self._cache_file)
                return

            try:
                with open(self._cache_file, encoding="utf-8") as f:
                    data = json.load(f)

                version = data.get("version", "1.0")
                last_updated = data.get("last_updated", "")
                providers_data = data.get("providers", {})

                cached_models: dict[str, list[ModelInfo]] = {}

                for provider_name, models_list in providers_data.items():
                    models = []
                    for model_dict in models_list:
                        model = ModelInfo(
                            id=model_dict.get("id", ""),
                            name=model_dict.get("name", ""),
                            provider=model_dict.get("provider", provider_name),
                            description=model_dict.get("description", ""),
                            context_length=model_dict.get("context_length", 4096),
                            capabilities=model_dict.get("capabilities"),
                            pricing=model_dict.get("pricing"),
                        )
                        models.append(model)
                    cached_models[provider_name] = models

                self._cached_models = cached_models
                self._cache_timestamp = time.time()

                total_models = sum(len(models) for models in cached_models.values())
                logger.info("Loaded %d models from disk cache (version: %s, last updated: %s)", total_models, version, last_updated)

            except json.JSONDecodeError as e:
                logger.exception("Failed to parse disk cache file: %s", e)
            except Exception as e:
                logger.exception("Error loading disk cache: %s", e)

    def _save_cache_to_disk(self, models_by_provider: dict[str, list[ModelInfo]]) -> bool:
        """Save discovered models to disk cache file.

        Args:
            models_by_provider: Dictionary mapping provider names to model lists

        Returns:
            True if save successful, False otherwise

        """
        with self._cache_lock:
            try:
                self._cache_file.parent.mkdir(parents=True, exist_ok=True)

                now = datetime.now(UTC).isoformat()

                providers_data: dict[str, list[dict[str, Any]]] = {}

                for provider_name, models in models_by_provider.items():
                    models_list = []
                    for model in models:
                        model_dict = {
                            "id": model.id,
                            "name": model.name,
                            "provider": model.provider,
                            "description": model.description,
                            "context_length": model.context_length,
                            "capabilities": model.capabilities,
                            "pricing": model.pricing,
                        }
                        models_list.append(model_dict)
                    providers_data[provider_name] = models_list

                cache_data = {
                    "version": "1.0",
                    "last_updated": now,
                    "cache_ttl_seconds": self.cache_ttl,
                    "auto_update_interval_hours": self._auto_update_interval / 3600,
                    "providers": providers_data,
                }

                with open(self._cache_file, "w", encoding="utf-8") as f:
                    json.dump(cache_data, f, indent=2, ensure_ascii=False)

                total_models = sum(len(models) for models in models_by_provider.values())
                logger.info("Saved %d models to disk cache: %s", total_models, self._cache_file)
                return True

            except Exception as e:
                logger.exception("Failed to save disk cache: %s", e)
                return False

    def _detect_new_models(self, new_models: dict[str, list[ModelInfo]]) -> dict[str, list[str]]:
        """Detect models that weren't in previous cache.

        Args:
            new_models: Newly fetched models by provider

        Returns:
            Dictionary mapping provider names to lists of new model IDs

        """
        with self._cache_lock:
            if not self._cached_models:
                return {}

            new_model_ids: dict[str, list[str]] = {}

            for provider_name, models in new_models.items():
                if provider_name not in self._cached_models:
                    new_model_ids[provider_name] = [m.id for m in models]
                    continue

                cached_ids = {m.id for m in self._cached_models[provider_name]}
                if provider_new_ids := [m.id for m in models if m.id not in cached_ids]:
                    new_model_ids[provider_name] = provider_new_ids

            return new_model_ids


_DISCOVERY_SERVICE: ModelDiscoveryService | None = None


def get_model_discovery_service() -> ModelDiscoveryService:
    """Get the global model discovery service instance."""
    global _DISCOVERY_SERVICE
    if _DISCOVERY_SERVICE is None:
        _DISCOVERY_SERVICE = ModelDiscoveryService()
    return _DISCOVERY_SERVICE

"""AI Model Manager for Intellicrack.

This module manages AI model integration, configuration, and lifecycle
for the Intellicrack security research platform.

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
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""

import json
import os
from pathlib import Path
from typing import Any

from intellicrack.ai.llm_backends import LLMConfig, LLMManager, LLMProvider
from intellicrack.ai.model_cache_manager import get_cache_manager
from intellicrack.ai.model_performance_monitor import get_performance_monitor
from intellicrack.utils.logger import get_logger, log_all_methods


logger = get_logger(__name__)


@log_all_methods
class AIModelManager:
    """Centralized AI model management for Intellicrack."""

    def __init__(self, config_path: str | None = None) -> None:
        """Initialize the AI Model Manager.

        Args:
            config_path: Path to model configuration file

        """
        self.config_path: str = config_path or self._get_default_config_path()
        self.models: dict[str, dict[str, Any]] = {}
        self.active_model: str | None = None
        self.config: dict[str, Any] = {}
        self.llm_manager: LLMManager = LLMManager()
        self.cache_manager: Any = get_cache_manager()
        self.performance_monitor: Any = get_performance_monitor()

        self._load_configuration()
        self._initialize_models()

    def _get_default_config_path(self) -> str:
        """Get default configuration path.

        Creates the necessary directory structure if it does not exist and
        returns the path to the model configuration file in the user's home
        directory.

        Returns:
            Path to the default model configuration file located at
                ~/.intellicrack/models/model_config.json.

        """
        config_dir = Path.home() / ".intellicrack" / "models"
        config_dir.mkdir(parents=True, exist_ok=True)
        return str(config_dir / "model_config.json")

    def _load_configuration(self) -> None:
        """Load model configuration from file.

        Uses default configuration if file does not exist or loading fails.

        """
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path) as f:
                    self.config = json.load(f)
                logger.info("Loaded model configuration from %s", self.config_path)
            except Exception as e:
                logger.exception("Failed to load model config: %s", e)
                self.config = self._get_default_config()
        else:
            self.config = self._get_default_config()
            self._save_configuration()

    def _save_configuration(self) -> None:
        """Save model configuration to file.

        Logs errors if save operation fails.

        """
        try:
            with open(self.config_path, "w") as f:
                json.dump(self.config, f, indent=2)
            logger.info("Saved model configuration to %s", self.config_path)
        except Exception as e:
            logger.exception("Failed to save model config: %s", e)

    def _get_default_config(self) -> dict[str, Any]:
        """Get default model configuration.

        Provides a baseline configuration for all supported AI model providers,
        including OpenAI, Anthropic, Google, and local model backends. Each
        model has provider-specific parameters and default values.

        Returns:
            Default model configuration dictionary containing models section
                with provider configurations, default model name, cache
                settings, and performance monitoring flags.

        """
        return {
            "models": {
                "gpt-4": {
                    "provider": "openai",
                    "enabled": False,
                    "api_key": "",
                    "max_tokens": 4096,
                    "temperature": 0.7,
                },
                "claude-3": {
                    "provider": "anthropic",
                    "enabled": False,
                    "api_key": "",
                    "max_tokens": 4096,
                    "temperature": 0.7,
                },
                "gemini-pro": {
                    "provider": "google",
                    "enabled": False,
                    "api_key": "",
                    "max_tokens": 4096,
                    "temperature": 0.7,
                },
                "llama3": {
                    "provider": "local",
                    "enabled": True,
                    "model_path": "",
                    "max_tokens": 2048,
                    "temperature": 0.7,
                },
                "codellama": {
                    "provider": "local",
                    "enabled": True,
                    "model_path": "",
                    "max_tokens": 2048,
                    "temperature": 0.7,
                },
            },
            "default_model": "llama3",
            "cache_enabled": True,
            "cache_size_mb": 1024,
            "performance_monitoring": True,
        }

    def _initialize_models(self) -> None:
        """Initialize configured models.

        Sets the default active model if available.

        """
        for model_name, model_config in self.config["models"].items():
            if model_config.get("enabled", False):
                try:
                    self._setup_model(model_name, model_config)
                    logger.info("Initialized model: %s", model_name)
                except Exception as e:
                    logger.exception("Failed to initialize model %s: %s", model_name, e)

        # Set default active model
        default_model = self.config.get("default_model")
        if default_model and default_model in self.models:
            self.active_model = default_model
            logger.info("Set active model: %s", default_model)

    def _setup_model(self, name: str, config: dict[str, Any]) -> None:
        """Set up individual model.

        Initializes a model based on its provider type (OpenAI, Anthropic,
        Google, or local). Registers the model in the internal models registry
        for later lazy-loading and use.

        Args:
            name: Model name identifying the model instance.
            config: Model configuration dictionary containing provider type,
                API keys, and model-specific parameters.

        Raises:
            ValueError: If an unknown or unsupported provider is specified in
                the configuration.

        """
        provider = config.get("provider", "local")

        if provider == "openai":
            self._setup_openai_model(name, config)
        elif provider == "anthropic":
            self._setup_anthropic_model(name, config)
        elif provider == "google":
            self._setup_google_model(name, config)
        elif provider == "local":
            self._setup_local_model(name, config)
        else:
            raise ValueError(f"Unknown provider: {provider}")

        self.models[name] = {
            "provider": provider,
            "config": config,
            "instance": None,  # Lazy load actual model
        }

    def _setup_openai_model(self, name: str, config: dict[str, Any]) -> None:
        """Set up OpenAI model.

        Configures an OpenAI model by creating an LLMConfig and registering
        it with the LLM manager. API keys are resolved from the config or the
        OPENAI_API_KEY environment variable.

        Args:
            name: Model name identifying the OpenAI model instance.
            config: Model configuration dictionary containing API key, max
                tokens, temperature, and other OpenAI-specific parameters.

        Raises:
            ValueError: If no API key is provided in the config or found in
                the OPENAI_API_KEY environment variable.

        """
        api_key = config.get("api_key") or os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise ValueError(f"No API key for OpenAI model {name}")

        llm_config = LLMConfig(
            provider=LLMProvider.OPENAI,
            model_name=name,
            api_key=api_key,
            max_tokens=config.get("max_tokens", 4096),
            temperature=config.get("temperature", 0.7),
        )

        self.llm_manager.add_provider(LLMProvider.OPENAI, llm_config)

    def _setup_anthropic_model(self, name: str, config: dict[str, Any]) -> None:
        """Set up Anthropic model.

        Configures an Anthropic model by creating an LLMConfig and registering
        it with the LLM manager. API keys are resolved from the config or the
        ANTHROPIC_API_KEY environment variable.

        Args:
            name: Model name identifying the Anthropic model instance.
            config: Model configuration dictionary containing API key, max
                tokens, temperature, and other Anthropic-specific parameters.

        Raises:
            ValueError: If no API key is provided in the config or found in
                the ANTHROPIC_API_KEY environment variable.

        """
        api_key = config.get("api_key") or os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            raise ValueError(f"No API key for Anthropic model {name}")

        llm_config = LLMConfig(
            provider=LLMProvider.ANTHROPIC,
            model_name=name,
            api_key=api_key,
            max_tokens=config.get("max_tokens", 4096),
            temperature=config.get("temperature", 0.7),
        )

        self.llm_manager.add_provider(LLMProvider.ANTHROPIC, llm_config)

    def _setup_google_model(self, name: str, config: dict[str, Any]) -> None:
        """Set up Google model.

        Configures a Google model by creating an LLMConfig and registering
        it with the LLM manager. API keys are resolved from the config or the
        GOOGLE_API_KEY environment variable.

        Args:
            name: Model name identifying the Google model instance.
            config: Model configuration dictionary containing API key, max
                tokens, temperature, and other Google-specific parameters.

        Raises:
            ValueError: If no API key is provided in the config or found in
                the GOOGLE_API_KEY environment variable.

        """
        api_key = config.get("api_key") or os.getenv("GOOGLE_API_KEY")
        if not api_key:
            raise ValueError(f"No API key for Google model {name}")

        llm_config = LLMConfig(
            provider=LLMProvider.GOOGLE,
            model_name=name,
            api_key=api_key,
            max_tokens=config.get("max_tokens", 4096),
            temperature=config.get("temperature", 0.7),
        )

        self.llm_manager.add_provider(LLMProvider.GOOGLE, llm_config)

    def _setup_local_model(self, name: str, config: dict[str, Any]) -> None:
        """Set up local model.

        Configures a locally-hosted model by validating the model path and
        preparing it for lazy-loading. If the model path is invalid or does
        not exist, logs a warning and returns without raising an error.

        Args:
            name: Model name identifying the local model instance.
            config: Model configuration dictionary containing model_path and
                other model-specific parameters for local backends.

        """
        model_path = config.get("model_path")
        if not model_path or not os.path.exists(model_path):
            logger.warning("Model path not found for %s: %s", name, model_path)
            return

        # Local model setup would involve loading the model
        # This is framework-specific (transformers, llama.cpp, etc.)
        logger.info("Local model %s configured at %s", name, model_path)

    def get_model(self, name: str | None = None) -> Any:
        """Get a model instance.

        Retrieves a model instance by name, using the active model if no name
        is specified. Models are lazy-loaded on first access and cached for
        subsequent requests.

        Args:
            name: Model name (uses active model if not specified).

        Returns:
            Model instance loaded from cache or constructed on first access.

        Raises:
            ValueError: If model name is not specified and no active model is
                set.
            ValueError: If the specified model is not found in the loaded
                models registry.

        """
        model_name: str | None = name or self.active_model
        if not model_name:
            raise ValueError("No model specified and no active model set")

        if model_name not in self.models:
            raise ValueError(f"Model {model_name} not found")

        model_info: dict[str, Any] = self.models[model_name]

        # Lazy load model instance
        if model_info["instance"] is None:
            model_info["instance"] = self._load_model(model_name, model_info)

        return model_info["instance"]

    def _load_model(self, name: str, model_info: dict[str, Any]) -> Any:
        """Load actual model instance.

        Loads a model instance from cache if available, otherwise delegates to
        the appropriate provider-specific loader. Supports caching to avoid
        redundant load operations.

        Args:
            name: Model name used for cache key and logging purposes.
            model_info: Model information dictionary containing provider type
                and configuration.

        Returns:
            Loaded model instance or provider handle for API-based models.

        Raises:
            ValueError: If provider type is unknown or not supported.

        """
        provider: str = model_info["provider"]
        config: dict[str, Any] = model_info["config"]

        # Check cache first
        if self.config.get("cache_enabled", True):
            cached_model: Any = self.cache_manager.get_model(name)
            if cached_model is not None:
                logger.info("Loaded model %s from cache", name)
                return cached_model

        # Load model based on provider
        if provider in ["openai", "anthropic", "google"]:
            # Use LLM manager for API-based models
            return self.llm_manager.get_provider(provider)
        if provider == "local":
            # Load local model
            return self._load_local_model(name, config)
        raise ValueError(f"Unknown provider: {provider}")

    def _load_local_model(self, name: str, config: dict[str, Any]) -> dict[str, Any]:
        """Load local model from disk.

        Attempts to load the model using the transformers library, with
        llama.cpp as a fallback backend if transformers is unavailable. Caches
        loaded models to avoid redundant disk operations.

        Args:
            name: Model name used for cache key and logging purposes.
            config: Model configuration dictionary containing model_path and
                other parameters.

        Returns:
            Dictionary with 'model' and 'tokenizer' keys for transformers
                backend, or 'model' and 'tokenizer' set to None for
                llama.cpp backend.

        Raises:
            ValueError: If model path is invalid, not a string, or does not
                exist on the filesystem.
            RuntimeError: If no local model backend is available (neither
                transformers nor llama-cpp-python installed).

        """
        model_path: Any = config.get("model_path")

        try:
            # Try to load with transformers
            from transformers import AutoModel, AutoTokenizer

            if not isinstance(model_path, str):
                raise ValueError(f"Invalid model path: {model_path}")

            model: Any = AutoModel.from_pretrained(model_path)
            tokenizer: Any = AutoTokenizer.from_pretrained(model_path)

            # Cache the model
            if self.config.get("cache_enabled", True):
                self.cache_manager.cache_model(name, model, tokenizer)

            return {"model": model, "tokenizer": tokenizer}
        except ImportError:
            logger.warning("Transformers not available, trying llama.cpp")

            try:
                # Try llama.cpp as fallback
                import llama_cpp

                if not isinstance(model_path, str):
                    raise ValueError(f"Invalid model path: {model_path}")

                model_instance: Any = llama_cpp.Llama(model_path=model_path)

                # Cache the model
                if self.config.get("cache_enabled", True):
                    self.cache_manager.cache_model(name, model_instance, None)

                return {"model": model_instance, "tokenizer": None}
            except ImportError:
                logger.exception("No local model backend available")
                raise RuntimeError("No local model backend available (install transformers or llama-cpp-python)") from None

    def set_active_model(self, name: str) -> None:
        """Set the active model.

        Sets the specified model as the active/default model for subsequent
        operations. Validates that the model exists in the loaded models
        registry before activation.

        Args:
            name: Model name to set as active.

        Raises:
            ValueError: If the specified model is not found in the loaded
                models registry.

        """
        if name not in self.models:
            raise ValueError(f"Model {name} not found")

        self.active_model = name
        logger.info("Set active model: %s", name)

    def list_models(self) -> list[str]:
        """List available models.

        Returns:
            List of model names

        """
        return list(self.models.keys())

    def get_model_info(self, name: str | None = None) -> dict[str, Any]:
        """Get model information.

        Retrieves configuration and metadata for a model, including provider
        type, configuration parameters, and lazy-loaded instance handle.

        Args:
            name: Model name (uses active model if not specified).

        Returns:
            Model information dictionary containing provider type, config, and
                instance keys.

        Raises:
            ValueError: If model name is not specified and no active model is
                set.
            ValueError: If the specified model is not found in the loaded
                models registry.

        """
        model_name: str | None = name or self.active_model
        if not model_name:
            raise ValueError("No model specified and no active model set")

        if model_name not in self.models:
            raise ValueError(f"Model {model_name} not found")

        result: dict[str, Any] = self.models[model_name]
        return result

    def configure_model(self, name: str, config: dict[str, Any]) -> None:
        """Configure a model.

        Args:
            name: Model name.
            config: Model configuration dictionary.

        """
        if name not in self.config["models"]:
            self.config["models"][name] = {}

        self.config["models"][name].update(config)
        self._save_configuration()

        # Reinitialize model if enabled
        if config.get("enabled"):
            self._setup_model(name, self.config["models"][name])
            logger.info("Reconfigured model: %s", name)

    def enable_model(self, name: str) -> None:
        """Enable a model.

        Enables a configured model by setting its enabled flag and initializing
        it for use. The model must exist in the configuration file.

        Args:
            name: Model name to enable.

        Raises:
            ValueError: If model is not found in the configuration file.

        """
        if name not in self.config["models"]:
            raise ValueError(f"Model {name} not found in configuration")

        self.config["models"][name]["enabled"] = True
        self._save_configuration()

        # Initialize the model
        self._setup_model(name, self.config["models"][name])
        logger.info("Enabled model: %s", name)

    def disable_model(self, name: str) -> None:
        """Disable a model.

        Disables a configured model by setting its enabled flag and unloading
        it from memory. Updates the active model if the disabled model is
        currently active.

        Args:
            name: Model name to disable.

        Raises:
            ValueError: If model is not found in the configuration file.

        """
        if name not in self.config["models"]:
            raise ValueError(f"Model {name} not found in configuration")

        self.config["models"][name]["enabled"] = False
        self._save_configuration()

        # Remove from loaded models
        if name in self.models:
            del self.models[name]

        # Update active model if necessary
        if self.active_model == name:
            self.active_model = None

        logger.info("Disabled model: %s", name)

    def get_performance_stats(self, name: str | None = None) -> dict[str, Any]:
        """Get performance statistics for a model.

        Retrieves performance metrics for a model from the performance monitor,
        including inference time, throughput, and resource utilization if
        performance monitoring is enabled.

        Args:
            name: Model name (uses active model if not specified).

        Returns:
            Performance statistics dictionary containing timing, throughput,
                and resource metrics, or a message indicating performance
                monitoring is disabled.

        Raises:
            ValueError: If model name is not specified and no active model is
                set.

        """
        model_name: str | None = name or self.active_model
        if model_name:
            stats: dict[str, Any] = (
                self.performance_monitor.get_stats(model_name)
                if self.config.get("performance_monitoring", True)
                else {"message": "Performance monitoring disabled"}
            )
            return stats
        raise ValueError("No model specified and no active model set")

    def cleanup(self) -> None:
        """Cleanup resources.

        Clears cache and unloads all models.

        """
        # Clear cache
        if self.cache_manager:
            self.cache_manager.clear()

        # Clear loaded models
        self.models.clear()
        self.active_model = None

        logger.info("AI Model Manager cleaned up")


_model_manager: AIModelManager | None = None


def get_model_manager(config_path: str | None = None) -> AIModelManager:
    """Get the global AI Model Manager instance.

    Args:
        config_path: Path to model configuration file

    Returns:
        AIModelManager instance

    """
    global _model_manager

    if _model_manager is None:
        _model_manager = AIModelManager(config_path)

    return _model_manager

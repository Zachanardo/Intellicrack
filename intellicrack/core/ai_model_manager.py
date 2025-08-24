"""AI Model Manager for Intellicrack.

This module manages AI model integration, configuration, and lifecycle
for the Intellicrack security research platform.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from intellicrack.ai.llm_backends import LLMConfig, LLMManager, LLMProvider
from intellicrack.ai.model_cache_manager import get_cache_manager
from intellicrack.ai.model_performance_monitor import get_performance_monitor
from intellicrack.utils.logger import get_logger

logger = get_logger(__name__)


class AIModelManager:
    """Centralized AI model management for Intellicrack."""

    def __init__(self, config_path: Optional[str] = None):
        """Initialize the AI Model Manager.

        Args:
            config_path: Path to model configuration file
        """
        self.config_path = config_path or self._get_default_config_path()
        self.models = {}
        self.active_model = None
        self.llm_manager = LLMManager()
        self.cache_manager = get_cache_manager()
        self.performance_monitor = get_performance_monitor()

        self._load_configuration()
        self._initialize_models()

    def _get_default_config_path(self) -> str:
        """Get default configuration path."""
        config_dir = Path.home() / ".intellicrack" / "models"
        config_dir.mkdir(parents=True, exist_ok=True)
        return str(config_dir / "model_config.json")

    def _load_configuration(self):
        """Load model configuration from file."""
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, 'r') as f:
                    self.config = json.load(f)
                logger.info(f"Loaded model configuration from {self.config_path}")
            except Exception as e:
                logger.error(f"Failed to load model config: {e}")
                self.config = self._get_default_config()
        else:
            self.config = self._get_default_config()
            self._save_configuration()

    def _save_configuration(self):
        """Save model configuration to file."""
        try:
            with open(self.config_path, 'w') as f:
                json.dump(self.config, f, indent=2)
            logger.info(f"Saved model configuration to {self.config_path}")
        except Exception as e:
            logger.error(f"Failed to save model config: {e}")

    def _get_default_config(self) -> Dict[str, Any]:
        """Get default model configuration."""
        return {
            "models": {
                "gpt-4": {
                    "provider": "openai",
                    "enabled": False,
                    "api_key": "",
                    "max_tokens": 4096,
                    "temperature": 0.7
                },
                "claude-3": {
                    "provider": "anthropic",
                    "enabled": False,
                    "api_key": "",
                    "max_tokens": 4096,
                    "temperature": 0.7
                },
                "gemini-pro": {
                    "provider": "google",
                    "enabled": False,
                    "api_key": "",
                    "max_tokens": 4096,
                    "temperature": 0.7
                },
                "llama3": {
                    "provider": "local",
                    "enabled": True,
                    "model_path": "",
                    "max_tokens": 2048,
                    "temperature": 0.7
                },
                "codellama": {
                    "provider": "local",
                    "enabled": True,
                    "model_path": "",
                    "max_tokens": 2048,
                    "temperature": 0.7
                }
            },
            "default_model": "llama3",
            "cache_enabled": True,
            "cache_size_mb": 1024,
            "performance_monitoring": True
        }

    def _initialize_models(self):
        """Initialize configured models."""
        for model_name, model_config in self.config["models"].items():
            if model_config.get("enabled", False):
                try:
                    self._setup_model(model_name, model_config)
                    logger.info(f"Initialized model: {model_name}")
                except Exception as e:
                    logger.error(f"Failed to initialize model {model_name}: {e}")

        # Set default active model
        default_model = self.config.get("default_model")
        if default_model and default_model in self.models:
            self.active_model = default_model
            logger.info(f"Set active model: {default_model}")

    def _setup_model(self, name: str, config: Dict[str, Any]):
        """Setup individual model.

        Args:
            name: Model name
            config: Model configuration
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
            "instance": None  # Lazy load actual model
        }

    def _setup_openai_model(self, name: str, config: Dict[str, Any]):
        """Setup OpenAI model."""
        api_key = config.get("api_key") or os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise ValueError(f"No API key for OpenAI model {name}")

        llm_config = LLMConfig(
            provider=LLMProvider.OPENAI,
            model_name=name,
            api_key=api_key,
            max_tokens=config.get("max_tokens", 4096),
            temperature=config.get("temperature", 0.7)
        )

        self.llm_manager.add_provider(LLMProvider.OPENAI, llm_config)

    def _setup_anthropic_model(self, name: str, config: Dict[str, Any]):
        """Setup Anthropic model."""
        api_key = config.get("api_key") or os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            raise ValueError(f"No API key for Anthropic model {name}")

        llm_config = LLMConfig(
            provider=LLMProvider.ANTHROPIC,
            model_name=name,
            api_key=api_key,
            max_tokens=config.get("max_tokens", 4096),
            temperature=config.get("temperature", 0.7)
        )

        self.llm_manager.add_provider(LLMProvider.ANTHROPIC, llm_config)

    def _setup_google_model(self, name: str, config: Dict[str, Any]):
        """Setup Google model."""
        api_key = config.get("api_key") or os.getenv("GOOGLE_API_KEY")
        if not api_key:
            raise ValueError(f"No API key for Google model {name}")

        llm_config = LLMConfig(
            provider=LLMProvider.GOOGLE,
            model_name=name,
            api_key=api_key,
            max_tokens=config.get("max_tokens", 4096),
            temperature=config.get("temperature", 0.7)
        )

        self.llm_manager.add_provider(LLMProvider.GOOGLE, llm_config)

    def _setup_local_model(self, name: str, config: Dict[str, Any]):
        """Setup local model."""
        model_path = config.get("model_path")
        if not model_path or not os.path.exists(model_path):
            logger.warning(f"Model path not found for {name}: {model_path}")
            return

        # Local model setup would involve loading the model
        # This is framework-specific (transformers, llama.cpp, etc.)
        logger.info(f"Local model {name} configured at {model_path}")

    def get_model(self, name: Optional[str] = None):
        """Get a model instance.

        Args:
            name: Model name (uses active model if not specified)

        Returns:
            Model instance
        """
        model_name = name or self.active_model
        if not model_name:
            raise ValueError("No model specified and no active model set")

        if model_name not in self.models:
            raise ValueError(f"Model {model_name} not found")

        model_info = self.models[model_name]

        # Lazy load model instance
        if model_info["instance"] is None:
            model_info["instance"] = self._load_model(model_name, model_info)

        return model_info["instance"]

    def _load_model(self, name: str, model_info: Dict[str, Any]):
        """Load actual model instance.

        Args:
            name: Model name
            model_info: Model information

        Returns:
            Loaded model instance
        """
        provider = model_info["provider"]
        config = model_info["config"]

        # Check cache first
        if self.config.get("cache_enabled", True):
            cached_model = self.cache_manager.get_model(name)
            if cached_model:
                logger.info(f"Loaded model {name} from cache")
                return cached_model

        # Load model based on provider
        if provider in ["openai", "anthropic", "google"]:
            # Use LLM manager for API-based models
            return self.llm_manager.get_provider(provider)
        elif provider == "local":
            # Load local model
            return self._load_local_model(name, config)
        else:
            raise ValueError(f"Unknown provider: {provider}")

    def _load_local_model(self, name: str, config: Dict[str, Any]):
        """Load local model from disk.

        Args:
            name: Model name
            config: Model configuration

        Returns:
            Loaded model
        """
        model_path = config.get("model_path")

        try:
            # Try to load with transformers
            from transformers import AutoModel, AutoTokenizer

            model = AutoModel.from_pretrained(model_path)
            tokenizer = AutoTokenizer.from_pretrained(model_path)

            # Cache the model
            if self.config.get("cache_enabled", True):
                self.cache_manager.cache_model(name, model, tokenizer)

            return {"model": model, "tokenizer": tokenizer}
        except ImportError:
            logger.warning("Transformers not available, trying llama.cpp")

            try:
                # Try llama.cpp as fallback
                import llama_cpp

                model = llama_cpp.Llama(model_path=model_path)

                # Cache the model
                if self.config.get("cache_enabled", True):
                    self.cache_manager.cache_model(name, model, None)

                return {"model": model, "tokenizer": None}
            except ImportError:
                logger.error("No local model backend available")
                raise RuntimeError("No local model backend available (install transformers or llama-cpp-python)") from None

    def set_active_model(self, name: str):
        """Set the active model.

        Args:
            name: Model name
        """
        if name not in self.models:
            raise ValueError(f"Model {name} not found")

        self.active_model = name
        logger.info(f"Set active model: {name}")

    def list_models(self) -> List[str]:
        """List available models.

        Returns:
            List of model names
        """
        return list(self.models.keys())

    def get_model_info(self, name: Optional[str] = None) -> Dict[str, Any]:
        """Get model information.

        Args:
            name: Model name (uses active model if not specified)

        Returns:
            Model information dictionary
        """
        model_name = name or self.active_model
        if not model_name:
            raise ValueError("No model specified and no active model set")

        if model_name not in self.models:
            raise ValueError(f"Model {model_name} not found")

        return self.models[model_name]

    def configure_model(self, name: str, config: Dict[str, Any]):
        """Configure a model.

        Args:
            name: Model name
            config: Model configuration
        """
        if name not in self.config["models"]:
            self.config["models"][name] = {}

        self.config["models"][name].update(config)
        self._save_configuration()

        # Reinitialize model if enabled
        if config.get("enabled", False):
            self._setup_model(name, self.config["models"][name])
            logger.info(f"Reconfigured model: {name}")

    def enable_model(self, name: str):
        """Enable a model.

        Args:
            name: Model name
        """
        if name not in self.config["models"]:
            raise ValueError(f"Model {name} not found in configuration")

        self.config["models"][name]["enabled"] = True
        self._save_configuration()

        # Initialize the model
        self._setup_model(name, self.config["models"][name])
        logger.info(f"Enabled model: {name}")

    def disable_model(self, name: str):
        """Disable a model.

        Args:
            name: Model name
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

        logger.info(f"Disabled model: {name}")

    def get_performance_stats(self, name: Optional[str] = None) -> Dict[str, Any]:
        """Get performance statistics for a model.

        Args:
            name: Model name (uses active model if not specified)

        Returns:
            Performance statistics
        """
        model_name = name or self.active_model
        if not model_name:
            raise ValueError("No model specified and no active model set")

        if self.config.get("performance_monitoring", True):
            return self.performance_monitor.get_stats(model_name)
        else:
            return {"message": "Performance monitoring disabled"}

    def cleanup(self):
        """Cleanup resources."""
        # Clear cache
        if self.cache_manager:
            self.cache_manager.clear()

        # Clear loaded models
        self.models.clear()
        self.active_model = None

        logger.info("AI Model Manager cleaned up")


# Singleton instance
_model_manager = None


def get_model_manager(config_path: Optional[str] = None) -> AIModelManager:
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

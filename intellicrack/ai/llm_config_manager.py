"""LLM Configuration Manager for Intellicrack.

This module provides a compatibility layer for LLM configuration management,
delegating all storage to the central IntellicrackConfig system. Legacy JSON
files in ~/.intellicrack/llm_configs/ are automatically migrated on first use.

IMPORTANT: This is now a wrapper around IntellicrackConfig. All configuration
is stored in the central config.json file under the 'llm_configuration' section.
The separate JSON files (models.json, profiles.json, metrics.json) are no longer
used except for one-time migration.

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
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ..utils.deprecation_warnings import deprecated_config_method
from ..utils.logger import get_logger
from .llm_backends import LLMConfig, LLMProvider, get_llm_manager


if TYPE_CHECKING:
    from .llm_backends import LLMManager

logger = get_logger(__name__)


class LLMConfigManager:
    """Production-ready LLM configuration manager using central IntellicrackConfig.

    This class provides a clean API for managing LLM configurations while storing
    all data in the central config.json file. Legacy JSON files are only read
    during migration, never written to. Single source of truth: central config.

    Features:
    - Model configuration management
    - Profile management for different use cases
    - Metrics tracking and aggregation
    - Automatic migration from legacy JSON files
    - Thread-safe operations through central config
    """

    def __init__(self, config_dir: str | Path | None = None) -> None:
        """Initialize the LLM configuration manager.

        Args:
            config_dir: Directory to store configuration files.
                       Defaults to ~/.intellicrack/llm_configs

        """
        resolved_dir: Path
        if config_dir is None:
            resolved_dir = Path.home() / ".intellicrack" / "llm_configs"
        elif isinstance(config_dir, str):
            resolved_dir = Path(config_dir)
        else:
            resolved_dir = config_dir

        self.config_dir: Path = resolved_dir
        self.config_dir.mkdir(parents=True, exist_ok=True)

        self.config_file: Path = self.config_dir / "models.json"
        self.profiles_file: Path = self.config_dir / "profiles.json"
        self.metrics_file: Path = self.config_dir / "metrics.json"

        self.configs: dict[str, Any] = {}
        self.profiles: dict[str, dict[str, Any]] = {}
        self.metrics: dict[str, Any] = {}

        self._load_all_configs()

    def _load_all_configs(self) -> None:
        """Load all configuration files."""
        from intellicrack.core.config_manager import get_config

        loaded_configs = self._load_json_file(self.config_file, {})
        if isinstance(loaded_configs, dict):
            self.configs = dict(loaded_configs)

        loaded_profiles = self._load_json_file(self.profiles_file, self._get_default_profiles())
        if isinstance(loaded_profiles, dict):
            self.profiles = {str(k): v if isinstance(v, dict) else {} for k, v in loaded_profiles.items()}

        loaded_metrics = self._load_json_file(self.metrics_file, {})
        if isinstance(loaded_metrics, dict):
            self.metrics = dict(loaded_metrics)

        try:
            central_config = get_config()

            central_models = central_config.get("llm_configuration.models", {})
            if isinstance(central_models, dict):
                self.configs.update(central_models)

            central_profiles = central_config.get("llm_configuration.profiles", {})
            if isinstance(central_profiles, dict):
                for key, value in central_profiles.items():
                    if isinstance(value, dict):
                        self.profiles[str(key)] = dict(value)

            central_metrics = central_config.get("llm_configuration.metrics", {})
            if isinstance(central_metrics, dict):
                self.metrics.update(central_metrics)

        except Exception as e:
            logger.warning("Could not load from central config: %s", e)

    def _load_json_file(
        self,
        file_path: Path,
        default: dict[str, object] | list[object],
    ) -> dict[str, object] | list[object]:
        """Load a JSON file with error handling - ONLY for migration purposes.

        Args:
            file_path: Path to the JSON file to load
            default: Default value to return if file doesn't exist or loading fails

        Returns:
            Loaded JSON data as dict or list, or default value on error

        """
        if not file_path.exists():
            return default

        try:
            with open(file_path, encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.exception("Failed to load %s: %s", file_path, e)
            return default

    # NOTE: _save_json_file method has been REMOVED
    # All saves now go directly to central config only
    # No dual storage - production-ready single source of truth

    def _get_default_profiles(self) -> dict[str, dict[str, Any]]:
        """Get default model profiles for different use cases with dynamic model recommendations."""
        recommended_models = self._get_recommended_models_for_profiles()

        return {
            "code_generation": {
                "name": "Code Generation",
                "description": "Optimized for generating code and scripts",
                "settings": {
                    "temperature": 0.2,
                    "max_tokens": 4096,
                    "top_p": 0.95,
                    "frequency_penalty": 0.0,
                    "presence_penalty": 0.0,
                },
                "recommended_models": recommended_models.get("code_generation", []),
            },
            "analysis": {
                "name": "Binary Analysis",
                "description": "Optimized for analyzing binaries and patterns",
                "settings": {
                    "temperature": 0.1,
                    "max_tokens": 2048,
                    "top_p": 0.9,
                    "frequency_penalty": 0.0,
                    "presence_penalty": 0.0,
                },
                "recommended_models": recommended_models.get("analysis", []),
            },
            "creative": {
                "name": "Creative Tasks",
                "description": "For brainstorming and creative problem solving",
                "settings": {
                    "temperature": 0.8,
                    "max_tokens": 2048,
                    "top_p": 0.95,
                    "frequency_penalty": 0.3,
                    "presence_penalty": 0.3,
                },
                "recommended_models": recommended_models.get("creative", []),
            },
            "fast_inference": {
                "name": "Fast Inference",
                "description": "Optimized for speed with smaller models",
                "settings": {
                    "temperature": 0.3,
                    "max_tokens": 1024,
                    "top_p": 0.9,
                    "frequency_penalty": 0.0,
                    "presence_penalty": 0.0,
                },
                "recommended_models": recommended_models.get("fast_inference", []),
            },
        }

    def _get_recommended_models_for_profiles(self) -> dict[str, list[str]]:
        """Get dynamically recommended models for each profile based on discovered models.

        Returns:
            Dictionary mapping profile names to lists of recommended model IDs

        """
        try:
            import json
            from pathlib import Path

            cache_file = Path("config/model_cache.json")
            if not cache_file.exists():
                return {
                    "code_generation": [],
                    "analysis": [],
                    "creative": [],
                    "fast_inference": [],
                }

            with open(cache_file, encoding="utf-8") as f:
                cache_data = json.load(f)

            all_models: dict[str, list[dict[str, Any]]] = cache_data.get("providers", {})

            openai_models = [m.get("id", "") for m in all_models.get("OpenAI", [])]
            anthropic_models = [m.get("id", "") for m in all_models.get("Anthropic", [])]
            ollama_models = [m.get("id", "") for m in all_models.get("Ollama", [])]
            local_models = [m.get("id", "") for m in all_models.get("Local GGUF", [])]

            large_models = []
            fast_models = []
            creative_models = []

            for model_id in openai_models:
                if "gpt-4" in model_id and "turbo" not in model_id:
                    large_models.append(model_id)
                elif "gpt-4o" in model_id or "gpt-4-turbo" in model_id:
                    large_models.append(model_id)
                    creative_models.append(model_id)
                elif "gpt-3.5" in model_id or "turbo" in model_id:
                    fast_models.append(model_id)

            for model_id in anthropic_models:
                if "opus" in model_id:
                    large_models.append(model_id)
                elif "sonnet" in model_id:
                    large_models.append(model_id)
                    creative_models.append(model_id)
                elif "haiku" in model_id:
                    fast_models.append(model_id)

            for model_id in ollama_models:
                if "codellama" in model_id or "deepseek" in model_id or "starcoder" in model_id:
                    large_models.append(model_id)
                elif "mistral" in model_id or "llama2" in model_id.lower():
                    fast_models.append(model_id)

            for model_id in local_models:
                if "code" in model_id.lower():
                    large_models.append(model_id)
                else:
                    fast_models.append(model_id)

            return {
                "code_generation": large_models[:5] if large_models else [],
                "analysis": large_models[:3] if large_models else [],
                "creative": creative_models[:3] if creative_models else large_models[:3],
                "fast_inference": fast_models[:3] if fast_models else [],
            }

        except Exception as e:
            logger.debug("Could not get dynamic model recommendations: %s", e)
            return {
                "code_generation": [],
                "analysis": [],
                "creative": [],
                "fast_inference": [],
            }

    @deprecated_config_method("IntellicrackConfig.set('llm_configuration.models.{model_id}', config)")
    def save_model_config(self, model_id: str, config: LLMConfig, metadata: dict[str, Any] | None = None) -> None:
        """Save a model configuration.

        Args:
            model_id: Unique identifier for the model
            config: LLMConfig object
            metadata: Optional metadata (description, tags, etc.)

        """
        from intellicrack.core.config_manager import get_config

        config_data = {
            "provider": config.provider.value,
            "model_name": config.model_name,
            "api_key": config.api_key,
            "api_base": config.api_base,
            "model_path": config.model_path,
            "context_length": config.context_length,
            "temperature": config.temperature,
            "max_tokens": config.max_tokens,
            "tools_enabled": config.tools_enabled,
            "custom_params": config.custom_params or {},
            "created_at": datetime.now().isoformat(),
            "metadata": metadata or {},
        }

        # Save to internal cache
        self.configs[model_id] = config_data

        # Save to central config
        central_config = get_config()
        central_config.set(f"llm_configuration.models.{model_id}", config_data)
        central_config.save()  # Ensure it's persisted immediately

    @deprecated_config_method("IntellicrackConfig.get('llm_configuration.models.{model_id}')")
    def load_model_config(self, model_id: str) -> LLMConfig | None:
        """Load a model configuration by ID.

        Args:
            model_id: Model identifier

        Returns:
            LLMConfig object or None if not found

        """
        from intellicrack.core.config_manager import get_config

        central_config = get_config()
        raw_config = central_config.get(f"llm_configuration.models.{model_id}")

        config_data: dict[str, Any] | None = None
        if isinstance(raw_config, dict):
            config_data = raw_config
        elif model_id in self.configs:
            cached = self.configs[model_id]
            if isinstance(cached, dict):
                config_data = cached

        if config_data is None:
            return None

        try:
            provider_value = config_data.get("provider")
            if not isinstance(provider_value, str):
                return None
            provider = LLMProvider(provider_value)

            model_name = config_data.get("model_name")
            if not isinstance(model_name, str):
                return None

            return LLMConfig(
                provider=provider,
                model_name=model_name,
                api_key=config_data.get("api_key") if isinstance(config_data.get("api_key"), str) else None,
                api_base=config_data.get("api_base") if isinstance(config_data.get("api_base"), str) else None,
                model_path=config_data.get("model_path") if isinstance(config_data.get("model_path"), str) else None,
                context_length=int(config_data.get("context_length", 4096)),
                temperature=float(config_data.get("temperature", 0.7)),
                max_tokens=int(config_data.get("max_tokens", 2048)),
                tools_enabled=bool(config_data.get("tools_enabled", True)),
                custom_params=config_data.get("custom_params") if isinstance(config_data.get("custom_params"), dict) else {},
            )
        except Exception as e:
            logger.exception("Failed to load config for %s: %s", model_id, e)
            return None

    def delete_model_config(self, model_id: str) -> bool:
        """Delete a model configuration.

        Args:
            model_id: Model identifier

        Returns:
            True if deleted, False otherwise

        """
        from intellicrack.core.config_manager import get_config

        if model_id in self.configs:
            # Delete from internal cache
            del self.configs[model_id]

            # Delete from central config
            central_config = get_config()
            central_config.set(f"llm_configuration.models.{model_id}", None)

            # No longer saving to JSON files - central config is the single source of truth

            # Also remove metrics from both central config and internal cache
            if model_id in self.metrics:
                del self.metrics[model_id]
                central_config.set(f"llm_configuration.metrics.{model_id}", None)
                central_config.save()  # Persist the deletion immediately

            return True
        return False

    def list_model_configs(self) -> dict[str, dict[str, Any]]:
        """List all saved model configurations.

        Returns:
            Dictionary of model_id -> config data

        """
        from intellicrack.core.config_manager import get_config

        central_config = get_config()
        raw_configs = central_config.get("llm_configuration.models", {})

        if isinstance(raw_configs, dict) and raw_configs:
            central_configs: dict[str, dict[str, Any]] = {
                str(key): dict(value)
                for key, value in raw_configs.items()
                if isinstance(value, dict)
            }
            self.configs.update(central_configs)
            return central_configs.copy()

        result: dict[str, dict[str, Any]] = {
            str(key): dict(value)
            for key, value in self.configs.items()
            if isinstance(value, dict)
        }
        return result

    def auto_load_models(
        self,
        llm_manager: "LLMManager | None" = None,
    ) -> tuple[int, int]:
        """Auto-load all saved models into the LLM manager.

        Args:
            llm_manager: LLMManager instance (uses global if not provided)

        Returns:
            Tuple of (loaded_count, failed_count) for models loaded

        """
        if llm_manager is None:
            llm_manager = get_llm_manager()

        loaded = 0
        failed = 0

        for model_id, config_data in self.configs.items():
            if config_data.get("metadata", {}).get("auto_load", True):
                if config := self.load_model_config(model_id):
                    try:
                        if llm_manager.register_llm(model_id, config):
                            loaded += 1
                            logger.info("Auto-loaded model: %s", model_id)
                        else:
                            failed += 1
                            logger.warning("Failed to register model: %s", model_id)
                    except Exception as e:
                        failed += 1
                        logger.exception("Error loading model %s: %s", model_id, e)
                else:
                    failed += 1

        logger.info("Auto-load complete: %d loaded, %d failed", loaded, failed)
        return loaded, failed

    @deprecated_config_method("IntellicrackConfig.set('llm_configuration.profiles.{profile_id}', data)")
    def save_profile(self, profile_id: str, profile_data: dict[str, Any]) -> None:
        """Save a model profile.

        Args:
            profile_id: Unique profile identifier
            profile_data: Profile configuration

        """
        from intellicrack.core.config_manager import get_config

        # Save to internal cache
        self.profiles[profile_id] = profile_data

        # Save to central config
        central_config = get_config()
        central_config.set(f"llm_configuration.profiles.{profile_id}", profile_data)

        # No longer saving to JSON files - central config is the single source of truth
        central_config.save()  # Persist immediately

    def get_profile(self, profile_id: str) -> dict[str, Any] | None:
        """Get a model profile by ID.

        Args:
            profile_id: Profile identifier

        Returns:
            Profile data or None

        """
        from intellicrack.core.config_manager import get_config

        central_config = get_config()
        raw_profile = central_config.get(f"llm_configuration.profiles.{profile_id}")

        if isinstance(raw_profile, dict):
            return dict(raw_profile)

        cached_profile = self.profiles.get(profile_id)
        return cached_profile if isinstance(cached_profile, dict) else None

    def list_profiles(self) -> dict[str, dict[str, Any]]:
        """List all available profiles.

        Returns:
            Dictionary of profile_id -> profile data

        """
        from intellicrack.core.config_manager import get_config

        central_config = get_config()
        raw_profiles = central_config.get("llm_configuration.profiles", {})

        if isinstance(raw_profiles, dict) and raw_profiles:
            central_profiles: dict[str, dict[str, Any]] = {
                str(key): dict(value)
                for key, value in raw_profiles.items()
                if isinstance(value, dict)
            }
            for key, value in central_profiles.items():
                self.profiles[key] = value
            return central_profiles.copy()

        return self.profiles.copy()

    def apply_profile(self, config: LLMConfig, profile_id: str) -> LLMConfig:
        """Apply a profile to a model configuration.

        Args:
            config: Base LLMConfig
            profile_id: Profile to apply

        Returns:
            Modified LLMConfig

        """
        profile = self.get_profile(profile_id)
        if not profile:
            logger.warning("Profile not found: %s", profile_id)
            return config

        settings = profile.get("settings", {})

        # Apply profile settings
        if "temperature" in settings:
            config.temperature = settings["temperature"]
        if "max_tokens" in settings:
            config.max_tokens = settings["max_tokens"]

        # Apply custom parameters
        if config.custom_params is None:
            config.custom_params = {}

        for key in ["top_p", "frequency_penalty", "presence_penalty"]:
            if key in settings:
                config.custom_params[key] = settings[key]

        return config

    def save_metrics(self, model_id: str, metrics: dict[str, Any]) -> None:
        """Save performance metrics for a model.

        Args:
            model_id: Model identifier
            metrics: Performance metrics (speed, memory, etc.)

        """
        from intellicrack.core.config_manager import get_config

        if model_id not in self.metrics:
            self.metrics[model_id] = {
                "history": [],
                "aggregate": {},
            }

        # Add timestamp
        metrics["timestamp"] = datetime.now().isoformat()

        # Add to history
        self.metrics[model_id]["history"].append(metrics)

        # Keep only last 100 entries
        if len(self.metrics[model_id]["history"]) > 100:
            self.metrics[model_id]["history"] = self.metrics[model_id]["history"][-100:]

        # Update aggregates
        self._update_aggregate_metrics(model_id)

        # Save to central config
        central_config = get_config()
        central_config.set(f"llm_configuration.metrics.{model_id}", self.metrics[model_id])
        central_config.save()  # Persist immediately to central config

    def _update_aggregate_metrics(self, model_id: str) -> None:
        """Update aggregate metrics for a model."""
        history = self.metrics[model_id]["history"]
        if not history:
            return

        # Calculate averages
        total_tokens = sum(m.get("tokens_generated", 0) for m in history)
        total_time = sum(m.get("generation_time", 0) for m in history)
        total_memory = sum(m.get("memory_mb", 0) for m in history if m.get("memory_mb"))

        count = len(history)
        memory_count = sum(bool(m.get("memory_mb")) for m in history)

        self.metrics[model_id]["aggregate"] = {
            "total_uses": count,
            "total_tokens": total_tokens,
            "avg_tokens_per_use": total_tokens / count if count > 0 else 0,
            "avg_generation_time": total_time / count if count > 0 else 0,
            "avg_memory_mb": total_memory / memory_count if memory_count > 0 else 0,
            "tokens_per_second": total_tokens / total_time if total_time > 0 else 0,
            "last_used": history[-1]["timestamp"],
        }

    def get_metrics(self, model_id: str) -> dict[str, Any] | None:
        """Get metrics for a model.

        Args:
            model_id: Model identifier

        Returns:
            Metrics data or None

        """
        from intellicrack.core.config_manager import get_config

        central_config = get_config()
        raw_metrics = central_config.get(f"llm_configuration.metrics.{model_id}")

        if isinstance(raw_metrics, dict):
            return dict(raw_metrics)

        cached_metrics = self.metrics.get(model_id)
        return cached_metrics if isinstance(cached_metrics, dict) else None

    def export_config(self, export_path: str, include_api_keys: bool = False) -> None:
        """Export all configurations to a file.

        Args:
            export_path: Path to export file
            include_api_keys: Whether to include API keys

        """
        export_data = {
            "version": "1.0",
            "exported_at": datetime.now().isoformat(),
            "configs": {},
            "profiles": self.profiles,
            "metrics": self.metrics,
        }

        # Copy configs, optionally removing API keys
        for model_id, config in self.configs.items():
            config_copy = config.copy()
            if not include_api_keys and "api_key" in config_copy:
                config_copy["api_key"] = "***REDACTED***"
            export_data["configs"][model_id] = config_copy

        try:
            with open(export_path, "w", encoding="utf-8") as f:
                json.dump(export_data, f, indent=2, default=str)
            logger.info("Exported configuration to %s", export_path)
        except Exception as e:
            logger.exception("Failed to export configuration: %s", e)

    def switch_backend(self, backend_name: str) -> bool:
        """Switch to a different LLM backend.

        Args:
            backend_name: Name of the backend to switch to (e.g., 'openai', 'anthropic', 'ollama')

        Returns:
            True if switch was successful, False otherwise

        """
        from intellicrack.core.config_manager import get_config

        valid_backends = {
            "openai": LLMProvider.OPENAI,
            "anthropic": LLMProvider.ANTHROPIC,
            "google": LLMProvider.GOOGLE,
            "ollama": LLMProvider.OLLAMA,
            "local": LLMProvider.LOCAL_API,
            "local_api": LLMProvider.LOCAL_API,
            "local_gguf": LLMProvider.LOCAL_GGUF,
            "llamacpp": LLMProvider.LLAMACPP,
            "huggingface": LLMProvider.HUGGINGFACE,
            "pytorch": LLMProvider.PYTORCH,
        }

        normalized_name = backend_name.lower().strip()

        if normalized_name not in valid_backends:
            logger.exception("Unknown backend: %s. Valid backends: %s", backend_name, list(valid_backends.keys()))
            return False

        try:
            central_config = get_config()
            raw_current = central_config.get("llm_configuration.active_backend", "")
            current_backend = str(raw_current) if raw_current else ""

            if current_backend == normalized_name:
                logger.info("Already using backend: %s", normalized_name)
                return True

            raw_backend = central_config.get(f"llm_configuration.backends.{normalized_name}", {})
            backend_config = dict(raw_backend) if isinstance(raw_backend, dict) else {}
            if not backend_config:
                backend_config = self._create_default_backend_config(normalized_name)
                central_config.set(f"llm_configuration.backends.{normalized_name}", backend_config)

            llm_manager = get_llm_manager()

            provider = valid_backends[normalized_name]
            raw_api_key = backend_config.get("api_key")
            api_key = str(raw_api_key) if raw_api_key else os.environ.get(f"{normalized_name.upper()}_API_KEY", "")
            raw_api_base = backend_config.get("api_base", "")
            api_base = str(raw_api_base) if raw_api_base else ""
            default_model = self._get_default_model_for_backend(normalized_name)
            raw_model = backend_config.get("default_model", default_model)
            model_name = str(raw_model) if raw_model else default_model

            config = LLMConfig(
                provider=provider,
                model_name=model_name,
                api_key=api_key,
                api_base=api_base or None,
                context_length=backend_config.get("context_length", 4096),
                temperature=backend_config.get("temperature", 0.7),
                max_tokens=backend_config.get("max_tokens", 2048),
                tools_enabled=backend_config.get("tools_enabled", True),
            )

            backend_id = f"{normalized_name}_default"
            if llm_manager.register_llm(backend_id, config):
                central_config.set("llm_configuration.active_backend", normalized_name)
                central_config.set("llm_configuration.active_backend_id", backend_id)
                central_config.save()

                logger.info("Successfully switched to backend: %s", normalized_name)
                return True
            logger.exception("Failed to register backend: %s", normalized_name)
            return False

        except Exception as e:
            logger.exception("Error switching to backend %s: %s", backend_name, e)
            return False

    def _create_default_backend_config(self, backend_name: str) -> dict[str, Any]:
        """Create default configuration for a backend.

        Args:
            backend_name: Name of the backend

        Returns:
            Default configuration dictionary

        """
        defaults = {
            "openai": {
                "api_base": "https://api.openai.com/v1",
                "default_model": "gpt-4-turbo-preview",
                "context_length": 128000,
                "max_tokens": 4096,
            },
            "anthropic": {
                "api_base": "https://api.anthropic.com",
                "default_model": "claude-3-sonnet-20240229",
                "context_length": 200000,
                "max_tokens": 4096,
            },
            "google": {
                "api_base": "https://generativelanguage.googleapis.com",
                "default_model": "gemini-pro",
                "context_length": 32000,
                "max_tokens": 2048,
            },
            "ollama": {
                "api_base": "http://localhost:11434",
                "default_model": "llama3",
                "context_length": 8192,
                "max_tokens": 2048,
            },
            "local": {
                "api_base": "",
                "default_model": "local-model",
                "context_length": 4096,
                "max_tokens": 2048,
            },
            "lmstudio": {
                "api_base": "http://localhost:1234/v1",
                "default_model": "local-model",
                "context_length": 4096,
                "max_tokens": 2048,
            },
            "openrouter": {
                "api_base": "https://openrouter.ai/api/v1",
                "default_model": "openai/gpt-3.5-turbo",
                "context_length": 16000,
                "max_tokens": 4096,
            },
        }

        backend_defaults = defaults.get(
            backend_name,
            {
                "api_base": "",
                "default_model": "default",
                "context_length": 4096,
                "max_tokens": 2048,
            },
        )

        return {
            "enabled": True,
            "api_key": "",
            "api_base": backend_defaults["api_base"],
            "default_model": backend_defaults["default_model"],
            "context_length": backend_defaults["context_length"],
            "max_tokens": backend_defaults["max_tokens"],
            "temperature": 0.7,
            "tools_enabled": True,
            "created_at": datetime.now().isoformat(),
        }

    def _get_default_model_for_backend(self, backend_name: str) -> str:
        """Get the default model name for a backend.

        Args:
            backend_name: Name of the backend

        Returns:
            Default model name

        """
        model_defaults = {
            "openai": "gpt-4-turbo-preview",
            "anthropic": "claude-3-sonnet-20240229",
            "google": "gemini-pro",
            "ollama": "llama3",
            "local": "local-model",
            "lmstudio": "local-model",
            "openrouter": "openai/gpt-3.5-turbo",
        }
        return model_defaults.get(backend_name, "default")

    def import_config(self, import_path: str, merge: bool = True) -> None:
        """Import configurations from a file.

        Args:
            import_path: Path to import file
            merge: Whether to merge with existing configs

        """
        try:
            with open(import_path, encoding="utf-8") as f:
                import_data = json.load(f)

            if not merge:
                self.configs = {}
                self.profiles = self._get_default_profiles()
                self.metrics = {}

            # Import configs
            for model_id, config in import_data.get("configs", {}).items():
                if "***REDACTED***" not in str(config.get("api_key", "")):
                    self.configs[model_id] = config
                else:
                    logger.warning("Skipping %s - API key redacted", model_id)

            # Import profiles
            self.profiles.update(import_data.get("profiles", {}))

            # Import metrics
            self.metrics.update(import_data.get("metrics", {}))

            # Save all to central config
            from intellicrack.core.config_manager import get_config

            central_config = get_config()

            # Save models
            for model_id, config_data in self.configs.items():
                central_config.set(f"llm_configuration.models.{model_id}", config_data)

            # Save profiles
            for profile_id, profile_data in self.profiles.items():
                central_config.set(f"llm_configuration.profiles.{profile_id}", profile_data)

            # Save metrics
            central_config.set("llm_configuration.metrics", self.metrics)

            # Persist all changes
            central_config.save()

            logger.info("Imported configuration from %s", import_path)

        except Exception as e:
            logger.exception("Failed to import configuration: %s", e)


# Global instance
_CONFIG_MANAGER = None


def get_llm_config_manager() -> LLMConfigManager:
    """Get the global LLM configuration manager."""
    global _CONFIG_MANAGER
    if _CONFIG_MANAGER is None:
        _CONFIG_MANAGER = LLMConfigManager()
    return _CONFIG_MANAGER

"""LLM Configuration Manager for Intellicrack

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
along with Intellicrack.  If not, see <https://www.gnu.org/licenses/>.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from ..utils.logger import get_logger
from .llm_backends import LLMConfig, LLMProvider, get_llm_manager

logger = get_logger(__name__)


class LLMConfigManager:
    """Manages saving, loading, and organizing LLM configurations."""

    def __init__(self, config_dir: str | None = None):
        """Initialize the LLM configuration manager.

        Args:
            config_dir: Directory to store configuration files.
                       Defaults to ~/.intellicrack/llm_configs

        """
        if config_dir is None:
            config_dir = Path.home() / ".intellicrack" / "llm_configs"

        self.config_dir = Path(config_dir)
        self.config_dir.mkdir(parents=True, exist_ok=True)

        self.config_file = self.config_dir / "models.json"
        self.profiles_file = self.config_dir / "profiles.json"
        self.metrics_file = self.config_dir / "metrics.json"

        self.configs = {}
        self.profiles = {}
        self.metrics = {}

        self._load_all_configs()

    def _load_all_configs(self):
        """Load all configuration files."""
        self.configs = self._load_json_file(self.config_file, {})
        self.profiles = self._load_json_file(
            self.profiles_file, self._get_default_profiles())
        self.metrics = self._load_json_file(self.metrics_file, {})

    def _load_json_file(self, file_path: Path, default: Any) -> Any:
        """Load a JSON file with error handling."""
        if not file_path.exists():
            return default

        try:
            with open(file_path, encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load {file_path}: {e}")
            return default

    def _save_json_file(self, file_path: Path, data: Any):
        """Save data to a JSON file."""
        try:
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, default=str)
            logger.info(f"Saved configuration to {file_path}")
        except Exception as e:
            logger.error(f"Failed to save {file_path}: {e}")

    def _get_default_profiles(self) -> dict[str, dict[str, Any]]:
        """Get default model profiles for different use cases."""
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
                "recommended_models": [
                    "gpt-4", "claude-3-5-sonnet-20241022", "codellama",
                    "deepseek-coder", "starcoder",
                ],
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
                "recommended_models": [
                    "gpt-4", "claude-3-opus-20240229", "llama2-70b",
                ],
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
                "recommended_models": [
                    "gpt-4", "claude-3-5-sonnet-20241022", "mixtral-8x7b",
                ],
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
                "recommended_models": [
                    "gpt-3.5-turbo", "claude-3-haiku-20240307", "mistral-7b",
                ],
            },
        }

    def save_model_config(self, model_id: str, config: LLMConfig, metadata: dict | None = None):
        """Save a model configuration.

        Args:
            model_id: Unique identifier for the model
            config: LLMConfig object
            metadata: Optional metadata (description, tags, etc.)

        """
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

        self.configs[model_id] = config_data
        self._save_json_file(self.config_file, self.configs)

    def load_model_config(self, model_id: str) -> LLMConfig | None:
        """Load a model configuration by ID.

        Args:
            model_id: Model identifier

        Returns:
            LLMConfig object or None if not found

        """
        if model_id not in self.configs:
            return None

        config_data = self.configs[model_id]

        try:
            provider = LLMProvider(config_data["provider"])

            config = LLMConfig(
                provider=provider,
                model_name=config_data["model_name"],
                api_key=config_data.get("api_key"),
                api_base=config_data.get("api_base"),
                model_path=config_data.get("model_path"),
                context_length=config_data.get("context_length", 4096),
                temperature=config_data.get("temperature", 0.7),
                max_tokens=config_data.get("max_tokens", 2048),
                tools_enabled=config_data.get("tools_enabled", True),
                custom_params=config_data.get("custom_params", {}),
            )

            return config

        except Exception as e:
            logger.error(f"Failed to load config for {model_id}: {e}")
            return None

    def delete_model_config(self, model_id: str) -> bool:
        """Delete a model configuration.

        Args:
            model_id: Model identifier

        Returns:
            True if deleted, False otherwise

        """
        if model_id in self.configs:
            del self.configs[model_id]
            self._save_json_file(self.config_file, self.configs)

            # Also remove metrics
            if model_id in self.metrics:
                del self.metrics[model_id]
                self._save_json_file(self.metrics_file, self.metrics)

            return True
        return False

    def list_model_configs(self) -> dict[str, dict[str, Any]]:
        """List all saved model configurations.

        Returns:
            Dictionary of model_id -> config data

        """
        return self.configs.copy()

    def auto_load_models(self, llm_manager=None):
        """Auto-load all saved models into the LLM manager.

        Args:
            llm_manager: LLMManager instance (uses global if not provided)

        """
        if llm_manager is None:
            llm_manager = get_llm_manager()

        loaded = 0
        failed = 0

        for model_id, config_data in self.configs.items():
            if config_data.get("metadata", {}).get("auto_load", True):
                config = self.load_model_config(model_id)
                if config:
                    try:
                        if llm_manager.register_llm(model_id, config):
                            loaded += 1
                            logger.info(f"Auto-loaded model: {model_id}")
                        else:
                            failed += 1
                            logger.warning(
                                f"Failed to register model: {model_id}")
                    except Exception as e:
                        failed += 1
                        logger.error(f"Error loading model {model_id}: {e}")
                else:
                    failed += 1

        logger.info(f"Auto-load complete: {loaded} loaded, {failed} failed")
        return loaded, failed

    def save_profile(self, profile_id: str, profile_data: dict[str, Any]):
        """Save a model profile.

        Args:
            profile_id: Unique profile identifier
            profile_data: Profile configuration

        """
        self.profiles[profile_id] = profile_data
        self._save_json_file(self.profiles_file, self.profiles)

    def get_profile(self, profile_id: str) -> dict[str, Any] | None:
        """Get a model profile by ID.

        Args:
            profile_id: Profile identifier

        Returns:
            Profile data or None

        """
        return self.profiles.get(profile_id)

    def list_profiles(self) -> dict[str, dict[str, Any]]:
        """List all available profiles.

        Returns:
            Dictionary of profile_id -> profile data

        """
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
            logger.warning(f"Profile not found: {profile_id}")
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

    def save_metrics(self, model_id: str, metrics: dict[str, Any]):
        """Save performance metrics for a model.

        Args:
            model_id: Model identifier
            metrics: Performance metrics (speed, memory, etc.)

        """
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

        self._save_json_file(self.metrics_file, self.metrics)

    def _update_aggregate_metrics(self, model_id: str):
        """Update aggregate metrics for a model."""
        history = self.metrics[model_id]["history"]
        if not history:
            return

        # Calculate averages
        total_tokens = sum(m.get("tokens_generated", 0) for m in history)
        total_time = sum(m.get("generation_time", 0) for m in history)
        total_memory = sum(m.get("memory_mb", 0)
                           for m in history if m.get("memory_mb"))

        count = len(history)
        memory_count = sum(1 for m in history if m.get("memory_mb"))

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
        return self.metrics.get(model_id)

    def export_config(self, export_path: str, include_api_keys: bool = False):
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
            logger.info(f"Exported configuration to {export_path}")
        except Exception as e:
            logger.error(f"Failed to export configuration: {e}")

    def import_config(self, import_path: str, merge: bool = True):
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
                    logger.warning(f"Skipping {model_id} - API key redacted")

            # Import profiles
            self.profiles.update(import_data.get("profiles", {}))

            # Import metrics
            self.metrics.update(import_data.get("metrics", {}))

            # Save all
            self._save_json_file(self.config_file, self.configs)
            self._save_json_file(self.profiles_file, self.profiles)
            self._save_json_file(self.metrics_file, self.metrics)

            logger.info(f"Imported configuration from {import_path}")

        except Exception as e:
            logger.error(f"Failed to import configuration: {e}")


# Global instance
_CONFIG_MANAGER = None


def get_llm_config_manager() -> LLMConfigManager:
    """Get the global LLM configuration manager."""
    global _CONFIG_MANAGER
    if _CONFIG_MANAGER is None:
        _CONFIG_MANAGER = LLMConfigManager()
    return _CONFIG_MANAGER

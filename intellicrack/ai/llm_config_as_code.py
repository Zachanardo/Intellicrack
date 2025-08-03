"""Config-as-Code Support for Intellicrack LLM System

Provides YAML/JSON configuration management with schema validation.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import json
import os
import re
from pathlib import Path
from typing import Any

from ..utils.logger import get_logger

logger = get_logger(__name__)

# Optional YAML support
HAS_YAML = False
try:
    import yaml

    HAS_YAML = True
except ImportError:
    logger.warning("PyYAML not available - YAML support disabled. Install with: pip install pyyaml")

# Optional JSON Schema validation
HAS_JSONSCHEMA = False
try:
    import jsonschema

    HAS_JSONSCHEMA = True
except ImportError:
    logger.warning(
        "jsonschema not available - schema validation disabled. Install with: pip install jsonschema"
    )


class ConfigValidationError(Exception):
    """Raised when configuration validation fails."""


class ConfigAsCodeManager:
    """Manages configuration files with YAML/JSON support and schema validation."""

    def __init__(self, config_dir: str | None = None):
        """Initialize the config-as-code manager.

        Args:
            config_dir: Directory for configuration files

        """
        if config_dir is None:
            config_dir = Path.home() / ".intellicrack" / "config"

        self.config_dir = Path(config_dir)
        self.config_dir.mkdir(parents=True, exist_ok=True)

        # Schema definitions
        self.schemas = self._load_schemas()

        logger.info(f"ConfigAsCodeManager initialized with directory: {self.config_dir}")

    def _load_schemas(self) -> dict[str, dict[str, Any]]:
        """Load JSON schemas for validation."""
        schemas = {}

        # LLM Model Configuration Schema
        schemas["llm_model"] = {
            "type": "object",
            "properties": {
                "provider": {
                    "type": "string",
                    "enum": [
                        "openai",
                        "anthropic",
                        "llamacpp",
                        "ollama",
                        "huggingface",
                        "local_api",
                        "local_gguf",
                        "pytorch",
                        "tensorflow",
                        "onnx",
                        "safetensors",
                        "gptq",
                        "huggingface_local",
                    ],
                },
                "model_name": {"type": "string"},
                "api_key": {"type": ["string", "null"]},
                "api_base": {"type": ["string", "null"]},
                "model_path": {"type": ["string", "null"]},
                "context_length": {"type": "integer", "minimum": 512, "maximum": 2000000},
                "temperature": {"type": "number", "minimum": 0.0, "maximum": 2.0},
                "max_tokens": {"type": "integer", "minimum": 1, "maximum": 100000},
                "tools_enabled": {"type": "boolean"},
                "custom_params": {"type": "object"},
            },
            "required": ["provider", "model_name"],
            "additionalProperties": True,
        }

        # Fallback Chain Configuration Schema
        schemas["fallback_chain"] = {
            "type": "object",
            "properties": {
                "chain_id": {"type": "string"},
                "max_retries": {"type": "integer", "minimum": 1, "maximum": 10},
                "retry_delay": {"type": "number", "minimum": 0.1, "maximum": 60.0},
                "circuit_failure_threshold": {"type": "integer", "minimum": 1, "maximum": 100},
                "enable_adaptive_ordering": {"type": "boolean"},
                "models": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "model_id": {"type": "string"},
                            **schemas["llm_model"]["properties"],
                        },
                        "required": ["model_id"] + schemas["llm_model"]["required"],
                    },
                    "minItems": 1,
                },
            },
            "required": ["chain_id", "models"],
            "additionalProperties": False,
        }

        # Complete Configuration Schema
        schemas["complete_config"] = {
            "type": "object",
            "properties": {
                "version": {"type": "string"},
                "environment": {"type": "string", "enum": ["development", "staging", "production"]},
                "metadata": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "description": {"type": "string"},
                        "author": {"type": "string"},
                        "created_at": {"type": "string"},
                        "updated_at": {"type": "string"},
                    },
                },
                "models": {
                    "type": "object",
                    "patternProperties": {
                        "^[a-zA-Z0-9_-]+$": schemas["llm_model"],
                    },
                },
                "fallback_chains": {
                    "type": "object",
                    "patternProperties": {
                        "^[a-zA-Z0-9_-]+$": schemas["fallback_chain"],
                    },
                },
                "profiles": {
                    "type": "object",
                    "patternProperties": {
                        "^[a-zA-Z0-9_-]+$": {
                            "type": "object",
                            "properties": {
                                "name": {"type": "string"},
                                "description": {"type": "string"},
                                "settings": {"type": "object"},
                                "recommended_models": {
                                    "type": "array",
                                    "items": {"type": "string"},
                                },
                            },
                            "required": ["name", "settings"],
                        },
                    },
                },
                "default_settings": {
                    "type": "object",
                    "properties": {
                        "default_chain": {"type": "string"},
                        "default_model": {"type": "string"},
                        "default_profile": {"type": "string"},
                        "auto_load_models": {"type": "boolean"},
                        "enable_fallback_chains": {"type": "boolean"},
                    },
                },
            },
            "required": ["version"],
            "additionalProperties": True,
        }

        return schemas

    def validate_config(self, config: dict[str, Any], schema_name: str = "complete_config") -> bool:
        """Validate configuration against schema.

        Args:
            config: Configuration dictionary to validate
            schema_name: Name of schema to validate against

        Returns:
            True if valid

        Raises:
            ConfigValidationError: If validation fails

        """
        if not HAS_JSONSCHEMA:
            logger.warning("Schema validation skipped - jsonschema not available")
            return True

        if schema_name not in self.schemas:
            raise ConfigValidationError(f"Unknown schema: {schema_name}")

        schema = self.schemas[schema_name]

        try:
            jsonschema.validate(config, schema)
            logger.debug(f"Configuration validation passed for schema: {schema_name}")
            return True
        except jsonschema.ValidationError as e:
            error_msg = f"Configuration validation failed: {e.message}"
            if e.absolute_path:
                error_msg += f" at path: {'.'.join(str(p) for p in e.absolute_path)}"

            logger.error(error_msg)
            raise ConfigValidationError(error_msg) from e

    def load_config(self, file_path: str | Path, validate: bool = True) -> dict[str, Any]:
        """Load configuration from YAML or JSON file.

        Args:
            file_path: Path to configuration file
            validate: Whether to validate against schema

        Returns:
            Configuration dictionary

        Raises:
            ConfigValidationError: If validation fails
            FileNotFoundError: If file doesn't exist

        """
        file_path = Path(file_path)

        if not file_path.exists():
            raise FileNotFoundError(f"Configuration file not found: {file_path}")

        # Determine file format
        suffix = file_path.suffix.lower()

        try:
            with open(file_path, encoding="utf-8") as f:
                if suffix in [".yaml", ".yml"]:
                    if not HAS_YAML:
                        raise ConfigValidationError("YAML support not available - install PyYAML")
                    config = yaml.safe_load(f)
                elif suffix == ".json":
                    config = json.load(f)
                else:
                    # Try to auto-detect format
                    content = f.read()
                    f.seek(0)

                    if content.strip().startswith("{"):
                        config = json.load(f)
                    else:
                        if not HAS_YAML:
                            raise ConfigValidationError(
                                "Could not determine file format and YAML not available"
                            )
                        config = yaml.safe_load(f)

            logger.info(f"Loaded configuration from: {file_path}")

            # Perform environment variable substitution
            config = self._substitute_env_vars(config)

            # Validate if requested
            if validate:
                self.validate_config(config)

            return config

        except (yaml.YAMLError if HAS_YAML else Exception, json.JSONDecodeError) as e:
            raise ConfigValidationError(f"Failed to parse configuration file: {e}") from e

    def save_config(
        self,
        config: dict[str, Any],
        file_path: str | Path,
        format_type: str | None = None,
        validate: bool = True,
    ) -> None:
        """Save configuration to YAML or JSON file.

        Args:
            config: Configuration dictionary to save
            file_path: Output file path
            format_type: Format ('yaml' or 'json', auto-detected if None)
            validate: Whether to validate before saving

        Raises:
            ConfigValidationError: If validation fails

        """
        file_path = Path(file_path)

        # Validate before saving
        if validate:
            self.validate_config(config)

        # Determine format
        if format_type is None:
            suffix = file_path.suffix.lower()
            if suffix in [".yaml", ".yml"]:
                format_type = "yaml"
            elif suffix == ".json":
                format_type = "json"
            else:
                format_type = "yaml"  # Default to YAML

        # Ensure directory exists
        file_path.parent.mkdir(parents=True, exist_ok=True)

        try:
            with open(file_path, "w", encoding="utf-8") as f:
                if format_type == "yaml":
                    if not HAS_YAML:
                        raise ConfigValidationError("YAML support not available - install PyYAML")
                    yaml.dump(
                        config,
                        f,
                        default_flow_style=False,
                        sort_keys=False,
                        allow_unicode=True,
                        indent=2,
                    )
                else:
                    json.dump(config, f, indent=2, ensure_ascii=False, default=str)

            logger.info(f"Saved configuration to: {file_path}")

        except Exception as e:
            raise ConfigValidationError(f"Failed to save configuration: {e}") from e

    def _substitute_env_vars(self, obj: Any) -> Any:
        """Recursively substitute environment variables in configuration.

        Supports syntax: ${VAR_NAME}, ${VAR_NAME:default_value}
        """
        if isinstance(obj, dict):
            return {key: self._substitute_env_vars(value) for key, value in obj.items()}
        if isinstance(obj, list):
            return [self._substitute_env_vars(item) for item in obj]
        if isinstance(obj, str):
            return self._substitute_string_vars(obj)
        return obj

    def _substitute_string_vars(self, text: str) -> str:
        """Substitute environment variables in a string."""
        # Pattern: ${VAR_NAME} or ${VAR_NAME:default}
        pattern = r"\$\{([^}:]+)(?::([^}]*))?\}"

        def replace_var(match):
            var_name = match.group(1)
            default_value = match.group(2) if match.group(2) is not None else ""

            return os.environ.get(var_name, default_value)

        return re.sub(pattern, replace_var, text)

    def create_template_config(self, environment: str = "development") -> dict[str, Any]:
        """Create a template configuration file.

        Args:
            environment: Target environment

        Returns:
            Template configuration dictionary

        """
        from datetime import datetime

        template = {
            "version": "1.0",
            "environment": environment,
            "metadata": {
                "name": "Intellicrack LLM Configuration",
                "description": "Configuration for LLM models and fallback chains",
                "author": "Generated by Intellicrack",
                "created_at": datetime.now().isoformat(),
                "updated_at": datetime.now().isoformat(),
            },
            "models": {
                "gpt-4": {
                    "provider": "openai",
                    "model_name": "gpt-4",
                    "api_key": "${OPENAI_API_KEY}",
                    "context_length": 8192,
                    "temperature": 0.7,
                    "max_tokens": 2048,
                    "tools_enabled": True,
                },
                "claude-3-sonnet": {
                    "provider": "anthropic",
                    "model_name": "claude-3-5-sonnet-20241022",
                    "api_key": "${ANTHROPIC_API_KEY}",
                    "context_length": 200000,
                    "temperature": 0.7,
                    "max_tokens": 2048,
                    "tools_enabled": True,
                },
                "local-llama": {
                    "provider": "ollama",
                    "model_name": "llama3.1:8b",
                    "api_base": "http://localhost:11434",
                    "context_length": 4096,
                    "temperature": 0.7,
                    "max_tokens": 2048,
                    "tools_enabled": False,
                },
            },
            "fallback_chains": {
                "primary": {
                    "chain_id": "primary",
                    "max_retries": 3,
                    "retry_delay": 1.0,
                    "circuit_failure_threshold": 5,
                    "enable_adaptive_ordering": True,
                    "models": [
                        {
                            "model_id": "gpt-4",
                            "provider": "openai",
                            "model_name": "gpt-4",
                            "api_key": "${OPENAI_API_KEY}",
                            "tools_enabled": True,
                        },
                        {
                            "model_id": "claude-3-sonnet",
                            "provider": "anthropic",
                            "model_name": "claude-3-5-sonnet-20241022",
                            "api_key": "${ANTHROPIC_API_KEY}",
                            "tools_enabled": True,
                        },
                        {
                            "model_id": "local-llama",
                            "provider": "ollama",
                            "model_name": "llama3.1:8b",
                            "api_base": "http://localhost:11434",
                            "tools_enabled": False,
                        },
                    ],
                },
                "fast": {
                    "chain_id": "fast",
                    "max_retries": 2,
                    "retry_delay": 0.5,
                    "circuit_failure_threshold": 3,
                    "enable_adaptive_ordering": True,
                    "models": [
                        {
                            "model_id": "local-llama",
                            "provider": "ollama",
                            "model_name": "llama3.1:8b",
                            "api_base": "http://localhost:11434",
                            "tools_enabled": False,
                        },
                    ],
                },
            },
            "profiles": {
                "code_generation": {
                    "name": "Code Generation",
                    "description": "Optimized for generating code and scripts",
                    "settings": {
                        "temperature": 0.2,
                        "max_tokens": 4096,
                        "top_p": 0.95,
                    },
                    "recommended_models": ["gpt-4", "claude-3-sonnet"],
                },
                "analysis": {
                    "name": "Binary Analysis",
                    "description": "Optimized for analyzing binaries and patterns",
                    "settings": {
                        "temperature": 0.1,
                        "max_tokens": 2048,
                        "top_p": 0.9,
                    },
                    "recommended_models": ["gpt-4", "claude-3-sonnet"],
                },
            },
            "default_settings": {
                "default_chain": "primary",
                "default_model": "gpt-4",
                "default_profile": "code_generation",
                "auto_load_models": True,
                "enable_fallback_chains": True,
            },
        }

        return template

    def export_current_config(self, llm_manager=None, fallback_manager=None) -> dict[str, Any]:
        """Export current system configuration.

        Args:
            llm_manager: LLMManager instance
            fallback_manager: FallbackManager instance

        Returns:
            Current configuration as dictionary

        """
        from datetime import datetime

        from .llm_backends import get_llm_manager
        from .llm_fallback_chains import get_fallback_manager

        if llm_manager is None:
            llm_manager = get_llm_manager()
        if fallback_manager is None:
            fallback_manager = get_fallback_manager()

        config = {
            "version": "1.0",
            "environment": "exported",
            "metadata": {
                "name": "Exported Intellicrack Configuration",
                "description": "Exported from running system",
                "exported_at": datetime.now().isoformat(),
            },
            "models": {},
            "fallback_chains": {},
            "profiles": {},
            "default_settings": {
                "enable_fallback_chains": True,
                "auto_load_models": True,
            },
        }

        # Export LLM models
        for llm_id in llm_manager.get_available_llms():
            info = llm_manager.get_llm_info(llm_id)
            if info:
                model_config = {
                    "provider": info["provider"],
                    "model_name": info["model_name"],
                    "context_length": info["context_length"],
                    "tools_enabled": info["tools_enabled"],
                }
                config["models"][llm_id] = model_config

        # Export fallback chains
        config["fallback_chains"] = fallback_manager.export_configuration().get("chains", {})
        config["default_settings"]["default_chain"] = fallback_manager.default_chain_id

        return config

    def apply_config(self, config: dict[str, Any], llm_manager=None, fallback_manager=None):
        """Apply configuration to the system.

        Args:
            config: Configuration dictionary
            llm_manager: LLMManager instance
            fallback_manager: FallbackManager instance

        """
        from .llm_backends import LLMConfig, LLMProvider, get_llm_manager
        from .llm_fallback_chains import get_fallback_manager

        if llm_manager is None:
            llm_manager = get_llm_manager()
        if fallback_manager is None:
            fallback_manager = get_fallback_manager()

        # Apply models
        for model_id, model_config in config.get("models", {}).items():
            try:
                provider = LLMProvider(model_config["provider"])
                llm_config = LLMConfig(
                    provider=provider,
                    model_name=model_config["model_name"],
                    api_key=model_config.get("api_key"),
                    api_base=model_config.get("api_base"),
                    model_path=model_config.get("model_path"),
                    context_length=model_config.get("context_length", 4096),
                    temperature=model_config.get("temperature", 0.7),
                    max_tokens=model_config.get("max_tokens", 2048),
                    tools_enabled=model_config.get("tools_enabled", True),
                    custom_params=model_config.get("custom_params", {}),
                )

                llm_manager.register_llm(model_id, llm_config)
                logger.info(f"Applied model configuration: {model_id}")

            except Exception as e:
                logger.error(f"Failed to apply model config {model_id}: {e}")

        # Apply fallback chains
        chains_config = {
            "chains": config.get("fallback_chains", {}),
            "default_chain": config.get("default_settings", {}).get("default_chain"),
        }

        try:
            fallback_manager.import_configuration(chains_config)
            logger.info("Applied fallback chains configuration")
        except Exception as e:
            logger.error(f"Failed to apply fallback chains: {e}")

    def generate_config_files(
        self, output_dir: str | None = None, environments: list[str] = None
    ) -> list[Path]:
        """Generate configuration files for multiple environments.

        Args:
            output_dir: Output directory (uses config_dir if None)
            environments: List of environments to generate

        Returns:
            List of generated file paths

        """
        if output_dir is None:
            output_dir = self.config_dir
        else:
            output_dir = Path(output_dir)

        if environments is None:
            environments = ["development", "staging", "production"]

        generated_files = []

        for env in environments:
            template = self.create_template_config(env)

            # Customize for environment
            if env == "production":
                # More conservative settings for production
                template["default_settings"]["auto_load_models"] = False
                for chain in template["fallback_chains"].values():
                    chain["max_retries"] = 2
                    chain["circuit_failure_threshold"] = 3
            elif env == "development":
                # More aggressive settings for development
                for chain in template["fallback_chains"].values():
                    chain["enable_adaptive_ordering"] = True
                    chain["max_retries"] = 5

            file_path = output_dir / f"llm_config_{env}.yaml"
            self.save_config(template, file_path)
            generated_files.append(file_path)

        logger.info(f"Generated {len(generated_files)} configuration files in {output_dir}")
        return generated_files


# Global instance
_CONFIG_AS_CODE_MANAGER = None


def get_config_as_code_manager() -> ConfigAsCodeManager:
    """Get the global config-as-code manager instance."""
    global _CONFIG_AS_CODE_MANAGER
    if _CONFIG_AS_CODE_MANAGER is None:
        _CONFIG_AS_CODE_MANAGER = ConfigAsCodeManager()
    return _CONFIG_AS_CODE_MANAGER


def load_config_file(
    file_path: str | Path, apply_to_system: bool = True, validate: bool = True
) -> dict[str, Any]:
    """Convenience function to load and optionally apply configuration.

    Args:
        file_path: Path to configuration file
        apply_to_system: Whether to apply to current system
        validate: Whether to validate configuration

    Returns:
        Loaded configuration dictionary

    """
    manager = get_config_as_code_manager()
    config = manager.load_config(file_path, validate)

    if apply_to_system:
        manager.apply_config(config)

    return config


def save_current_config(file_path: str | Path, format_type: str = "yaml") -> None:
    """Convenience function to save current system configuration.

    Args:
        file_path: Output file path
        format_type: Format ('yaml' or 'json')

    """
    manager = get_config_as_code_manager()
    config = manager.export_current_config()
    manager.save_config(config, file_path, format_type)


def create_config_template(output_path: str | Path, environment: str = "development") -> None:
    """Create a template configuration file.

    Args:
        output_path: Output file path
        environment: Target environment

    """
    manager = get_config_as_code_manager()
    template = manager.create_template_config(environment)
    manager.save_config(template, output_path)

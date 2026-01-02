"""Production tests for LLM Config-as-Code management.

This test suite validates the ConfigAsCodeManager's ability to handle
real LLM configuration management for Intellicrack's AI-driven analysis
and script generation capabilities.
"""

import json
import os
from pathlib import Path
from typing import Any

import pytest

from intellicrack.ai.llm_config_as_code import (
    ConfigAsCodeManager,
    ConfigValidationError,
    create_config_template,
    get_config_as_code_manager,
)


@pytest.fixture
def config_manager(tmp_path: Path) -> ConfigAsCodeManager:
    """Create ConfigAsCodeManager for testing.

    Args:
        tmp_path: Temporary directory for config files

    Returns:
        ConfigAsCodeManager: Initialized config manager
    """
    return ConfigAsCodeManager(config_dir=str(tmp_path / "config"))


@pytest.fixture
def valid_llm_model_config() -> dict[str, Any]:
    """Create valid LLM model configuration.

    Returns:
        dict[str, Any]: Valid model configuration
    """
    return {
        "provider": "openai",
        "model_name": "gpt-4",
        "api_key": "sk-test-key-12345",
        "context_length": 8192,
        "temperature": 0.7,
        "max_tokens": 2048,
        "tools_enabled": True,
    }


@pytest.fixture
def valid_complete_config() -> dict[str, Any]:
    """Create valid complete configuration.

    Returns:
        dict[str, Any]: Valid complete configuration
    """
    return {
        "version": "1.0",
        "environment": "development",
        "metadata": {
            "name": "Test Configuration",
            "description": "Test LLM config for Intellicrack",
            "author": "Test Suite",
        },
        "models": {
            "gpt-4-analyzer": {
                "provider": "openai",
                "model_name": "gpt-4",
                "api_key": "sk-test-key",
                "context_length": 8192,
                "temperature": 0.2,
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
                        "api_key": "sk-test",
                        "tools_enabled": True,
                    }
                ],
            }
        },
        "default_settings": {
            "default_chain": "primary",
            "default_model": "gpt-4-analyzer",
            "auto_load_models": True,
            "enable_fallback_chains": True,
        },
    }


class TestConfigAsCodeManagerInitialization:
    """Tests for ConfigAsCodeManager initialization."""

    def test_initialization_creates_config_directory(self, tmp_path: Path) -> None:
        """ConfigAsCodeManager creates configuration directory."""
        config_dir = tmp_path / "test_config"

        manager = ConfigAsCodeManager(config_dir=str(config_dir))

        assert config_dir.exists()
        assert config_dir.is_dir()
        assert manager.config_dir == config_dir

    def test_initialization_loads_schemas(self, config_manager: ConfigAsCodeManager) -> None:
        """ConfigAsCodeManager loads all required schemas."""
        assert "llm_model" in config_manager.schemas
        assert "fallback_chain" in config_manager.schemas
        assert "complete_config" in config_manager.schemas

    def test_initialization_with_default_location(self) -> None:
        """ConfigAsCodeManager uses default location when none specified."""
        manager = ConfigAsCodeManager()

        expected_dir = Path.home() / ".intellicrack" / "config"
        assert manager.config_dir == expected_dir
        assert manager.config_dir.exists()


class TestSchemaValidation:
    """Tests for schema validation functionality."""

    def test_validate_valid_llm_model_config(
        self, config_manager: ConfigAsCodeManager, valid_llm_model_config: dict[str, Any]
    ) -> None:
        """validate_config accepts valid LLM model configuration."""
        result = config_manager.validate_config(valid_llm_model_config, "llm_model")

        assert result is True

    def test_validate_invalid_provider_rejected(self, config_manager: ConfigAsCodeManager) -> None:
        """validate_config rejects invalid provider names."""
        invalid_config = {
            "provider": "invalid_provider",
            "model_name": "test-model",
        }

        with pytest.raises(ConfigValidationError) as exc_info:
            config_manager.validate_config(invalid_config, "llm_model")

        assert "invalid_provider" in str(exc_info.value).lower() or "validation" in str(exc_info.value).lower()

    def test_validate_missing_required_fields(self, config_manager: ConfigAsCodeManager) -> None:
        """validate_config rejects configurations missing required fields."""
        incomplete_config = {"provider": "openai"}

        with pytest.raises(ConfigValidationError) as exc_info:
            config_manager.validate_config(incomplete_config, "llm_model")

        assert "required" in str(exc_info.value).lower() or "model_name" in str(exc_info.value).lower()

    def test_validate_invalid_temperature_range(self, config_manager: ConfigAsCodeManager) -> None:
        """validate_config rejects temperature values outside valid range."""
        invalid_config = {
            "provider": "openai",
            "model_name": "gpt-4",
            "temperature": 3.0,
        }

        with pytest.raises(ConfigValidationError):
            config_manager.validate_config(invalid_config, "llm_model")

    def test_validate_invalid_context_length(self, config_manager: ConfigAsCodeManager) -> None:
        """validate_config rejects context_length below minimum."""
        invalid_config = {
            "provider": "openai",
            "model_name": "gpt-4",
            "context_length": 256,
        }

        with pytest.raises(ConfigValidationError):
            config_manager.validate_config(invalid_config, "llm_model")

    def test_validate_complete_config_valid(
        self, config_manager: ConfigAsCodeManager, valid_complete_config: dict[str, Any]
    ) -> None:
        """validate_config accepts valid complete configuration."""
        result = config_manager.validate_config(valid_complete_config, "complete_config")

        assert result is True

    def test_validate_unknown_schema_raises_error(self, config_manager: ConfigAsCodeManager) -> None:
        """validate_config raises error for unknown schema name."""
        with pytest.raises(ConfigValidationError) as exc_info:
            config_manager.validate_config({}, "nonexistent_schema")

        assert "Unknown schema" in str(exc_info.value)


class TestConfigLoading:
    """Tests for configuration file loading."""

    def test_load_json_config_file(
        self, config_manager: ConfigAsCodeManager, valid_complete_config: dict[str, Any]
    ) -> None:
        """load_config successfully loads JSON configuration files."""
        config_file = config_manager.config_dir / "test.json"

        with open(config_file, "w") as f:
            json.dump(valid_complete_config, f)

        loaded = config_manager.load_config(config_file)

        assert loaded["version"] == "1.0"
        assert loaded["environment"] == "development"
        assert "gpt-4-analyzer" in loaded["models"]

    def test_load_config_validates_by_default(self, config_manager: ConfigAsCodeManager) -> None:
        """load_config validates configuration by default."""
        invalid_config = {"version": "1.0", "models": {"invalid": {"provider": "fake"}}}

        config_file = config_manager.config_dir / "invalid.json"
        with open(config_file, "w") as f:
            json.dump(invalid_config, f)

        with pytest.raises(ConfigValidationError):
            config_manager.load_config(config_file)

    def test_load_config_skip_validation(self, config_manager: ConfigAsCodeManager) -> None:
        """load_config can skip validation when requested."""
        invalid_config = {"test": "data"}

        config_file = config_manager.config_dir / "test.json"
        with open(config_file, "w") as f:
            json.dump(invalid_config, f)

        loaded = config_manager.load_config(config_file, validate=False)

        assert loaded["test"] == "data"

    def test_load_config_nonexistent_file(self, config_manager: ConfigAsCodeManager) -> None:
        """load_config raises FileNotFoundError for missing files."""
        with pytest.raises(FileNotFoundError):
            config_manager.load_config(config_manager.config_dir / "nonexistent.json")

    def test_load_config_malformed_json(self, config_manager: ConfigAsCodeManager) -> None:
        """load_config handles malformed JSON gracefully."""
        config_file = config_manager.config_dir / "malformed.json"

        with open(config_file, "w") as f:
            f.write("{invalid json content")

        with pytest.raises(ConfigValidationError) as exc_info:
            config_manager.load_config(config_file)

        assert "parse" in str(exc_info.value).lower()


class TestEnvironmentVariableSubstitution:
    """Tests for environment variable substitution."""

    def test_substitute_env_vars_basic(self, config_manager: ConfigAsCodeManager) -> None:
        """Environment variable substitution works for basic variables."""
        os.environ["TEST_API_KEY"] = "test-key-12345"

        config = {"api_key": "${TEST_API_KEY}"}

        result = config_manager._substitute_env_vars(config)

        assert isinstance(result, dict)
        assert result["api_key"] == "test-key-12345"

        del os.environ["TEST_API_KEY"]

    def test_substitute_env_vars_with_default(self, config_manager: ConfigAsCodeManager) -> None:
        """Environment variable substitution uses default when var not set."""
        config = {"api_key": "${NONEXISTENT_KEY:default_value}"}

        result = config_manager._substitute_env_vars(config)

        assert isinstance(result, dict)
        assert result["api_key"] == "default_value"

    def test_substitute_env_vars_nested_objects(self, config_manager: ConfigAsCodeManager) -> None:
        """Environment variable substitution works in nested objects."""
        os.environ["TEST_MODEL"] = "gpt-4"

        config = {
            "models": {
                "primary": {"model_name": "${TEST_MODEL}", "api_key": "${API_KEY:default}"}
            }
        }

        result = config_manager._substitute_env_vars(config)

        assert isinstance(result, dict)
        models = result["models"]
        assert isinstance(models, dict)
        primary = models["primary"]
        assert isinstance(primary, dict)
        assert primary["model_name"] == "gpt-4"
        assert primary["api_key"] == "default"

        del os.environ["TEST_MODEL"]

    def test_substitute_env_vars_in_lists(self, config_manager: ConfigAsCodeManager) -> None:
        """Environment variable substitution works in lists."""
        os.environ["ENDPOINT"] = "http://localhost:11434"

        config = {"endpoints": ["${ENDPOINT}", "${BACKUP:http://fallback:8080}"]}

        result = config_manager._substitute_env_vars(config)

        assert isinstance(result, dict)
        endpoints = result["endpoints"]
        assert isinstance(endpoints, list)
        assert endpoints[0] == "http://localhost:11434"
        assert endpoints[1] == "http://fallback:8080"

        del os.environ["ENDPOINT"]


class TestConfigSaving:
    """Tests for configuration file saving."""

    def test_save_json_config(
        self, config_manager: ConfigAsCodeManager, valid_complete_config: dict[str, Any]
    ) -> None:
        """save_config creates valid JSON files."""
        output_file = config_manager.config_dir / "output.json"

        config_manager.save_config(valid_complete_config, output_file, format_type="json")

        assert output_file.exists()

        with open(output_file) as f:
            loaded = json.load(f)

        assert loaded["version"] == "1.0"
        assert "gpt-4-analyzer" in loaded["models"]

    def test_save_config_creates_parent_directories(
        self, config_manager: ConfigAsCodeManager, valid_complete_config: dict[str, Any]
    ) -> None:
        """save_config creates parent directories if they don't exist."""
        output_file = config_manager.config_dir / "subdir" / "nested" / "config.json"

        config_manager.save_config(valid_complete_config, output_file)

        assert output_file.exists()
        assert output_file.parent.exists()

    def test_save_config_validates_before_saving(self, config_manager: ConfigAsCodeManager) -> None:
        """save_config validates configuration before writing."""
        invalid_config = {"version": "1.0", "models": {"bad": {"provider": "invalid"}}}

        output_file = config_manager.config_dir / "invalid.json"

        with pytest.raises(ConfigValidationError):
            config_manager.save_config(invalid_config, output_file)

        assert not output_file.exists()

    def test_save_config_skip_validation(self, config_manager: ConfigAsCodeManager) -> None:
        """save_config can skip validation when requested."""
        test_config = {"arbitrary": "data"}

        output_file = config_manager.config_dir / "test.json"

        config_manager.save_config(test_config, output_file, validate=False)

        assert output_file.exists()


class TestTemplateGeneration:
    """Tests for configuration template generation."""

    def test_create_template_config_generates_valid_config(self, config_manager: ConfigAsCodeManager) -> None:
        """create_template_config generates valid configuration."""
        template = config_manager.create_template_config("development")

        assert template["version"] == "1.0"
        assert template["environment"] == "development"
        assert "gpt-4" in template["models"]
        assert "claude-3-sonnet" in template["models"]
        assert "local-llama" in template["models"]

    def test_create_template_includes_fallback_chains(self, config_manager: ConfigAsCodeManager) -> None:
        """create_template_config includes fallback chain configurations."""
        template = config_manager.create_template_config("production")

        assert "fallback_chains" in template
        assert "primary" in template["fallback_chains"]
        assert "fast" in template["fallback_chains"]

    def test_create_template_includes_profiles(self, config_manager: ConfigAsCodeManager) -> None:
        """create_template_config includes analysis profiles."""
        template = config_manager.create_template_config()

        assert "profiles" in template
        assert "code_generation" in template["profiles"]
        assert "analysis" in template["profiles"]

    def test_create_template_includes_metadata(self, config_manager: ConfigAsCodeManager) -> None:
        """create_template_config includes metadata section."""
        template = config_manager.create_template_config()

        assert "metadata" in template
        assert template["metadata"]["name"] == "Intellicrack LLM Configuration"
        assert "created_at" in template["metadata"]


class TestConfigFileGeneration:
    """Tests for multi-environment configuration file generation."""

    def test_generate_config_files_creates_all_environments(self, config_manager: ConfigAsCodeManager) -> None:
        """generate_config_files creates files for all specified environments."""
        generated = config_manager.generate_config_files()

        assert len(generated) == 3

        file_names = [f.name for f in generated]
        assert "llm_config_development.yaml" in file_names
        assert "llm_config_staging.yaml" in file_names
        assert "llm_config_production.yaml" in file_names

    def test_generate_config_files_custom_environments(self, config_manager: ConfigAsCodeManager) -> None:
        """generate_config_files supports custom environment list."""
        generated = config_manager.generate_config_files(environments=["testing", "staging"])

        assert len(generated) == 2

        file_names = [f.name for f in generated]
        assert "llm_config_testing.yaml" in file_names
        assert "llm_config_staging.yaml" in file_names

    def test_generate_config_files_production_has_conservative_settings(
        self, config_manager: ConfigAsCodeManager
    ) -> None:
        """Production config files have conservative retry settings."""
        generated = config_manager.generate_config_files(environments=["production"])

        config_file = generated[0]
        loaded = config_manager.load_config(config_file)

        assert loaded["default_settings"]["auto_load_models"] is False

        for chain in loaded["fallback_chains"].values():
            assert chain["max_retries"] == 2
            assert chain["circuit_failure_threshold"] == 3


class TestConfigRoundTrip:
    """Tests for configuration round-trip (save/load cycles)."""

    def test_json_round_trip_preserves_data(
        self, config_manager: ConfigAsCodeManager, valid_complete_config: dict[str, Any]
    ) -> None:
        """Configuration survives JSON save/load cycle."""
        output_file = config_manager.config_dir / "roundtrip.json"

        config_manager.save_config(valid_complete_config, output_file, format_type="json")
        loaded = config_manager.load_config(output_file)

        assert loaded["version"] == valid_complete_config["version"]
        assert loaded["models"] == valid_complete_config["models"]
        assert loaded["fallback_chains"] == valid_complete_config["fallback_chains"]

    def test_multiple_save_load_cycles(
        self, config_manager: ConfigAsCodeManager, valid_complete_config: dict[str, Any]
    ) -> None:
        """Configuration remains stable across multiple save/load cycles."""
        config_file = config_manager.config_dir / "multi_cycle.json"

        current_config = valid_complete_config

        for _ in range(3):
            config_manager.save_config(current_config, config_file)
            current_config = config_manager.load_config(config_file)

        assert current_config["version"] == valid_complete_config["version"]
        assert len(current_config["models"]) == len(valid_complete_config["models"])


class TestGlobalFunctions:
    """Tests for global convenience functions."""

    def test_get_config_as_code_manager_returns_singleton(self) -> None:
        """get_config_as_code_manager returns same instance."""
        manager1 = get_config_as_code_manager()
        manager2 = get_config_as_code_manager()

        assert manager1 is manager2

    def test_create_config_template_creates_file(self, tmp_path: Path) -> None:
        """create_config_template convenience function creates template file."""
        output_file = tmp_path / "template.json"

        create_config_template(output_file, environment="development")

        assert output_file.exists()

        with open(output_file) as f:
            config = json.load(f)

        assert config["environment"] == "development"


class TestEdgeCases:
    """Edge case tests for ConfigAsCodeManager."""

    def test_load_config_with_unicode_content(self, config_manager: ConfigAsCodeManager) -> None:
        """Configuration files with unicode characters load correctly."""
        config = {
            "version": "1.0",
            "metadata": {
                "name": "Test Config 测试",
                "description": "Configuration with unicode: 日本語, emoji: 🔧",
            },
        }

        config_file = config_manager.config_dir / "unicode.json"

        with open(config_file, "w", encoding="utf-8") as f:
            json.dump(config, f, ensure_ascii=False)

        loaded = config_manager.load_config(config_file, validate=False)

        assert "测试" in loaded["metadata"]["name"]
        assert "🔧" in loaded["metadata"]["description"]

    def test_validate_config_with_extra_properties(
        self, config_manager: ConfigAsCodeManager, valid_llm_model_config: dict[str, Any]
    ) -> None:
        """Validation accepts configurations with extra properties."""
        config_with_extras = {
            **valid_llm_model_config,
            "custom_field": "custom_value",
            "experimental_feature": True,
        }

        result = config_manager.validate_config(config_with_extras, "llm_model")

        assert result is True

    def test_substitute_env_vars_handles_empty_default(self, config_manager: ConfigAsCodeManager) -> None:
        """Environment variable substitution handles empty default values."""
        config = {"value": "${NONEXISTENT:}"}

        result = config_manager._substitute_env_vars(config)

        assert isinstance(result, dict)
        assert result["value"] == ""

    def test_save_config_handles_datetime_objects(self, config_manager: ConfigAsCodeManager) -> None:
        """save_config serializes datetime objects correctly."""
        from datetime import datetime

        config = {
            "version": "1.0",
            "timestamp": datetime(2025, 1, 15, 10, 30, 0),
        }

        output_file = config_manager.config_dir / "datetime.json"

        config_manager.save_config(config, output_file, validate=False)

        assert output_file.exists()

        with open(output_file) as f:
            loaded = json.load(f)

        assert "2025-01-15" in loaded["timestamp"]


class TestFallbackChainValidation:
    """Tests for fallback chain configuration validation."""

    def test_validate_fallback_chain_valid(self, config_manager: ConfigAsCodeManager) -> None:
        """validate_config accepts valid fallback chain configuration."""
        valid_chain = {
            "chain_id": "test_chain",
            "max_retries": 3,
            "retry_delay": 1.0,
            "circuit_failure_threshold": 5,
            "enable_adaptive_ordering": True,
            "models": [
                {
                    "model_id": "gpt-4",
                    "provider": "openai",
                    "model_name": "gpt-4",
                }
            ],
        }

        result = config_manager.validate_config(valid_chain, "fallback_chain")

        assert result is True

    def test_validate_fallback_chain_requires_models(self, config_manager: ConfigAsCodeManager) -> None:
        """validate_config requires at least one model in fallback chain."""
        invalid_chain = {
            "chain_id": "empty_chain",
            "models": [],
        }

        with pytest.raises(ConfigValidationError):
            config_manager.validate_config(invalid_chain, "fallback_chain")

    def test_validate_fallback_chain_rejects_invalid_retry_values(
        self, config_manager: ConfigAsCodeManager
    ) -> None:
        """validate_config rejects invalid retry configuration."""
        invalid_chain = {
            "chain_id": "bad_retries",
            "max_retries": 0,
            "models": [{"model_id": "test", "provider": "openai", "model_name": "gpt-4"}],
        }

        with pytest.raises(ConfigValidationError):
            config_manager.validate_config(invalid_chain, "fallback_chain")


class TestIntegrationScenarios:
    """Integration tests combining multiple operations."""

    def test_complete_configuration_workflow(
        self, config_manager: ConfigAsCodeManager, valid_complete_config: dict[str, Any]
    ) -> None:
        """Complete workflow: validate, save, load, validate again."""
        config_manager.validate_config(valid_complete_config)

        config_file = config_manager.config_dir / "workflow.json"
        config_manager.save_config(valid_complete_config, config_file)

        loaded = config_manager.load_config(config_file)

        assert loaded == valid_complete_config

    def test_environment_specific_generation_and_loading(self, config_manager: ConfigAsCodeManager) -> None:
        """Generate environment-specific configs and load them successfully."""
        generated = config_manager.generate_config_files(environments=["development", "production"])

        for config_file in generated:
            loaded = config_manager.load_config(config_file)

            assert "version" in loaded
            assert "models" in loaded
            assert "fallback_chains" in loaded

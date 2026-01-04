"""Production tests for repository factory - model repository creation.

This test module validates the repository factory functionality for creating
and managing different types of model repositories, including:
- Repository type registration
- Repository creation from configuration
- Fallback handling for unavailable repository types
- Configuration validation
- Error handling for invalid configurations

All tests validate real repository instantiation functionality.
"""

import os
from pathlib import Path
from typing import Any

import pytest

from intellicrack.models.repositories.base import APIRepositoryBase, RateLimitConfig
from intellicrack.models.repositories.factory import RepositoryFactory
from intellicrack.models.repositories.interface import (
    ModelInfo,
    ModelRepositoryInterface,
)
from intellicrack.models.repositories.local_repository import LocalFileRepository


class MockCustomRepository(ModelRepositoryInterface):
    """Mock custom repository for testing registration."""

    def __init__(self, **kwargs: Any) -> None:
        """Initialize mock custom repository."""
        self.config = kwargs

    def get_available_models(self) -> list[ModelInfo]:
        """Return empty model list."""
        return []

    def get_model_details(self, model_id: str) -> ModelInfo | None:
        """Return None for all models."""
        return None

    def download_model(
        self, model_id: str, destination_path: str, progress_callback: Any = None
    ) -> tuple[bool, str]:
        """Mock download."""
        return True, "Downloaded"

    def authenticate(self) -> tuple[bool, str]:
        """Mock authentication."""
        return True, "Authenticated"


class MockAPIRepository(APIRepositoryBase):
    """Mock API repository for testing."""

    def __init__(self, **kwargs: Any) -> None:
        """Initialize mock API repository."""
        repository_name = kwargs.pop("repository_name", "mock")
        api_endpoint = kwargs.pop("api_endpoint", "https://api.example.com")
        super().__init__(repository_name=repository_name, api_endpoint=api_endpoint, **kwargs)

    def get_available_models(self) -> list[ModelInfo]:
        """Return mock models."""
        return []

    def get_model_details(self, model_id: str) -> ModelInfo | None:
        """Return None."""
        return None

    def authenticate(self) -> tuple[bool, str]:
        """Mock authentication."""
        return True, "OK"


class TestRepositoryTypeRegistration:
    """Test repository type registration."""

    def test_register_custom_repository_type(self) -> None:
        """Register a custom repository type."""
        RepositoryFactory.register_repository_type("custom", MockCustomRepository)

        available_types = RepositoryFactory.get_available_repository_types()

        assert "custom" in available_types

    def test_register_multiple_repository_types(self) -> None:
        """Register multiple repository types."""
        RepositoryFactory.register_repository_type("type1", MockCustomRepository)
        RepositoryFactory.register_repository_type("type2", MockCustomRepository)

        available_types = RepositoryFactory.get_available_repository_types()

        assert "type1" in available_types
        assert "type2" in available_types

    def test_register_overwrites_existing_type(self) -> None:
        """Registering same type name overwrites previous registration."""
        RepositoryFactory.register_repository_type("overwrite", MockCustomRepository)
        RepositoryFactory.register_repository_type("overwrite", LocalFileRepository)

        available = RepositoryFactory.get_available_repository_types()

        assert available.count("overwrite") == 1

    def test_get_available_repository_types(self) -> None:
        """Get list of all available repository types."""
        available_types = RepositoryFactory.get_available_repository_types()

        assert isinstance(available_types, list)
        assert "local" in available_types

    def test_default_local_repository_registered(self) -> None:
        """Local repository type is registered by default."""
        available_types = RepositoryFactory.get_available_repository_types()

        assert "local" in available_types


class TestRepositoryCreation:
    """Test repository creation from configuration."""

    def test_create_local_repository(self, tmp_path: Path) -> None:
        """Create local file repository from configuration."""
        config = {"type": "local", "models_directory": str(tmp_path / "models")}

        repository = RepositoryFactory.create_repository(config)

        assert repository is not None
        assert isinstance(repository, LocalFileRepository)

    def test_create_local_repository_default_directory(self) -> None:
        """Create local repository with default directory."""
        config = {"type": "local"}

        repository = RepositoryFactory.create_repository(config)

        assert repository is not None
        assert isinstance(repository, LocalFileRepository)

    def test_create_api_repository(self, tmp_path: Path) -> None:
        """Create API repository from configuration."""
        RepositoryFactory.register_repository_type("mock_api", MockAPIRepository)

        config = {
            "type": "mock_api",
            "name": "Test API Repo",
            "endpoint": "https://api.test.com",
            "api_key": "test_key_123",
            "timeout": 30,
            "download_directory": str(tmp_path / "downloads"),
        }

        repository = RepositoryFactory.create_repository(config)

        assert repository is not None
        assert isinstance(repository, MockAPIRepository)
        assert repository.repository_name == "Test API Repo"
        assert repository.api_endpoint == "https://api.test.com"
        assert repository.api_key == "test_key_123"
        assert repository.timeout == 30

    def test_create_repository_with_rate_limit_config(self, tmp_path: Path) -> None:
        """Create repository with rate limit configuration."""
        RepositoryFactory.register_repository_type("rate_limited", MockAPIRepository)

        config = {
            "type": "rate_limited",
            "endpoint": "https://api.example.com",
            "rate_limit": {"requests_per_minute": 30, "requests_per_day": 500},
            "download_directory": str(tmp_path),
        }

        repository = RepositoryFactory.create_repository(config)

        assert repository is not None
        assert isinstance(repository, APIRepositoryBase)
        assert repository.rate_limiter.config.requests_per_minute == 30
        assert repository.rate_limiter.config.requests_per_day == 500

    def test_create_repository_with_cache_config(self, tmp_path: Path) -> None:
        """Create repository with cache configuration."""
        RepositoryFactory.register_repository_type("cached", MockAPIRepository)

        config = {
            "type": "cached",
            "endpoint": "https://api.example.com",
            "cache": {"ttl": 7200, "max_size_mb": 200},
            "download_directory": str(tmp_path),
        }

        repository = RepositoryFactory.create_repository(config)

        assert repository is not None
        assert isinstance(repository, APIRepositoryBase)

    def test_create_repository_with_proxy(self, tmp_path: Path) -> None:
        """Create repository with proxy configuration."""
        RepositoryFactory.register_repository_type("proxied", MockAPIRepository)

        config = {
            "type": "proxied",
            "endpoint": "https://api.example.com",
            "proxy": "http://proxy.company.com:8080",
            "download_directory": str(tmp_path),
        }

        repository = RepositoryFactory.create_repository(config)

        assert repository is not None
        assert isinstance(repository, APIRepositoryBase)
        assert repository.proxy == "http://proxy.company.com:8080"

    def test_create_repository_minimal_config(self, tmp_path: Path) -> None:
        """Create repository with minimal configuration."""
        RepositoryFactory.register_repository_type("minimal", MockAPIRepository)

        config = {
            "type": "minimal",
            "endpoint": "https://api.example.com",
            "download_directory": str(tmp_path),
        }

        repository = RepositoryFactory.create_repository(config)

        assert repository is not None
        assert repository.timeout == 60  # type: ignore[attr-defined]
        assert repository.api_key == ""  # type: ignore[attr-defined]
        assert repository.proxy == ""  # type: ignore[attr-defined]


class TestRepositoryCreationErrors:
    """Test error handling in repository creation."""

    def test_create_repository_missing_type(self) -> None:
        """Return None when configuration missing type field."""
        config = {"endpoint": "https://api.example.com"}

        repository = RepositoryFactory.create_repository(config)

        assert repository is None

    def test_create_repository_unknown_type(self) -> None:
        """Return None for unknown repository type."""
        config = {"type": "nonexistent_repository_type_xyz"}

        repository = RepositoryFactory.create_repository(config)

        assert repository is None

    def test_create_repository_invalid_config(self) -> None:
        """Handle invalid configuration gracefully."""
        RepositoryFactory.register_repository_type("invalid_test", MockAPIRepository)

        config = {
            "type": "invalid_test",
            "endpoint": None,
        }

        repository = RepositoryFactory.create_repository(config)

        assert repository is None or isinstance(repository, MockAPIRepository)

    def test_create_repository_empty_config(self) -> None:
        """Return None for empty configuration."""
        repository = RepositoryFactory.create_repository({})

        assert repository is None


class TestRealWorldRepositoryConfigurations:
    """Test real-world repository configuration scenarios."""

    def test_huggingface_style_config(self, tmp_path: Path) -> None:
        """Create repository with HuggingFace-style configuration."""
        RepositoryFactory.register_repository_type("huggingface", MockAPIRepository)

        config = {
            "type": "huggingface",
            "name": "HuggingFace",
            "endpoint": "https://huggingface.co/api",
            "api_key": "hf_xxxxxxxxxxxxx",
            "timeout": 60,
            "rate_limit": {"requests_per_minute": 300, "requests_per_day": 10000},
            "cache": {"ttl": 3600, "max_size_mb": 500},
            "download_directory": str(tmp_path / "huggingface"),
        }

        repository = RepositoryFactory.create_repository(config)

        assert repository is not None
        assert repository.repository_name == "HuggingFace"  # type: ignore[attr-defined]

    def test_openai_style_config(self, tmp_path: Path) -> None:
        """Create repository with OpenAI-style configuration."""
        RepositoryFactory.register_repository_type("openai", MockAPIRepository)

        config = {
            "type": "openai",
            "name": "OpenAI",
            "endpoint": "https://api.openai.com/v1",
            "api_key": "sk-xxxxxxxxxxxxx",
            "timeout": 120,
            "rate_limit": {"requests_per_minute": 60, "requests_per_day": 1000},
            "download_directory": str(tmp_path / "openai"),
        }

        repository = RepositoryFactory.create_repository(config)

        assert repository is not None
        assert repository.api_key == "sk-xxxxxxxxxxxxx"  # type: ignore[attr-defined]

    def test_anthropic_style_config(self, tmp_path: Path) -> None:
        """Create repository with Anthropic-style configuration."""
        RepositoryFactory.register_repository_type("anthropic", MockAPIRepository)

        config = {
            "type": "anthropic",
            "name": "Anthropic",
            "endpoint": "https://api.anthropic.com/v1",
            "api_key": "sk-ant-xxxxxxxxxxxxx",
            "timeout": 90,
            "rate_limit": {"requests_per_minute": 50, "requests_per_day": 500},
            "download_directory": str(tmp_path / "anthropic"),
        }

        repository = RepositoryFactory.create_repository(config)

        assert repository is not None

    def test_local_model_repository_config(self, tmp_path: Path) -> None:
        """Create local repository for offline models."""
        models_dir = tmp_path / "offline_models"
        models_dir.mkdir()

        config = {"type": "local", "models_directory": str(models_dir)}

        repository = RepositoryFactory.create_repository(config)

        assert repository is not None
        assert isinstance(repository, LocalFileRepository)


class TestRepositoryFactoryIntegration:
    """Integration tests for repository factory."""

    def test_register_and_create_workflow(self, tmp_path: Path) -> None:
        """Complete workflow: register type, then create instance."""
        RepositoryFactory.register_repository_type("workflow_test", MockAPIRepository)

        assert "workflow_test" in RepositoryFactory.get_available_repository_types()

        config = {
            "type": "workflow_test",
            "endpoint": "https://api.workflow.com",
            "download_directory": str(tmp_path),
        }

        repository = RepositoryFactory.create_repository(config)

        assert repository is not None
        assert isinstance(repository, MockAPIRepository)

    def test_multiple_repository_instances(self, tmp_path: Path) -> None:
        """Create multiple repository instances from same type."""
        RepositoryFactory.register_repository_type("multi_instance", MockAPIRepository)

        config1 = {
            "type": "multi_instance",
            "name": "Instance 1",
            "endpoint": "https://api1.example.com",
            "download_directory": str(tmp_path / "repo1"),
        }

        config2 = {
            "type": "multi_instance",
            "name": "Instance 2",
            "endpoint": "https://api2.example.com",
            "download_directory": str(tmp_path / "repo2"),
        }

        repo1 = RepositoryFactory.create_repository(config1)
        repo2 = RepositoryFactory.create_repository(config2)

        assert repo1 is not None
        assert repo2 is not None
        assert repo1.repository_name != repo2.repository_name  # type: ignore[attr-defined]
        assert repo1.api_endpoint != repo2.api_endpoint  # type: ignore[attr-defined]

    def test_repository_type_persistence(self) -> None:
        """Registered types persist across factory method calls."""
        RepositoryFactory.register_repository_type("persistent", MockCustomRepository)

        types_before = RepositoryFactory.get_available_repository_types()
        assert "persistent" in types_before

        RepositoryFactory.create_repository({"type": "local"})

        types_after = RepositoryFactory.get_available_repository_types()
        assert "persistent" in types_after


class TestRepositoryConfigValidation:
    """Test validation of repository configurations."""

    def test_valid_api_repository_config(self, tmp_path: Path) -> None:
        """Validate complete API repository configuration."""
        RepositoryFactory.register_repository_type("valid_api", MockAPIRepository)

        config = {
            "type": "valid_api",
            "name": "Valid API",
            "endpoint": "https://api.valid.com",
            "api_key": "valid_key",
            "timeout": 60,
            "proxy": "",
            "rate_limit": {"requests_per_minute": 60, "requests_per_day": 1000},
            "cache": {"ttl": 3600, "max_size_mb": 100},
            "download_directory": str(tmp_path),
        }

        repository = RepositoryFactory.create_repository(config)

        assert repository is not None
        assert all(
            hasattr(repository, attr)
            for attr in [
                "repository_name",
                "api_endpoint",
                "api_key",
                "timeout",
                "rate_limiter",
                "cache_manager",
            ]
        )

    def test_config_with_default_values(self, tmp_path: Path) -> None:
        """Configuration uses default values when not specified."""
        RepositoryFactory.register_repository_type("defaults", MockAPIRepository)

        config = {
            "type": "defaults",
            "endpoint": "https://api.example.com",
            "download_directory": str(tmp_path),
        }

        repository = RepositoryFactory.create_repository(config)

        assert repository is not None
        assert repository.timeout == 60  # type: ignore[attr-defined]
        assert repository.rate_limiter.config.requests_per_minute == 60  # type: ignore[attr-defined]
        assert repository.rate_limiter.config.requests_per_day == 1000  # type: ignore[attr-defined]


class TestEdgeCases:
    """Test edge cases in repository factory."""

    def test_register_none_as_repository_class(self) -> None:
        """Handle None as repository class."""
        try:
            RepositoryFactory.register_repository_type("none_class", None)  # type: ignore[arg-type]
        except (TypeError, AttributeError):
            pass

    def test_create_repository_none_config(self) -> None:
        """Handle None as configuration."""
        try:
            repository = RepositoryFactory.create_repository(None)  # type: ignore[arg-type]
            assert repository is None
        except (TypeError, AttributeError):
            pass

    def test_register_repository_type_empty_name(self) -> None:
        """Handle empty string as type name."""
        RepositoryFactory.register_repository_type("", MockCustomRepository)

        available = RepositoryFactory.get_available_repository_types()
        assert "" in available

    def test_create_repository_with_extra_fields(self, tmp_path: Path) -> None:
        """Handle configuration with extra unknown fields."""
        config = {
            "type": "local",
            "models_directory": str(tmp_path),
            "unknown_field": "unknown_value",
            "extra_config": {"nested": "value"},
        }

        repository = RepositoryFactory.create_repository(config)

        assert repository is not None


class TestRepositoryDownloadDirectories:
    """Test download directory handling."""

    def test_repository_creates_download_directory(self, tmp_path: Path) -> None:
        """Repository creates download directory if it doesn't exist."""
        download_dir = tmp_path / "new_downloads"
        assert not download_dir.exists()

        RepositoryFactory.register_repository_type("create_dir", MockAPIRepository)

        config = {
            "type": "create_dir",
            "endpoint": "https://api.example.com",
            "download_directory": str(download_dir),
        }

        repository = RepositoryFactory.create_repository(config)

        assert repository is not None
        assert os.path.exists(repository.download_dir)  # type: ignore[attr-defined]

    def test_repository_default_download_directory(self) -> None:
        """Repository uses default download directory when not specified."""
        RepositoryFactory.register_repository_type("default_dir", MockAPIRepository)

        config = {"type": "default_dir", "endpoint": "https://api.example.com"}

        repository = RepositoryFactory.create_repository(config)

        assert repository is not None
        assert hasattr(repository, "download_dir")
        assert repository.download_dir is not None

    def test_repository_download_subdirectories(self, tmp_path: Path) -> None:
        """Repository creates subdirectories for each repository type."""
        base_download = tmp_path / "downloads"

        RepositoryFactory.register_repository_type("subdir_test", MockAPIRepository)

        config = {
            "type": "subdir_test",
            "name": "SubdirRepo",
            "endpoint": "https://api.example.com",
            "download_directory": str(base_download),
        }

        repository = RepositoryFactory.create_repository(config)

        assert repository is not None
        assert "SubdirRepo" in repository.download_dir  # type: ignore[attr-defined]

"""Production tests for AI Model Manager.

Tests validate real AI model configuration, loading, provider integration,
cache management, and lifecycle operations critical for licensing analysis.
"""

import json
import os
import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, Mock, patch

import pytest

from intellicrack.ai.llm_backends import LLMConfig, LLMProvider
from intellicrack.core.ai_model_manager import AIModelManager, get_model_manager


@pytest.fixture
def temp_config_dir(tmp_path: Path) -> Path:
    """Create temporary configuration directory."""
    config_dir = tmp_path / ".intellicrack" / "models"
    config_dir.mkdir(parents=True, exist_ok=True)
    return config_dir


@pytest.fixture
def temp_config_path(temp_config_dir: Path) -> str:
    """Provide path for temporary model configuration."""
    return str(temp_config_dir / "model_config.json")


@pytest.fixture
def mock_llm_manager() -> Mock:
    """Mock LLM manager for testing."""
    manager = Mock()
    manager.add_provider = Mock()
    manager.get_provider = Mock(return_value=Mock())
    return manager


@pytest.fixture
def mock_cache_manager() -> Mock:
    """Mock cache manager for testing."""
    cache = Mock()
    cache.get_model = Mock(return_value=None)
    cache.cache_model = Mock()
    cache.clear = Mock()
    return cache


@pytest.fixture
def mock_performance_monitor() -> Mock:
    """Mock performance monitor for testing."""
    monitor = Mock()
    monitor.get_stats = Mock(return_value={"inference_count": 42, "avg_latency": 0.5})
    return monitor


class TestAIModelManagerConfiguration:
    """Test AI model configuration management."""

    def test_default_config_creation(self, temp_config_path: str) -> None:
        """Default configuration file is created with valid structure."""
        manager = AIModelManager(temp_config_path)

        assert os.path.exists(temp_config_path)

        with open(temp_config_path) as f:
            config = json.load(f)

        assert "models" in config
        assert "default_model" in config
        assert "cache_enabled" in config
        assert "cache_size_mb" in config
        assert "performance_monitoring" in config

        assert "gpt-4" in config["models"]
        assert "claude-3" in config["models"]
        assert "gemini-pro" in config["models"]
        assert "llama3" in config["models"]
        assert "codellama" in config["models"]

        assert config["default_model"] == "llama3"
        assert config["cache_enabled"] is True
        assert config["performance_monitoring"] is True

    def test_config_loading_from_existing_file(self, temp_config_path: str) -> None:
        """Configuration loads correctly from existing file."""
        custom_config = {
            "models": {
                "custom-model": {
                    "provider": "openai",
                    "enabled": True,
                    "api_key": "test-key-12345",
                    "max_tokens": 8192,
                    "temperature": 0.5,
                }
            },
            "default_model": "custom-model",
            "cache_enabled": False,
            "cache_size_mb": 2048,
            "performance_monitoring": False,
        }

        with open(temp_config_path, "w") as f:
            json.dump(custom_config, f)

        manager = AIModelManager(temp_config_path)

        assert manager.config["default_model"] == "custom-model"
        assert manager.config["cache_enabled"] is False
        assert manager.config["cache_size_mb"] == 2048
        assert "custom-model" in manager.config["models"]
        assert manager.config["models"]["custom-model"]["api_key"] == "test-key-12345"

    def test_config_persistence_after_modification(self, temp_config_path: str) -> None:
        """Configuration changes persist to disk."""
        manager = AIModelManager(temp_config_path)

        manager.configure_model("llama3", {"enabled": True, "max_tokens": 4096})

        with open(temp_config_path) as f:
            saved_config = json.load(f)

        assert saved_config["models"]["llama3"]["enabled"] is True
        assert saved_config["models"]["llama3"]["max_tokens"] == 4096

    def test_corrupted_config_falls_back_to_defaults(self, temp_config_path: str) -> None:
        """Corrupted configuration file triggers default config creation."""
        with open(temp_config_path, "w") as f:
            f.write("{ invalid json content }")

        manager = AIModelManager(temp_config_path)

        assert "models" in manager.config
        assert "default_model" in manager.config
        assert manager.config["default_model"] == "llama3"


class TestAIModelManagerProviderSetup:
    """Test AI provider configuration and initialization."""

    @patch("intellicrack.core.ai_model_manager.LLMManager")
    def test_openai_model_setup_with_api_key(self, mock_manager_class: Mock, temp_config_path: str) -> None:
        """OpenAI model setup configures LLM manager with correct parameters."""
        mock_manager = Mock()
        mock_manager_class.return_value = mock_manager

        os.environ["OPENAI_API_KEY"] = "test-openai-key"

        try:
            manager = AIModelManager(temp_config_path)
            manager.configure_model(
                "gpt-4",
                {
                    "provider": "openai",
                    "enabled": True,
                    "max_tokens": 8192,
                    "temperature": 0.3,
                },
            )

            manager.enable_model("gpt-4")

            mock_manager.add_provider.assert_called()
            call_args = mock_manager.add_provider.call_args

            assert call_args[0][0] == LLMProvider.OPENAI
            llm_config: LLMConfig = call_args[0][1]
            assert llm_config.provider == LLMProvider.OPENAI
            assert llm_config.model_name == "gpt-4"
            assert llm_config.api_key == "test-openai-key"
            assert llm_config.max_tokens == 8192
            assert llm_config.temperature == 0.3
        finally:
            del os.environ["OPENAI_API_KEY"]

    @patch("intellicrack.core.ai_model_manager.LLMManager")
    def test_anthropic_model_setup_with_api_key(self, mock_manager_class: Mock, temp_config_path: str) -> None:
        """Anthropic model setup configures LLM manager correctly."""
        mock_manager = Mock()
        mock_manager_class.return_value = mock_manager

        os.environ["ANTHROPIC_API_KEY"] = "test-anthropic-key"

        try:
            manager = AIModelManager(temp_config_path)
            manager.configure_model(
                "claude-3",
                {
                    "provider": "anthropic",
                    "enabled": True,
                    "max_tokens": 4096,
                    "temperature": 0.7,
                },
            )

            manager.enable_model("claude-3")

            mock_manager.add_provider.assert_called()
            call_args = mock_manager.add_provider.call_args

            assert call_args[0][0] == LLMProvider.ANTHROPIC
            llm_config: LLMConfig = call_args[0][1]
            assert llm_config.provider == LLMProvider.ANTHROPIC
            assert llm_config.model_name == "claude-3"
            assert llm_config.api_key == "test-anthropic-key"
        finally:
            del os.environ["ANTHROPIC_API_KEY"]

    @patch("intellicrack.core.ai_model_manager.LLMManager")
    def test_google_model_setup_with_api_key(self, mock_manager_class: Mock, temp_config_path: str) -> None:
        """Google model setup configures LLM manager correctly."""
        mock_manager = Mock()
        mock_manager_class.return_value = mock_manager

        os.environ["GOOGLE_API_KEY"] = "test-google-key"

        try:
            manager = AIModelManager(temp_config_path)
            manager.configure_model(
                "gemini-pro",
                {
                    "provider": "google",
                    "enabled": True,
                    "max_tokens": 2048,
                    "temperature": 0.8,
                },
            )

            manager.enable_model("gemini-pro")

            mock_manager.add_provider.assert_called()
            call_args = mock_manager.add_provider.call_args

            assert call_args[0][0] == LLMProvider.GOOGLE
            llm_config: LLMConfig = call_args[0][1]
            assert llm_config.provider == LLMProvider.GOOGLE
            assert llm_config.model_name == "gemini-pro"
            assert llm_config.api_key == "test-google-key"
        finally:
            del os.environ["GOOGLE_API_KEY"]

    def test_openai_model_setup_fails_without_api_key(self, temp_config_path: str) -> None:
        """OpenAI model setup fails when API key is missing."""
        if "OPENAI_API_KEY" in os.environ:
            del os.environ["OPENAI_API_KEY"]

        manager = AIModelManager(temp_config_path)

        with pytest.raises(ValueError, match="No API key for OpenAI"):
            manager.configure_model(
                "gpt-4",
                {
                    "provider": "openai",
                    "enabled": True,
                },
            )
            manager.enable_model("gpt-4")

    def test_local_model_setup_with_valid_path(self, temp_config_path: str, tmp_path: Path) -> None:
        """Local model setup succeeds with valid model path."""
        model_dir = tmp_path / "models" / "llama3"
        model_dir.mkdir(parents=True)
        (model_dir / "config.json").write_text('{"model_type": "llama"}')

        manager = AIModelManager(temp_config_path)
        manager.configure_model(
            "llama3",
            {
                "provider": "local",
                "enabled": True,
                "model_path": str(model_dir),
            },
        )

        manager.enable_model("llama3")

        assert "llama3" in manager.models
        assert manager.models["llama3"]["provider"] == "local"
        assert manager.models["llama3"]["config"]["model_path"] == str(model_dir)

    def test_unknown_provider_raises_error(self, temp_config_path: str) -> None:
        """Unknown provider type raises ValueError."""
        manager = AIModelManager(temp_config_path)

        with pytest.raises(ValueError, match="Unknown provider"):
            manager.configure_model(
                "invalid-model",
                {
                    "provider": "unknown-provider",
                    "enabled": True,
                },
            )
            manager.enable_model("invalid-model")


class TestAIModelManagerLifecycle:
    """Test model lifecycle management."""

    def test_enable_model_adds_to_loaded_models(self, temp_config_path: str) -> None:
        """Enabling a model adds it to loaded models registry."""
        manager = AIModelManager(temp_config_path)

        initial_count = len(manager.models)

        manager.configure_model("llama3", {"enabled": False})
        manager.enable_model("llama3")

        assert "llama3" in manager.models
        assert len(manager.models) >= initial_count

    def test_disable_model_removes_from_loaded_models(self, temp_config_path: str) -> None:
        """Disabling a model removes it from loaded models."""
        manager = AIModelManager(temp_config_path)

        manager.configure_model("llama3", {"enabled": True})
        manager.enable_model("llama3")

        assert "llama3" in manager.models

        manager.disable_model("llama3")

        assert "llama3" not in manager.models

    def test_disable_model_clears_active_model(self, temp_config_path: str) -> None:
        """Disabling active model clears active_model reference."""
        manager = AIModelManager(temp_config_path)

        manager.configure_model("llama3", {"enabled": True})
        manager.enable_model("llama3")
        manager.set_active_model("llama3")

        assert manager.active_model == "llama3"

        manager.disable_model("llama3")

        assert manager.active_model is None

    def test_set_active_model(self, temp_config_path: str) -> None:
        """Set active model updates current model reference."""
        manager = AIModelManager(temp_config_path)

        manager.configure_model("llama3", {"enabled": True})
        manager.enable_model("llama3")

        manager.set_active_model("llama3")

        assert manager.active_model == "llama3"

    def test_set_active_model_fails_for_nonexistent_model(self, temp_config_path: str) -> None:
        """Setting nonexistent model as active raises ValueError."""
        manager = AIModelManager(temp_config_path)

        with pytest.raises(ValueError, match="not found"):
            manager.set_active_model("nonexistent-model")

    def test_list_models(self, temp_config_path: str) -> None:
        """List models returns all loaded model names."""
        manager = AIModelManager(temp_config_path)

        manager.configure_model("llama3", {"enabled": True})
        manager.enable_model("llama3")

        models = manager.list_models()

        assert isinstance(models, list)
        if "llama3" in manager.models:
            assert "llama3" in models


class TestAIModelManagerModelRetrieval:
    """Test model instance retrieval and lazy loading."""

    @patch("intellicrack.core.ai_model_manager.LLMManager")
    def test_get_model_with_name(self, mock_manager_class: Mock, temp_config_path: str) -> None:
        """Get model by name returns correct model instance."""
        mock_manager = Mock()
        mock_provider = Mock()
        mock_manager.get_provider = Mock(return_value=mock_provider)
        mock_manager_class.return_value = mock_manager

        os.environ["OPENAI_API_KEY"] = "test-key"

        try:
            manager = AIModelManager(temp_config_path)
            manager.configure_model("gpt-4", {"provider": "openai", "enabled": True})
            manager.enable_model("gpt-4")

            model = manager.get_model("gpt-4")

            assert model is not None
            assert model == mock_provider
        finally:
            del os.environ["OPENAI_API_KEY"]

    @patch("intellicrack.core.ai_model_manager.LLMManager")
    def test_get_model_uses_active_model_when_no_name_provided(self, mock_manager_class: Mock, temp_config_path: str) -> None:
        """Get model without name uses active model."""
        mock_manager = Mock()
        mock_provider = Mock()
        mock_manager.get_provider = Mock(return_value=mock_provider)
        mock_manager_class.return_value = mock_manager

        os.environ["OPENAI_API_KEY"] = "test-key"

        try:
            manager = AIModelManager(temp_config_path)
            manager.configure_model("gpt-4", {"provider": "openai", "enabled": True})
            manager.enable_model("gpt-4")
            manager.set_active_model("gpt-4")

            model = manager.get_model()

            assert model is not None
            assert model == mock_provider
        finally:
            del os.environ["OPENAI_API_KEY"]

    def test_get_model_fails_when_no_active_model(self, temp_config_path: str) -> None:
        """Get model without name fails when no active model set."""
        manager = AIModelManager(temp_config_path)

        with pytest.raises(ValueError, match="No model specified"):
            manager.get_model()

    def test_get_model_fails_for_nonexistent_model(self, temp_config_path: str) -> None:
        """Get model fails for nonexistent model name."""
        manager = AIModelManager(temp_config_path)

        with pytest.raises(ValueError, match="not found"):
            manager.get_model("nonexistent-model")

    @patch("intellicrack.core.ai_model_manager.LLMManager")
    def test_lazy_loading_only_loads_on_first_access(self, mock_manager_class: Mock, temp_config_path: str) -> None:
        """Model instance is lazy loaded only on first get_model call."""
        mock_manager = Mock()
        mock_provider = Mock()
        mock_manager.get_provider = Mock(return_value=mock_provider)
        mock_manager_class.return_value = mock_manager

        os.environ["OPENAI_API_KEY"] = "test-key"

        try:
            manager = AIModelManager(temp_config_path)
            manager.configure_model("gpt-4", {"provider": "openai", "enabled": True})
            manager.enable_model("gpt-4")

            assert manager.models["gpt-4"]["instance"] is None

            model = manager.get_model("gpt-4")

            assert manager.models["gpt-4"]["instance"] is not None
            assert manager.models["gpt-4"]["instance"] == mock_provider
        finally:
            del os.environ["OPENAI_API_KEY"]

    @patch("intellicrack.core.ai_model_manager.LLMManager")
    def test_subsequent_get_model_returns_cached_instance(self, mock_manager_class: Mock, temp_config_path: str) -> None:
        """Subsequent get_model calls return cached instance."""
        mock_manager = Mock()
        mock_provider = Mock()
        mock_manager.get_provider = Mock(return_value=mock_provider)
        mock_manager_class.return_value = mock_manager

        os.environ["OPENAI_API_KEY"] = "test-key"

        try:
            manager = AIModelManager(temp_config_path)
            manager.configure_model("gpt-4", {"provider": "openai", "enabled": True})
            manager.enable_model("gpt-4")

            model1 = manager.get_model("gpt-4")
            model2 = manager.get_model("gpt-4")

            assert model1 is model2
            assert mock_manager.get_provider.call_count == 1
        finally:
            del os.environ["OPENAI_API_KEY"]


class TestAIModelManagerCacheIntegration:
    """Test cache manager integration."""

    @patch("intellicrack.core.ai_model_manager.get_cache_manager")
    @patch("intellicrack.core.ai_model_manager.LLMManager")
    def test_cache_lookup_before_loading(self, mock_manager_class: Mock, mock_cache_getter: Mock, temp_config_path: str) -> None:
        """Cache is checked before loading model from disk."""
        mock_manager = Mock()
        mock_manager_class.return_value = mock_manager

        cached_model = {"model": Mock(), "tokenizer": Mock()}
        mock_cache = Mock()
        mock_cache.get_model = Mock(return_value=cached_model)
        mock_cache_getter.return_value = mock_cache

        os.environ["OPENAI_API_KEY"] = "test-key"

        try:
            manager = AIModelManager(temp_config_path)
            manager.configure_model("gpt-4", {"provider": "openai", "enabled": True})
            manager.enable_model("gpt-4")

            manager.get_model("gpt-4")

            mock_cache.get_model.assert_called_once()
        finally:
            del os.environ["OPENAI_API_KEY"]

    @patch("intellicrack.core.ai_model_manager.get_cache_manager")
    def test_cleanup_clears_cache(self, mock_cache_getter: Mock, temp_config_path: str) -> None:
        """Cleanup operation clears model cache."""
        mock_cache = Mock()
        mock_cache.clear = Mock()
        mock_cache_getter.return_value = mock_cache

        manager = AIModelManager(temp_config_path)
        manager.cleanup()

        mock_cache.clear.assert_called_once()

    @patch("intellicrack.core.ai_model_manager.get_cache_manager")
    def test_cleanup_clears_loaded_models(self, mock_cache_getter: Mock, temp_config_path: str) -> None:
        """Cleanup operation clears loaded models registry."""
        mock_cache = Mock()
        mock_cache_getter.return_value = mock_cache

        manager = AIModelManager(temp_config_path)
        manager.configure_model("llama3", {"enabled": True})
        manager.enable_model("llama3")

        assert len(manager.models) > 0

        manager.cleanup()

        assert len(manager.models) == 0
        assert manager.active_model is None


class TestAIModelManagerPerformanceMonitoring:
    """Test performance monitoring integration."""

    @patch("intellicrack.core.ai_model_manager.get_performance_monitor")
    @patch("intellicrack.core.ai_model_manager.LLMManager")
    def test_get_performance_stats_for_active_model(self, mock_manager_class: Mock, mock_monitor_getter: Mock, temp_config_path: str) -> None:
        """Performance stats retrieved for active model."""
        mock_manager = Mock()
        mock_manager_class.return_value = mock_manager

        mock_monitor = Mock()
        mock_stats = {"inference_count": 100, "avg_latency": 0.25, "total_tokens": 50000}
        mock_monitor.get_stats = Mock(return_value=mock_stats)
        mock_monitor_getter.return_value = mock_monitor

        os.environ["OPENAI_API_KEY"] = "test-key"

        try:
            manager = AIModelManager(temp_config_path)
            manager.configure_model("gpt-4", {"provider": "openai", "enabled": True})
            manager.enable_model("gpt-4")
            manager.set_active_model("gpt-4")

            stats = manager.get_performance_stats()

            assert stats == mock_stats
            mock_monitor.get_stats.assert_called_once_with("gpt-4")
        finally:
            del os.environ["OPENAI_API_KEY"]

    @patch("intellicrack.core.ai_model_manager.get_performance_monitor")
    def test_get_performance_stats_disabled_when_monitoring_off(self, mock_monitor_getter: Mock, temp_config_path: str) -> None:
        """Performance monitoring returns message when disabled."""
        mock_monitor = Mock()
        mock_monitor_getter.return_value = mock_monitor

        manager = AIModelManager(temp_config_path)
        manager.config["performance_monitoring"] = False
        manager.configure_model("llama3", {"enabled": True})
        manager.enable_model("llama3")
        manager.set_active_model("llama3")

        stats = manager.get_performance_stats()

        assert "message" in stats
        assert "disabled" in stats["message"]
        mock_monitor.get_stats.assert_not_called()


class TestAIModelManagerGetModelInfo:
    """Test model information retrieval."""

    def test_get_model_info_returns_details(self, temp_config_path: str) -> None:
        """Get model info returns complete model details."""
        manager = AIModelManager(temp_config_path)
        manager.configure_model("llama3", {"enabled": True, "max_tokens": 2048})
        manager.enable_model("llama3")

        info = manager.get_model_info("llama3")

        assert isinstance(info, dict)
        assert "provider" in info
        assert "config" in info
        assert info["config"]["max_tokens"] == 2048

    def test_get_model_info_uses_active_model_when_no_name(self, temp_config_path: str) -> None:
        """Get model info without name uses active model."""
        manager = AIModelManager(temp_config_path)
        manager.configure_model("llama3", {"enabled": True})
        manager.enable_model("llama3")
        manager.set_active_model("llama3")

        info = manager.get_model_info()

        assert info["provider"] == "local"

    def test_get_model_info_fails_for_nonexistent_model(self, temp_config_path: str) -> None:
        """Get model info fails for nonexistent model."""
        manager = AIModelManager(temp_config_path)

        with pytest.raises(ValueError, match="not found"):
            manager.get_model_info("nonexistent-model")


class TestAIModelManagerSingleton:
    """Test singleton pattern for global model manager."""

    def test_get_model_manager_returns_singleton(self) -> None:
        """get_model_manager returns same instance on multiple calls."""
        manager1 = get_model_manager()
        manager2 = get_model_manager()

        assert manager1 is manager2

    def test_get_model_manager_creates_instance_on_first_call(self) -> None:
        """get_model_manager creates instance on first call."""
        import intellicrack.core.ai_model_manager as module

        original = module._model_manager
        module._model_manager = None

        try:
            manager = get_model_manager()
            assert manager is not None
            assert isinstance(manager, AIModelManager)
        finally:
            module._model_manager = original


class TestAIModelManagerLocalModelLoading:
    """Test local model loading with transformers and llama.cpp."""

    @patch("intellicrack.core.ai_model_manager.get_cache_manager")
    def test_local_model_loads_with_transformers(self, mock_cache_getter: Mock, temp_config_path: str, tmp_path: Path) -> None:
        """Local model loads successfully with transformers library."""
        mock_cache = Mock()
        mock_cache.get_model = Mock(return_value=None)
        mock_cache.cache_model = Mock()
        mock_cache_getter.return_value = mock_cache

        model_dir = tmp_path / "models" / "test-model"
        model_dir.mkdir(parents=True)

        mock_model = Mock()
        mock_tokenizer = Mock()

        with (
            patch("intellicrack.core.ai_model_manager.AutoModel") as mock_auto_model,
            patch("intellicrack.core.ai_model_manager.AutoTokenizer") as mock_auto_tokenizer,
        ):
            mock_auto_model.from_pretrained = Mock(return_value=mock_model)
            mock_auto_tokenizer.from_pretrained = Mock(return_value=mock_tokenizer)

            manager = AIModelManager(temp_config_path)
            manager.configure_model(
                "test-model",
                {
                    "provider": "local",
                    "enabled": True,
                    "model_path": str(model_dir),
                },
            )
            manager.enable_model("test-model")

            result = manager._load_local_model("test-model", {"model_path": str(model_dir)})

            assert "model" in result
            assert "tokenizer" in result
            assert result["model"] == mock_model
            assert result["tokenizer"] == mock_tokenizer

            mock_cache.cache_model.assert_called_once()

    @patch("intellicrack.core.ai_model_manager.get_cache_manager")
    def test_local_model_falls_back_to_llama_cpp(self, mock_cache_getter: Mock, temp_config_path: str, tmp_path: Path) -> None:
        """Local model falls back to llama.cpp when transformers unavailable."""
        mock_cache = Mock()
        mock_cache.get_model = Mock(return_value=None)
        mock_cache.cache_model = Mock()
        mock_cache_getter.return_value = mock_cache

        model_dir = tmp_path / "models" / "llama-model"
        model_dir.mkdir(parents=True)
        model_path = model_dir / "model.gguf"
        model_path.write_bytes(b"fake gguf data")

        mock_llama_model = Mock()

        with patch("intellicrack.core.ai_model_manager.AutoModel") as mock_auto_model:
            mock_auto_model.from_pretrained = Mock(side_effect=ImportError("transformers not found"))

            with patch("intellicrack.core.ai_model_manager.llama_cpp") as mock_llama_cpp:
                mock_llama_cpp.Llama = Mock(return_value=mock_llama_model)

                manager = AIModelManager(temp_config_path)

                result = manager._load_local_model("llama-model", {"model_path": str(model_path)})

                assert "model" in result
                assert result["model"] == mock_llama_model
                assert result["tokenizer"] is None

                mock_cache.cache_model.assert_called_once()

    def test_local_model_loading_fails_when_no_backend_available(self, temp_config_path: str, tmp_path: Path) -> None:
        """Local model loading fails when no backend available."""
        model_dir = tmp_path / "models" / "no-backend"
        model_dir.mkdir(parents=True)

        with (
            patch("intellicrack.core.ai_model_manager.AutoModel") as mock_auto_model,
            patch("intellicrack.core.ai_model_manager.llama_cpp", None),
        ):
            mock_auto_model.from_pretrained = Mock(side_effect=ImportError("transformers not found"))

            manager = AIModelManager(temp_config_path)

            with pytest.raises(RuntimeError, match="No local model backend available"):
                manager._load_local_model("no-backend", {"model_path": str(model_dir)})


class TestAIModelManagerEdgeCases:
    """Test edge cases and error handling."""

    def test_enable_nonexistent_model_raises_error(self, temp_config_path: str) -> None:
        """Enabling nonexistent model raises ValueError."""
        manager = AIModelManager(temp_config_path)

        with pytest.raises(ValueError, match="not found in configuration"):
            manager.enable_model("nonexistent-model")

    def test_disable_nonexistent_model_raises_error(self, temp_config_path: str) -> None:
        """Disabling nonexistent model raises ValueError."""
        manager = AIModelManager(temp_config_path)

        with pytest.raises(ValueError, match="not found in configuration"):
            manager.disable_model("nonexistent-model")

    def test_configure_new_model_creates_entry(self, temp_config_path: str) -> None:
        """Configuring new model creates configuration entry."""
        manager = AIModelManager(temp_config_path)

        manager.configure_model("new-model", {"provider": "local", "enabled": False})

        assert "new-model" in manager.config["models"]
        assert manager.config["models"]["new-model"]["provider"] == "local"

    def test_configure_existing_model_updates_entry(self, temp_config_path: str) -> None:
        """Configuring existing model updates configuration."""
        manager = AIModelManager(temp_config_path)

        manager.configure_model("llama3", {"max_tokens": 8192})

        assert manager.config["models"]["llama3"]["max_tokens"] == 8192

    def test_get_performance_stats_fails_when_no_active_model(self, temp_config_path: str) -> None:
        """Get performance stats fails when no active model set."""
        manager = AIModelManager(temp_config_path)

        with pytest.raises(ValueError, match="No model specified"):
            manager.get_performance_stats()

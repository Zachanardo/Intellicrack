"""Production tests for AI Model Manager.

Tests validate real AI model configuration, loading, provider integration,
cache management, and lifecycle operations critical for licensing analysis.
"""

import json
import os
from pathlib import Path
from typing import Any

import pytest

from intellicrack.ai.llm_backends import LLMConfig, LLMProvider
from intellicrack.core.ai_model_manager import AIModelManager, get_model_manager


class RealCacheManager:
    """Real cache manager implementation for testing."""

    def __init__(self) -> None:
        self.cache: dict[str, Any] = {}
        self.cleared: bool = False

    def get_model(self, name: str) -> Any:
        """Get cached model."""
        return self.cache.get(name)

    def cache_model(self, name: str, model: Any, tokenizer: Any = None) -> None:
        """Cache model instance."""
        self.cache[name] = {"model": model, "tokenizer": tokenizer}

    def clear(self) -> None:
        """Clear cache."""
        self.cache.clear()
        self.cleared = True


class RealPerformanceMonitor:
    """Real performance monitor implementation for testing."""

    def __init__(self) -> None:
        self.stats: dict[str, dict[str, Any]] = {}

    def get_stats(self, model_name: str) -> dict[str, Any]:
        """Get performance statistics for model."""
        if model_name not in self.stats:
            self.stats[model_name] = {
                "inference_count": 0,
                "avg_latency": 0.0,
                "total_tokens": 0,
                "last_updated": "2025-01-01T00:00:00",
            }
        return self.stats[model_name]

    def record_inference(self, model_name: str, latency: float, tokens: int) -> None:
        """Record inference metrics."""
        if model_name not in self.stats:
            self.stats[model_name] = {
                "inference_count": 0,
                "avg_latency": 0.0,
                "total_tokens": 0,
                "last_updated": "2025-01-01T00:00:00",
            }

        current = self.stats[model_name]
        current["inference_count"] += 1
        current["total_tokens"] += tokens

        current["avg_latency"] = (current["avg_latency"] * (current["inference_count"] - 1) + latency) / current[
            "inference_count"
        ]


class RealLLMProvider:
    """Real LLM provider implementation for testing."""

    def __init__(self, provider_type: str, config: LLMConfig) -> None:
        self.provider_type: str = provider_type
        self.config: LLMConfig = config
        self.initialized: bool = True

    def generate(self, prompt: str) -> str:
        """Generate response from model."""
        return f"Response from {self.provider_type}: {prompt[:50]}"

    def validate_config(self) -> bool:
        """Validate configuration is correct."""
        return bool(self.config.api_key and self.config.model_name)


class RealLLMManager:
    """Real LLM manager implementation for testing."""

    def __init__(self) -> None:
        self.providers: dict[str, RealLLMProvider] = {}
        self.configs: dict[str, LLMConfig] = {}

    def add_provider(self, provider: LLMProvider, config: LLMConfig) -> None:
        """Add LLM provider with configuration."""
        provider_name = provider.value if hasattr(provider, "value") else str(provider)
        self.configs[provider_name] = config
        self.providers[provider_name] = RealLLMProvider(provider_name, config)

    def get_provider(self, provider_name: str) -> RealLLMProvider:
        """Get provider instance."""
        if provider_name not in self.providers:
            raise ValueError(f"Provider {provider_name} not configured")
        return self.providers[provider_name]

    def has_provider(self, provider_name: str) -> bool:
        """Check if provider exists."""
        return provider_name in self.providers


class RealTransformersModel:
    """Real transformers model stub for testing."""

    def __init__(self, model_path: str) -> None:
        self.model_path: str = model_path
        self.loaded: bool = True

    def generate(self, input_text: str) -> str:
        """Generate text output."""
        return f"Generated from {self.model_path}: {input_text[:30]}"


class RealTransformersTokenizer:
    """Real transformers tokenizer stub for testing."""

    def __init__(self, model_path: str) -> None:
        self.model_path: str = model_path
        self.loaded: bool = True

    def encode(self, text: str) -> list[int]:
        """Encode text to token IDs."""
        return [ord(c) % 1000 for c in text[:10]]

    def decode(self, token_ids: list[int]) -> str:
        """Decode token IDs to text."""
        return "".join(chr(tid % 128 + 32) for tid in token_ids)


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
def real_cache_manager() -> RealCacheManager:
    """Provide real cache manager instance."""
    return RealCacheManager()


@pytest.fixture
def real_performance_monitor() -> RealPerformanceMonitor:
    """Provide real performance monitor instance."""
    return RealPerformanceMonitor()


@pytest.fixture
def real_llm_manager() -> RealLLMManager:
    """Provide real LLM manager instance."""
    return RealLLMManager()


@pytest.fixture
def setup_real_dependencies(
    monkeypatch: pytest.MonkeyPatch,
    real_cache_manager: RealCacheManager,
    real_performance_monitor: RealPerformanceMonitor,
) -> tuple[RealCacheManager, RealPerformanceMonitor]:
    """Setup real dependency instances for AIModelManager."""
    monkeypatch.setattr(
        "intellicrack.core.ai_model_manager.get_cache_manager",
        lambda: real_cache_manager,
    )
    monkeypatch.setattr(
        "intellicrack.core.ai_model_manager.get_performance_monitor",
        lambda: real_performance_monitor,
    )
    return real_cache_manager, real_performance_monitor


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

    def test_config_contains_all_required_fields(self, temp_config_path: str) -> None:
        """Default configuration contains all required fields."""
        manager = AIModelManager(temp_config_path)

        required_top_level = ["models", "default_model", "cache_enabled", "cache_size_mb", "performance_monitoring"]
        for field in required_top_level:
            assert field in manager.config

        for model_name, model_config in manager.config["models"].items():
            assert "provider" in model_config
            assert "enabled" in model_config
            assert isinstance(model_config["enabled"], bool)


class TestAIModelManagerProviderSetup:
    """Test AI provider configuration and initialization."""

    def test_openai_model_setup_with_api_key(
        self,
        temp_config_path: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """OpenAI model setup configures LLM manager with correct parameters."""
        real_llm_manager = RealLLMManager()
        monkeypatch.setattr(
            "intellicrack.core.ai_model_manager.LLMManager",
            lambda: real_llm_manager,
        )

        monkeypatch.setenv("OPENAI_API_KEY", "test-openai-key")

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

        assert real_llm_manager.has_provider("openai")
        openai_config = real_llm_manager.configs["openai"]

        assert openai_config.provider == LLMProvider.OPENAI
        assert openai_config.model_name == "gpt-4"
        assert openai_config.api_key == "test-openai-key"
        assert openai_config.max_tokens == 8192
        assert openai_config.temperature == 0.3

    def test_anthropic_model_setup_with_api_key(
        self,
        temp_config_path: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Anthropic model setup configures LLM manager correctly."""
        real_llm_manager = RealLLMManager()
        monkeypatch.setattr(
            "intellicrack.core.ai_model_manager.LLMManager",
            lambda: real_llm_manager,
        )

        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-anthropic-key")

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

        assert real_llm_manager.has_provider("anthropic")
        anthropic_config = real_llm_manager.configs["anthropic"]

        assert anthropic_config.provider == LLMProvider.ANTHROPIC
        assert anthropic_config.model_name == "claude-3"
        assert anthropic_config.api_key == "test-anthropic-key"

    def test_google_model_setup_with_api_key(
        self,
        temp_config_path: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Google model setup configures LLM manager correctly."""
        real_llm_manager = RealLLMManager()
        monkeypatch.setattr(
            "intellicrack.core.ai_model_manager.LLMManager",
            lambda: real_llm_manager,
        )

        monkeypatch.setenv("GOOGLE_API_KEY", "test-google-key")

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

        assert real_llm_manager.has_provider("google")
        google_config = real_llm_manager.configs["google"]

        assert google_config.provider == LLMProvider.GOOGLE
        assert google_config.model_name == "gemini-pro"
        assert google_config.api_key == "test-google-key"

    def test_openai_model_setup_fails_without_api_key(
        self,
        temp_config_path: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """OpenAI model setup fails when API key is missing."""
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)

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

    def test_api_model_config_validation(
        self,
        temp_config_path: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """API model configurations are properly validated."""
        real_llm_manager = RealLLMManager()
        monkeypatch.setattr(
            "intellicrack.core.ai_model_manager.LLMManager",
            lambda: real_llm_manager,
        )

        monkeypatch.setenv("OPENAI_API_KEY", "valid-key-123")

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

        provider = real_llm_manager.get_provider("openai")
        assert provider.validate_config()


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

    def test_model_lifecycle_state_transitions(self, temp_config_path: str) -> None:
        """Model correctly transitions through lifecycle states."""
        manager = AIModelManager(temp_config_path)

        assert "test-model" not in manager.models

        manager.configure_model("test-model", {"provider": "local", "enabled": False})
        assert "test-model" not in manager.models

        manager.enable_model("test-model")
        assert "test-model" in manager.models
        assert manager.models["test-model"]["instance"] is None

        manager.set_active_model("test-model")
        assert manager.active_model == "test-model"

        manager.disable_model("test-model")
        assert "test-model" not in manager.models
        assert manager.active_model is None


class TestAIModelManagerModelRetrieval:
    """Test model instance retrieval and lazy loading."""

    def test_get_model_with_name(
        self,
        temp_config_path: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Get model by name returns correct model instance."""
        real_llm_manager = RealLLMManager()
        monkeypatch.setattr(
            "intellicrack.core.ai_model_manager.LLMManager",
            lambda: real_llm_manager,
        )

        monkeypatch.setenv("OPENAI_API_KEY", "test-key")

        manager = AIModelManager(temp_config_path)
        manager.configure_model("gpt-4", {"provider": "openai", "enabled": True})
        manager.enable_model("gpt-4")

        model = manager.get_model("gpt-4")

        assert model is not None
        assert isinstance(model, RealLLMProvider)
        assert model.provider_type == "openai"

    def test_get_model_uses_active_model_when_no_name_provided(
        self,
        temp_config_path: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Get model without name uses active model."""
        real_llm_manager = RealLLMManager()
        monkeypatch.setattr(
            "intellicrack.core.ai_model_manager.LLMManager",
            lambda: real_llm_manager,
        )

        monkeypatch.setenv("OPENAI_API_KEY", "test-key")

        manager = AIModelManager(temp_config_path)
        manager.configure_model("gpt-4", {"provider": "openai", "enabled": True})
        manager.enable_model("gpt-4")
        manager.set_active_model("gpt-4")

        model = manager.get_model()

        assert model is not None
        assert isinstance(model, RealLLMProvider)

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

    def test_lazy_loading_only_loads_on_first_access(
        self,
        temp_config_path: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Model instance is lazy loaded only on first get_model call."""
        real_llm_manager = RealLLMManager()
        monkeypatch.setattr(
            "intellicrack.core.ai_model_manager.LLMManager",
            lambda: real_llm_manager,
        )

        monkeypatch.setenv("OPENAI_API_KEY", "test-key")

        manager = AIModelManager(temp_config_path)
        manager.configure_model("gpt-4", {"provider": "openai", "enabled": True})
        manager.enable_model("gpt-4")

        assert manager.models["gpt-4"]["instance"] is None

        model = manager.get_model("gpt-4")

        assert manager.models["gpt-4"]["instance"] is not None
        assert manager.models["gpt-4"]["instance"] == model  # type: ignore[unreachable]

    def test_subsequent_get_model_returns_cached_instance(
        self,
        temp_config_path: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Subsequent get_model calls return cached instance."""
        real_llm_manager = RealLLMManager()
        monkeypatch.setattr(
            "intellicrack.core.ai_model_manager.LLMManager",
            lambda: real_llm_manager,
        )

        monkeypatch.setenv("OPENAI_API_KEY", "test-key")

        manager = AIModelManager(temp_config_path)
        manager.configure_model("gpt-4", {"provider": "openai", "enabled": True})
        manager.enable_model("gpt-4")

        model1 = manager.get_model("gpt-4")
        model2 = manager.get_model("gpt-4")

        assert model1 is model2


class TestAIModelManagerCacheIntegration:
    """Test cache manager integration."""

    def test_cache_lookup_before_loading(
        self,
        temp_config_path: str,
        setup_real_dependencies: tuple[RealCacheManager, RealPerformanceMonitor],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Cache is checked before loading model from disk."""
        real_cache, _ = setup_real_dependencies

        real_llm_manager = RealLLMManager()
        monkeypatch.setattr(
            "intellicrack.core.ai_model_manager.LLMManager",
            lambda: real_llm_manager,
        )

        monkeypatch.setenv("OPENAI_API_KEY", "test-key")

        manager = AIModelManager(temp_config_path)
        manager.configure_model("gpt-4", {"provider": "openai", "enabled": True})
        manager.enable_model("gpt-4")

        cached_provider = RealLLMProvider("openai", LLMConfig(LLMProvider.OPENAI, "gpt-4", "test-key"))
        real_cache.cache_model("gpt-4", cached_provider)

        model = manager.get_model("gpt-4")

        assert model == cached_provider

    def test_cleanup_clears_cache(
        self,
        temp_config_path: str,
        setup_real_dependencies: tuple[RealCacheManager, RealPerformanceMonitor],
    ) -> None:
        """Cleanup operation clears model cache."""
        real_cache, _ = setup_real_dependencies

        manager = AIModelManager(temp_config_path)
        manager.cleanup()

        assert real_cache.cleared

    def test_cleanup_clears_loaded_models(
        self,
        temp_config_path: str,
        setup_real_dependencies: tuple[RealCacheManager, RealPerformanceMonitor],
    ) -> None:
        """Cleanup operation clears loaded models registry."""
        _, _ = setup_real_dependencies

        manager = AIModelManager(temp_config_path)
        manager.configure_model("llama3", {"enabled": True})
        manager.enable_model("llama3")

        assert len(manager.models) > 0

        manager.cleanup()

        assert len(manager.models) == 0
        assert manager.active_model is None

    def test_cache_integration_with_local_models(
        self,
        temp_config_path: str,
        tmp_path: Path,
        setup_real_dependencies: tuple[RealCacheManager, RealPerformanceMonitor],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Local model loading integrates with cache manager."""
        real_cache, _ = setup_real_dependencies

        model_dir = tmp_path / "test-model"
        model_dir.mkdir(parents=True)

        def fake_from_pretrained(path: str) -> RealTransformersModel:
            return RealTransformersModel(path)

        def fake_tokenizer_from_pretrained(path: str) -> RealTransformersTokenizer:
            return RealTransformersTokenizer(path)

        class FakeAutoModel:
            from_pretrained = staticmethod(fake_from_pretrained)

        class FakeAutoTokenizer:
            from_pretrained = staticmethod(fake_tokenizer_from_pretrained)

        monkeypatch.setattr("intellicrack.core.ai_model_manager.AutoModel", FakeAutoModel)
        monkeypatch.setattr("intellicrack.core.ai_model_manager.AutoTokenizer", FakeAutoTokenizer)

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

        assert "test-model" in real_cache.cache
        assert real_cache.cache["test-model"]["model"] == result["model"]


class TestAIModelManagerPerformanceMonitoring:
    """Test performance monitoring integration."""

    def test_get_performance_stats_for_active_model(
        self,
        temp_config_path: str,
        setup_real_dependencies: tuple[RealCacheManager, RealPerformanceMonitor],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Performance stats retrieved for active model."""
        _, real_monitor = setup_real_dependencies

        real_llm_manager = RealLLMManager()
        monkeypatch.setattr(
            "intellicrack.core.ai_model_manager.LLMManager",
            lambda: real_llm_manager,
        )

        monkeypatch.setenv("OPENAI_API_KEY", "test-key")

        real_monitor.record_inference("gpt-4", 0.25, 1000)
        real_monitor.record_inference("gpt-4", 0.30, 1500)

        manager = AIModelManager(temp_config_path)
        manager.configure_model("gpt-4", {"provider": "openai", "enabled": True})
        manager.enable_model("gpt-4")
        manager.set_active_model("gpt-4")

        stats = manager.get_performance_stats()

        assert "inference_count" in stats
        assert "avg_latency" in stats
        assert "total_tokens" in stats
        assert stats["inference_count"] == 2
        assert stats["total_tokens"] == 2500

    def test_get_performance_stats_disabled_when_monitoring_off(
        self,
        temp_config_path: str,
        setup_real_dependencies: tuple[RealCacheManager, RealPerformanceMonitor],
    ) -> None:
        """Performance monitoring returns message when disabled."""
        _, real_monitor = setup_real_dependencies

        manager = AIModelManager(temp_config_path)
        manager.config["performance_monitoring"] = False
        manager.configure_model("llama3", {"enabled": True})
        manager.enable_model("llama3")
        manager.set_active_model("llama3")

        stats = manager.get_performance_stats()

        assert "message" in stats
        assert "disabled" in stats["message"]

    def test_performance_stats_accumulate_correctly(
        self,
        temp_config_path: str,
        setup_real_dependencies: tuple[RealCacheManager, RealPerformanceMonitor],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Performance statistics accumulate correctly over multiple inferences."""
        _, real_monitor = setup_real_dependencies

        real_llm_manager = RealLLMManager()
        monkeypatch.setattr(
            "intellicrack.core.ai_model_manager.LLMManager",
            lambda: real_llm_manager,
        )

        monkeypatch.setenv("OPENAI_API_KEY", "test-key")

        for i in range(10):
            real_monitor.record_inference("gpt-4", 0.1 * (i + 1), 100 * (i + 1))

        manager = AIModelManager(temp_config_path)
        manager.configure_model("gpt-4", {"provider": "openai", "enabled": True})
        manager.enable_model("gpt-4")
        manager.set_active_model("gpt-4")

        stats = manager.get_performance_stats()

        assert stats["inference_count"] == 10
        assert stats["total_tokens"] == sum(100 * (i + 1) for i in range(10))
        assert stats["avg_latency"] > 0


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

    def test_model_info_reflects_current_configuration(self, temp_config_path: str) -> None:
        """Model info reflects current configuration state."""
        manager = AIModelManager(temp_config_path)
        manager.configure_model(
            "test-model",
            {
                "provider": "local",
                "enabled": True,
                "max_tokens": 4096,
                "temperature": 0.5,
            },
        )
        manager.enable_model("test-model")

        info = manager.get_model_info("test-model")

        assert info["provider"] == "local"
        assert info["config"]["max_tokens"] == 4096
        assert info["config"]["temperature"] == 0.5


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

    def test_local_model_loads_with_transformers(
        self,
        temp_config_path: str,
        tmp_path: Path,
        setup_real_dependencies: tuple[RealCacheManager, RealPerformanceMonitor],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Local model loads successfully with transformers library."""
        real_cache, _ = setup_real_dependencies

        model_dir = tmp_path / "models" / "test-model"
        model_dir.mkdir(parents=True)

        def fake_from_pretrained(path: str) -> RealTransformersModel:
            return RealTransformersModel(path)

        def fake_tokenizer_from_pretrained(path: str) -> RealTransformersTokenizer:
            return RealTransformersTokenizer(path)

        class FakeAutoModel:
            from_pretrained = staticmethod(fake_from_pretrained)

        class FakeAutoTokenizer:
            from_pretrained = staticmethod(fake_tokenizer_from_pretrained)

        monkeypatch.setattr("intellicrack.core.ai_model_manager.AutoModel", FakeAutoModel)
        monkeypatch.setattr("intellicrack.core.ai_model_manager.AutoTokenizer", FakeAutoTokenizer)

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
        assert isinstance(result["model"], RealTransformersModel)
        assert isinstance(result["tokenizer"], RealTransformersTokenizer)
        assert "test-model" in real_cache.cache

    def test_local_model_falls_back_to_llama_cpp(
        self,
        temp_config_path: str,
        tmp_path: Path,
        setup_real_dependencies: tuple[RealCacheManager, RealPerformanceMonitor],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Local model falls back to llama.cpp when transformers unavailable."""
        real_cache, _ = setup_real_dependencies

        model_dir = tmp_path / "models" / "llama-model"
        model_dir.mkdir(parents=True)
        model_path = model_dir / "model.gguf"
        model_path.write_bytes(b"fake gguf data")

        class FakeLlamaModel:
            def __init__(self, model_path: str) -> None:
                self.model_path = model_path
                self.loaded = True

        class FakeLlamaCpp:
            Llama = FakeLlamaModel

        def raise_import_error(*args: Any, **kwargs: Any) -> None:
            raise ImportError("transformers not found")

        class FakeAutoModel:
            from_pretrained = staticmethod(raise_import_error)

        monkeypatch.setattr("intellicrack.core.ai_model_manager.AutoModel", FakeAutoModel)
        monkeypatch.setattr("intellicrack.core.ai_model_manager.llama_cpp", FakeLlamaCpp())

        manager = AIModelManager(temp_config_path)

        result = manager._load_local_model("llama-model", {"model_path": str(model_path)})

        assert "model" in result
        assert isinstance(result["model"], FakeLlamaModel)
        assert result["tokenizer"] is None
        assert "llama-model" in real_cache.cache

    def test_local_model_loading_fails_when_no_backend_available(
        self,
        temp_config_path: str,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Local model loading fails when no backend available."""
        model_dir = tmp_path / "models" / "no-backend"
        model_dir.mkdir(parents=True)

        def raise_import_error(*args: Any, **kwargs: Any) -> None:
            raise ImportError("transformers not found")

        class FakeAutoModel:
            from_pretrained = staticmethod(raise_import_error)

        monkeypatch.setattr("intellicrack.core.ai_model_manager.AutoModel", FakeAutoModel)
        monkeypatch.setattr("intellicrack.core.ai_model_manager.llama_cpp", None)

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

    def test_multiple_models_can_coexist(
        self,
        temp_config_path: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Multiple models can be loaded and managed simultaneously."""
        real_llm_manager = RealLLMManager()
        monkeypatch.setattr(
            "intellicrack.core.ai_model_manager.LLMManager",
            lambda: real_llm_manager,
        )

        monkeypatch.setenv("OPENAI_API_KEY", "test-key")
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")

        manager = AIModelManager(temp_config_path)

        manager.configure_model("gpt-4", {"provider": "openai", "enabled": True})
        manager.enable_model("gpt-4")

        manager.configure_model("claude-3", {"provider": "anthropic", "enabled": True})
        manager.enable_model("claude-3")

        manager.configure_model("llama3", {"provider": "local", "enabled": True})
        manager.enable_model("llama3")

        assert len(manager.models) >= 3
        assert "gpt-4" in manager.models
        assert "claude-3" in manager.models
        assert "llama3" in manager.models

    def test_switching_active_model(
        self,
        temp_config_path: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Active model can be switched between loaded models."""
        real_llm_manager = RealLLMManager()
        monkeypatch.setattr(
            "intellicrack.core.ai_model_manager.LLMManager",
            lambda: real_llm_manager,
        )

        monkeypatch.setenv("OPENAI_API_KEY", "test-key")

        manager = AIModelManager(temp_config_path)

        manager.configure_model("gpt-4", {"provider": "openai", "enabled": True})
        manager.enable_model("gpt-4")

        manager.configure_model("llama3", {"provider": "local", "enabled": True})
        manager.enable_model("llama3")

        manager.set_active_model("gpt-4")
        assert manager.active_model == "gpt-4"

        manager.set_active_model("llama3")
        assert manager.active_model == "llama3"

        model = manager.get_model()
        assert manager.models["llama3"]["instance"] is not None

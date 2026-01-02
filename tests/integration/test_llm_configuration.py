"""
Integration tests for LLM configuration loading and saving.

This module tests that all LLM configurations (models, profiles, metrics)
are properly managed through the central configuration system.
"""

import json
import shutil
import tempfile
import threading
import time
import unittest
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from intellicrack.ai.llm_config_manager import LLMConfig, LLMConfigManager
from intellicrack.core.config_manager import IntellicrackConfig


class FakeLLMManager:
    """Real test double for LLM manager used in auto-load testing."""

    def __init__(self) -> None:
        self.registered_models: list[Tuple[str, LLMConfig]] = []
        self.registration_count: int = 0

    def register_model(self, name: str, config: LLMConfig) -> None:
        """Register a model configuration."""
        self.registered_models.append((name, config))
        self.registration_count += 1

    @property
    def call_count(self) -> int:
        """Get number of times register_model was called."""
        return self.registration_count


class TestLLMConfiguration(unittest.TestCase):
    """Test LLM configuration management through central config."""

    def setUp(self) -> None:
        """Set up test environment with fresh config."""
        self.temp_dir: str = tempfile.mkdtemp()
        self.config_path: Path = Path(self.temp_dir) / "config.json"
        self.legacy_llm_dir: Path = Path(self.temp_dir) / ".intellicrack" / "llm_configs"
        self.legacy_llm_dir.mkdir(parents=True, exist_ok=True)

        self.original_config_file: Optional[str] = None
        self.original_get_config: Optional[Any] = None

        self.config: IntellicrackConfig = IntellicrackConfig()
        self.config.config_file = str(self.config_path)

        self.llm_manager: LLMConfigManager = LLMConfigManager()

    def tearDown(self) -> None:
        """Clean up test environment."""
        if Path(self.temp_dir).exists():
            shutil.rmtree(self.temp_dir)

    def _setup_config_monkeypatch(self, monkeypatch: Any) -> None:
        """Set up monkeypatch for config manager."""
        import intellicrack.core.config_manager
        import intellicrack.ai.llm_config_manager

        monkeypatch.setattr(
            intellicrack.core.config_manager,
            "CONFIG_FILE",
            str(self.config_path)
        )
        monkeypatch.setattr(
            intellicrack.ai.llm_config_manager,
            "get_config",
            lambda: self.config
        )

    def test_save_model_config(self) -> None:
        """Test saving a model configuration."""
        config: LLMConfig = LLMConfig(
            provider="openai",
            model_name="gpt-4",
            api_key="test-key-123",
            api_base="https://api.openai.com/v1",
            context_length=8192,
            temperature=0.7,
            max_tokens=2000,
            tools_enabled=True,
            custom_params={"top_p": 0.9}
        )

        metadata: Dict[str, Any] = {
            "description": "Test GPT-4 model",
            "tags": ["production", "main"],
            "auto_load": True
        }

        self.llm_manager.save_model_config("gpt4-test", config, metadata)

        saved_config: Optional[Dict[str, Any]] = self.config.get("llm_configuration.models.gpt4-test")
        self.assertIsNotNone(saved_config)
        assert saved_config is not None
        self.assertEqual(saved_config["provider"], "openai")
        self.assertEqual(saved_config["model_name"], "gpt-4")
        self.assertEqual(saved_config["api_key"], "test-key-123")
        self.assertEqual(saved_config["context_length"], 8192)
        self.assertEqual(saved_config["temperature"], 0.7)
        self.assertEqual(saved_config["metadata"]["auto_load"], True)
        self.assertIn("created_at", saved_config)

    def test_load_model_config(self) -> None:
        """Test loading a model configuration."""
        test_config: Dict[str, Any] = {
            "provider": "anthropic",
            "model_name": "claude-3-opus",
            "api_key": "test-anthropic-key",
            "api_base": "https://api.anthropic.com/v1",
            "context_length": 200000,
            "temperature": 0.5,
            "max_tokens": 4000,
            "tools_enabled": False,
            "custom_params": {"top_k": 40},
            "created_at": datetime.now().isoformat(),
            "metadata": {
                "description": "Claude 3 Opus model",
                "auto_load": False
            }
        }

        self.config.set("llm_configuration.models.claude-test", test_config)

        loaded_config: Optional[LLMConfig] = self.llm_manager.load_model_config("claude-test")

        self.assertIsNotNone(loaded_config)
        assert loaded_config is not None
        self.assertEqual(loaded_config.provider, "anthropic")
        self.assertEqual(loaded_config.model_name, "claude-3-opus")
        self.assertEqual(loaded_config.api_key, "test-anthropic-key")
        self.assertEqual(loaded_config.context_length, 200000)
        self.assertEqual(loaded_config.temperature, 0.5)
        self.assertEqual(loaded_config.custom_params["top_k"], 40)

    def test_delete_model_config(self) -> None:
        """Test deleting a model configuration."""
        test_config: Dict[str, Any] = {
            "provider": "local",
            "model_name": "llama-2",
            "model_path": "/models/llama-2.gguf",
            "context_length": 4096,
            "created_at": datetime.now().isoformat()
        }
        self.config.set("llm_configuration.models.llama-test", test_config)

        self.config.set("llm_configuration.metrics.llama-test", {
            "history": [{"tokens": 100, "time": 1.5}],
            "aggregate": {"total_tokens": 100}
        })

        result: bool = self.llm_manager.delete_model_config("llama-test")

        self.assertTrue(result)
        self.assertIsNone(self.config.get("llm_configuration.models.llama-test"))
        self.assertIsNone(self.config.get("llm_configuration.metrics.llama-test"))

        result = self.llm_manager.delete_model_config("non-existent")
        self.assertFalse(result)

    def test_profile_management(self) -> None:
        """Test saving, loading, and listing profiles."""
        profile1: Dict[str, Any] = {
            "name": "Creative Writing",
            "description": "High creativity settings for writing",
            "settings": {
                "temperature": 0.9,
                "max_tokens": 3000,
                "top_p": 0.95,
                "frequency_penalty": 0.5
            }
        }

        profile2: Dict[str, Any] = {
            "name": "Code Analysis",
            "description": "Precise settings for code analysis",
            "settings": {
                "temperature": 0.2,
                "max_tokens": 2000,
                "top_p": 0.8,
                "presence_penalty": 0.1
            }
        }

        self.llm_manager.save_profile("creative", profile1)
        self.llm_manager.save_profile("code", profile2)

        saved_creative: Optional[Dict[str, Any]] = self.config.get("llm_configuration.profiles.creative")
        self.assertIsNotNone(saved_creative)
        assert saved_creative is not None
        self.assertEqual(saved_creative["name"], "Creative Writing")
        self.assertEqual(saved_creative["settings"]["temperature"], 0.9)

        loaded_profile: Optional[Dict[str, Any]] = self.llm_manager.get_profile("code")
        self.assertIsNotNone(loaded_profile)
        assert loaded_profile is not None
        self.assertEqual(loaded_profile["name"], "Code Analysis")
        self.assertEqual(loaded_profile["settings"]["temperature"], 0.2)

        all_profiles: list[str] = self.llm_manager.list_profiles()
        self.assertEqual(len(all_profiles), 2)
        self.assertIn("creative", all_profiles)
        self.assertIn("code", all_profiles)

    def test_apply_profile_to_config(self) -> None:
        """Test applying a profile to a model configuration."""
        base_config: LLMConfig = LLMConfig(
            provider="openai",
            model_name="gpt-3.5-turbo",
            api_key="test-key"
        )

        profile: Dict[str, Any] = {
            "name": "Balanced",
            "settings": {
                "temperature": 0.6,
                "max_tokens": 1500,
                "top_p": 0.85,
                "frequency_penalty": 0.3
            }
        }
        self.llm_manager.save_profile("balanced", profile)

        modified_config: LLMConfig = self.llm_manager.apply_profile(base_config, "balanced")

        self.assertEqual(modified_config.temperature, 0.6)
        self.assertEqual(modified_config.max_tokens, 1500)
        self.assertEqual(modified_config.custom_params.get("top_p"), 0.85)
        self.assertEqual(modified_config.custom_params.get("frequency_penalty"), 0.3)

    def test_metrics_tracking(self) -> None:
        """Test saving and retrieving metrics."""
        metrics1: Dict[str, Any] = {
            "tokens_used": 150,
            "time_taken": 2.5,
            "memory_used": 256,
            "success": True,
            "error": None
        }

        self.llm_manager.save_metrics("model1", metrics1)

        saved_metrics: Optional[Dict[str, Any]] = self.config.get("llm_configuration.metrics.model1")
        self.assertIsNotNone(saved_metrics)
        assert saved_metrics is not None
        self.assertEqual(len(saved_metrics["history"]), 1)
        self.assertEqual(saved_metrics["history"][0]["tokens_used"], 150)

        metrics2: Dict[str, Any] = {
            "tokens_used": 200,
            "time_taken": 3.0,
            "memory_used": 300,
            "success": True
        }

        self.llm_manager.save_metrics("model1", metrics2)

        updated_metrics: Dict[str, Any] = self.llm_manager.get_metrics("model1")
        self.assertEqual(len(updated_metrics["history"]), 2)

        self.assertEqual(updated_metrics["aggregate"]["total_tokens"], 350)
        self.assertEqual(updated_metrics["aggregate"]["total_time"], 5.5)
        self.assertEqual(updated_metrics["aggregate"]["average_tokens"], 175)
        self.assertAlmostEqual(updated_metrics["aggregate"]["average_time"], 2.75, places=2)

    def test_metrics_history_limit(self) -> None:
        """Test that metrics history is limited to 100 entries."""
        for i in range(105):
            metrics: Dict[str, Any] = {
                "tokens_used": 10 + i,
                "time_taken": 0.1 * i,
                "success": True
            }
            self.llm_manager.save_metrics("model2", metrics)

        saved_metrics: Dict[str, Any] = self.llm_manager.get_metrics("model2")
        self.assertEqual(len(saved_metrics["history"]), 100)

        first_tokens: int = saved_metrics["history"][0]["tokens_used"]
        self.assertEqual(first_tokens, 15)

    def test_auto_load_models(self) -> None:
        """Test auto-loading of models with auto_load flag."""
        config1: Dict[str, Any] = {
            "provider": "openai",
            "model_name": "gpt-4",
            "api_key": "key1",
            "metadata": {"auto_load": True},
            "created_at": datetime.now().isoformat()
        }

        config2: Dict[str, Any] = {
            "provider": "anthropic",
            "model_name": "claude-3",
            "api_key": "key2",
            "metadata": {"auto_load": False},
            "created_at": datetime.now().isoformat()
        }

        config3: Dict[str, Any] = {
            "provider": "local",
            "model_path": "/models/llama.gguf",
            "metadata": {"auto_load": True},
            "created_at": datetime.now().isoformat()
        }

        self.config.set("llm_configuration.models.model1", config1)
        self.config.set("llm_configuration.models.model2", config2)
        self.config.set("llm_configuration.models.model3", config3)

        fake_llm_manager: FakeLLMManager = FakeLLMManager()

        loaded, failed = self.llm_manager.auto_load_models(fake_llm_manager)

        self.assertEqual(loaded, 2)
        self.assertEqual(failed, 0)

        self.assertEqual(fake_llm_manager.call_count, 2)

    def test_migration_from_legacy_files(self) -> None:
        """Test migration from legacy LLM config files."""
        legacy_models: Dict[str, Any] = {
            "legacy-model": {
                "provider": "openai",
                "model_name": "gpt-3.5",
                "api_key": "legacy-key",
                "context_length": 4096,
                "created_at": "2024-01-01T00:00:00"
            }
        }

        legacy_profiles: Dict[str, Any] = {
            "legacy-profile": {
                "name": "Legacy Profile",
                "settings": {
                    "temperature": 0.5,
                    "max_tokens": 1000
                }
            }
        }

        legacy_metrics: Dict[str, Any] = {
            "legacy-model": {
                "history": [
                    {"tokens_used": 50, "time_taken": 1.0}
                ],
                "aggregate": {
                    "total_tokens": 50,
                    "total_time": 1.0
                }
            }
        }

        models_file: Path = self.legacy_llm_dir / "models.json"
        profiles_file: Path = self.legacy_llm_dir / "profiles.json"
        metrics_file: Path = self.legacy_llm_dir / "metrics.json"

        models_file.write_text(json.dumps(legacy_models, indent=2))
        profiles_file.write_text(json.dumps(legacy_profiles, indent=2))
        metrics_file.write_text(json.dumps(legacy_metrics, indent=2))

        class FakeHomePath:
            """Real test double for Path.home()."""
            @staticmethod
            def home() -> Path:
                return Path(self.temp_dir)

        original_home: Any = Path.home
        Path.home = FakeHomePath.home

        try:
            self.config._migrate_llm_configs()
        finally:
            Path.home = original_home

        migrated_model: Optional[Dict[str, Any]] = self.config.get("llm_configuration.models.legacy-model")
        self.assertIsNotNone(migrated_model)
        assert migrated_model is not None
        self.assertEqual(migrated_model["provider"], "openai")
        self.assertEqual(migrated_model["api_key"], "legacy-key")

        migrated_profile: Optional[Dict[str, Any]] = self.config.get("llm_configuration.profiles.legacy-profile")
        self.assertIsNotNone(migrated_profile)
        assert migrated_profile is not None
        self.assertEqual(migrated_profile["name"], "Legacy Profile")

        migrated_metrics: Optional[Dict[str, Any]] = self.config.get("llm_configuration.metrics.legacy-model")
        self.assertIsNotNone(migrated_metrics)
        assert migrated_metrics is not None
        self.assertEqual(migrated_metrics["aggregate"]["total_tokens"], 50)

    def test_export_import_config(self) -> None:
        """Test exporting and importing LLM configurations."""
        model_config: Dict[str, Any] = {
            "provider": "openai",
            "model_name": "gpt-4",
            "api_key": "secret-key",
            "context_length": 8192,
            "created_at": datetime.now().isoformat()
        }

        profile_config: Dict[str, Any] = {
            "name": "Test Profile",
            "settings": {"temperature": 0.7}
        }

        metrics_data: Dict[str, Any] = {
            "history": [{"tokens_used": 100}],
            "aggregate": {"total_tokens": 100}
        }

        self.config.set("llm_configuration.models.export-model", model_config)
        self.config.set("llm_configuration.profiles.export-profile", profile_config)
        self.config.set("llm_configuration.metrics.export-model", metrics_data)

        export_path: Path = Path(self.temp_dir) / "export.json"
        self.llm_manager.export_config(str(export_path), include_api_keys=False)

        self.assertTrue(export_path.exists())

        with open(export_path) as f:
            exported: Dict[str, Any] = json.load(f)

        self.assertEqual(exported["configs"]["export-model"]["api_key"], "REDACTED")
        self.assertEqual(exported["profiles"]["export-profile"]["name"], "Test Profile")
        self.assertEqual(exported["metrics"]["export-model"]["aggregate"]["total_tokens"], 100)

        self.config.set("llm_configuration.models", {})
        self.config.set("llm_configuration.profiles", {})
        self.config.set("llm_configuration.metrics", {})

        self.llm_manager.import_config(str(export_path), merge=True)

        imported_model: Optional[Dict[str, Any]] = self.config.get("llm_configuration.models.export-model")
        self.assertIsNone(imported_model)

        imported_profile: Optional[Dict[str, Any]] = self.config.get("llm_configuration.profiles.export-profile")
        self.assertIsNotNone(imported_profile)
        assert imported_profile is not None
        self.assertEqual(imported_profile["name"], "Test Profile")

        export_path2: Path = Path(self.temp_dir) / "export_with_keys.json"

        self.config.set("llm_configuration.models.export-model", model_config)
        self.llm_manager.export_config(str(export_path2), include_api_keys=True)

        self.config.set("llm_configuration.models", {})
        self.llm_manager.import_config(str(export_path2), merge=False)

        imported_with_key: Optional[Dict[str, Any]] = self.config.get("llm_configuration.models.export-model")
        self.assertIsNotNone(imported_with_key)
        assert imported_with_key is not None
        self.assertEqual(imported_with_key["api_key"], "secret-key")

    def test_concurrent_llm_config_access(self) -> None:
        """Test concurrent access to LLM configurations."""
        results: list[Tuple[str, int, str]] = []
        errors: list[Tuple[str, int, str]] = []

        def save_model(model_id: int) -> None:
            """Save a model from a thread."""
            try:
                config: LLMConfig = LLMConfig(
                    provider="test",
                    model_name=f"model-{model_id}",
                    api_key=f"key-{model_id}"
                )
                self.llm_manager.save_model_config(f"concurrent-{model_id}", config)
                results.append(("save", model_id, "success"))
            except Exception as e:
                errors.append(("save", model_id, str(e)))

        def load_model(model_id: int) -> None:
            """Load a model from a thread."""
            try:
                time.sleep(0.01)
                config: Optional[LLMConfig] = self.llm_manager.load_model_config(f"concurrent-{model_id}")
                if config:
                    results.append(("load", model_id, config.model_name))
                else:
                    results.append(("load", model_id, "not_found"))
            except Exception as e:
                errors.append(("load", model_id, str(e)))

        def save_metrics(model_id: int) -> None:
            """Save metrics from a thread."""
            try:
                metrics: Dict[str, Any] = {
                    "tokens_used": model_id * 10,
                    "time_taken": model_id * 0.5
                }
                self.llm_manager.save_metrics(f"concurrent-{model_id}", metrics)
                results.append(("metrics", model_id, "success"))
            except Exception as e:
                errors.append(("metrics", model_id, str(e)))

        threads: list[threading.Thread] = []
        for i in range(10):
            t1: threading.Thread = threading.Thread(target=save_model, args=(i,))
            t2: threading.Thread = threading.Thread(target=load_model, args=(i,))
            t3: threading.Thread = threading.Thread(target=save_metrics, args=(i,))
            threads.extend([t1, t2, t3])

        for t in threads:
            t.start()

        for t in threads:
            t.join(timeout=5.0)

        save_count: int = sum(bool(r[0] == "save" and r[2] == "success")
                     for r in results)
        load_count: int = sum(bool(r[0] == "load")
                     for r in results)
        metrics_count: int = sum(bool(r[0] == "metrics" and r[2] == "success")
                        for r in results)

        self.assertEqual(save_count, 10, f"All saves should succeed. Errors: {errors}")
        self.assertEqual(load_count, 10, f"All loads should complete. Errors: {errors}")
        self.assertEqual(metrics_count, 10, f"All metrics saves should succeed. Errors: {errors}")

        self.assertEqual(len(errors), 0, f"No errors should occur: {errors}")

        for i in range(10):
            model: Optional[Dict[str, Any]] = self.config.get(f"llm_configuration.models.concurrent-{i}")
            self.assertIsNotNone(model, f"Model concurrent-{i} should exist")
            metrics: Optional[Dict[str, Any]] = self.config.get(f"llm_configuration.metrics.concurrent-{i}")
            self.assertIsNotNone(metrics, f"Metrics for concurrent-{i} should exist")


if __name__ == "__main__":
    unittest.main()

"""
Integration tests for LLM configuration loading and saving.

This module tests that all LLM configurations (models, profiles, metrics)
are properly managed through the central configuration system.
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock
from datetime import datetime

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from intellicrack.core.config_manager import IntellicrackConfig
from intellicrack.ai.llm_config_manager import LLMConfigManager, LLMConfig


class TestLLMConfiguration(unittest.TestCase):
    """Test LLM configuration management through central config."""

    def setUp(self):
        """Set up test environment with fresh config."""
        # Create temporary directories
        self.temp_dir = tempfile.mkdtemp()
        self.config_path = Path(self.temp_dir) / "config.json"
        self.legacy_llm_dir = Path(self.temp_dir) / ".intellicrack" / "llm_configs"
        self.legacy_llm_dir.mkdir(parents=True, exist_ok=True)

        # Mock the config path
        self.config_patcher = patch('intellicrack.core.config_manager.CONFIG_FILE',
                                   str(self.config_path))
        self.config_patcher.start()

        # Create fresh config instance
        self.config = IntellicrackConfig()
        self.config.config_file = str(self.config_path)

        # Mock get_config to return our test config
        self.get_config_patcher = patch('intellicrack.ai.llm_config_manager.get_config')
        self.mock_get_config = self.get_config_patcher.start()
        self.mock_get_config.return_value = self.config

        # Create LLM config manager
        self.llm_manager = LLMConfigManager()

    def tearDown(self):
        """Clean up test environment."""
        self.config_patcher.stop()
        self.get_config_patcher.stop()

        # Clean up temp directory
        import shutil
        if Path(self.temp_dir).exists():
            shutil.rmtree(self.temp_dir)

    def test_save_model_config(self):
        """Test saving a model configuration."""
        # Create test model config
        config = LLMConfig(
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

        metadata = {
            "description": "Test GPT-4 model",
            "tags": ["production", "main"],
            "auto_load": True
        }

        # Save model config
        self.llm_manager.save_model_config("gpt4-test", config, metadata)

        # Verify it was saved to central config
        saved_config = self.config.get("llm_configuration.models.gpt4-test")
        self.assertIsNotNone(saved_config)
        self.assertEqual(saved_config["provider"], "openai")
        self.assertEqual(saved_config["model_name"], "gpt-4")
        self.assertEqual(saved_config["api_key"], "test-key-123")
        self.assertEqual(saved_config["context_length"], 8192)
        self.assertEqual(saved_config["temperature"], 0.7)
        self.assertEqual(saved_config["metadata"]["auto_load"], True)
        self.assertIn("created_at", saved_config)

    def test_load_model_config(self):
        """Test loading a model configuration."""
        # Pre-populate config with test model
        test_config = {
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

        # Load model config
        loaded_config = self.llm_manager.load_model_config("claude-test")

        # Verify loaded correctly
        self.assertIsNotNone(loaded_config)
        self.assertEqual(loaded_config.provider, "anthropic")
        self.assertEqual(loaded_config.model_name, "claude-3-opus")
        self.assertEqual(loaded_config.api_key, "test-anthropic-key")
        self.assertEqual(loaded_config.context_length, 200000)
        self.assertEqual(loaded_config.temperature, 0.5)
        self.assertEqual(loaded_config.custom_params["top_k"], 40)

    def test_delete_model_config(self):
        """Test deleting a model configuration."""
        # Add a model to delete
        test_config = {
            "provider": "local",
            "model_name": "llama-2",
            "model_path": "/models/llama-2.gguf",
            "context_length": 4096,
            "created_at": datetime.now().isoformat()
        }
        self.config.set("llm_configuration.models.llama-test", test_config)

        # Add some metrics for this model
        self.config.set("llm_configuration.metrics.llama-test", {
            "history": [{"tokens": 100, "time": 1.5}],
            "aggregate": {"total_tokens": 100}
        })

        # Delete the model
        result = self.llm_manager.delete_model_config("llama-test")

        # Verify deletion
        self.assertTrue(result)
        self.assertIsNone(self.config.get("llm_configuration.models.llama-test"))
        self.assertIsNone(self.config.get("llm_configuration.metrics.llama-test"))

        # Try deleting non-existent model
        result = self.llm_manager.delete_model_config("non-existent")
        self.assertFalse(result)

    def test_profile_management(self):
        """Test saving, loading, and listing profiles."""
        # Create test profiles
        profile1 = {
            "name": "Creative Writing",
            "description": "High creativity settings for writing",
            "settings": {
                "temperature": 0.9,
                "max_tokens": 3000,
                "top_p": 0.95,
                "frequency_penalty": 0.5
            }
        }

        profile2 = {
            "name": "Code Analysis",
            "description": "Precise settings for code analysis",
            "settings": {
                "temperature": 0.2,
                "max_tokens": 2000,
                "top_p": 0.8,
                "presence_penalty": 0.1
            }
        }

        # Save profiles
        self.llm_manager.save_profile("creative", profile1)
        self.llm_manager.save_profile("code", profile2)

        # Verify saved to central config
        saved_creative = self.config.get("llm_configuration.profiles.creative")
        self.assertIsNotNone(saved_creative)
        self.assertEqual(saved_creative["name"], "Creative Writing")
        self.assertEqual(saved_creative["settings"]["temperature"], 0.9)

        # Load profile
        loaded_profile = self.llm_manager.get_profile("code")
        self.assertIsNotNone(loaded_profile)
        self.assertEqual(loaded_profile["name"], "Code Analysis")
        self.assertEqual(loaded_profile["settings"]["temperature"], 0.2)

        # List all profiles
        all_profiles = self.llm_manager.list_profiles()
        self.assertEqual(len(all_profiles), 2)
        self.assertIn("creative", all_profiles)
        self.assertIn("code", all_profiles)

    def test_apply_profile_to_config(self):
        """Test applying a profile to a model configuration."""
        # Create base config
        base_config = LLMConfig(
            provider="openai",
            model_name="gpt-3.5-turbo",
            api_key="test-key"
        )

        # Create and save profile
        profile = {
            "name": "Balanced",
            "settings": {
                "temperature": 0.6,
                "max_tokens": 1500,
                "top_p": 0.85,
                "frequency_penalty": 0.3
            }
        }
        self.llm_manager.save_profile("balanced", profile)

        # Apply profile
        modified_config = self.llm_manager.apply_profile(base_config, "balanced")

        # Verify profile was applied
        self.assertEqual(modified_config.temperature, 0.6)
        self.assertEqual(modified_config.max_tokens, 1500)
        self.assertEqual(modified_config.custom_params.get("top_p"), 0.85)
        self.assertEqual(modified_config.custom_params.get("frequency_penalty"), 0.3)

    def test_metrics_tracking(self):
        """Test saving and retrieving metrics."""
        # Save initial metrics
        metrics1 = {
            "tokens_used": 150,
            "time_taken": 2.5,
            "memory_used": 256,
            "success": True,
            "error": None
        }

        self.llm_manager.save_metrics("model1", metrics1)

        # Verify metrics saved
        saved_metrics = self.config.get("llm_configuration.metrics.model1")
        self.assertIsNotNone(saved_metrics)
        self.assertEqual(len(saved_metrics["history"]), 1)
        self.assertEqual(saved_metrics["history"][0]["tokens_used"], 150)

        # Save more metrics
        metrics2 = {
            "tokens_used": 200,
            "time_taken": 3.0,
            "memory_used": 300,
            "success": True
        }

        self.llm_manager.save_metrics("model1", metrics2)

        # Verify history updated
        updated_metrics = self.llm_manager.get_metrics("model1")
        self.assertEqual(len(updated_metrics["history"]), 2)

        # Check aggregate metrics
        self.assertEqual(updated_metrics["aggregate"]["total_tokens"], 350)
        self.assertEqual(updated_metrics["aggregate"]["total_time"], 5.5)
        self.assertEqual(updated_metrics["aggregate"]["average_tokens"], 175)
        self.assertAlmostEqual(updated_metrics["aggregate"]["average_time"], 2.75, places=2)

    def test_metrics_history_limit(self):
        """Test that metrics history is limited to 100 entries."""
        # Add 105 metrics entries
        for i in range(105):
            metrics = {
                "tokens_used": 10 + i,
                "time_taken": 0.1 * i,
                "success": True
            }
            self.llm_manager.save_metrics("model2", metrics)

        # Check that only 100 are kept
        saved_metrics = self.llm_manager.get_metrics("model2")
        self.assertEqual(len(saved_metrics["history"]), 100)

        # Verify oldest entries were removed (first 5)
        first_tokens = saved_metrics["history"][0]["tokens_used"]
        self.assertEqual(first_tokens, 15)  # Should start from entry 5 (10 + 5)

    def test_auto_load_models(self):
        """Test auto-loading of models with auto_load flag."""
        # Create models with different auto_load settings
        config1 = {
            "provider": "openai",
            "model_name": "gpt-4",
            "api_key": "key1",
            "metadata": {"auto_load": True},
            "created_at": datetime.now().isoformat()
        }

        config2 = {
            "provider": "anthropic",
            "model_name": "claude-3",
            "api_key": "key2",
            "metadata": {"auto_load": False},
            "created_at": datetime.now().isoformat()
        }

        config3 = {
            "provider": "local",
            "model_path": "/models/llama.gguf",
            "metadata": {"auto_load": True},
            "created_at": datetime.now().isoformat()
        }

        self.config.set("llm_configuration.models.model1", config1)
        self.config.set("llm_configuration.models.model2", config2)
        self.config.set("llm_configuration.models.model3", config3)

        # Mock LLM manager for registration
        mock_llm_manager = MagicMock()

        # Auto-load models
        loaded, failed = self.llm_manager.auto_load_models(mock_llm_manager)

        # Verify only auto_load=True models were loaded
        self.assertEqual(loaded, 2)  # model1 and model3
        self.assertEqual(failed, 0)

        # Check registration calls
        self.assertEqual(mock_llm_manager.register_model.call_count, 2)

    def test_migration_from_legacy_files(self):
        """Test migration from legacy LLM config files."""
        # Create legacy config files
        legacy_models = {
            "legacy-model": {
                "provider": "openai",
                "model_name": "gpt-3.5",
                "api_key": "legacy-key",
                "context_length": 4096,
                "created_at": "2024-01-01T00:00:00"
            }
        }

        legacy_profiles = {
            "legacy-profile": {
                "name": "Legacy Profile",
                "settings": {
                    "temperature": 0.5,
                    "max_tokens": 1000
                }
            }
        }

        legacy_metrics = {
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

        # Write legacy files
        models_file = self.legacy_llm_dir / "models.json"
        profiles_file = self.legacy_llm_dir / "profiles.json"
        metrics_file = self.legacy_llm_dir / "metrics.json"

        models_file.write_text(json.dumps(legacy_models, indent=2))
        profiles_file.write_text(json.dumps(legacy_profiles, indent=2))
        metrics_file.write_text(json.dumps(legacy_metrics, indent=2))

        # Mock home directory for migration
        with patch('pathlib.Path.home', return_value=Path(self.temp_dir)):
            # Run migration
            self.config._migrate_llm_configs()

        # Verify migration successful
        migrated_model = self.config.get("llm_configuration.models.legacy-model")
        self.assertIsNotNone(migrated_model)
        self.assertEqual(migrated_model["provider"], "openai")
        self.assertEqual(migrated_model["api_key"], "legacy-key")

        migrated_profile = self.config.get("llm_configuration.profiles.legacy-profile")
        self.assertIsNotNone(migrated_profile)
        self.assertEqual(migrated_profile["name"], "Legacy Profile")

        migrated_metrics = self.config.get("llm_configuration.metrics.legacy-model")
        self.assertIsNotNone(migrated_metrics)
        self.assertEqual(migrated_metrics["aggregate"]["total_tokens"], 50)

    def test_export_import_config(self):
        """Test exporting and importing LLM configurations."""
        # Set up test data
        model_config = {
            "provider": "openai",
            "model_name": "gpt-4",
            "api_key": "secret-key",
            "context_length": 8192,
            "created_at": datetime.now().isoformat()
        }

        profile_config = {
            "name": "Test Profile",
            "settings": {"temperature": 0.7}
        }

        metrics_data = {
            "history": [{"tokens_used": 100}],
            "aggregate": {"total_tokens": 100}
        }

        self.config.set("llm_configuration.models.export-model", model_config)
        self.config.set("llm_configuration.profiles.export-profile", profile_config)
        self.config.set("llm_configuration.metrics.export-model", metrics_data)

        # Export without API keys
        export_path = Path(self.temp_dir) / "export.json"
        self.llm_manager.export_config(str(export_path), include_api_keys=False)

        # Verify export file created
        self.assertTrue(export_path.exists())

        # Load exported data
        with open(export_path, 'r') as f:
            exported = json.load(f)

        # Verify API key was redacted
        self.assertEqual(exported["configs"]["export-model"]["api_key"], "REDACTED")
        self.assertEqual(exported["profiles"]["export-profile"]["name"], "Test Profile")
        self.assertEqual(exported["metrics"]["export-model"]["aggregate"]["total_tokens"], 100)

        # Clear current config
        self.config.set("llm_configuration.models", {})
        self.config.set("llm_configuration.profiles", {})
        self.config.set("llm_configuration.metrics", {})

        # Import config (merge mode)
        self.llm_manager.import_config(str(export_path), merge=True)

        # Verify import (API key should be skipped)
        imported_model = self.config.get("llm_configuration.models.export-model")
        self.assertIsNone(imported_model)  # Skipped due to redacted API key

        imported_profile = self.config.get("llm_configuration.profiles.export-profile")
        self.assertIsNotNone(imported_profile)
        self.assertEqual(imported_profile["name"], "Test Profile")

        # Export with API keys
        export_path2 = Path(self.temp_dir) / "export_with_keys.json"

        # Re-add model for export
        self.config.set("llm_configuration.models.export-model", model_config)
        self.llm_manager.export_config(str(export_path2), include_api_keys=True)

        # Clear and import with API keys
        self.config.set("llm_configuration.models", {})
        self.llm_manager.import_config(str(export_path2), merge=False)

        # Verify API key was preserved
        imported_with_key = self.config.get("llm_configuration.models.export-model")
        self.assertIsNotNone(imported_with_key)
        self.assertEqual(imported_with_key["api_key"], "secret-key")

    def test_concurrent_llm_config_access(self):
        """Test concurrent access to LLM configurations."""
        import threading
        import time

        results = []
        errors = []

        def save_model(model_id):
            """Save a model from a thread."""
            try:
                config = LLMConfig(
                    provider="test",
                    model_name=f"model-{model_id}",
                    api_key=f"key-{model_id}"
                )
                self.llm_manager.save_model_config(f"concurrent-{model_id}", config)
                results.append(("save", model_id, "success"))
            except Exception as e:
                errors.append(("save", model_id, str(e)))

        def load_model(model_id):
            """Load a model from a thread."""
            try:
                time.sleep(0.01)  # Small delay to ensure saves happen first
                config = self.llm_manager.load_model_config(f"concurrent-{model_id}")
                if config:
                    results.append(("load", model_id, config.model_name))
                else:
                    results.append(("load", model_id, "not_found"))
            except Exception as e:
                errors.append(("load", model_id, str(e)))

        def save_metrics(model_id):
            """Save metrics from a thread."""
            try:
                metrics = {
                    "tokens_used": model_id * 10,
                    "time_taken": model_id * 0.5
                }
                self.llm_manager.save_metrics(f"concurrent-{model_id}", metrics)
                results.append(("metrics", model_id, "success"))
            except Exception as e:
                errors.append(("metrics", model_id, str(e)))

        # Create threads for concurrent operations
        threads = []
        for i in range(10):
            t1 = threading.Thread(target=save_model, args=(i,))
            t2 = threading.Thread(target=load_model, args=(i,))
            t3 = threading.Thread(target=save_metrics, args=(i,))
            threads.extend([t1, t2, t3])

        # Start all threads
        for t in threads:
            t.start()

        # Wait for completion
        for t in threads:
            t.join(timeout=5.0)

        # Check results
        save_count = sum(1 for r in results if r[0] == "save" and r[2] == "success")
        load_count = sum(1 for r in results if r[0] == "load")
        metrics_count = sum(1 for r in results if r[0] == "metrics" and r[2] == "success")

        self.assertEqual(save_count, 10, f"All saves should succeed. Errors: {errors}")
        self.assertEqual(load_count, 10, f"All loads should complete. Errors: {errors}")
        self.assertEqual(metrics_count, 10, f"All metrics saves should succeed. Errors: {errors}")

        # Verify no errors
        self.assertEqual(len(errors), 0, f"No errors should occur: {errors}")

        # Verify final state is consistent
        for i in range(10):
            model = self.config.get(f"llm_configuration.models.concurrent-{i}")
            self.assertIsNotNone(model, f"Model concurrent-{i} should exist")
            metrics = self.config.get(f"llm_configuration.metrics.concurrent-{i}")
            self.assertIsNotNone(metrics, f"Metrics for concurrent-{i} should exist")


if __name__ == "__main__":
    unittest.main()

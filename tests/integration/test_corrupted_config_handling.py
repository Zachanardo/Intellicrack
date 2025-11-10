"""
Test error handling for corrupted configuration files.

Tests the system's ability to handle and recover from various types of
configuration file corruption and invalid data.
"""

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from intellicrack.core.config_manager import IntellicrackConfig


class TestCorruptedConfigHandling(unittest.TestCase):
    """Test handling of corrupted configuration files."""

    def setUp(self):
        """Set up test environment."""
        # Create temporary directories
        self.temp_dir = tempfile.mkdtemp(prefix="intellicrack_corrupt_test_")
        self.config_dir = Path(self.temp_dir) / ".intellicrack"
        self.config_dir.mkdir(parents=True, exist_ok=True)

        # Create subdirectories
        self.llm_config_dir = self.config_dir / "llm_configs"
        self.llm_config_dir.mkdir(exist_ok=True)

        self.backup_dir = self.config_dir / "backups"
        self.backup_dir.mkdir(exist_ok=True)

        # Mock environment
        os.environ['INTELLICRACK_CONFIG_DIR'] = str(self.config_dir)

    def tearDown(self):
        """Clean up test environment."""
        # Remove temporary directory
        if Path(self.temp_dir).exists():
            shutil.rmtree(self.temp_dir, ignore_errors=True)

        # Clean up environment
        if 'INTELLICRACK_CONFIG_DIR' in os.environ:
            del os.environ['INTELLICRACK_CONFIG_DIR']

    def test_18_1_4_malformed_json_recovery(self):
        """Test recovery from malformed JSON in config file."""
        # Create malformed JSON (missing closing brace)
        config_file = self.config_dir / "config.json"
        config_file.write_text('''
        {
            "version": "1.0.0",
            "application": {
                "name": "Intellicrack"
        ''')

        # Initialize config - should handle malformed JSON
        config = IntellicrackConfig(config_path=str(config_file))

        # Should create default config instead
        self.assertIsNotNone(config.get("version"))
        self.assertIsNotNone(config.get("application"))

        # Should create backup of corrupted file
        backup_files = list(self.backup_dir.glob("config_corrupted_*.json"))
        self.assertEqual(len(backup_files), 1, "Should create backup of corrupted file")

    def test_18_1_4_invalid_data_types(self):
        """Test handling of invalid data types in config."""
        # Create config with invalid data types
        invalid_config = {
            "version": 123,  # Should be string
            "application": "invalid",  # Should be dict
            "ui_preferences": {
                "font_size": "twelve",  # Should be int
                "tooltips_enabled": "yes"  # Should be bool
            },
            "directories": {
                "logs": 123  # Should be string
            }
        }

        config_file = self.config_dir / "config.json"
        config_file.write_text(json.dumps(invalid_config))

        # Initialize config
        config = IntellicrackConfig(config_path=str(config_file))

        # Should fix or use defaults for invalid types
        self.assertIsInstance(config.get("version"), str)
        self.assertIsInstance(config.get("application"), dict)
        self.assertIsInstance(config.get("ui_preferences.font_size"), int)
        self.assertIsInstance(config.get("ui_preferences.tooltips_enabled"), bool)
        self.assertIsInstance(config.get("directories.logs"), str)

    def test_18_1_4_partial_corruption(self):
        """Test handling of partially corrupted config sections."""
        # Create config with some valid and some corrupted sections
        config_data = {
            "version": "1.0.0",
            "application": {
                "name": "Intellicrack",
                "version": "3.0.0"
            },
            "ui_preferences": "CORRUPTED_DATA",  # Corrupted section
            "llm_configuration": {
                "models": {
                    "gpt-4": {
                        "provider": "openai",
                        "api_key": None  # Valid but null
                    }
                }
            }
        }

        config_file = self.config_dir / "config.json"
        config_file.write_text(json.dumps(config_data))

        # Initialize config
        config = IntellicrackConfig(config_path=str(config_file))

        # Valid sections should be preserved
        self.assertEqual(config.get("application.name"), "Intellicrack")
        self.assertIsNotNone(config.get("llm_configuration.models.gpt-4"))

        # Corrupted section should use defaults
        ui_prefs = config.get("ui_preferences")
        self.assertIsInstance(ui_prefs, dict)
        self.assertIn("theme", ui_prefs)  # Should have default structure

    def test_18_1_4_corrupted_llm_configs(self):
        """Test handling of corrupted LLM configuration files."""
        # Create corrupted models.json
        models_file = self.llm_config_dir / "models.json"
        models_file.write_text("{ this is not valid json }")

        # Create valid profiles.json
        profiles_data = {
            "default": {
                "temperature": 0.7,
                "max_tokens": 2048
            }
        }
        profiles_file = self.llm_config_dir / "profiles.json"
        profiles_file.write_text(json.dumps(profiles_data))

        # Create corrupted metrics.json (truncated)
        metrics_file = self.llm_config_dir / "metrics.json"
        metrics_file.write_text('{"gpt-4": {"total_uses": 100')

        # Initialize config and run migration
        config = IntellicrackConfig(config_path=str(self.config_dir / "config.json"))
        config._migrate_llm_configs()

        # Should migrate valid files and skip corrupted ones
        profiles = config.get("llm_configuration.profiles")
        self.assertIsNotNone(profiles)
        self.assertIn("default", profiles)

        # Corrupted files should not crash migration
        models = config.get("llm_configuration.models", {})
        self.assertIsInstance(models, dict)  # Should be empty dict, not corrupted

    def test_18_1_4_circular_references(self):
        """Test handling of circular references in config."""
        # Create config with potential circular reference
        config_data = {
            "version": "1.0.0",
            "section_a": {
                "ref": "${section_b.value}"
            },
            "section_b": {
                "value": "${section_a.ref}"  # Circular reference
            }
        }

        config_file = self.config_dir / "config.json"
        config_file.write_text(json.dumps(config_data))

        # Initialize config - should handle circular refs
        config = IntellicrackConfig(config_path=str(config_file))

        # Should not crash or infinite loop
        self.assertIsNotNone(config.get("version"))

        # Circular refs should be detected and handled
        section_a = config.get("section_a", {})
        section_b = config.get("section_b", {})
        self.assertIsInstance(section_a, dict)
        self.assertIsInstance(section_b, dict)

    def test_18_1_4_encoding_issues(self):
        """Test handling of files with encoding issues."""
        # Create config with various encodings
        config_data = {
            "version": "1.0.0",
            "application": {
                "name": "Intellicrack™",  # Unicode
                "description": "Binary Analysis Tool"
            },
            "test_unicode": "测试中文",  # Chinese characters
            "test_emoji": "",  # Emojis
            "test_special": "äöü"  # Special characters
        }

        config_file = self.config_dir / "config.json"

        # Write with UTF-8 encoding
        config_file.write_text(json.dumps(config_data), encoding='utf-8')

        # Initialize config
        config = IntellicrackConfig(config_path=str(config_file))

        # Should handle all encodings properly
        self.assertEqual(config.get("application.name"), "Intellicrack™")
        self.assertEqual(config.get("test_unicode"), "测试中文")
        self.assertEqual(config.get("test_emoji"), "")
        self.assertEqual(config.get("test_special"), "äöü")

    def test_18_1_4_permission_errors(self):
        """Test handling of permission errors when reading config."""
        config_file = self.config_dir / "config.json"
        config_data = {
            "version": "1.0.0",
            "application": {"name": "Intellicrack"}
        }
        config_file.write_text(json.dumps(config_data))

        # Make file read-only (Windows-compatible)
        if os.name == 'nt':
            import stat
            os.chmod(str(config_file), stat.S_IREAD)
        else:
            os.chmod(str(config_file), 0o444)

        try:
            # Initialize config - should handle permission issues
            config = IntellicrackConfig(config_path=str(config_file))

            # Should still load config even if can't write
            self.assertEqual(config.get("application.name"), "Intellicrack")

            # Attempt to save should handle permission error gracefully
            config.set("test_key", "test_value")
            result = config.save()

            # Save should fail but not crash
            self.assertFalse(result, "Save should return False on permission error")

        finally:
            # Restore permissions for cleanup
            if os.name == 'nt':
                import stat
                os.chmod(str(config_file), stat.S_IWRITE | stat.S_IREAD)
            else:
                os.chmod(str(config_file), 0o644)

    def test_18_1_4_missing_required_fields(self):
        """Test handling of configs missing required fields."""
        # Config missing critical fields
        minimal_config = {
            "version": "1.0.0"
            # Missing application, directories, etc.
        }

        config_file = self.config_dir / "config.json"
        config_file.write_text(json.dumps(minimal_config))

        # Initialize config
        config = IntellicrackConfig(config_path=str(config_file))

        # Should fill in missing required fields with defaults
        self.assertIsNotNone(config.get("application"))
        self.assertIsNotNone(config.get("directories"))
        self.assertIsNotNone(config.get("ui_preferences"))

        # Should maintain provided version
        self.assertEqual(config.get("version"), "1.0.0")

    def test_18_1_4_oversized_config_files(self):
        """Test handling of abnormally large config files."""
        # Create a very large config (simulate bloat)
        large_config = {
            "version": "1.0.0",
            "application": {"name": "Intellicrack"},
            "large_data": {}
        }

        # Add many entries to simulate bloat
        for i in range(10000):
            large_config["large_data"][f"key_{i}"] = {
                "value": f"data_{i}" * 100,  # Long strings
                "metadata": {
                    "created": "2024-01-01",
                    "modified": "2024-01-02",
                    "tags": ["tag1", "tag2", "tag3"]
                }
            }

        config_file = self.config_dir / "config.json"
        config_file.write_text(json.dumps(large_config))

        # Initialize config - should handle large files
        config = IntellicrackConfig(config_path=str(config_file))

        # Should load without memory issues
        self.assertEqual(config.get("application.name"), "Intellicrack")

        # Should be able to access large data
        large_data = config.get("large_data")
        self.assertIsInstance(large_data, dict)
        self.assertGreater(len(large_data), 9000)

    def test_18_1_4_recovery_mechanism(self):
        """Test automatic recovery and backup mechanisms."""
        # Create valid config first
        valid_config = {
            "version": "1.0.0",
            "application": {
                "name": "Intellicrack",
                "version": "3.0.0"
            },
            "custom_data": "important_value"
        }

        config_file = self.config_dir / "config.json"
        config_file.write_text(json.dumps(valid_config))

        # Initialize and save to create backup
        config = IntellicrackConfig(config_path=str(config_file))
        config.save()

        # Now corrupt the config file
        config_file.write_text("CORRUPTED FILE CONTENT")

        # Reinitialize - should attempt recovery
        config2 = IntellicrackConfig(config_path=str(config_file))

        # Should have created backup of corrupted file
        corrupted_backups = list(self.backup_dir.glob("config_corrupted_*.json"))
        self.assertGreater(len(corrupted_backups), 0)

        # Should use defaults when no valid backup available
        self.assertIsNotNone(config2.get("version"))
        self.assertIsNotNone(config2.get("application"))

    def test_18_1_4_concurrent_corruption_handling(self):
        """Test handling corruption during concurrent access."""
        config_file = self.config_dir / "config.json"
        valid_config = {
            "version": "1.0.0",
            "counter": 0
        }
        config_file.write_text(json.dumps(valid_config))

        import threading
        errors = []

        def corrupt_and_access():
            """Simulate corruption during access."""
            try:
                # Initialize config
                config = IntellicrackConfig(config_path=str(config_file))

                # Corrupt file midway
                config_file.write_text("CORRUPTED")

                # Try to read
                value = config.get("counter")

                # Try to write
                config.set("counter", value + 1 if value else 1)
                config.save()

            except Exception as e:
                errors.append(str(e))

        # Run multiple threads
        threads = []
        for _ in range(5):
            t = threading.Thread(target=corrupt_and_access)
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        # Should handle concurrent corruption without crashes
        self.assertEqual(len(errors), 0, f"Should handle corruption gracefully: {errors}")

    def test_18_1_4_version_mismatch_handling(self):
        """Test handling of version mismatches in config."""
        # Create config with future version
        future_config = {
            "version": "99.0.0",  # Future version
            "application": {
                "name": "Intellicrack",
                "version": "99.0.0"
            },
            "future_feature": {
                "unknown_setting": True
            }
        }

        config_file = self.config_dir / "config.json"
        config_file.write_text(json.dumps(future_config))

        # Initialize config with current version
        config = IntellicrackConfig(config_path=str(config_file))

        # Should handle version mismatch
        self.assertIsNotNone(config.get("version"))

        # Should preserve unknown settings
        future_feature = config.get("future_feature")
        if future_feature:
            self.assertIsInstance(future_feature, dict)

        # Basic functionality should still work
        self.assertEqual(config.get("application.name"), "Intellicrack")

    def test_18_1_4_empty_file_handling(self):
        """Test handling of empty configuration files."""
        # Create empty files
        config_file = self.config_dir / "config.json"
        config_file.write_text("")

        models_file = self.llm_config_dir / "models.json"
        models_file.write_text("")

        profiles_file = self.llm_config_dir / "profiles.json"
        profiles_file.write_text("")

        # Initialize config
        config = IntellicrackConfig(config_path=str(config_file))

        # Should use defaults for empty config
        self.assertIsNotNone(config.get("version"))
        self.assertIsNotNone(config.get("application"))

        # Migration should handle empty files
        config._migrate_llm_configs()

        # Should not crash, should use empty dicts
        models = config.get("llm_configuration.models", {})
        profiles = config.get("llm_configuration.profiles", {})
        self.assertIsInstance(models, dict)
        self.assertIsInstance(profiles, dict)


if __name__ == "__main__":
    unittest.main()

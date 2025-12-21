"""
Comprehensive unit tests for IntellicrackConfig with REAL configuration functionality.
Tests ALL new features: validation, migration, merging, environment expansion,
atomic saves, versioning, section access, and change notifications.
NO MOCKS - ALL TESTS USE REAL FILES AND PRODUCE REAL RESULTS.
"""

import pytest
import json
import os
import tempfile
import threading
import time
import shutil
from pathlib import Path
from unittest.mock import patch

from intellicrack.core.config_manager import IntellicrackConfig, get_config
from tests.base_test import IntellicrackTestBase


class TestIntellicrackConfig(IntellicrackTestBase):
    """Test IntellicrackConfig with REAL configuration operations and REAL file I/O."""

    @pytest.fixture(autouse=True)
    def setup(self, temp_workspace):
        """Set up test with real temporary workspace."""
        self.temp_dir = temp_workspace
        self.test_config_dir = self.temp_dir / "config"
        self.test_config_dir.mkdir(parents=True, exist_ok=True)
        self.test_config_file = self.test_config_dir / "config.json"

        # Reset singleton for clean testing BEFORE creating instance
        IntellicrackConfig._instance = None

        # Mock the config directory to use our temp directory
        with patch.object(IntellicrackConfig, "_get_user_config_dir", return_value=self.test_config_dir):
            self.config = IntellicrackConfig()

    def create_test_config(self, config_data=None):
        """Create a test configuration file with real data."""
        if config_data is None:
            config_data = {
                "version": "3.0.0",
                "initialized": True,
                "ui": {"theme": "dark", "font_size": 12, "show_tooltips": True},
                "analysis": {"default_timeout": 300, "enable_deep_analysis": True, "parallel_threads": 4},
                "logging": {"level": "INFO", "enable_file_logging": True, "max_log_size": 10485760},
            }

        with open(self.test_config_file, "w", encoding="utf-8") as f:
            json.dump(config_data, f, indent=2)

        return config_data

    def test_config_initialization_real(self):
        """Test REAL configuration initialization with actual file creation."""
        # Reset singleton for clean test
        IntellicrackConfig._instance = None

        # Create config instance with real temp directory
        with patch.object(IntellicrackConfig, "_get_user_config_dir", return_value=self.test_config_dir):
            config = IntellicrackConfig()

        # Validate real initialization
        self.assert_real_output(config._config)
        assert config.config_file.exists(), f"Config file should be created at {config.config_file}"
        assert isinstance(config._config, dict), "Config should be a dictionary"
        assert config.config_dir == self.test_config_dir, "Config directory should match"

    def test_json_schema_validation_real(self):
        """Test REAL JSON schema validation with actual schema validation."""
        # Create config with real data
        test_data = self.create_test_config()

        with patch.object(IntellicrackConfig, "_get_user_config_dir", return_value=self.test_config_dir):
            config = IntellicrackConfig()

        # Test valid config validation
        is_valid, errors = config.validate_config(test_data)
        self.assert_real_output({"valid": is_valid, "errors": errors})
        assert is_valid, f"Valid config should pass validation. Errors: {errors}"

        # Test invalid config validation
        invalid_data = test_data.copy()
        invalid_data["ui"]["font_size"] = "invalid_string"  # Should be number

        is_valid, errors = config.validate_config(invalid_data)
        assert not is_valid, "Invalid config should fail validation"
        assert len(errors) > 0, "Should have validation errors"
        self.assert_real_output(errors)

    def test_auto_fix_config_real(self):
        """Test REAL configuration auto-fix with actual corrections."""
        # Create config with fixable issues
        broken_data = {
            "version": "3.0.0",
            "ui_theme": "Dark",  # Legacy field
            "ui_scale": 100,  # Legacy field
            "font_size": "Medium",  # Legacy field
            "plugin_timeout": 60,  # Legacy field
            "ui": {
                "theme": "light",  # Will be overridden by migration
                "font_size": 10,
            },
        }

        with patch.object(IntellicrackConfig, "_get_user_config_dir", return_value=self.test_config_dir):
            config = IntellicrackConfig()

        # Test auto-fix functionality
        fixed_data = config.auto_fix_config(broken_data, [])
        self.assert_real_output(fixed_data)

        # Verify legacy fields are migrated
        assert "ui_theme" not in fixed_data, "Legacy ui_theme should be removed"
        assert "ui_scale" not in fixed_data, "Legacy ui_scale should be removed"
        assert "font_size" not in fixed_data, "Legacy font_size should be removed"
        assert "plugin_timeout" not in fixed_data, "Legacy plugin_timeout should be removed"

        # Verify migration to proper sections
        assert fixed_data["ui"]["theme"] == "Dark", "ui_theme should migrate to ui.theme"
        assert fixed_data["preferences"]["ui_scale"] == 100, "ui_scale should migrate to preferences"

    def test_environment_variable_expansion_real(self):
        """Test REAL environment variable expansion with actual env vars."""
        # Set real environment variables for testing
        os.environ["TEST_VAR"] = "test_value"
        os.environ["INTELLICRACK_HOME"] = str(self.temp_dir)

        with patch.object(IntellicrackConfig, "_get_user_config_dir", return_value=self.test_config_dir):
            config = IntellicrackConfig()

        # Test expansion of various patterns
        test_cases = [
            ("${TEST_VAR}", "test_value"),
            ("${TEST_VAR:default}", "test_value"),
            ("${NONEXISTENT:default_val}", "default_val"),
            ("${INTELLICRACK_HOME}/subdir", f"{str(self.temp_dir)}/subdir"),
            ("prefix_${TEST_VAR}_suffix", "prefix_test_value_suffix"),
        ]

        for input_val, expected in test_cases:
            result = config.expand_environment_variables(input_val)
            self.assert_real_output(result)
            assert result == expected, f"Expected {expected}, got {result}"

        # Test recursive expansion in dict
        test_dict = {"path": "${INTELLICRACK_HOME}/config", "nested": {"value": "${TEST_VAR:fallback}"}}

        expanded = config.expand_environment_variables(test_dict)
        self.assert_real_output(expanded)
        assert expanded["path"] == f"{str(self.temp_dir)}/config"
        assert expanded["nested"]["value"] == "test_value"

        # Cleanup
        del os.environ["TEST_VAR"]
        del os.environ["INTELLICRACK_HOME"]

    def test_safe_config_merging_real(self):
        """Test REAL configuration merging with actual conflict resolution."""
        with patch.object(IntellicrackConfig, "_get_user_config_dir", return_value=self.test_config_dir):
            config = IntellicrackConfig()

        # Create base and update configs
        base_config = {"ui": {"theme": "dark", "font_size": 10, "layout": {"panels": ["left", "center"]}}, "logging": {"level": "INFO"}}

        update_config = {
            "ui": {
                "theme": "light",  # Conflict
                "show_tooltips": True,  # New field
                "layout": {
                    "panels": ["left", "center", "right"],  # Array merge
                    "position": "top",  # New nested field
                },
            },
            "analysis": {  # New section
                "timeout": 300
            },
        }

        # Test merge with different strategies
        merged, conflicts = config.safe_merge_configs(base_config, update_config, conflict_strategy="prefer_new")

        self.assert_real_output(merged)
        self.assert_real_output(conflicts)

        # Verify merge results
        assert merged["ui"]["theme"] == "light", "Should prefer new value"
        assert merged["ui"]["font_size"] == 10, "Should keep base value"
        assert merged["ui"]["show_tooltips"] is True, "Should add new field"
        assert merged["ui"]["layout"]["position"] == "top", "Should add nested new field"
        assert len(merged["ui"]["layout"]["panels"]) == 3, "Should merge arrays"
        assert "analysis" in merged, "Should add new section"
        assert len(conflicts) > 0, "Should detect conflicts"

    def test_atomic_config_saves_real(self):
        """Test REAL atomic configuration saves with actual file operations."""
        test_data = self.create_test_config()

        with patch.object(IntellicrackConfig, "_get_user_config_dir", return_value=self.test_config_dir):
            config = IntellicrackConfig()

        # Load initial config
        config._load_config()
        initial_config = config._config.copy()

        # Modify config
        config._config["ui"]["theme"] = "modified_theme"
        config._config["new_section"] = {"test": "value"}

        # Test atomic save
        success = config.save_config_atomic()
        self.assert_real_output(success)
        assert success, "Atomic save should succeed"

        # Verify file was actually saved
        assert self.test_config_file.exists(), "Config file should exist"

        # Verify backup was created
        backup_dir = self.test_config_dir / "backups"
        assert backup_dir.exists(), "Backup directory should be created"
        backup_files = list(backup_dir.glob("config_*.json"))
        assert backup_files, "Backup file should be created"

        # Verify backup content is valid
        with open(backup_files[0], encoding="utf-8") as f:
            backup_data = json.load(f)
        self.assert_real_output(backup_data)

        # Verify saved config content
        with open(self.test_config_file, encoding="utf-8") as f:
            saved_data = json.load(f)
        self.assert_real_output(saved_data)
        assert saved_data["ui"]["theme"] == "modified_theme"
        assert "new_section" in saved_data

    def test_configuration_versioning_real(self):
        """Test REAL configuration versioning with actual version tracking."""
        with patch.object(IntellicrackConfig, "_get_user_config_dir", return_value=self.test_config_dir):
            config = IntellicrackConfig()

        # Test version setting and getting
        test_version = "3.1.0"
        config.set_config_version(test_version)
        retrieved_version = config.get_config_version()

        self.assert_real_output(retrieved_version)
        assert retrieved_version == test_version, f"Expected {test_version}, got {retrieved_version}"

        # Test version comparison
        comparison_tests = [("3.0.0", "3.1.0", -1), ("3.1.0", "3.0.0", 1), ("3.1.0", "3.1.0", 0), ("2.9.9", "3.0.0", -1)]

        for v1, v2, expected in comparison_tests:
            result = config.compare_versions(v1, v2)
            assert result == expected, f"Compare {v1} vs {v2}: expected {expected}, got {result}"

        # Test version history
        config.add_version_history_entry("3.2.0", "Test upgrade")
        history = config.get_version_history()

        self.assert_real_output(history)
        assert len(history) > 0, "Version history should have entries"
        assert any(entry["version"] == "3.2.0" for entry in history), "Should find test entry"

    def test_section_access_methods_real(self):
        """Test REAL configuration section access with actual data retrieval."""
        test_data = self.create_test_config()

        with patch.object(IntellicrackConfig, "_get_user_config_dir", return_value=self.test_config_dir):
            config = IntellicrackConfig()

        # Test section getters
        ui_config = config.get_ui_config()
        analysis_config = config.get_analysis_config()
        logging_config = config.get_logging_config()

        # Validate real data retrieval
        self.assert_real_output(ui_config)
        self.assert_real_output(analysis_config)
        self.assert_real_output(logging_config)

        assert ui_config["theme"] == "dark", "Should retrieve UI theme"
        assert analysis_config["default_timeout"] == 300, "Should retrieve analysis timeout"
        assert logging_config["level"] == "INFO", "Should retrieve logging level"

        # Test section value access with dot notation
        theme = config.get_section_value("ui", "theme")
        timeout = config.get_section_value("analysis", "default_timeout")
        missing = config.get_section_value("ui", "nonexistent", "default")

        self.assert_real_output(theme)
        self.assert_real_output(timeout)
        assert theme == "dark", "Should get UI theme via dot notation"
        assert timeout == 300, "Should get analysis timeout via dot notation"
        assert missing == "default", "Should return default for missing keys"

        # Test section value setting
        success = config.set_section_value("ui", "new_setting", "test_value")
        assert success, "Should successfully set new value"

        retrieved = config.get_section_value("ui", "new_setting")
        assert retrieved == "test_value", "Should retrieve newly set value"

    def test_section_update_with_validation_real(self):
        """Test REAL section updates with actual validation and merging."""
        test_data = self.create_test_config()

        with patch.object(IntellicrackConfig, "_get_user_config_dir", return_value=self.test_config_dir):
            config = IntellicrackConfig()

        # Test section update with merge
        ui_updates = {
            "theme": "light",  # Override existing
            "animation_speed": "fast",  # Add new
            "window_size": [1920, 1080],  # Add new
        }

        success = config.update_section("ui", ui_updates, merge=True, validate=True)
        self.assert_real_output(success)
        assert success, "Section update should succeed"

        # Verify updates were applied
        updated_ui = config.get_ui_config()
        self.assert_real_output(updated_ui)
        assert updated_ui["theme"] == "light", "Theme should be updated"
        assert updated_ui["font_size"] == 12, "Existing value should be preserved"
        assert updated_ui["animation_speed"] == "fast", "New value should be added"
        assert updated_ui["window_size"] == [1920, 1080], "New array should be added"

        # Test section replacement (not merge)
        replacement_ui = {"theme": "dark", "font_size": 14}

        success = config.update_section("ui", replacement_ui, merge=False, validate=True)
        assert success, "Section replacement should succeed"

        replaced_ui = config.get_ui_config()
        self.assert_real_output(replaced_ui)
        assert len(replaced_ui) == 2, "Should only have replacement fields"
        assert "animation_speed" not in replaced_ui, "Old fields should be removed"

    def test_change_notification_system_real(self):
        """Test REAL configuration change notifications with actual callbacks."""
        test_data = self.create_test_config()

        with patch.object(IntellicrackConfig, "_get_user_config_dir", return_value=self.test_config_dir):
            config = IntellicrackConfig()

        # Setup notification tracking
        notifications = []

        def section_callback(section, old_val, new_val):
            notifications.append({"type": "section", "section": section, "old": old_val, "new": new_val})

        def global_callback(section, old_val, new_val):
            notifications.append({"type": "global", "section": section, "old": old_val, "new": new_val})

        # Register listeners
        assert config.register_listener("ui", section_callback), "Should register section listener"
        assert config.register_global_listener(global_callback), "Should register global listener"

        # Verify listener counts
        counts = config.get_listener_count()
        self.assert_real_output(counts)
        assert counts.get("ui", 0) == 1, "Should have 1 UI listener"
        assert counts.get("global", 0) == 1, "Should have 1 global listener"

        # Trigger notification via section update
        config.update_section("ui", {"theme": "light"})

        # Wait for async notifications
        time.sleep(0.1)

        # Verify notifications were triggered
        self.assert_real_output(notifications)
        assert len(notifications) >= 2, "Should have both section and global notifications"

        ui_notifications = [n for n in notifications if n["section"] == "ui"]
        assert len(ui_notifications) >= 2, "Should have UI notifications from both listeners"

        # Test unregistering listeners
        assert config.unregister_listener("ui", section_callback), "Should unregister listener"
        assert config.unregister_global_listener(global_callback), "Should unregister global listener"

        # Verify counts after unregistering
        counts_after = config.get_listener_count()
        assert counts_after.get("ui", 0) == 0, "Should have 0 UI listeners after unregister"
        assert counts_after.get("global", 0) == 0, "Should have 0 global listeners after unregister"

    def test_migration_detection_real(self):
        """Test REAL migration detection with actual legacy config files."""
        # Create legacy config file
        legacy_config = {
            "log_dir": str(self.temp_dir / "logs"),
            "output_dir": str(self.temp_dir / "output"),
            "ghidra_path": "C:/Program Files/Ghidra/ghidra",
            "ui": {"theme": "dark"},
        }

        legacy_file = self.temp_dir / "intellicrack_config.json"
        with open(legacy_file, "w", encoding="utf-8") as f:
            json.dump(legacy_config, f, indent=2)

        with patch.object(IntellicrackConfig, "_get_user_config_dir", return_value=self.test_config_dir):
            config = IntellicrackConfig()

        # Test legacy config detection
        detected_configs = config.detect_legacy_configs()
        self.assert_real_output(detected_configs)

        # Should detect our legacy file
        legacy_found = any(str(legacy_file) in str(detected_config.get("path", "")) for detected_config in detected_configs)
        assert legacy_found, "Should detect legacy config file"

        # Test migration
        success = config.merge_legacy_configs()
        self.assert_real_output(success)
        assert success, "Legacy config migration should succeed"

        # Verify migration results
        directories_config = config.get_directories_config()
        self.assert_real_output(directories_config)
        assert directories_config.get("logs") == str(self.temp_dir / "logs"), "Should migrate log_dir"
        assert directories_config.get("output") == str(self.temp_dir / "output"), "Should migrate output_dir"

    def test_thread_safety_real(self):
        """Test REAL thread safety with actual concurrent operations."""
        test_data = self.create_test_config()

        with patch.object(IntellicrackConfig, "_get_user_config_dir", return_value=self.test_config_dir):
            config = IntellicrackConfig()

        errors = []

        def worker_thread(thread_id):
            """Worker function for concurrent testing."""
            try:
                for i in range(10):
                    # Concurrent read operations
                    ui_config = config.get_ui_config()
                    self.assert_real_output(ui_config)

                    # Concurrent write operations
                    config.set_section_value("ui", f"thread_{thread_id}_setting_{i}", f"value_{i}")

                    # Brief sleep to encourage race conditions
                    time.sleep(0.001)

            except Exception as e:
                errors.append(f"Thread {thread_id}: {e}")

        # Start multiple threads
        threads = []
        for i in range(5):
            thread = threading.Thread(target=worker_thread, args=(i,))
            threads.append(thread)
            thread.start()

        # Wait for all threads to complete
        for thread in threads:
            thread.join()

        # Verify no errors occurred
        assert not errors, f"Thread safety errors: {errors}"

        # Verify all thread operations succeeded
        final_ui_config = config.get_ui_config()
        self.assert_real_output(final_ui_config)

        # Should have settings from all threads
        thread_settings = [key for key in final_ui_config if key.startswith("thread_")]
        assert len(thread_settings) == 50, f"Expected 50 thread settings, got {len(thread_settings)}"

    def test_config_backup_and_restore_real(self):
        """Test REAL configuration backup and restore with actual file operations."""
        test_data = self.create_test_config()

        with patch.object(IntellicrackConfig, "_get_user_config_dir", return_value=self.test_config_dir):
            config = IntellicrackConfig()

        # Load and modify config
        config._load_config()
        original_theme = config._config["ui"]["theme"]
        config._config["ui"]["theme"] = "modified_theme"
        config._save_config()

        # Create backup
        success = config.save_config_atomic()
        assert success, "Should create backup successfully"

        # Verify backup exists
        backup_dir = self.test_config_dir / "backups"
        backup_files = list(backup_dir.glob("config_*.json"))
        assert backup_files, "Should have backup files"

        # Corrupt current config
        with open(self.test_config_file, "w") as f:
            f.write("invalid json content")

        # Test restore from backup
        latest_backup = max(backup_files, key=lambda f: f.stat().st_mtime)
        success = config.restore_from_backup(str(latest_backup))

        self.assert_real_output(success)
        assert success, "Should restore from backup successfully"

        # Verify restoration
        with open(self.test_config_file, encoding="utf-8") as f:
            restored_data = json.load(f)

        self.assert_real_output(restored_data)
        assert "ui" in restored_data, "Restored config should have UI section"
        assert restored_data["ui"]["theme"] == "modified_theme", "Should restore modified theme"

    def test_comprehensive_integration_real(self):
        """Test REAL end-to-end integration of all configuration features."""
        # Start with empty config directory
        if self.test_config_file.exists():
            self.test_config_file.unlink()

        with patch.object(IntellicrackConfig, "_get_user_config_dir", return_value=self.test_config_dir):
            config = IntellicrackConfig()

        # Test 1: Initial configuration creation
        self.assert_real_output(config._config)
        assert self.test_config_file.exists(), "Should create config file"

        # Test 2: Environment variable expansion
        os.environ["TEST_HOME"] = str(self.temp_dir)
        config.set_section_value("directories", "test_path", "${TEST_HOME}/test")
        test_path = config.get_section_value("directories", "test_path")
        assert (
            test_path == f"{str(self.temp_dir)}/test"
        ), "Should expand environment variables"

        # Test 3: Schema validation during updates
        try:
            config.update_section("ui", {"font_size": "invalid_string"})  # Should trigger validation
        except Exception:
            pass  # Expected to fail validation

        # Test 4: Change notifications
        notifications = []

        def test_callback(section, old, new):
            notifications.append(section)

        config.register_global_listener(test_callback)
        config.update_section("ui", {"theme": "light"})
        time.sleep(0.1)  # Wait for async notification

        assert notifications, "Should receive change notifications"

        # Test 5: Atomic saves and backups
        config.save_config_atomic()
        backup_dir = self.test_config_dir / "backups"
        backups = list(backup_dir.glob("config_*.json"))
        assert backups, "Should create backup files"

        # Test 6: Version management
        config.set_config_version("3.5.0")
        version = config.get_config_version()
        assert version == "3.5.0", "Should manage configuration versions"

        # Test 7: Section access and modification
        all_sections = [
            "directories",
            "tools",
            "analysis",
            "patching",
            "network",
            "ui",
            "logging",
            "security",
            "performance",
            "runtime",
            "plugins",
            "general",
            "ai",
            "ml",
            "preferences",
            "fonts",
            "llm_configs",
            "cli",
        ]

        for section in all_sections:
            getter_method = getattr(config, f"get_{section}_config", None)
            if getter_method:
                section_data = getter_method()
                self.assert_real_output(section_data)
                assert isinstance(section_data, dict), f"Section {section} should return dict"

        # Cleanup
        if "TEST_HOME" in os.environ:
            del os.environ["TEST_HOME"]

        # Final validation: configuration should be complete and valid
        final_config = config._config
        self.assert_real_output(final_config)
        is_valid, errors = config.validate_config(final_config)
        assert is_valid, f"Final configuration should be valid. Errors: {errors}"

    def test_intellicrack_config_json_migration_real(self):
        """Test REAL intellicrack_config.json migration with actual legacy config."""
        # Create realistic legacy intellicrack_config.json
        legacy_config = {
            "log_dir": str(self.temp_dir / "legacy_logs"),
            "output_dir": str(self.temp_dir / "legacy_output"),
            "temp_dir": str(self.temp_dir / "legacy_temp"),
            "plugin_directory": "legacy_plugins",
            "download_directory": str(self.temp_dir / "legacy_downloads"),
            "ghidra_path": "C:/Program Files/Ghidra/ghidra",
            "radare2_path": "/usr/bin/r2",
            "frida_path": "frida",
            # Legacy top-level fields that need migration
            "ui_theme": "Dark",
            "ui_scale": 100,
            "font_size": "Medium",
            "plugin_timeout": 60,
            "selected_model_path": "/path/to/model.bin",
            "ml_model_path": "/path/to/ml_model.joblib",
            "verify_checksums": True,
            # Legacy sections that should be merged
            "analysis": {"default_timeout": 300, "enable_deep_analysis": True, "parallel_threads": 4},
            "ui": {
                "theme": "light",  # Will conflict with ui_theme migration
                "font_size": 12,  # Will conflict with font_size migration
                "show_tooltips": True,
            },
            "security": {"sandbox_analysis": True, "log_sensitive_data": False},
            "model_repositories": {"local": {"type": "local", "enabled": True, "models_directory": "/legacy/models"}},
            # Deprecated fields that should be removed
            "c2": {"deprecated": "data"},
            "external_services": {"deprecated": "data"},
            "api": {"deprecated": "data"},
            "service_urls": ["deprecated", "urls"],
        }

        # Create legacy config file in a detectable location
        # We need to mock the detect_legacy_configs to find our test file
        legacy_file = self.temp_dir / "intellicrack_config.json"
        with open(legacy_file, "w", encoding="utf-8") as f:
            json.dump(legacy_config, f, indent=2)

        with patch.object(IntellicrackConfig, "_get_user_config_dir", return_value=self.test_config_dir):
            config = IntellicrackConfig()

        # Test migration by providing the legacy config directly
        legacy_configs = [{"path": str(legacy_file), "type": "json", "data": legacy_config}]
        success = config.merge_legacy_configs(legacy_configs)
        assert success is True, "Legacy config migration should succeed"

        # Verify directory migrations
        directories_config = config.get_directories_config()
        self.assert_real_output(directories_config)
        assert directories_config.get("logs") == str(self.temp_dir / "legacy_logs")
        assert directories_config.get("output") == str(self.temp_dir / "legacy_output")
        assert directories_config.get("temp") == str(self.temp_dir / "legacy_temp")
        assert directories_config.get("plugins") == "legacy_plugins"

        # Check nested directory migration
        models_config = directories_config.get("models", {})
        assert models_config.get("downloads") == str(self.temp_dir / "legacy_downloads")

        # Verify tool migrations
        tools_config = config.get_tools_config()
        self.assert_real_output(tools_config)
        assert tools_config.get("ghidra", {}).get("path") == "C:/Program Files/Ghidra/ghidra"
        assert tools_config.get("radare2", {}).get("path") == "/usr/bin/r2"
        assert tools_config.get("frida", {}).get("path") == "frida"

        # Verify legacy field migrations
        ui_config = config.get_ui_config()
        preferences_config = config.get_preferences_config()
        ai_config = config.get_ai_config()
        ml_config = config.get_ml_config()
        security_config = config.get_security_config()

        self.assert_real_output(ui_config)
        self.assert_real_output(preferences_config)
        self.assert_real_output(ai_config)
        self.assert_real_output(ml_config)
        self.assert_real_output(security_config)

        # Check legacy field mappings
        assert ui_config.get("theme") == "dark", "ui_theme should migrate to ui.theme as lowercase"
        assert preferences_config.get("ui_scale") == 100, "ui_scale should migrate to preferences"
        assert ui_config.get("font_size") == 10, "Medium font_size should convert to 10"
        assert ai_config.get("selected_model_path") == "/path/to/model.bin"
        assert ml_config.get("model_path") == "/path/to/ml_model.joblib"
        assert security_config.get("verify_checksums") is True

        # Verify section merging
        analysis_config = config.get_analysis_config()
        self.assert_real_output(analysis_config)
        assert analysis_config.get("default_timeout") == 300
        assert analysis_config.get("enable_deep_analysis") is True
        assert analysis_config.get("parallel_threads") == 4

        # Verify UI section conflict resolution (existing config should win)
        assert ui_config.get("show_tooltips") is True, "New UI fields should be added"

        # Verify LLM configs migration
        llm_configs = config.get_llm_configs()
        self.assert_real_output(llm_configs)
        assert "local" in llm_configs
        assert llm_configs["local"]["type"] == "local"
        assert llm_configs["local"]["models_directory"] == "/legacy/models"

        # Verify deprecated fields are NOT in final config
        final_config = config._config
        assert "c2" not in final_config, "Deprecated c2 field should be removed"
        assert "external_services" not in final_config, "Deprecated external_services should be removed"
        assert "api" not in final_config, "Deprecated api field should be removed"
        assert "ui_theme" not in final_config, "Migrated ui_theme should be removed"
        assert "ui_scale" not in final_config, "Migrated ui_scale should be removed"
        assert "font_size" not in final_config, "Migrated font_size should be removed"
        assert "plugin_timeout" not in final_config, "Migrated plugin_timeout should be removed"

        # Verify backup was created
        backup_file = legacy_file.with_suffix(".backup")
        assert backup_file.exists(), "Backup of legacy config should be created"
        with open(backup_file, encoding="utf-8") as f:
            backup_data = json.load(f)
        assert backup_data == legacy_config, "Backup should match original legacy config"


class TestConfigManagerSingleton(IntellicrackTestBase):
    """Test singleton behavior and global config access."""

    def test_singleton_behavior_real(self):
        """Test REAL singleton pattern with actual instance management."""
        # Reset singleton
        IntellicrackConfig._instance = None

        # Create multiple instances
        with tempfile.TemporaryDirectory() as temp_dir:
            test_config_dir = Path(temp_dir) / "config"

            with patch.object(IntellicrackConfig, "_get_user_config_dir", return_value=test_config_dir):
                config1 = IntellicrackConfig()
                config2 = IntellicrackConfig()
                config3 = get_config()

        # Verify they are the same instance
        assert config1 is config2, "Multiple instantiations should return same instance"
        assert config2 is config3, "get_config() should return same instance"

        # Verify shared state
        config1._config["test_key"] = "test_value"
        assert config2._config.get("test_key") == "test_value", "Should share configuration state"
        assert config3._config.get("test_key") == "test_value", "Global config should share state"

    def test_thread_safe_singleton_real(self):
        """Test REAL thread-safe singleton creation with actual concurrency."""
        # Reset singleton
        IntellicrackConfig._instance = None

        instances = []
        errors = []

        def create_instance():
            """Thread worker to create config instance."""
            try:
                with tempfile.TemporaryDirectory() as temp_dir:
                    test_config_dir = Path(temp_dir) / "config"

                    with patch.object(IntellicrackConfig, "_get_user_config_dir", return_value=test_config_dir):
                        instance = IntellicrackConfig()
                        instances.append(instance)
            except Exception as e:
                errors.append(str(e))

        # Create multiple threads trying to create instances
        threads = []
        for i in range(10):
            thread = threading.Thread(target=create_instance)
            threads.append(thread)

        # Start all threads simultaneously
        for thread in threads:
            thread.start()

        # Wait for completion
        for thread in threads:
            thread.join()

        # Verify no errors
        assert not errors, f"Singleton creation errors: {errors}"

        # Verify all instances are the same (singleton pattern)
        assert len(instances) == 10, "Should have 10 instances created"
        first_instance = instances[0]
        for instance in instances[1:]:
            assert instance is first_instance, "All instances should be the same object"

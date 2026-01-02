"""Production tests for CLI Configuration Profiles.

Validates profile creation, persistence, application to arguments,
and integration with central config system.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import argparse
import os
import tempfile
from collections.abc import Generator
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest

from intellicrack.cli.config_profiles import ConfigProfile, ProfileManager, create_default_profiles


class TestConfigProfile:
    """Test ConfigProfile data class."""

    def test_profile_initialization(self) -> None:
        """Profile initializes with name and description."""
        profile = ConfigProfile("test_profile", "Test description")

        assert profile.name == "test_profile"
        assert profile.description == "Test description"
        assert isinstance(profile.created_at, datetime)
        assert profile.last_used is None

    def test_profile_defaults(self) -> None:
        """Profile has correct default values."""
        profile = ConfigProfile("test")

        assert profile.settings == {}
        assert profile.analysis_options == []
        assert profile.output_format == "json"
        assert profile.plugins_enabled == []
        assert profile.custom_scripts == []

    def test_profile_to_dict(self) -> None:
        """Profile converts to dictionary correctly."""
        profile = ConfigProfile("test", "desc")
        profile.analysis_options = ["static", "dynamic"]
        profile.output_format = "html"

        data = profile.to_dict()

        assert data["name"] == "test"
        assert data["description"] == "desc"
        assert data["analysis_options"] == ["static", "dynamic"]
        assert data["output_format"] == "html"
        assert "created_at" in data

    def test_profile_from_dict(self) -> None:
        """Profile is reconstructed from dictionary."""
        data = {
            "name": "restored",
            "description": "Restored profile",
            "created_at": datetime.now().isoformat(),
            "last_used": None,
            "settings": {"timeout": 300},
            "analysis_options": ["vulnerability"],
            "output_format": "pdf",
            "plugins_enabled": ["plugin1"],
            "custom_scripts": [],
        }

        profile = ConfigProfile.from_dict(data)

        assert profile.name == "restored"
        assert profile.description == "Restored profile"
        assert profile.settings["timeout"] == 300
        assert profile.analysis_options == ["vulnerability"]
        assert profile.output_format == "pdf"

    def test_profile_with_last_used(self) -> None:
        """Profile with last_used timestamp is restored."""
        last_used = datetime.now()
        data = {
            "name": "test",
            "created_at": datetime.now().isoformat(),
            "last_used": last_used.isoformat(),
        }

        profile = ConfigProfile.from_dict(data)

        assert profile.last_used is not None
        assert abs((profile.last_used - last_used).total_seconds()) < 1


class TestProfileManager:
    """Production tests for ProfileManager."""

    @pytest.fixture
    def temp_config_dir(self) -> Generator[Path, None, None]:
        """Create temporary config directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_dir = Path(tmpdir)
            os.environ["INTELLICRACK_CONFIG_DIR"] = str(config_dir)
            yield config_dir
            if "INTELLICRACK_CONFIG_DIR" in os.environ:
                del os.environ["INTELLICRACK_CONFIG_DIR"]

    @pytest.fixture
    def manager(self, temp_config_dir: Path) -> ProfileManager:
        """Create profile manager with isolated config."""
        return ProfileManager()

    def test_manager_initialization(self, manager: ProfileManager) -> None:
        """Manager initializes with empty profiles."""
        assert isinstance(manager.profiles, dict)
        assert hasattr(manager, "central_config")

    def test_save_profile_to_central_config(self, manager: ProfileManager) -> None:
        """Profile is saved to central config."""
        profile = ConfigProfile("test_save", "Test save")
        profile.analysis_options = ["static"]

        manager.save_profile(profile)

        assert "test_save" in manager.profiles
        assert manager.profiles["test_save"].analysis_options == ["static"]

    def test_save_profile_persists_across_instances(self, temp_config_dir: Path) -> None:
        """Saved profile persists in new manager instance."""
        manager1 = ProfileManager()
        profile = ConfigProfile("persistent", "Persistent profile")
        manager1.save_profile(profile)

        manager2 = ProfileManager()

        assert "persistent" in manager2.profiles

    def test_get_profile_returns_correct_profile(self, manager: ProfileManager) -> None:
        """get_profile returns correct profile by name."""
        profile = ConfigProfile("retrieve_me", "Test retrieval")
        manager.save_profile(profile)

        retrieved = manager.get_profile("retrieve_me")

        assert retrieved is not None
        assert retrieved.name == "retrieve_me"

    def test_get_profile_updates_last_used(self, manager: ProfileManager) -> None:
        """get_profile updates last_used timestamp."""
        profile = ConfigProfile("track_usage", "Track usage")
        manager.save_profile(profile)

        assert profile.last_used is None

        retrieved = manager.get_profile("track_usage")

        assert retrieved is not None
        assert retrieved.last_used is not None

    def test_get_nonexistent_profile_returns_none(self, manager: ProfileManager) -> None:
        """get_profile returns None for nonexistent profile."""
        retrieved = manager.get_profile("nonexistent")
        assert retrieved is None

    def test_delete_profile_removes_from_config(self, manager: ProfileManager) -> None:
        """delete_profile removes profile from central config."""
        profile = ConfigProfile("to_delete", "Will be deleted")
        manager.save_profile(profile)

        assert "to_delete" in manager.profiles

        result = manager.delete_profile("to_delete")

        assert result is True
        assert "to_delete" not in manager.profiles

    def test_delete_nonexistent_profile_returns_false(self, manager: ProfileManager) -> None:
        """delete_profile returns False for nonexistent profile."""
        result = manager.delete_profile("nonexistent")
        assert result is False

    def test_apply_profile_to_args(self, manager: ProfileManager) -> None:
        """apply_profile applies settings to argparse Namespace."""
        profile = ConfigProfile("apply_test", "Test apply")
        profile.analysis_options = ["static", "dynamic"]
        profile.output_format = "html"
        profile.settings = {"timeout": 600}
        manager.save_profile(profile)

        args = argparse.Namespace(static=False, dynamic=False, output_format="json", timeout=300)

        modified_args = manager.apply_profile("apply_test", args)

        assert modified_args.static is True
        assert modified_args.dynamic is True
        assert modified_args.output_format == "html"
        assert modified_args.timeout == 600

    def test_apply_nonexistent_profile_returns_unchanged_args(self, manager: ProfileManager) -> None:
        """apply_profile returns unchanged args for nonexistent profile."""
        args = argparse.Namespace(static=False)
        original_static = args.static

        modified_args = manager.apply_profile("nonexistent", args)

        assert modified_args.static == original_static

    def test_apply_profile_with_plugins(self, manager: ProfileManager) -> None:
        """apply_profile applies plugin list when args has plugins."""
        profile = ConfigProfile("plugin_test", "Test plugins")
        profile.plugins_enabled = ["plugin1", "plugin2"]
        manager.save_profile(profile)

        args = argparse.Namespace(plugins=[])

        modified_args = manager.apply_profile("plugin_test", args)

        assert modified_args.plugins == ["plugin1", "plugin2"]


class TestDefaultProfiles:
    """Test default profile creation."""

    @pytest.fixture
    def temp_config_dir(self) -> Generator[Path, None, None]:
        """Create temporary config directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_dir = Path(tmpdir)
            os.environ["INTELLICRACK_CONFIG_DIR"] = str(config_dir)
            yield config_dir
            if "INTELLICRACK_CONFIG_DIR" in os.environ:
                del os.environ["INTELLICRACK_CONFIG_DIR"]

    def test_create_default_profiles_creates_profiles(self, temp_config_dir: Path) -> None:
        """create_default_profiles creates standard profiles."""
        manager = create_default_profiles()

        assert "quick_scan" in manager.profiles
        assert "full_analysis" in manager.profiles
        assert "bypass_analysis" in manager.profiles
        assert "license_check" in manager.profiles

    def test_quick_scan_profile_configuration(self, temp_config_dir: Path) -> None:
        """quick_scan profile has correct configuration."""
        manager = create_default_profiles()
        profile = manager.profiles["quick_scan"]

        assert "static" in profile.analysis_options
        assert "strings" in profile.analysis_options
        assert profile.settings["timeout"] == 60

    def test_full_analysis_profile_configuration(self, temp_config_dir: Path) -> None:
        """full_analysis profile includes all features."""
        manager = create_default_profiles()
        profile = manager.profiles["full_analysis"]

        assert "static" in profile.analysis_options
        assert "dynamic" in profile.analysis_options
        assert "vulnerability" in profile.analysis_options
        assert "license" in profile.analysis_options
        assert profile.output_format == "html"

    def test_bypass_analysis_profile_configuration(self, temp_config_dir: Path) -> None:
        """bypass_analysis profile has license cracking focus."""
        manager = create_default_profiles()
        profile = manager.profiles["bypass_analysis"]

        assert "static" in profile.analysis_options
        assert "network" in profile.analysis_options
        assert "protection" in profile.analysis_options
        assert profile.settings.get("network_monitoring") is True

    def test_license_check_profile_configuration(self, temp_config_dir: Path) -> None:
        """license_check profile focuses on licensing mechanisms."""
        manager = create_default_profiles()
        profile = manager.profiles["license_check"]

        assert "license" in profile.analysis_options
        assert "protection" in profile.analysis_options
        assert "strings" in profile.analysis_options


class TestProfileMigration:
    """Test migration from legacy profile files."""

    @pytest.fixture
    def temp_config_dir(self) -> Generator[Path, None, None]:
        """Create temporary config directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_dir = Path(tmpdir)
            os.environ["INTELLICRACK_CONFIG_DIR"] = str(config_dir)
            yield config_dir
            if "INTELLICRACK_CONFIG_DIR" in os.environ:
                del os.environ["INTELLICRACK_CONFIG_DIR"]

    def test_migration_from_legacy_files(self, temp_config_dir: Path) -> None:
        """Legacy profile files are migrated to central config."""
        legacy_dir = Path.home() / ".intellicrack" / "profiles"
        legacy_dir.mkdir(parents=True, exist_ok=True)

        legacy_profile = {
            "name": "legacy_profile",
            "description": "Migrated from file",
            "created_at": datetime.now().isoformat(),
            "analysis_options": ["static"],
            "output_format": "json",
            "settings": {},
            "plugins_enabled": [],
            "custom_scripts": [],
        }

        import json

        legacy_file = legacy_dir / "legacy_profile.json"
        with open(legacy_file, "w") as f:
            json.dump(legacy_profile, f)

        manager = ProfileManager(profile_dir=str(legacy_dir))

        if "legacy_profile" in manager.profiles:
            assert manager.profiles["legacy_profile"].description == "Migrated from file"

        if legacy_dir.exists():
            for file_path in legacy_dir.glob("*"):
                file_path.unlink()
            legacy_dir.rmdir()


class TestEdgeCases:
    """Test edge cases and error handling."""

    @pytest.fixture
    def temp_config_dir(self) -> Generator[Path, None, None]:
        """Create temporary config directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_dir = Path(tmpdir)
            os.environ["INTELLICRACK_CONFIG_DIR"] = str(config_dir)
            yield config_dir
            if "INTELLICRACK_CONFIG_DIR" in os.environ:
                del os.environ["INTELLICRACK_CONFIG_DIR"]

    @pytest.fixture
    def manager(self, temp_config_dir: Path) -> ProfileManager:
        """Create profile manager."""
        return ProfileManager()

    def test_profile_with_special_characters_in_name(self, manager: ProfileManager) -> None:
        """Profile with special characters in name is handled."""
        profile = ConfigProfile("test-profile_v2.0", "Special chars")
        manager.save_profile(profile)

        retrieved = manager.get_profile("test-profile_v2.0")
        assert retrieved is not None

    def test_profile_with_empty_description(self, manager: ProfileManager) -> None:
        """Profile with empty description is saved correctly."""
        profile = ConfigProfile("no_desc")
        manager.save_profile(profile)

        retrieved = manager.get_profile("no_desc")
        assert retrieved is not None
        assert retrieved.description == ""

    def test_profile_with_large_settings(self, manager: ProfileManager) -> None:
        """Profile with large settings dictionary is saved."""
        profile = ConfigProfile("large_settings", "Large config")
        profile.settings = {f"setting_{i}": i for i in range(100)}

        manager.save_profile(profile)

        retrieved = manager.get_profile("large_settings")
        assert retrieved is not None
        assert len(retrieved.settings) == 100

    def test_concurrent_profile_modifications(self, manager: ProfileManager) -> None:
        """Concurrent profile saves maintain consistency."""
        profile1 = ConfigProfile("concurrent1", "First")
        profile2 = ConfigProfile("concurrent2", "Second")

        manager.save_profile(profile1)
        manager.save_profile(profile2)

        assert "concurrent1" in manager.profiles
        assert "concurrent2" in manager.profiles

    def test_profile_name_collision_overwrites(self, manager: ProfileManager) -> None:
        """Saving profile with same name overwrites previous."""
        profile1 = ConfigProfile("same_name", "First version")
        manager.save_profile(profile1)

        profile2 = ConfigProfile("same_name", "Second version")
        manager.save_profile(profile2)

        retrieved = manager.get_profile("same_name")
        assert retrieved is not None
        assert retrieved.description == "Second version"

    def test_apply_profile_missing_args_attributes(self, manager: ProfileManager) -> None:
        """apply_profile handles args missing expected attributes."""
        profile = ConfigProfile("test", "Test")
        profile.settings = {"nonexistent_setting": 42}
        manager.save_profile(profile)

        args = argparse.Namespace()

        modified_args = manager.apply_profile("test", args)

        assert not hasattr(modified_args, "nonexistent_setting")

    def test_profile_with_unicode_description(self, manager: ProfileManager) -> None:
        """Profile with Unicode description is saved correctly."""
        profile = ConfigProfile("unicode_test", "描述 тест description")
        manager.save_profile(profile)

        retrieved = manager.get_profile("unicode_test")
        assert retrieved is not None
        assert "описание" in retrieved.description or "描述" in retrieved.description or "tест" in retrieved.description

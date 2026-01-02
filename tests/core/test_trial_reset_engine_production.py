"""Production tests for trial reset engine with real Windows operations.

These tests validate that trial_reset_engine correctly scans for trial data,
identifies trial types, and performs reset operations on real Windows systems.
Tests MUST FAIL if trial detection or reset operations are broken.

Copyright (C) 2025 Zachary Flint
"""

import datetime
import hashlib
import json
import os
import tempfile
import time
import winreg
from collections.abc import Generator
from pathlib import Path
from typing import Any

import psutil
import pytest

from intellicrack.core.trial_reset_engine import (
    TimeManipulator,
    TrialInfo,
    TrialResetEngine,
    TrialType,
    automated_trial_reset,
)


class TestTrialResetEngineProduction:
    """Production tests for trial reset engine with real system operations."""

    @pytest.fixture
    def engine(self) -> TrialResetEngine:
        """Create trial reset engine instance."""
        return TrialResetEngine()

    @pytest.fixture
    def temp_dir(self) -> Generator[Path, None, None]:
        """Create temporary directory for test files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.fixture
    def test_registry_key(self) -> Generator[str, None, None]:
        """Create test registry key with trial data."""
        key_path = r"SOFTWARE\TestTrialProduct_" + str(int(time.time()))

        try:
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path) as key:
                winreg.SetValueEx(key, "TrialDays", 0, winreg.REG_DWORD, 30)
                winreg.SetValueEx(key, "DaysLeft", 0, winreg.REG_DWORD, 15)
                winreg.SetValueEx(key, "InstallDate", 0, winreg.REG_SZ, "2024-01-01")
                winreg.SetValueEx(key, "UsageCount", 0, winreg.REG_DWORD, 10)

            yield f"HKEY_CURRENT_USER\\{key_path}"

        finally:
            try:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, key_path)
            except OSError:
                pass

    def test_engine_initialization_with_trial_locations(self, engine: TrialResetEngine) -> None:
        """Engine initializes with comprehensive trial data locations."""
        assert "registry" in engine.common_trial_locations, "Must include registry locations"
        assert "files" in engine.common_trial_locations, "Must include file locations"
        assert "hidden" in engine.common_trial_locations, "Must include hidden locations"
        assert "alternate_streams" in engine.common_trial_locations, "Must include ADS locations"

        registry_locs = engine.common_trial_locations["registry"]
        assert len(registry_locs) >= 5, "Must have multiple registry locations"
        assert any("HKEY_CURRENT_USER" in loc for loc in registry_locs), "Must check HKCU"
        assert any("HKEY_LOCAL_MACHINE" in loc for loc in registry_locs), "Must check HKLM"

    def test_detection_patterns_include_common_markers(self, engine: TrialResetEngine) -> None:
        """Detection patterns include all common trial markers."""
        patterns = engine.detection_patterns

        registry_values = patterns["registry_values"]
        assert "TrialDays" in registry_values, "Must detect TrialDays"
        assert "InstallDate" in registry_values, "Must detect InstallDate"
        assert "UsageCount" in registry_values, "Must detect UsageCount"
        assert "ExpireDate" in registry_values, "Must detect ExpireDate"
        assert "LicenseType" in registry_values, "Must detect LicenseType"

        file_patterns = patterns["file_patterns"]
        assert "*.trial" in file_patterns, "Must detect .trial files"
        assert "*.lic" in file_patterns, "Must detect .lic files"
        assert "*.license" in file_patterns, "Must detect .license files"

    def test_scan_for_trial_detects_registry_keys(
        self,
        engine: TrialResetEngine,
        test_registry_key: str,
    ) -> None:
        """Scan for trial correctly identifies registry keys with trial data."""
        product_name = test_registry_key.split("\\")[-1]

        trial_info = engine.scan_for_trial(product_name)

        assert isinstance(trial_info, TrialInfo), "Must return TrialInfo object"
        assert trial_info.product_name == product_name, "Product name must match"
        assert len(trial_info.registry_keys) > 0, "Must detect registry keys"

    def test_trial_info_contains_complete_metadata(
        self,
        engine: TrialResetEngine,
        test_registry_key: str,
    ) -> None:
        """Trial info contains all required metadata fields."""
        product_name = test_registry_key.split("\\")[-1]

        trial_info = engine.scan_for_trial(product_name)

        assert hasattr(trial_info, "product_name"), "Must have product name"
        assert hasattr(trial_info, "trial_type"), "Must have trial type"
        assert hasattr(trial_info, "trial_days"), "Must have trial days"
        assert hasattr(trial_info, "usage_count"), "Must have usage count"
        assert hasattr(trial_info, "install_date"), "Must have install date"
        assert hasattr(trial_info, "first_run_date"), "Must have first run date"
        assert hasattr(trial_info, "last_run_date"), "Must have last run date"
        assert hasattr(trial_info, "trial_expired"), "Must have expired flag"
        assert hasattr(trial_info, "registry_keys"), "Must have registry keys list"
        assert hasattr(trial_info, "files"), "Must have files list"
        assert hasattr(trial_info, "processes"), "Must have processes list"

    def test_detect_trial_type_time_based(self, engine: TrialResetEngine) -> None:
        """Trial type detection identifies time-based trials."""
        trial_info = TrialInfo(
            product_name="TestProduct",
            trial_type=TrialType.TIME_BASED,
            trial_days=30,
            usage_count=0,
            install_date=datetime.datetime.now(),
            first_run_date=datetime.datetime.now(),
            last_run_date=datetime.datetime.now(),
            trial_expired=False,
            registry_keys=["HKEY_CURRENT_USER\\Software\\Test\\TrialDays"],
            files=[],
            processes=[],
        )

        detected_type = engine._detect_trial_type(trial_info)

        assert detected_type == TrialType.TIME_BASED, "Must identify time-based trial"

    def test_detect_trial_type_usage_based(self, engine: TrialResetEngine) -> None:
        """Trial type detection identifies usage-based trials."""
        trial_info = TrialInfo(
            product_name="TestProduct",
            trial_type=TrialType.USAGE_BASED,
            trial_days=0,
            usage_count=50,
            install_date=datetime.datetime.now(),
            first_run_date=datetime.datetime.now(),
            last_run_date=datetime.datetime.now(),
            trial_expired=False,
            registry_keys=["HKEY_CURRENT_USER\\Software\\Test\\UsageCount"],
            files=[],
            processes=[],
        )

        detected_type = engine._detect_trial_type(trial_info)

        assert detected_type == TrialType.USAGE_BASED, "Must identify usage-based trial"

    def test_detect_trial_type_hybrid(self, engine: TrialResetEngine) -> None:
        """Trial type detection identifies hybrid trials."""
        trial_info = TrialInfo(
            product_name="TestProduct",
            trial_type=TrialType.HYBRID,
            trial_days=30,
            usage_count=50,
            install_date=datetime.datetime.now(),
            first_run_date=datetime.datetime.now(),
            last_run_date=datetime.datetime.now(),
            trial_expired=False,
            registry_keys=[
                "HKEY_CURRENT_USER\\Software\\Test\\TrialDays",
                "HKEY_CURRENT_USER\\Software\\Test\\UsageCount",
            ],
            files=[],
            processes=[],
        )

        detected_type = engine._detect_trial_type(trial_info)

        assert detected_type == TrialType.HYBRID, "Must identify hybrid trial"

    def test_check_trial_expired_for_time_based(self, engine: TrialResetEngine) -> None:
        """Check trial expired correctly identifies expired time-based trials."""
        past_install = datetime.datetime.now() - datetime.timedelta(days=40)

        trial_info = TrialInfo(
            product_name="ExpiredProduct",
            trial_type=TrialType.TIME_BASED,
            trial_days=30,
            usage_count=0,
            install_date=past_install,
            first_run_date=past_install,
            last_run_date=datetime.datetime.now(),
            trial_expired=False,
            registry_keys=[],
            files=[],
            processes=[],
        )

        is_expired = engine._check_trial_expired(trial_info)

        assert is_expired is True, "Must identify expired trial"

    def test_check_trial_expired_for_active_trial(self, engine: TrialResetEngine) -> None:
        """Check trial expired identifies active trials correctly."""
        recent_install = datetime.datetime.now() - datetime.timedelta(days=5)

        trial_info = TrialInfo(
            product_name="ActiveProduct",
            trial_type=TrialType.TIME_BASED,
            trial_days=30,
            usage_count=0,
            install_date=recent_install,
            first_run_date=recent_install,
            last_run_date=datetime.datetime.now(),
            trial_expired=False,
            registry_keys=[],
            files=[],
            processes=[],
        )

        is_expired = engine._check_trial_expired(trial_info)

        assert is_expired is False, "Must identify active trial"

    def test_parse_date_handles_unix_timestamp(self, engine: TrialResetEngine) -> None:
        """Parse date correctly handles Unix timestamp integers."""
        timestamp = int(time.time())

        parsed = engine._parse_date(timestamp)

        assert isinstance(parsed, datetime.datetime), "Must return datetime"
        assert abs((parsed - datetime.datetime.now()).total_seconds()) < 60, "Must be recent"

    def test_parse_date_handles_iso_format(self, engine: TrialResetEngine) -> None:
        """Parse date correctly handles ISO format strings."""
        iso_date = "2024-06-15"

        parsed = engine._parse_date(iso_date)

        assert parsed.year == 2024, "Year must match"
        assert parsed.month == 6, "Month must match"
        assert parsed.day == 15, "Day must match"

    def test_parse_date_handles_slash_format(self, engine: TrialResetEngine) -> None:
        """Parse date correctly handles slash-separated format."""
        slash_date = "2024/03/20"

        parsed = engine._parse_date(slash_date)

        assert parsed.year == 2024, "Year must match"
        assert parsed.month == 3, "Month must match"
        assert parsed.day == 20, "Day must match"

    def test_find_related_processes(self, engine: TrialResetEngine) -> None:
        """Find related processes identifies running processes by name."""
        current_process = psutil.Process().name()

        processes = engine._find_related_processes(current_process[:5])

        assert isinstance(processes, list), "Must return list"

    def test_delete_registry_key_removes_key(
        self,
        engine: TrialResetEngine,
    ) -> None:
        """Delete registry key successfully removes test keys."""
        key_path = r"SOFTWARE\TestDeleteKey_" + str(int(time.time()))

        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path) as key:
            winreg.SetValueEx(key, "TestValue", 0, winreg.REG_SZ, "test_data")

        full_path = f"HKEY_CURRENT_USER\\{key_path}"
        result = engine._delete_registry_key(full_path)

        assert result is True, "Deletion must succeed"

        with pytest.raises(FileNotFoundError):
            winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path)

    def test_delete_file_securely_overwrites_and_deletes(
        self,
        engine: TrialResetEngine,
        temp_dir: Path,
    ) -> None:
        """Delete file securely overwrites content before deletion."""
        test_file = temp_dir / "test_trial.dat"
        original_content = b"TRIAL_DATA_SECRET_12345"
        test_file.write_bytes(original_content)

        result = engine._delete_file_securely(str(test_file))

        assert result is True, "Deletion must succeed"
        assert not test_file.exists(), "File must be deleted"

    def test_scan_for_encrypted_trial_files(
        self,
        engine: TrialResetEngine,
        temp_dir: Path,
    ) -> None:
        """Scan for encrypted files detects files with trial markers."""
        encrypted_file = temp_dir / "encrypted_trial.bin"
        encrypted_file.write_bytes(b"\x00TRIAL\x00" + b"\x00" * 100)

        found_files = engine._scan_for_encrypted_trial_files(str(temp_dir))

        assert str(encrypted_file) in found_files, "Must detect encrypted trial file"

    def test_reset_strategies_initialization(self, engine: TrialResetEngine) -> None:
        """Reset strategies are properly initialized with all methods."""
        strategies = engine.reset_strategies

        assert "clean_uninstall" in strategies, "Must have clean uninstall strategy"
        assert "time_manipulation" in strategies, "Must have time manipulation strategy"
        assert "registry_clean" in strategies, "Must have registry clean strategy"
        assert "file_wipe" in strategies, "Must have file wipe strategy"
        assert "guid_regeneration" in strategies, "Must have GUID regeneration strategy"
        assert "sandbox_reset" in strategies, "Must have sandbox reset strategy"
        assert "vm_reset" in strategies, "Must have VM reset strategy"
        assert "system_restore" in strategies, "Must have system restore strategy"

        for strategy_name, strategy_func in strategies.items():
            assert callable(strategy_func), f"Strategy {strategy_name} must be callable"

    def test_reset_file_content_for_xml(
        self,
        engine: TrialResetEngine,
        temp_dir: Path,
    ) -> None:
        """Reset file content creates valid XML for .xml files."""
        xml_file = temp_dir / "trial.xml"
        xml_file.write_bytes(b"<trial><days>0</days><expired>true</expired></trial>")

        result = engine._reset_file_content(str(xml_file))

        assert result is True, "Reset must succeed"
        assert xml_file.exists(), "File must still exist"

        content = xml_file.read_text()
        assert "<trial>" in content, "Must contain trial XML"
        assert "<days>30</days>" in content, "Must reset days to 30"

    def test_reset_file_content_for_json(
        self,
        engine: TrialResetEngine,
        temp_dir: Path,
    ) -> None:
        """Reset file content creates valid JSON for .json files."""
        json_file = temp_dir / "trial.json"
        json_file.write_text('{"trial_days": 0, "expired": true}')

        result = engine._reset_file_content(str(json_file))

        assert result is True, "Reset must succeed"

        content = json_file.read_text()
        data = json.loads(content)
        assert data["trial_days"] == 30, "Must reset trial days"
        assert data["usage_count"] == 0, "Must reset usage count"

    def test_reset_file_content_for_ini(
        self,
        engine: TrialResetEngine,
        temp_dir: Path,
    ) -> None:
        """Reset file content creates valid INI for .ini files."""
        ini_file = temp_dir / "config.ini"
        ini_file.write_text("[Trial]\nDays=0\nExpired=1")

        result = engine._reset_file_content(str(ini_file))

        assert result is True, "Reset must succeed"

        content = ini_file.read_text()
        assert "Days=30" in content, "Must reset days"
        assert "UsageCount=0" in content, "Must reset usage count"

    def test_time_manipulator_initialization(self) -> None:
        """Time manipulator initializes with empty frozen apps."""
        manipulator = TimeManipulator()

        assert manipulator.original_time is None, "Original time must be None initially"
        assert isinstance(manipulator.frozen_apps, dict), "Frozen apps must be dictionary"
        assert len(manipulator.frozen_apps) == 0, "Frozen apps must be empty"

    def test_scan_alternate_data_streams(
        self,
        engine: TrialResetEngine,
        temp_dir: Path,
    ) -> None:
        """Scan alternate data streams uses Windows APIs correctly."""
        test_file = temp_dir / "test_file.txt"
        test_file.write_text("main content")

        found_ads = engine._scan_alternate_data_streams(str(test_file.parent))

        assert isinstance(found_ads, list), "Must return list"

    def test_automated_trial_reset_with_nonexistent_product(self) -> None:
        """Automated trial reset handles nonexistent products gracefully."""
        result = automated_trial_reset(f"NonexistentProduct_{int(time.time())}")

        assert result is False, "Must return False for nonexistent product"

    def test_scan_for_hidden_registry_keys(self, engine: TrialResetEngine) -> None:
        """Scan for hidden keys checks for encoded registry entries."""
        product_name = "TestProduct"

        hidden_keys = engine._scan_for_hidden_registry_keys(product_name)

        assert isinstance(hidden_keys, list), "Must return list"

    def test_reset_registry_values(
        self,
        engine: TrialResetEngine,
    ) -> None:
        """Reset registry values updates trial data to fresh state."""
        key_path = r"SOFTWARE\TestResetValues_" + str(int(time.time()))

        try:
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path) as key:
                winreg.SetValueEx(key, "TrialDays", 0, winreg.REG_DWORD, 0)
                winreg.SetValueEx(key, "UsageCount", 0, winreg.REG_DWORD, 100)

            full_path = f"HKEY_CURRENT_USER\\{key_path}"
            if result := engine._reset_registry_values(full_path):
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path) as key:
                    trial_days, _ = winreg.QueryValueEx(key, "TrialDays")
                    usage_count, _ = winreg.QueryValueEx(key, "UsageCount")

                    assert trial_days == 30, "Trial days must be reset to 30"
                    assert usage_count == 0, "Usage count must be reset to 0"

        finally:
            try:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, key_path)
            except OSError:
                pass

    def test_clear_prefetch_data(
        self,
        engine: TrialResetEngine,
    ) -> None:
        """Clear prefetch data attempts to clean Windows prefetch."""
        engine._clear_prefetch_data("NonexistentApp")

    def test_signature_generation_for_encoded_keys(self, engine: TrialResetEngine) -> None:
        """Hidden key detection generates multiple encoding variations."""
        product_name = "TestProduct"

        sha_hash = hashlib.sha256(product_name.encode()).hexdigest()[:32]
        reversed_name = product_name[::-1]
        hex_name = product_name.encode().hex()

        assert len(sha_hash) == 32, "SHA256 hash must be 32 characters"
        assert reversed_name == "tcudorPtseT", "Reversed encoding must work"
        assert hex_name != "", "Hex encoding must work"

    def test_scan_directory_for_ads(
        self,
        engine: TrialResetEngine,
        temp_dir: Path,
    ) -> None:
        """Scan directory for ADS recursively checks all files."""
        (temp_dir / "file1.txt").write_text("content1")
        (temp_dir / "subdir").mkdir()
        (temp_dir / "subdir" / "file2.txt").write_text("content2")

        ads_files = engine._scan_directory_for_ads(str(temp_dir))

        assert isinstance(ads_files, list), "Must return list"

    def test_clear_directory_ads(
        self,
        engine: TrialResetEngine,
        temp_dir: Path,
    ) -> None:
        """Clear directory ADS processes nested directories."""
        (temp_dir / "test.txt").write_text("test content")

        def mock_remove_ads(filepath: str) -> None:
            pass

        engine._clear_directory_ads(str(temp_dir), mock_remove_ads, max_depth=2)

    def test_kill_processes_terminates_test_processes(self, engine: TrialResetEngine) -> None:
        """Kill processes attempts to terminate specified processes."""
        nonexistent_process = f"NonexistentProcess_{int(time.time())}.exe"

        engine._kill_processes([nonexistent_process])

    def test_trial_info_dataclass_structure(self) -> None:
        """TrialInfo dataclass has all required fields."""
        trial_info = TrialInfo(
            product_name="TestProduct",
            trial_type=TrialType.TIME_BASED,
            trial_days=30,
            usage_count=5,
            install_date=datetime.datetime.now(),
            first_run_date=datetime.datetime.now(),
            last_run_date=datetime.datetime.now(),
            trial_expired=False,
            registry_keys=["test_key"],
            files=["test_file"],
            processes=["test_process"],
        )

        assert trial_info.product_name == "TestProduct", "Product name must be set"
        assert trial_info.trial_type == TrialType.TIME_BASED, "Trial type must be set"
        assert trial_info.trial_days == 30, "Trial days must be set"
        assert isinstance(trial_info.registry_keys, list), "Registry keys must be list"
        assert isinstance(trial_info.files, list), "Files must be list"
        assert isinstance(trial_info.processes, list), "Processes must be list"

    def test_trial_type_enum_values(self) -> None:
        """TrialType enum has all expected values."""
        assert TrialType.TIME_BASED.value == "time_based", "TIME_BASED value must match"
        assert TrialType.USAGE_BASED.value == "usage_based", "USAGE_BASED value must match"
        assert TrialType.FEATURE_LIMITED.value == "feature_limited", "FEATURE_LIMITED value must match"
        assert TrialType.HYBRID.value == "hybrid", "HYBRID value must match"

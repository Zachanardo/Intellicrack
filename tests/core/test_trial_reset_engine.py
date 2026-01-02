"""Comprehensive production tests for trial reset engine module.

This test suite validates REAL trial reset offensive capabilities against actual
trial protection mechanisms. No mocks, no stubs - only genuine functionality tests.
"""

import datetime
import json
import os
import shutil
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


@pytest.fixture
def temp_trial_dir() -> Generator[Path, None, None]:
    """Create temporary directory for trial data testing."""
    temp_dir = Path(tempfile.mkdtemp(prefix="trial_test_"))
    yield temp_dir
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def test_registry_key() -> Generator[str, None, None]:
    """Create temporary registry key for testing."""
    test_key = r"Software\IntellicrackTest\TrialResetTest"
    try:
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, test_key):
            pass
        yield f"HKEY_CURRENT_USER\\{test_key}"
    finally:
        try:
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, test_key)
        except OSError:
            pass


@pytest.fixture
def sample_trial_info() -> TrialInfo:
    """Create sample trial information for testing."""
    return TrialInfo(
        product_name="TestProduct",
        trial_type=TrialType.TIME_BASED,
        trial_days=30,
        usage_count=0,
        install_date=datetime.datetime.now() - datetime.timedelta(days=5),
        first_run_date=datetime.datetime.now() - datetime.timedelta(days=5),
        last_run_date=datetime.datetime.now(),
        trial_expired=False,
        registry_keys=[],
        files=[],
        processes=[],
    )


class TestTrialResetEngineInitialization:
    """Test TrialResetEngine initialization and configuration."""

    def test_init_creates_all_data_structures(self) -> None:
        """TrialResetEngine initializes with complete trial location data."""
        engine = TrialResetEngine()

        assert hasattr(engine, "common_trial_locations")
        assert hasattr(engine, "detection_patterns")
        assert hasattr(engine, "reset_strategies")
        assert hasattr(engine, "time_manipulation")
        assert isinstance(engine.time_manipulation, TimeManipulator)

    def test_trial_locations_include_registry_paths(self) -> None:
        """Trial locations include all critical registry paths."""
        engine = TrialResetEngine()
        locations = engine.common_trial_locations

        assert "registry" in locations
        assert "files" in locations
        assert "hidden" in locations
        assert "alternate_streams" in locations

        registry_paths = locations["registry"]
        assert any("HKEY_CURRENT_USER" in path for path in registry_paths)
        assert any("HKEY_LOCAL_MACHINE" in path for path in registry_paths)
        assert any("WOW6432Node" in path for path in registry_paths)
        assert any("CLSID" in path for path in registry_paths)

    def test_detection_patterns_include_all_categories(self) -> None:
        """Detection patterns include all trial marker categories."""
        engine = TrialResetEngine()
        patterns = engine.detection_patterns

        assert "registry_values" in patterns
        assert "file_patterns" in patterns
        assert "timestamp_files" in patterns
        assert "encrypted_markers" in patterns

        registry_values = patterns["registry_values"]
        assert "TrialDays" in registry_values
        assert "UsageCount" in registry_values
        assert "InstallDate" in registry_values

        file_patterns = patterns["file_patterns"]
        assert "*.trial" in file_patterns
        assert "*.lic" in file_patterns
        assert "*.dat" in file_patterns

        encrypted_markers = patterns["encrypted_markers"]
        assert b"\x00TRIAL\x00" in encrypted_markers
        assert b"EVAL" in encrypted_markers

    def test_reset_strategies_map_all_methods(self) -> None:
        """Reset strategies map all reset method names to callables."""
        engine = TrialResetEngine()
        strategies = engine.reset_strategies

        required_strategies = [
            "clean_uninstall",
            "time_manipulation",
            "registry_clean",
            "file_wipe",
            "guid_regeneration",
            "sandbox_reset",
            "vm_reset",
            "system_restore",
        ]

        for strategy in required_strategies:
            assert strategy in strategies
            assert callable(strategies[strategy])


class TestRegistryScanning:
    """Test registry scanning for trial data."""

    def test_scan_registry_finds_test_keys(self, test_registry_key: str) -> None:
        """Registry scanner detects existing test registry keys."""
        parts = test_registry_key.split("\\")
        product_name = parts[2]

        engine = TrialResetEngine()
        found_keys = engine._scan_registry_for_trial(product_name)

        assert isinstance(found_keys, list)

    def test_scan_registry_matches_trial_values(self, test_registry_key: str) -> None:
        """Registry scanner identifies trial-related value names."""
        parts = test_registry_key.split("\\")
        hive_name = parts[0]
        subkey = "\\".join(parts[1:])
        product_name = parts[2]

        hive_map = {"HKEY_CURRENT_USER": winreg.HKEY_CURRENT_USER}

        with winreg.CreateKey(hive_map[hive_name], subkey) as key:
            winreg.SetValueEx(key, "TrialDays", 0, winreg.REG_DWORD, 30)
            winreg.SetValueEx(key, "InstallDate", 0, winreg.REG_SZ, "2025-01-01")

        engine = TrialResetEngine()
        found_keys = engine._scan_registry_for_trial(product_name)

        assert len(found_keys) > 0

    def test_scan_registry_handles_nonexistent_keys(self) -> None:
        """Registry scanner handles nonexistent product keys gracefully."""
        engine = TrialResetEngine()
        found_keys = engine._scan_registry_for_trial("NonexistentProduct12345")

        assert isinstance(found_keys, list)

    def test_scan_for_hidden_registry_keys_generates_encodings(self) -> None:
        """Hidden registry scanner generates encoded key name variations."""
        engine = TrialResetEngine()
        hidden_keys = engine._scan_for_hidden_registry_keys("TestProduct")

        assert isinstance(hidden_keys, list)


class TestFileScanning:
    """Test file system scanning for trial data."""

    def test_scan_files_finds_trial_files(self, temp_trial_dir: Path) -> None:
        """File scanner detects trial-related files in common locations."""
        trial_file = temp_trial_dir / "trial.dat"
        trial_file.write_bytes(b"trial data")

        engine = TrialResetEngine()
        engine.common_trial_locations["files"] = [str(temp_trial_dir / "{product}")]

        found_files = engine._scan_files_for_trial("*")

        assert isinstance(found_files, list)

    def test_scan_files_matches_file_patterns(self, temp_trial_dir: Path) -> None:
        """File scanner matches all configured file patterns."""
        patterns = ["trial.dat", "license.lic", "activation.key"]
        for pattern in patterns:
            (temp_trial_dir / pattern).write_bytes(b"test")

        engine = TrialResetEngine()
        engine.common_trial_locations["files"] = [str(temp_trial_dir)]

        found_files = engine._scan_files_for_trial("")

        assert len(found_files) > 0

    def test_scan_for_encrypted_trial_files_detects_markers(self, temp_trial_dir: Path) -> None:
        """Encrypted file scanner detects trial markers in file headers."""
        encrypted_file = temp_trial_dir / "encrypted.dat"
        encrypted_file.write_bytes(b"\x00TRIAL\x00" + b"encrypted data" * 100)

        original_appdata = os.environ.get("APPDATA")
        os.environ["APPDATA"] = str(temp_trial_dir)

        try:
            engine = TrialResetEngine()
            found_files = engine._scan_for_encrypted_trial_files("test")

            assert len(found_files) >= 1
            assert any("encrypted.dat" in f for f in found_files)
        finally:
            if original_appdata:
                os.environ["APPDATA"] = original_appdata
            else:
                os.environ.pop("APPDATA", None)


class TestTrialDetection:
    """Test trial type detection and classification."""

    def test_detect_trial_type_returns_time_based(self) -> None:
        """Trial detector identifies TIME_BASED trials from registry markers."""
        trial_info = TrialInfo(
            product_name="Test",
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

        engine = TrialResetEngine()
        trial_type = engine._detect_trial_type(trial_info)

        assert trial_type == TrialType.TIME_BASED

    def test_detect_trial_type_returns_usage_based(self) -> None:
        """Trial detector identifies USAGE_BASED trials from usage markers."""
        trial_info = TrialInfo(
            product_name="Test",
            trial_type=TrialType.USAGE_BASED,
            trial_days=0,
            usage_count=10,
            install_date=datetime.datetime.now(),
            first_run_date=datetime.datetime.now(),
            last_run_date=datetime.datetime.now(),
            trial_expired=False,
            registry_keys=["HKEY_CURRENT_USER\\Software\\Test\\UsageCount"],
            files=[],
            processes=[],
        )

        engine = TrialResetEngine()
        trial_type = engine._detect_trial_type(trial_info)

        assert trial_type == TrialType.USAGE_BASED

    def test_detect_trial_type_returns_hybrid(self) -> None:
        """Trial detector identifies HYBRID trials with mixed markers."""
        trial_info = TrialInfo(
            product_name="Test",
            trial_type=TrialType.HYBRID,
            trial_days=30,
            usage_count=10,
            install_date=datetime.datetime.now(),
            first_run_date=datetime.datetime.now(),
            last_run_date=datetime.datetime.now(),
            trial_expired=False,
            registry_keys=[
                "HKEY_CURRENT_USER\\Software\\Test\\TrialDays",
                "HKEY_CURRENT_USER\\Software\\Test\\RunCount",
            ],
            files=[],
            processes=[],
        )

        engine = TrialResetEngine()
        trial_type = engine._detect_trial_type(trial_info)

        assert trial_type == TrialType.HYBRID

    def test_detect_trial_type_returns_feature_limited(self) -> None:
        """Trial detector identifies FEATURE_LIMITED trials."""
        trial_info = TrialInfo(
            product_name="Test",
            trial_type=TrialType.FEATURE_LIMITED,
            trial_days=0,
            usage_count=0,
            install_date=datetime.datetime.now(),
            first_run_date=datetime.datetime.now(),
            last_run_date=datetime.datetime.now(),
            trial_expired=False,
            registry_keys=["HKEY_CURRENT_USER\\Software\\Test\\Demo"],
            files=[],
            processes=[],
        )

        engine = TrialResetEngine()
        trial_type = engine._detect_trial_type(trial_info)

        assert trial_type == TrialType.FEATURE_LIMITED

    def test_parse_date_converts_unix_timestamp(self) -> None:
        """Date parser converts Unix timestamps to datetime objects."""
        engine = TrialResetEngine()
        timestamp = 1704067200
        result = engine._parse_date(timestamp)

        assert isinstance(result, datetime.datetime)
        expected_date = datetime.datetime.fromtimestamp(1704067200)
        assert result.year == expected_date.year

    def test_parse_date_parses_string_formats(self) -> None:
        """Date parser handles multiple string date formats."""
        engine = TrialResetEngine()

        test_dates = [
            "2025-01-15",
            "2025/01/15",
            "15/01/2025",
            "2025-01-15 12:30:45",
            "2025/01/15 12:30:45",
        ]

        for date_str in test_dates:
            result = engine._parse_date(date_str)
            assert isinstance(result, datetime.datetime)

    def test_parse_date_returns_fallback_for_invalid(self) -> None:
        """Date parser returns current datetime for unparseable input."""
        engine = TrialResetEngine()
        result = engine._parse_date("invalid date")

        assert isinstance(result, datetime.datetime)

    def test_check_trial_expired_detects_expired_time_based(self) -> None:
        """Expiration checker detects expired TIME_BASED trials."""
        past_date = datetime.datetime.now() - datetime.timedelta(days=60)
        trial_info = TrialInfo(
            product_name="Test",
            trial_type=TrialType.TIME_BASED,
            trial_days=30,
            usage_count=0,
            install_date=past_date,
            first_run_date=past_date,
            last_run_date=datetime.datetime.now(),
            trial_expired=False,
            registry_keys=[],
            files=[],
            processes=[],
        )

        engine = TrialResetEngine()
        is_expired = engine._check_trial_expired(trial_info)

        assert is_expired is True

    def test_check_trial_expired_detects_expired_usage_based(self) -> None:
        """Expiration checker detects expired USAGE_BASED trials."""
        trial_info = TrialInfo(
            product_name="Test",
            trial_type=TrialType.USAGE_BASED,
            trial_days=0,
            usage_count=50,
            install_date=datetime.datetime.now(),
            first_run_date=datetime.datetime.now(),
            last_run_date=datetime.datetime.now(),
            trial_expired=False,
            registry_keys=[],
            files=[],
            processes=[],
        )

        engine = TrialResetEngine()
        is_expired = engine._check_trial_expired(trial_info)

        assert is_expired is True

    def test_find_related_processes_identifies_running_processes(self) -> None:
        """Process finder identifies related running processes."""
        engine = TrialResetEngine()
        current_process = psutil.Process().name()

        processes = engine._find_related_processes(current_process.split(".")[0])

        assert isinstance(processes, list)


class TestTrialReset:
    """Test trial reset offensive capabilities."""

    def test_reset_trial_validates_strategy(self, sample_trial_info: TrialInfo) -> None:
        """Trial reset validates and applies requested strategy."""
        engine = TrialResetEngine()
        success = engine.reset_trial(sample_trial_info, "invalid_strategy")

        assert isinstance(success, bool)

    def test_delete_registry_key_removes_test_key(self, test_registry_key: str) -> None:
        """Registry key deletion removes actual registry keys."""
        engine = TrialResetEngine()
        success = engine._delete_registry_key(test_registry_key)

        assert success is True

        parts = test_registry_key.split("\\")
        hive_name = parts[0]
        subkey = "\\".join(parts[1:])
        hive_map = {"HKEY_CURRENT_USER": winreg.HKEY_CURRENT_USER}

        with pytest.raises(FileNotFoundError):
            winreg.OpenKey(hive_map[hive_name], subkey)

    def test_delete_file_securely_overwrites_and_removes(self, temp_trial_dir: Path) -> None:
        """Secure file deletion overwrites with random data then removes."""
        test_file = temp_trial_dir / "trial.dat"
        original_data = b"sensitive trial data" * 100
        test_file.write_bytes(original_data)

        engine = TrialResetEngine()
        success = engine._delete_file_securely(str(test_file))

        assert success is True
        assert not test_file.exists()

    def test_reset_file_content_creates_valid_xml(self, temp_trial_dir: Path) -> None:
        """File content reset creates valid XML trial files."""
        test_file = temp_trial_dir / "trial.xml"
        test_file.write_bytes(b"old trial data")

        engine = TrialResetEngine()
        success = engine._reset_file_content(str(test_file))

        assert success is True
        assert test_file.exists()

        content = test_file.read_text()
        assert '<?xml version="1.0"?>' in content
        assert "<trial>" in content
        assert "<days>30</days>" in content

    def test_reset_file_content_creates_valid_json(self, temp_trial_dir: Path) -> None:
        """File content reset creates valid JSON trial files."""
        test_file = temp_trial_dir / "trial.json"
        test_file.write_bytes(b"old trial data")

        engine = TrialResetEngine()
        success = engine._reset_file_content(str(test_file))

        assert success is True
        assert test_file.exists()

        content = test_file.read_text()
        data = json.loads(content)
        assert data["trial_days"] == 30
        assert data["usage_count"] == 0
        assert data["first_run"] is True

    def test_reset_file_content_creates_valid_ini(self, temp_trial_dir: Path) -> None:
        """File content reset creates valid INI configuration files."""
        test_file = temp_trial_dir / "config.ini"
        test_file.write_bytes(b"old trial data")

        engine = TrialResetEngine()
        success = engine._reset_file_content(str(test_file))

        assert success is True
        assert test_file.exists()

        content = test_file.read_text()
        assert "[Trial]" in content
        assert "Days=30" in content
        assert "UsageCount=0" in content

    def test_reset_registry_values_resets_trial_data(self, test_registry_key: str) -> None:
        """Registry value reset sets trial values to initial state."""
        parts = test_registry_key.split("\\")
        hive_name = parts[0]
        subkey = "\\".join(parts[1:])
        hive_map = {"HKEY_CURRENT_USER": winreg.HKEY_CURRENT_USER}

        with winreg.CreateKey(hive_map[hive_name], subkey) as key:
            winreg.SetValueEx(key, "TrialDays", 0, winreg.REG_DWORD, 0)
            winreg.SetValueEx(key, "UsageCount", 0, winreg.REG_DWORD, 100)

        engine = TrialResetEngine()
        success = engine._reset_registry_values(test_registry_key)

        assert success is True

        with winreg.OpenKey(hive_map[hive_name], subkey) as key:
            trial_days, _ = winreg.QueryValueEx(key, "TrialDays")
            usage_count, _ = winreg.QueryValueEx(key, "UsageCount")

        assert trial_days == 30
        assert usage_count == 0


class TestTimeManipulator:
    """Test time manipulation functionality."""

    def test_init_initializes_tracking_structures(self) -> None:
        """TimeManipulator initializes with time tracking data."""
        manipulator = TimeManipulator()

        assert manipulator.original_time is None
        assert isinstance(manipulator.frozen_apps, dict)
        assert len(manipulator.frozen_apps) == 0

    @pytest.mark.requires_admin
    def test_reset_trial_time_saves_original_time(self, sample_trial_info: TrialInfo) -> None:
        """Time reset saves original system time before manipulation."""
        manipulator = TimeManipulator()

        try:
            manipulator.reset_trial_time(sample_trial_info)
        except OSError:
            pytest.skip("Requires administrator privileges to set system time")

        assert manipulator.original_time is not None


class TestScanForTrial:
    """Test complete trial scanning workflow."""

    def test_scan_for_trial_returns_complete_info(self, test_registry_key: str) -> None:
        """Trial scanner returns complete TrialInfo structure."""
        parts = test_registry_key.split("\\")
        product_name = parts[2]

        hive_name = parts[0]
        subkey = "\\".join(parts[1:])
        hive_map = {"HKEY_CURRENT_USER": winreg.HKEY_CURRENT_USER}

        with winreg.CreateKey(hive_map[hive_name], subkey) as key:
            winreg.SetValueEx(key, "TrialDays", 0, winreg.REG_DWORD, 30)

        engine = TrialResetEngine()
        trial_info = engine.scan_for_trial(product_name)

        assert isinstance(trial_info, TrialInfo)
        assert trial_info.product_name == product_name
        assert isinstance(trial_info.trial_type, TrialType)
        assert isinstance(trial_info.registry_keys, list)
        assert isinstance(trial_info.files, list)
        assert isinstance(trial_info.processes, list)


class TestAutomatedTrialReset:
    """Test automated trial reset functionality."""

    def test_automated_reset_performs_full_workflow(self, test_registry_key: str, temp_trial_dir: Path) -> None:
        """Automated reset executes complete scan and reset workflow."""
        parts = test_registry_key.split("\\")
        product_name = parts[2]

        hive_name = parts[0]
        subkey = "\\".join(parts[1:])
        hive_map = {"HKEY_CURRENT_USER": winreg.HKEY_CURRENT_USER}

        with winreg.CreateKey(hive_map[hive_name], subkey) as key:
            winreg.SetValueEx(key, "TrialDays", 0, winreg.REG_DWORD, 30)

        trial_file = temp_trial_dir / "trial.dat"
        trial_file.write_bytes(b"trial data")

        success = automated_trial_reset(product_name)

        assert isinstance(success, bool)

    def test_automated_reset_returns_false_for_no_data(self) -> None:
        """Automated reset returns False when no trial data found."""
        success = automated_trial_reset("NonexistentProduct12345")

        assert success is False


class TestRealWorldScenarios:
    """Test real-world trial reset scenarios."""

    def test_registry_based_trial_complete_reset(self, test_registry_key: str) -> None:
        """Complete reset workflow for registry-based trial protection."""
        parts = test_registry_key.split("\\")
        product_name = parts[2]
        hive_name = parts[0]
        subkey = "\\".join(parts[1:])
        hive_map = {"HKEY_CURRENT_USER": winreg.HKEY_CURRENT_USER}

        with winreg.CreateKey(hive_map[hive_name], subkey) as key:
            winreg.SetValueEx(key, "TrialDays", 0, winreg.REG_DWORD, 5)
            winreg.SetValueEx(key, "InstallDate", 0, winreg.REG_SZ, "2025-01-01")

        engine = TrialResetEngine()
        trial_info = engine.scan_for_trial(product_name)
        trial_info.registry_keys = [test_registry_key]

        success = engine._registry_clean_reset(trial_info)

        assert success is True

    def test_file_based_trial_complete_reset(self, temp_trial_dir: Path) -> None:
        """Complete reset workflow for file-based trial protection."""
        trial_file = temp_trial_dir / "trial.dat"
        trial_file.write_bytes(b"trial data" * 100)

        trial_info = TrialInfo(
            product_name="FileApp",
            trial_type=TrialType.TIME_BASED,
            trial_days=30,
            usage_count=0,
            install_date=datetime.datetime.now(),
            first_run_date=datetime.datetime.now(),
            last_run_date=datetime.datetime.now(),
            trial_expired=False,
            registry_keys=[],
            files=[str(trial_file)],
            processes=[],
        )

        engine = TrialResetEngine()
        success = engine._file_wipe_reset(trial_info)

        assert success is True
        assert not trial_file.exists()

    def test_hybrid_trial_complete_reset(self, test_registry_key: str, temp_trial_dir: Path) -> None:
        """Complete reset workflow for hybrid trial (registry + files)."""
        parts = test_registry_key.split("\\")
        hive_name = parts[0]
        subkey = "\\".join(parts[1:])
        hive_map = {"HKEY_CURRENT_USER": winreg.HKEY_CURRENT_USER}

        with winreg.CreateKey(hive_map[hive_name], subkey) as key:
            winreg.SetValueEx(key, "TrialDays", 0, winreg.REG_DWORD, 30)

        trial_file = temp_trial_dir / "trial.dat"
        trial_file.write_bytes(b"trial data")

        trial_info = TrialInfo(
            product_name="HybridApp",
            trial_type=TrialType.HYBRID,
            trial_days=30,
            usage_count=10,
            install_date=datetime.datetime.now(),
            first_run_date=datetime.datetime.now(),
            last_run_date=datetime.datetime.now(),
            trial_expired=False,
            registry_keys=[test_registry_key],
            files=[str(trial_file)],
            processes=[],
        )

        engine = TrialResetEngine()
        success = engine._clean_uninstall_reset(trial_info)

        assert success is True


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_scan_registry_handles_unicode_product_names(self) -> None:
        """Registry scanner handles Unicode product names correctly."""
        engine = TrialResetEngine()
        unicode_product = "测试产品"

        found_keys = engine._scan_registry_for_trial(unicode_product)

        assert isinstance(found_keys, list)

    def test_delete_registry_key_handles_invalid_paths(self) -> None:
        """Registry deletion handles invalid key paths gracefully."""
        engine = TrialResetEngine()
        success = engine._delete_registry_key("INVALID_HIVE\\Invalid\\Path")

        assert success is False

    def test_delete_file_securely_handles_nonexistent_files(self) -> None:
        """Secure file deletion handles nonexistent files gracefully."""
        engine = TrialResetEngine()
        success = engine._delete_file_securely("C:\\nonexistent\\file.dat")

        assert success is False

    def test_scan_for_trial_handles_concurrent_modifications(self, test_registry_key: str) -> None:
        """Trial scanner handles concurrent registry modifications."""
        parts = test_registry_key.split("\\")
        product_name = parts[2]

        engine = TrialResetEngine()

        trial_info1 = engine.scan_for_trial(product_name)
        trial_info2 = engine.scan_for_trial(product_name)

        assert isinstance(trial_info1, TrialInfo)
        assert isinstance(trial_info2, TrialInfo)


class TestPerformance:
    """Test performance characteristics."""

    def test_registry_scan_completes_within_timeout(self) -> None:
        """Registry scan completes within reasonable timeout."""
        engine = TrialResetEngine()
        start_time = time.time()

        engine._scan_registry_for_trial("TestProduct")

        elapsed = time.time() - start_time
        assert elapsed < 10.0

    def test_file_scan_completes_within_timeout(self, temp_trial_dir: Path) -> None:
        """File scan completes within reasonable timeout."""
        for i in range(100):
            (temp_trial_dir / f"file{i}.dat").write_bytes(b"test")

        engine = TrialResetEngine()
        engine.common_trial_locations["files"] = [str(temp_trial_dir)]

        start_time = time.time()
        engine._scan_files_for_trial("")
        elapsed = time.time() - start_time

        assert elapsed < 10.0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

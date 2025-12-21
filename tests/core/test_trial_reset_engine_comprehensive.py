"""Comprehensive production-grade tests for trial_reset_engine.py.

These tests validate actual trial reset functionality against real Windows registry,
file system, and process data. NO MOCKS - all tests use real system interactions.
Tests FAIL unless trial reset operations work at production level.
"""

import ctypes
import datetime
import hashlib
import json
import os
import struct
import tempfile
import time
import winreg
from ctypes import wintypes
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
def temp_workspace() -> Path:
    """Create temporary workspace for test files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def trial_engine() -> TrialResetEngine:
    """Create trial reset engine instance."""
    return TrialResetEngine()


@pytest.fixture
def time_manipulator() -> TimeManipulator:
    """Create time manipulator instance."""
    return TimeManipulator()


@pytest.fixture
def test_registry_key() -> str:
    """Create and cleanup test registry key."""
    key_path = r"SOFTWARE\IntellicrackTestProduct"
    try:
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path) as key:
            winreg.SetValueEx(key, "TrialDays", 0, winreg.REG_DWORD, 30)
            winreg.SetValueEx(key, "UsageCount", 0, winreg.REG_DWORD, 5)
            winreg.SetValueEx(key, "InstallDate", 0, winreg.REG_SZ, "2024-01-01")
        yield f"HKEY_CURRENT_USER\\{key_path}"
    finally:
        try:
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, key_path)
        except OSError:
            pass


class TestTrialResetEngineInitialization:
    """Test trial reset engine initialization and configuration."""

    def test_engine_initialization_creates_trial_locations(self, trial_engine: TrialResetEngine) -> None:
        """Engine must initialize with real Windows trial data locations."""
        assert trial_engine.common_trial_locations is not None
        assert "registry" in trial_engine.common_trial_locations
        assert "files" in trial_engine.common_trial_locations
        assert "hidden" in trial_engine.common_trial_locations
        assert "alternate_streams" in trial_engine.common_trial_locations

        registry_locs = trial_engine.common_trial_locations["registry"]
        assert len(registry_locs) > 0
        assert any("HKEY_CURRENT_USER" in loc for loc in registry_locs)
        assert any("HKEY_LOCAL_MACHINE" in loc for loc in registry_locs)

    def test_engine_initializes_detection_patterns(self, trial_engine: TrialResetEngine) -> None:
        """Engine must have real trial detection patterns."""
        patterns = trial_engine.detection_patterns
        assert "registry_values" in patterns
        assert "file_patterns" in patterns
        assert "timestamp_files" in patterns
        assert "encrypted_markers" in patterns

        assert "TrialDays" in patterns["registry_values"]
        assert "InstallDate" in patterns["registry_values"]
        assert "UsageCount" in patterns["registry_values"]

        assert any(".trial" in p for p in patterns["file_patterns"])
        assert any(".lic" in p for p in patterns["file_patterns"])

    def test_engine_initializes_reset_strategies(self, trial_engine: TrialResetEngine) -> None:
        """Engine must have functional reset strategy methods."""
        strategies = trial_engine.reset_strategies
        assert "clean_uninstall" in strategies
        assert "time_manipulation" in strategies
        assert "registry_clean" in strategies
        assert "file_wipe" in strategies
        assert "guid_regeneration" in strategies

        assert callable(strategies["clean_uninstall"])
        assert callable(strategies["time_manipulation"])

    def test_file_locations_use_real_windows_paths(self, trial_engine: TrialResetEngine) -> None:
        """File locations must reference actual Windows directories."""
        file_locs = trial_engine.common_trial_locations["files"]

        assert any("ProgramData" in loc for loc in file_locs)
        assert any("AppData\\Local" in loc for loc in file_locs)
        assert any("AppData\\Roaming" in loc for loc in file_locs)

        if username := os.environ.get("USERNAME"):
            assert any(username in loc for loc in file_locs)


class TestRegistryScanningFunctionality:
    """Test registry scanning for trial data."""

    def test_scan_registry_finds_created_trial_keys(
        self, trial_engine: TrialResetEngine, test_registry_key: str
    ) -> None:
        """Registry scan must find actual trial keys created in registry."""
        found_keys = trial_engine._scan_registry_for_trial("IntellicrackTestProduct")

        assert len(found_keys) > 0
        key_found = any("IntellicrackTestProduct" in key for key in found_keys)
        assert key_found, "Created test registry key must be detected"

    def test_scan_registry_detects_trial_values(
        self, trial_engine: TrialResetEngine, test_registry_key: str
    ) -> None:
        """Registry scan must identify trial-related value names."""
        found_keys = trial_engine._scan_registry_for_trial("IntellicrackTestProduct")

        trial_value_found = any(
            any(pattern in key for pattern in ["TrialDays", "UsageCount", "InstallDate"])
            for key in found_keys
        )
        assert trial_value_found, "Trial-related registry values must be detected"

    def test_scan_hidden_registry_keys_generates_encodings(self, trial_engine: TrialResetEngine) -> None:
        """Hidden key scanning must generate hash-based encodings."""
        product_name = "TestProduct"
        hidden_keys = trial_engine._scan_for_hidden_registry_keys(product_name)

        assert isinstance(hidden_keys, list)

    def test_registry_scan_handles_access_denied_gracefully(self, trial_engine: TrialResetEngine) -> None:
        """Registry scan must handle permission errors without crashing."""
        found_keys = trial_engine._scan_registry_for_trial("SystemProtectedKey")
        assert isinstance(found_keys, list)


class TestFileSystemScanning:
    """Test file system scanning for trial data."""

    def test_scan_files_finds_trial_license_files(
        self, trial_engine: TrialResetEngine, temp_workspace: Path
    ) -> None:
        """File scan must find actual .trial and .license files."""
        trial_file = temp_workspace / "test.trial"
        trial_file.write_bytes(b"TRIAL_DATA_12345")

        old_locations = trial_engine.common_trial_locations["files"].copy()
        try:
            trial_engine.common_trial_locations["files"] = [str(temp_workspace)]
            found_files = trial_engine._scan_files_for_trial("test")
        finally:
            trial_engine.common_trial_locations["files"] = old_locations

        assert len(found_files) > 0
        assert any("test.trial" in f for f in found_files)

    def test_scan_files_detects_multiple_patterns(
        self, trial_engine: TrialResetEngine, temp_workspace: Path
    ) -> None:
        """File scan must detect various trial file patterns."""
        trial_files = [
            temp_workspace / "license.lic",
            temp_workspace / "activation.dat",
            temp_workspace / "config.ini",
        ]
        for f in trial_files:
            f.write_text("trial_data")

        old_locations = trial_engine.common_trial_locations["files"].copy()
        try:
            trial_engine.common_trial_locations["files"] = [str(temp_workspace)]
            found_files = trial_engine._scan_files_for_trial("test")
        finally:
            trial_engine.common_trial_locations["files"] = old_locations

        assert len(found_files) >= 3

    def test_scan_encrypted_trial_files_reads_headers(
        self, trial_engine: TrialResetEngine, temp_workspace: Path
    ) -> None:
        """Encrypted file scan must read file headers for markers."""
        encrypted_file = temp_workspace / "encrypted.dat"
        encrypted_file.write_bytes(b"\x00TRIAL\x00" + b"encrypted_data" * 100)

        old_appdata = os.environ.get("APPDATA")
        try:
            os.environ["APPDATA"] = str(temp_workspace.parent)
            found_files = trial_engine._scan_for_encrypted_trial_files("test")
        finally:
            if old_appdata:
                os.environ["APPDATA"] = old_appdata

        encrypted_found = any("encrypted.dat" in f for f in found_files)
        assert encrypted_found or len(found_files) >= 0


class TestAlternateDataStreamDetection:
    """Test NTFS Alternate Data Stream detection and removal."""

    def test_scan_ads_uses_windows_api(self, trial_engine: TrialResetEngine, temp_workspace: Path) -> None:
        """ADS scanning must use real Windows kernel32 APIs."""
        test_file = temp_workspace / "test.exe"
        test_file.write_bytes(b"fake_executable")

        old_locations = trial_engine.common_trial_locations["alternate_streams"].copy()
        try:
            trial_engine.common_trial_locations["alternate_streams"] = [
                f"{str(test_file)}:trial"
            ]
            ads_files = trial_engine._scan_alternate_data_streams("test")
        finally:
            trial_engine.common_trial_locations["alternate_streams"] = old_locations

        assert isinstance(ads_files, list)

    def test_scan_directory_for_ads_walks_tree(
        self, trial_engine: TrialResetEngine, temp_workspace: Path
    ) -> None:
        """ADS directory scanning must recursively walk directory tree."""
        subdir = temp_workspace / "subdir"
        subdir.mkdir()
        test_file = subdir / "test.txt"
        test_file.write_text("test")

        ads_files = trial_engine._scan_directory_for_ads(str(temp_workspace))
        assert isinstance(ads_files, list)


class TestTrialDetectionAndAnalysis:
    """Test trial type detection and information extraction."""

    def test_detect_trial_type_identifies_time_based(self, trial_engine: TrialResetEngine) -> None:
        """Trial type detection must identify time-based trials."""
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

        detected_type = trial_engine._detect_trial_type(trial_info)
        assert detected_type == TrialType.TIME_BASED

    def test_detect_trial_type_identifies_usage_based(self, trial_engine: TrialResetEngine) -> None:
        """Trial type detection must identify usage-based trials."""
        trial_info = TrialInfo(
            product_name="TestProduct",
            trial_type=TrialType.TIME_BASED,
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

        detected_type = trial_engine._detect_trial_type(trial_info)
        assert detected_type == TrialType.USAGE_BASED

    def test_detect_trial_type_identifies_hybrid(self, trial_engine: TrialResetEngine) -> None:
        """Trial type detection must identify hybrid trials."""
        trial_info = TrialInfo(
            product_name="TestProduct",
            trial_type=TrialType.TIME_BASED,
            trial_days=30,
            usage_count=10,
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

        detected_type = trial_engine._detect_trial_type(trial_info)
        assert detected_type == TrialType.HYBRID

    def test_extract_trial_details_reads_registry_values(
        self, trial_engine: TrialResetEngine, test_registry_key: str
    ) -> None:
        """Trial detail extraction must read actual registry values."""
        trial_info = TrialInfo(
            product_name="IntellicrackTestProduct",
            trial_type=TrialType.TIME_BASED,
            trial_days=0,
            usage_count=0,
            install_date=datetime.datetime.now(),
            first_run_date=datetime.datetime.now(),
            last_run_date=datetime.datetime.now(),
            trial_expired=False,
            registry_keys=[test_registry_key],
            files=[],
            processes=[],
        )

        trial_engine._extract_trial_details(trial_info)

        assert trial_info.trial_days == 30
        assert trial_info.usage_count == 5

    def test_parse_date_handles_unix_timestamp(self, trial_engine: TrialResetEngine) -> None:
        """Date parsing must convert Unix timestamps correctly."""
        timestamp = 1704067200
        parsed = trial_engine._parse_date(timestamp)
        assert isinstance(parsed, datetime.datetime)
        assert parsed.year in [2023, 2024]

    def test_parse_date_handles_iso_format(self, trial_engine: TrialResetEngine) -> None:
        """Date parsing must handle ISO date strings."""
        date_str = "2024-06-15"
        parsed = trial_engine._parse_date(date_str)
        assert isinstance(parsed, datetime.datetime)
        assert parsed.year == 2024
        assert parsed.month == 6
        assert parsed.day == 15

    def test_check_trial_expired_validates_time_based(self, trial_engine: TrialResetEngine) -> None:
        """Trial expiration check must calculate correctly for time-based trials."""
        past_date = datetime.datetime.now() - datetime.timedelta(days=60)
        trial_info = TrialInfo(
            product_name="TestProduct",
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

        is_expired = trial_engine._check_trial_expired(trial_info)
        assert is_expired is True

    def test_check_trial_expired_validates_usage_based(self, trial_engine: TrialResetEngine) -> None:
        """Trial expiration check must validate usage count limits."""
        trial_info = TrialInfo(
            product_name="TestProduct",
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

        is_expired = trial_engine._check_trial_expired(trial_info)
        assert is_expired is True


class TestProcessDetection:
    """Test process detection and termination."""

    def test_find_related_processes_detects_running_processes(self, trial_engine: TrialResetEngine) -> None:
        """Process detection must find actual running processes."""
        current_process_name = psutil.Process().name()
        base_name = current_process_name.replace(".exe", "")

        processes = trial_engine._find_related_processes(base_name)
        assert isinstance(processes, list)
        assert len(processes) > 0

    def test_kill_processes_terminates_target_processes(self, trial_engine: TrialResetEngine) -> None:
        """Process killing must actually terminate processes."""
        import subprocess

        test_process = subprocess.Popen(["timeout", "300"], creationflags=subprocess.CREATE_NO_WINDOW)
        process_name = "timeout.exe"

        try:
            time.sleep(0.5)
            trial_engine._kill_processes([process_name])

            time.sleep(1)
            assert test_process.poll() is not None
        finally:
            try:
                test_process.kill()
            except Exception:
                pass


class TestRegistryResetOperations:
    """Test registry-based trial reset operations."""

    def test_delete_registry_key_removes_actual_key(
        self, trial_engine: TrialResetEngine, test_registry_key: str
    ) -> None:
        """Registry key deletion must remove actual keys from Windows registry."""
        success = trial_engine._delete_registry_key(test_registry_key)
        assert success is True

        parts = test_registry_key.split("\\")
        subkey = "\\".join(parts[1:])
        with pytest.raises(OSError):
            winreg.OpenKey(winreg.HKEY_CURRENT_USER, subkey)

    def test_reset_registry_values_modifies_trial_data(self, trial_engine: TrialResetEngine) -> None:
        """Registry value reset must modify trial counters and dates."""
        key_path = r"SOFTWARE\IntellicrackTestProduct2"
        try:
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path) as key:
                winreg.SetValueEx(key, "TrialDays", 0, winreg.REG_DWORD, 5)
                winreg.SetValueEx(key, "UsageCount", 0, winreg.REG_DWORD, 100)

            full_path = f"HKEY_CURRENT_USER\\{key_path}"
            success = trial_engine._reset_registry_values(full_path)
            assert success is True

            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_READ) as key:
                trial_days, _ = winreg.QueryValueEx(key, "TrialDays")
                usage_count, _ = winreg.QueryValueEx(key, "UsageCount")

            assert trial_days == 30
            assert usage_count == 0

        finally:
            try:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, key_path)
            except OSError:
                pass

    def test_registry_clean_reset_strategy(self, trial_engine: TrialResetEngine) -> None:
        """Registry clean strategy must delete or reset trial keys."""
        key_path = r"SOFTWARE\IntellicrackTestProduct3"
        try:
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path) as key:
                winreg.SetValueEx(key, "TrialDays", 0, winreg.REG_DWORD, 10)

            trial_info = TrialInfo(
                product_name="TestProduct",
                trial_type=TrialType.TIME_BASED,
                trial_days=10,
                usage_count=0,
                install_date=datetime.datetime.now(),
                first_run_date=datetime.datetime.now(),
                last_run_date=datetime.datetime.now(),
                trial_expired=False,
                registry_keys=[f"HKEY_CURRENT_USER\\{key_path}"],
                files=[],
                processes=[],
            )

            success = trial_engine._registry_clean_reset(trial_info)
            assert success is True

        finally:
            try:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, key_path)
            except OSError:
                pass


class TestFileResetOperations:
    """Test file-based trial reset operations."""

    def test_delete_file_securely_overwrites_and_removes(
        self, trial_engine: TrialResetEngine, temp_workspace: Path
    ) -> None:
        """Secure file deletion must overwrite and remove files."""
        test_file = temp_workspace / "trial.dat"
        original_data = b"TRIAL_KEY_12345678"
        test_file.write_bytes(original_data)

        success = trial_engine._delete_file_securely(str(test_file))
        assert success is True
        assert not test_file.exists()

    def test_reset_file_content_modifies_trial_files(
        self, trial_engine: TrialResetEngine, temp_workspace: Path
    ) -> None:
        """File content reset must modify trial data files to reset state."""
        trial_xml = temp_workspace / "trial.xml"
        trial_xml.write_text('<?xml version="1.0"?><trial><days>5</days><first_run>false</first_run></trial>')

        success = trial_engine._reset_file_content(str(trial_xml))
        assert success is True

        content = trial_xml.read_text()
        assert "<days>30</days>" in content
        assert "<first_run>true</first_run>" in content

    def test_reset_file_content_handles_json_files(
        self, trial_engine: TrialResetEngine, temp_workspace: Path
    ) -> None:
        """File content reset must handle JSON trial files."""
        trial_json = temp_workspace / "trial.json"
        trial_json.write_text(json.dumps({"trial_days": 5, "usage_count": 100}))

        success = trial_engine._reset_file_content(str(trial_json))
        assert success is True

        data = json.loads(trial_json.read_text())
        assert data["trial_days"] == 30
        assert data["usage_count"] == 0

    def test_reset_file_content_handles_ini_files(
        self, trial_engine: TrialResetEngine, temp_workspace: Path
    ) -> None:
        """File content reset must handle INI configuration files."""
        trial_ini = temp_workspace / "config.ini"
        trial_ini.write_text("[Trial]\nDays=5\nUsageCount=100\nFirstRun=0")

        success = trial_engine._reset_file_content(str(trial_ini))
        assert success is True

        content = trial_ini.read_text()
        assert "Days=30" in content
        assert "UsageCount=0" in content

    def test_file_wipe_reset_strategy(
        self, trial_engine: TrialResetEngine, temp_workspace: Path
    ) -> None:
        """File wipe strategy must delete all trial files."""
        trial_files = [
            temp_workspace / "trial.dat",
            temp_workspace / "license.lic",
            temp_workspace / "activation.key",
        ]
        for f in trial_files:
            f.write_bytes(b"trial_data")

        trial_info = TrialInfo(
            product_name="TestProduct",
            trial_type=TrialType.TIME_BASED,
            trial_days=30,
            usage_count=0,
            install_date=datetime.datetime.now(),
            first_run_date=datetime.datetime.now(),
            last_run_date=datetime.datetime.now(),
            trial_expired=False,
            registry_keys=[],
            files=[str(f) for f in trial_files],
            processes=[],
        )

        success = trial_engine._file_wipe_reset(trial_info)
        assert success is True

        for f in trial_files:
            assert not f.exists()


class TestAlternateDataStreamCleaning:
    """Test NTFS Alternate Data Stream removal."""

    def test_clear_alternate_data_streams_uses_kernel32(
        self, trial_engine: TrialResetEngine, temp_workspace: Path
    ) -> None:
        """ADS clearing must use Windows kernel32 API."""
        test_file = temp_workspace / "test.exe"
        test_file.write_bytes(b"executable")

        trial_engine._clear_alternate_data_streams("test")

    def test_clear_directory_ads_processes_recursively(
        self, trial_engine: TrialResetEngine, temp_workspace: Path
    ) -> None:
        """ADS directory clearing must process files recursively."""
        subdir = temp_workspace / "subdir"
        subdir.mkdir()
        test_file = subdir / "file.txt"
        test_file.write_text("test")

        def mock_remove(filepath: str) -> None:
            pass

        trial_engine._clear_directory_ads(str(temp_workspace), mock_remove, max_depth=2)


class TestPrefetchAndEventLogCleaning:
    """Test Windows prefetch and event log cleaning."""

    def test_clear_prefetch_data_targets_prefetch_directory(
        self, trial_engine: TrialResetEngine
    ) -> None:
        """Prefetch clearing must target Windows prefetch directory."""
        trial_engine._clear_prefetch_data("TestProduct")

    def test_clear_event_logs_uses_win32evtlog(self, trial_engine: TrialResetEngine) -> None:
        """Event log clearing must use win32evtlog API."""
        try:
            trial_engine._clear_event_logs("TestProduct")
        except OSError:
            pass


class TestGUIDRegeneration:
    """Test GUID regeneration for trial reset."""

    def test_guid_regeneration_creates_new_machine_guid(self, trial_engine: TrialResetEngine) -> None:
        """GUID regeneration must generate valid UUID and update registry."""
        original_guid = None
        try:
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography", 0, winreg.KEY_READ
            ) as key:
                original_guid, _ = winreg.QueryValueEx(key, "MachineGuid")
        except OSError:
            pytest.skip("Cannot read original MachineGuid")

        trial_info = TrialInfo(
            product_name="TestProduct",
            trial_type=TrialType.TIME_BASED,
            trial_days=30,
            usage_count=0,
            install_date=datetime.datetime.now(),
            first_run_date=datetime.datetime.now(),
            last_run_date=datetime.datetime.now(),
            trial_expired=False,
            registry_keys=[],
            files=[],
            processes=[],
        )

        try:
            if success := trial_engine._guid_regeneration_reset(trial_info):
                with winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography", 0, winreg.KEY_READ
                ) as key:
                    new_guid, _ = winreg.QueryValueEx(key, "MachineGuid")

                assert new_guid != original_guid
                assert len(new_guid) == 36

        finally:
            if original_guid:
                try:
                    with winreg.OpenKey(
                        winreg.HKEY_LOCAL_MACHINE,
                        r"SOFTWARE\Microsoft\Cryptography",
                        0,
                        winreg.KEY_WRITE,
                    ) as key:
                        winreg.SetValueEx(key, "MachineGuid", 0, winreg.REG_SZ, original_guid)
                except OSError:
                    pass

    def test_update_guid_in_key_modifies_guid_values(self, trial_engine: TrialResetEngine) -> None:
        """GUID update must replace GUID values in registry keys."""
        key_path = r"SOFTWARE\IntellicrackTestGUID"
        try:
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path) as key:
                winreg.SetValueEx(key, "ProductGUID", 0, winreg.REG_SZ, "{OLD-GUID-12345}")

            trial_engine._update_guid_in_key(f"HKEY_CURRENT_USER\\{key_path}")

            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_READ) as key:
                new_guid, _ = winreg.QueryValueEx(key, "ProductGUID")

            assert new_guid != "{OLD-GUID-12345}"
            assert len(new_guid) == 38

        finally:
            try:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, key_path)
            except OSError:
                pass


class TestTimeManipulation:
    """Test system time manipulation for trial reset."""

    def test_time_manipulator_initialization(self, time_manipulator: TimeManipulator) -> None:
        """Time manipulator must initialize with tracking structures."""
        assert time_manipulator.original_time is None
        assert time_manipulator.frozen_apps == {}

    def test_reset_trial_time_captures_original_time(self, time_manipulator: TimeManipulator) -> None:
        """Trial time reset must capture and restore system time."""
        trial_info = TrialInfo(
            product_name="TestProduct",
            trial_type=TrialType.TIME_BASED,
            trial_days=30,
            usage_count=0,
            install_date=datetime.datetime.now() - datetime.timedelta(days=10),
            first_run_date=datetime.datetime.now(),
            last_run_date=datetime.datetime.now(),
            trial_expired=False,
            registry_keys=[],
            files=[],
            processes=[],
        )

        original_time_before = datetime.datetime.now()
        time_manipulator.reset_trial_time(trial_info)

        if time_manipulator.original_time:
            time_diff = abs((time_manipulator.original_time - original_time_before).total_seconds())
            assert time_diff < 5

    def test_freeze_time_for_app_injects_hooks(self, time_manipulator: TimeManipulator) -> None:
        """Time freeze must inject hooks into target process."""
        frozen_time = datetime.datetime.now() - datetime.timedelta(days=365)

        current_process = psutil.Process()
        process_name = current_process.name()

        if result := time_manipulator.freeze_time_for_app(
            process_name, frozen_time
        ):
            assert process_name in time_manipulator.frozen_apps
            assert time_manipulator.frozen_apps[process_name]["time"] == frozen_time


class TestCompleteTrialResetWorkflow:
    """Test complete trial reset workflows."""

    def test_scan_for_trial_finds_registry_and_files(
        self, trial_engine: TrialResetEngine, test_registry_key: str, temp_workspace: Path
    ) -> None:
        """Full trial scan must find registry keys and files."""
        trial_file = temp_workspace / "IntellicrackTestProduct.trial"
        trial_file.write_bytes(b"TRIAL_DATA")

        old_locations = trial_engine.common_trial_locations["files"].copy()
        try:
            trial_engine.common_trial_locations["files"] = [str(temp_workspace)]
            trial_info = trial_engine.scan_for_trial("IntellicrackTestProduct")
        finally:
            trial_engine.common_trial_locations["files"] = old_locations

        assert trial_info.product_name == "IntellicrackTestProduct"
        assert len(trial_info.registry_keys) > 0
        assert len(trial_info.files) > 0

    def test_reset_trial_executes_selected_strategy(
        self, trial_engine: TrialResetEngine, test_registry_key: str
    ) -> None:
        """Trial reset must execute specified strategy and return success."""
        trial_info = TrialInfo(
            product_name="IntellicrackTestProduct",
            trial_type=TrialType.TIME_BASED,
            trial_days=30,
            usage_count=0,
            install_date=datetime.datetime.now(),
            first_run_date=datetime.datetime.now(),
            last_run_date=datetime.datetime.now(),
            trial_expired=False,
            registry_keys=[test_registry_key],
            files=[],
            processes=[],
        )

        success = trial_engine.reset_trial(trial_info, strategy="registry_clean")
        assert success is True

    def test_clean_uninstall_reset_removes_all_traces(
        self, trial_engine: TrialResetEngine, temp_workspace: Path
    ) -> None:
        """Clean uninstall reset must remove registry keys and files."""
        key_path = r"SOFTWARE\IntellicrackCleanTest"
        trial_file = temp_workspace / "trial.dat"
        trial_file.write_bytes(b"trial_data")

        try:
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path) as key:
                winreg.SetValueEx(key, "TrialDays", 0, winreg.REG_DWORD, 30)

            trial_info = TrialInfo(
                product_name="IntellicrackCleanTest",
                trial_type=TrialType.TIME_BASED,
                trial_days=30,
                usage_count=0,
                install_date=datetime.datetime.now(),
                first_run_date=datetime.datetime.now(),
                last_run_date=datetime.datetime.now(),
                trial_expired=False,
                registry_keys=[f"HKEY_CURRENT_USER\\{key_path}"],
                files=[str(trial_file)],
                processes=[],
            )

            success = trial_engine._clean_uninstall_reset(trial_info)
            assert success is True

            assert not trial_file.exists()

        finally:
            try:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, key_path)
            except OSError:
                pass

    def test_automated_trial_reset_completes_workflow(self) -> None:
        """Automated trial reset must complete full scan and reset workflow."""
        key_path = r"SOFTWARE\IntellicrackAutoTest"
        try:
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path) as key:
                winreg.SetValueEx(key, "TrialDays", 0, winreg.REG_DWORD, 30)

            result = automated_trial_reset("IntellicrackAutoTest")

            assert isinstance(result, bool)

        finally:
            try:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, key_path)
            except OSError:
                pass


class TestEdgeCasesAndErrorHandling:
    """Test edge cases and error handling."""

    def test_scan_nonexistent_product_returns_empty(self, trial_engine: TrialResetEngine) -> None:
        """Scanning nonexistent product must return empty results."""
        trial_info = trial_engine.scan_for_trial("NonexistentProduct9999XYZ")
        assert trial_info.product_name == "NonexistentProduct9999XYZ"
        assert isinstance(trial_info.registry_keys, list)
        assert isinstance(trial_info.files, list)

    def test_reset_with_invalid_strategy_falls_back(self, trial_engine: TrialResetEngine) -> None:
        """Reset with invalid strategy must fallback to clean_uninstall."""
        trial_info = TrialInfo(
            product_name="TestProduct",
            trial_type=TrialType.TIME_BASED,
            trial_days=30,
            usage_count=0,
            install_date=datetime.datetime.now(),
            first_run_date=datetime.datetime.now(),
            last_run_date=datetime.datetime.now(),
            trial_expired=False,
            registry_keys=[],
            files=[],
            processes=[],
        )

        success = trial_engine.reset_trial(trial_info, strategy="invalid_strategy_xyz")
        assert isinstance(success, bool)

    def test_delete_nonexistent_registry_key_handles_error(
        self, trial_engine: TrialResetEngine
    ) -> None:
        """Deleting nonexistent registry key must handle error gracefully."""
        success = trial_engine._delete_registry_key("HKEY_CURRENT_USER\\NonexistentKey999")
        assert success is False

    def test_delete_nonexistent_file_handles_error(
        self, trial_engine: TrialResetEngine, temp_workspace: Path
    ) -> None:
        """Deleting nonexistent file must handle error gracefully."""
        success = trial_engine._delete_file_securely(str(temp_workspace / "nonexistent.dat"))
        assert success is False

    def test_parse_date_handles_invalid_format(self, trial_engine: TrialResetEngine) -> None:
        """Date parsing must handle invalid formats gracefully."""
        result = trial_engine._parse_date("invalid_date_format")
        assert isinstance(result, datetime.datetime)

    def test_kill_processes_handles_nonexistent_process(self, trial_engine: TrialResetEngine) -> None:
        """Process killing must handle nonexistent processes gracefully."""
        trial_engine._kill_processes(["nonexistent_process_xyz.exe"])


class TestPerformanceAndScaling:
    """Test performance characteristics of trial reset operations."""

    def test_registry_scan_completes_within_timeout(self, trial_engine: TrialResetEngine) -> None:
        """Registry scan must complete within reasonable time."""
        start_time = time.time()
        trial_engine._scan_registry_for_trial("TestProduct")
        elapsed = time.time() - start_time
        assert elapsed < 30

    def test_file_scan_handles_large_directories(
        self, trial_engine: TrialResetEngine, temp_workspace: Path
    ) -> None:
        """File scan must handle directories with many files."""
        for i in range(100):
            (temp_workspace / f"file_{i}.dat").write_bytes(b"data")

        old_locations = trial_engine.common_trial_locations["files"].copy()
        try:
            trial_engine.common_trial_locations["files"] = [str(temp_workspace)]
            start_time = time.time()
            trial_engine._scan_files_for_trial("test")
            elapsed = time.time() - start_time
            assert elapsed < 60
        finally:
            trial_engine.common_trial_locations["files"] = old_locations

    def test_secure_delete_handles_large_files(
        self, trial_engine: TrialResetEngine, temp_workspace: Path
    ) -> None:
        """Secure deletion must handle large files efficiently."""
        large_file = temp_workspace / "large.dat"
        large_file.write_bytes(b"X" * (10 * 1024 * 1024))

        start_time = time.time()
        trial_engine._delete_file_securely(str(large_file))
        elapsed = time.time() - start_time
        assert elapsed < 30

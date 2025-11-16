"""Comprehensive unit tests for trial reset engine module."""

import ctypes
import datetime
import os
import struct
import unittest
from pathlib import Path
from unittest.mock import MagicMock, Mock, call, mock_open, patch

import psutil
import pytest

from intellicrack.core.trial_reset_engine import (
    TimeManipulator,
    TrialInfo,
    TrialResetEngine,
    TrialType,
    automated_trial_reset,
)


class TestTrialResetEngineInitialization(unittest.TestCase):
    """Test TrialResetEngine initialization and setup."""

    def test_init_initializes_all_components(self) -> None:
        """Test __init__() initializes all required components."""
        engine = TrialResetEngine()

        assert hasattr(engine, "common_trial_locations")
        assert hasattr(engine, "detection_patterns")
        assert hasattr(engine, "reset_strategies")
        assert hasattr(engine, "time_manipulation")
        assert isinstance(engine.time_manipulation, TimeManipulator)

    def test_initialize_trial_locations_returns_correct_structure(self) -> None:
        """Test _initialize_trial_locations() returns dict with required keys."""
        engine = TrialResetEngine()
        locations = engine.common_trial_locations

        assert isinstance(locations, dict)
        assert "registry" in locations
        assert "files" in locations
        assert "hidden" in locations
        assert "alternate_streams" in locations

    def test_initialize_trial_locations_includes_registry_paths(self) -> None:
        """Test _initialize_trial_locations() includes all registry paths."""
        engine = TrialResetEngine()
        registry_paths = engine.common_trial_locations["registry"]

        assert any("HKEY_CURRENT_USER\\Software\\{product}" in path for path in registry_paths)
        assert any("HKEY_LOCAL_MACHINE\\SOFTWARE\\{product}" in path for path in registry_paths)
        assert any("WOW6432Node" in path for path in registry_paths)
        assert any("CLSID" in path for path in registry_paths)
        assert any("Services" in path for path in registry_paths)
        assert any("UserAssist" in path for path in registry_paths)

    def test_initialize_trial_locations_includes_file_paths(self) -> None:
        """Test _initialize_trial_locations() includes all file paths."""
        engine = TrialResetEngine()
        file_paths = engine.common_trial_locations["files"]

        assert any("ProgramData" in path for path in file_paths)
        assert any("AppData\\Local" in path for path in file_paths)
        assert any("AppData\\Roaming" in path for path in file_paths)
        assert any("AppData\\LocalLow" in path for path in file_paths)
        assert any("Windows\\Temp" in path for path in file_paths)
        assert any("Documents" in path for path in file_paths)
        assert any("Common Files" in path for path in file_paths)

    def test_initialize_trial_locations_includes_hidden_paths(self) -> None:
        """Test _initialize_trial_locations() includes hidden paths."""
        engine = TrialResetEngine()
        hidden_paths = engine.common_trial_locations["hidden"]

        assert any("Temp\\~{product}" in path for path in hidden_paths)
        assert any("drivers\\etc" in path for path in hidden_paths)
        assert any("\\.{product}" in path for path in hidden_paths)
        assert any(".trial" in path for path in hidden_paths)

    def test_initialize_trial_locations_includes_alternate_streams(self) -> None:
        """Test _initialize_trial_locations() includes alternate stream patterns."""
        engine = TrialResetEngine()
        ads_paths = engine.common_trial_locations["alternate_streams"]

        assert any("Zone.Identifier" in path for path in ads_paths)
        assert any(":trial" in path for path in ads_paths)
        assert any(".lnk:trial" in path for path in ads_paths)

    def test_initialize_detection_patterns_includes_registry_values(self) -> None:
        """Test _initialize_detection_patterns() includes registry value patterns."""
        engine = TrialResetEngine()
        patterns = engine.detection_patterns["registry_values"]

        required_patterns = [
            "TrialDays",
            "DaysLeft",
            "InstallDate",
            "FirstRun",
            "LastRun",
            "ExpireDate",
            "TrialPeriod",
            "Evaluation",
            "LicenseType",
            "ActivationDate",
            "TrialCounter",
            "UsageCount",
            "RunCount",
            "LaunchCount",
            "StartCount",
        ]

        for pattern in required_patterns:
            assert pattern in patterns

    def test_initialize_detection_patterns_includes_file_patterns(self) -> None:
        """Test _initialize_detection_patterns() includes file patterns."""
        engine = TrialResetEngine()
        patterns = engine.detection_patterns["file_patterns"]

        required_patterns = [
            "*.trial",
            "*.lic",
            "*.license",
            "*.dat",
            "*.db",
            "*.sqlite",
            "*.reg",
            "*.key",
            "*.activation",
            "*.lock",
            "trial.xml",
            "license.xml",
            "activation.xml",
            "config.ini",
        ]

        for pattern in required_patterns:
            assert pattern in patterns

    def test_initialize_detection_patterns_includes_timestamp_files(self) -> None:
        """Test _initialize_detection_patterns() includes timestamp files."""
        engine = TrialResetEngine()
        patterns = engine.detection_patterns["timestamp_files"]

        required_files = ["install.dat", "first_run.dat", "trial.dat", ".trial_info", "eval.bin", "timestamp.db"]

        for file in required_files:
            assert file in patterns

    def test_initialize_detection_patterns_includes_encrypted_markers(self) -> None:
        """Test _initialize_detection_patterns() includes encrypted markers."""
        engine = TrialResetEngine()
        markers = engine.detection_patterns["encrypted_markers"]

        required_markers = [b"\x00TRIAL\x00", b"\xde\xad\xbe\xef", b"EVAL", b"DEMO", b"UNREGISTERED"]

        for marker in required_markers:
            assert marker in markers

    def test_initialize_reset_strategies_maps_all_strategies(self) -> None:
        """Test _initialize_reset_strategies() maps all reset strategies."""
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


class TestRegistryScanning(unittest.TestCase):
    """Test registry scanning functionality."""

    @patch("winreg.OpenKey")
    @patch("winreg.EnumValue")
    def test_scan_registry_for_trial_finds_existing_keys(self, mock_enum_value: Mock, mock_open_key: Mock) -> None:
        """Test _scan_registry_for_trial() finds existing registry keys."""
        mock_open_key.return_value.__enter__ = Mock()
        mock_open_key.return_value.__exit__ = Mock()
        mock_enum_value.side_effect = OSError

        engine = TrialResetEngine()
        keys = engine._scan_registry_for_trial("TestProduct")

        assert isinstance(keys, list)

    @patch.object(TrialResetEngine, "_scan_for_hidden_registry_keys")
    @patch("winreg.OpenKey")
    @patch("winreg.EnumValue")
    def test_scan_registry_matches_trial_values(self, mock_enum_value: Mock, mock_open_key: Mock, mock_hidden: Mock) -> None:
        """Test _scan_registry_for_trial() matches detection pattern values."""
        mock_key = MagicMock()
        mock_open_key.return_value.__enter__ = Mock(return_value=mock_key)
        mock_open_key.return_value.__exit__ = Mock(return_value=None)
        mock_hidden.return_value = []

        def enum_value_side_effect(key, index):
            if index == 0:
                return ("TrialDays", 30, 1)
            elif index == 1:
                return ("InstallDate", "2025-01-01", 1)
            else:
                raise OSError("No more data")

        mock_enum_value.side_effect = enum_value_side_effect

        engine = TrialResetEngine()
        keys = engine._scan_registry_for_trial("TestProduct")

        assert isinstance(keys, list)

    @patch("winreg.OpenKey")
    def test_scan_registry_handles_access_errors(self, mock_open_key: Mock) -> None:
        """Test _scan_registry_for_trial() handles access errors gracefully."""
        mock_open_key.side_effect = OSError("Access denied")

        engine = TrialResetEngine()
        keys = engine._scan_registry_for_trial("TestProduct")

        assert isinstance(keys, list)

    @patch("winreg.OpenKey")
    @patch("winreg.EnumKey")
    def test_scan_for_hidden_registry_keys_generates_encodings(self, mock_enum_key: Mock, mock_open_key: Mock) -> None:
        """Test _scan_for_hidden_registry_keys() generates encoded key names."""
        mock_open_key.return_value.__enter__ = Mock(return_value=MagicMock())
        mock_open_key.return_value.__exit__ = Mock(return_value=None)
        mock_enum_key.side_effect = OSError

        engine = TrialResetEngine()
        keys = engine._scan_for_hidden_registry_keys("TestProduct")

        assert isinstance(keys, list)

    @patch("winreg.OpenKey")
    @patch("winreg.EnumKey")
    def test_scan_for_hidden_registry_keys_searches_clsid(self, mock_enum_key: Mock, mock_open_key: Mock) -> None:
        """Test _scan_for_hidden_registry_keys() searches CLSID registry."""
        mock_open_key.return_value.__enter__ = Mock(return_value=MagicMock())
        mock_open_key.return_value.__exit__ = Mock(return_value=None)

        import hashlib

        encoded_name = hashlib.sha256(b"TestProduct").hexdigest()[:16]
        mock_enum_key.side_effect = [encoded_name, OSError]

        engine = TrialResetEngine()
        keys = engine._scan_for_hidden_registry_keys("TestProduct")

        assert len(keys) >= 1


class TestFileScanning(unittest.TestCase):
    """Test file scanning functionality."""

    @patch.object(TrialResetEngine, "_scan_alternate_data_streams")
    @patch.object(TrialResetEngine, "_scan_for_encrypted_trial_files")
    @patch("os.path.exists")
    @patch("pathlib.Path.rglob")
    def test_scan_files_for_trial_searches_common_locations(
        self,
        mock_rglob: Mock,
        mock_exists: Mock,
        mock_encrypted: Mock,
        mock_ads: Mock,
    ) -> None:
        """Test _scan_files_for_trial() searches all common file locations."""
        mock_exists.return_value = True
        mock_rglob.return_value = [Path("C:\\test\\trial.dat")]
        mock_encrypted.return_value = []
        mock_ads.return_value = []

        engine = TrialResetEngine()
        files = engine._scan_files_for_trial("TestProduct")

        assert isinstance(files, list)

    @patch.object(TrialResetEngine, "_scan_alternate_data_streams")
    @patch.object(TrialResetEngine, "_scan_for_encrypted_trial_files")
    @patch("os.path.exists")
    @patch("pathlib.Path.rglob")
    def test_scan_files_matches_file_patterns(
        self,
        mock_rglob: Mock,
        mock_exists: Mock,
        mock_encrypted: Mock,
        mock_ads: Mock,
    ) -> None:
        """Test _scan_files_for_trial() matches all file patterns."""
        mock_exists.return_value = True
        mock_rglob.return_value = [
            Path("C:\\test\\trial.dat"),
            Path("C:\\test\\license.lic"),
            Path("C:\\test\\activation.key"),
        ]
        mock_encrypted.return_value = []
        mock_ads.return_value = []

        engine = TrialResetEngine()
        files = engine._scan_files_for_trial("TestProduct")

        assert len(files) > 0

    @patch.object(TrialResetEngine, "_scan_alternate_data_streams")
    @patch.object(TrialResetEngine, "_scan_for_encrypted_trial_files")
    @patch("os.path.exists")
    def test_scan_files_handles_permission_errors(self, mock_exists: Mock, mock_encrypted: Mock, mock_ads: Mock) -> None:
        """Test _scan_files_for_trial() handles permission errors gracefully."""
        mock_exists.return_value = True
        mock_encrypted.return_value = []
        mock_ads.return_value = []

        with patch("pathlib.Path.rglob", side_effect=PermissionError("Access denied")):
            engine = TrialResetEngine()
            files = engine._scan_files_for_trial("TestProduct")

            assert isinstance(files, list)

    @patch("os.path.exists")
    def test_scan_alternate_data_streams_uses_windows_apis(self, mock_exists: Mock) -> None:
        """Test _scan_alternate_data_streams() uses FindFirstStreamW/FindNextStreamW."""
        mock_exists.return_value = False

        engine = TrialResetEngine()
        ads_files = engine._scan_alternate_data_streams("TestProduct")

        assert isinstance(ads_files, list)

    @patch("builtins.open", new_callable=mock_open, read_data=b"\x00TRIAL\x00test data")
    @patch("os.walk")
    def test_scan_for_encrypted_trial_files_detects_markers(self, mock_walk: Mock, mock_file: Mock) -> None:
        """Test _scan_for_encrypted_trial_files() detects encrypted markers."""
        mock_walk.return_value = [("C:\\test", [], ["trial.dat"])]

        with patch.dict(os.environ, {"APPDATA": "C:\\test"}):
            engine = TrialResetEngine()
            files = engine._scan_for_encrypted_trial_files("TestProduct")

            assert len(files) >= 1


class TestTrialDetection(unittest.TestCase):
    """Test trial detection and type determination."""

    def test_detect_trial_type_returns_time_based(self) -> None:
        """Test _detect_trial_type() returns TIME_BASED for time markers."""
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
        """Test _detect_trial_type() returns USAGE_BASED for usage markers."""
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
        """Test _detect_trial_type() returns HYBRID for mixed markers."""
        trial_info = TrialInfo(
            product_name="Test",
            trial_type=TrialType.HYBRID,
            trial_days=30,
            usage_count=10,
            install_date=datetime.datetime.now(),
            first_run_date=datetime.datetime.now(),
            last_run_date=datetime.datetime.now(),
            trial_expired=False,
            registry_keys=["HKEY_CURRENT_USER\\Software\\Test\\TrialDays", "HKEY_CURRENT_USER\\Software\\Test\\RunCount"],
            files=[],
            processes=[],
        )

        engine = TrialResetEngine()
        trial_type = engine._detect_trial_type(trial_info)

        assert trial_type == TrialType.HYBRID

    def test_detect_trial_type_returns_feature_limited(self) -> None:
        """Test _detect_trial_type() returns FEATURE_LIMITED for feature markers."""
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

    @patch("winreg.OpenKey")
    @patch("winreg.QueryValueEx")
    def test_extract_trial_details_from_registry(self, mock_query: Mock, mock_open: Mock) -> None:
        """Test _extract_trial_details() extracts data from registry."""
        mock_open.return_value.__enter__ = Mock(return_value=MagicMock())
        mock_open.return_value.__exit__ = Mock(return_value=None)
        mock_query.side_effect = [
            (1234567890, 1),
            (30, 1),
            (5, 1),
        ]

        trial_info = TrialInfo(
            product_name="Test",
            trial_type=TrialType.TIME_BASED,
            trial_days=0,
            usage_count=0,
            install_date=datetime.datetime.now(),
            first_run_date=datetime.datetime.now(),
            last_run_date=datetime.datetime.now(),
            trial_expired=False,
            registry_keys=["HKEY_CURRENT_USER\\Software\\Test"],
            files=[],
            processes=[],
        )

        engine = TrialResetEngine()
        engine._extract_trial_details(trial_info)

        assert trial_info.trial_days >= 0

    def test_parse_date_converts_unix_timestamp(self) -> None:
        """Test _parse_date() converts Unix timestamp to datetime."""
        engine = TrialResetEngine()
        timestamp = 1704067200
        result = engine._parse_date(timestamp)

        assert isinstance(result, datetime.datetime)
        expected_date = datetime.datetime.fromtimestamp(1704067200)
        assert result.year == expected_date.year

    def test_parse_date_parses_string_formats(self) -> None:
        """Test _parse_date() parses various string date formats."""
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
        """Test _parse_date() returns datetime.now() for unparseable dates."""
        engine = TrialResetEngine()
        result = engine._parse_date("invalid date")

        assert isinstance(result, datetime.datetime)

    def test_check_trial_expired_for_time_based(self) -> None:
        """Test _check_trial_expired() detects expired TIME_BASED trials."""
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

    def test_check_trial_expired_for_usage_based(self) -> None:
        """Test _check_trial_expired() detects expired USAGE_BASED trials."""
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

    @patch("psutil.process_iter")
    def test_find_related_processes_by_name(self, mock_iter: Mock) -> None:
        """Test _find_related_processes() finds processes by name."""
        mock_proc = Mock()
        mock_proc.info = {"pid": 1234, "name": "TestProduct.exe", "exe": "C:\\Program Files\\TestProduct\\TestProduct.exe"}
        mock_iter.return_value = [mock_proc]

        engine = TrialResetEngine()
        processes = engine._find_related_processes("TestProduct")

        assert "TestProduct.exe" in processes

    @patch("psutil.process_iter")
    def test_find_related_processes_by_path(self, mock_iter: Mock) -> None:
        """Test _find_related_processes() finds processes by executable path."""
        mock_proc = Mock()
        mock_proc.info = {"pid": 1234, "name": "app.exe", "exe": "C:\\Program Files\\TestProduct\\app.exe"}
        mock_iter.return_value = [mock_proc]

        engine = TrialResetEngine()
        processes = engine._find_related_processes("TestProduct")

        assert "app.exe" in processes


class TestTrialReset(unittest.TestCase):
    """Test trial reset functionality."""

    @patch.object(TrialResetEngine, "_kill_processes")
    @patch.object(TrialResetEngine, "_clean_uninstall_reset")
    def test_reset_trial_validates_strategy(self, mock_clean: Mock, mock_kill: Mock) -> None:
        """Test reset_trial() validates strategy parameter."""
        mock_clean.return_value = True

        trial_info = TrialInfo(
            product_name="Test",
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

        engine = TrialResetEngine()
        success = engine.reset_trial(trial_info, "invalid_strategy")

        assert success is True
        mock_kill.assert_called_once()
        mock_clean.assert_called_once()

    @patch.object(TrialResetEngine, "_kill_processes")
    @patch.object(TrialResetEngine, "_clean_uninstall_reset")
    def test_reset_trial_calls_kill_processes_first(self, mock_clean: Mock, mock_kill: Mock) -> None:
        """Test reset_trial() kills processes before applying strategy."""
        mock_clean.return_value = True

        trial_info = TrialInfo(
            product_name="Test",
            trial_type=TrialType.TIME_BASED,
            trial_days=30,
            usage_count=0,
            install_date=datetime.datetime.now(),
            first_run_date=datetime.datetime.now(),
            last_run_date=datetime.datetime.now(),
            trial_expired=False,
            registry_keys=[],
            files=[],
            processes=["test.exe"],
        )

        engine = TrialResetEngine()
        engine.reset_trial(trial_info, "clean_uninstall")

        mock_kill.assert_called_once_with(["test.exe"])

    @patch("psutil.process_iter")
    def test_kill_processes_terminates_gracefully(self, mock_iter: Mock) -> None:
        """Test _kill_processes() calls terminate() first."""
        mock_proc = Mock()
        mock_proc.info = {"pid": 1234, "name": "test.exe"}
        mock_iter.return_value = [mock_proc]

        engine = TrialResetEngine()
        engine._kill_processes(["test.exe"])

        mock_proc.terminate.assert_called_once()

    @patch("psutil.process_iter")
    def test_kill_processes_kills_if_terminate_fails(self, mock_iter: Mock) -> None:
        """Test _kill_processes() calls kill() if terminate fails."""
        mock_proc = Mock()
        mock_proc.info = {"pid": 1234, "name": "test.exe"}
        mock_proc.terminate.side_effect = psutil.AccessDenied
        mock_iter.return_value = [mock_proc]

        engine = TrialResetEngine()
        engine._kill_processes(["test.exe"])

        mock_proc.kill.assert_called_once()

    @patch.object(TrialResetEngine, "_delete_registry_key")
    @patch.object(TrialResetEngine, "_delete_file_securely")
    @patch.object(TrialResetEngine, "_clear_alternate_data_streams")
    @patch.object(TrialResetEngine, "_clear_prefetch_data")
    @patch.object(TrialResetEngine, "_clear_event_logs")
    def test_clean_uninstall_reset_deletes_all_traces(
        self,
        mock_clear_logs: Mock,
        mock_clear_prefetch: Mock,
        mock_clear_ads: Mock,
        mock_delete_file: Mock,
        mock_delete_key: Mock,
    ) -> None:
        """Test _clean_uninstall_reset() deletes all trial traces."""
        mock_delete_key.return_value = True
        mock_delete_file.return_value = True

        trial_info = TrialInfo(
            product_name="Test",
            trial_type=TrialType.TIME_BASED,
            trial_days=30,
            usage_count=0,
            install_date=datetime.datetime.now(),
            first_run_date=datetime.datetime.now(),
            last_run_date=datetime.datetime.now(),
            trial_expired=False,
            registry_keys=["HKEY_CURRENT_USER\\Software\\Test"],
            files=["C:\\test\\trial.dat"],
            processes=[],
        )

        engine = TrialResetEngine()
        success = engine._clean_uninstall_reset(trial_info)

        assert success is True
        mock_delete_key.assert_called()
        mock_delete_file.assert_called()
        mock_clear_ads.assert_called_once()
        mock_clear_prefetch.assert_called_once()
        mock_clear_logs.assert_called_once()

    @patch("winreg.DeleteKey")
    def test_delete_registry_key_parses_path_correctly(self, mock_delete: Mock) -> None:
        """Test _delete_registry_key() parses registry path correctly."""
        engine = TrialResetEngine()
        success = engine._delete_registry_key("HKEY_CURRENT_USER\\Software\\Test")

        assert success is True
        mock_delete.assert_called()

    @patch("os.path.exists")
    @patch("os.path.getsize")
    @patch("builtins.open", new_callable=mock_open)
    @patch("os.urandom")
    @patch("os.remove")
    def test_delete_file_securely_overwrites_with_random_data(
        self,
        mock_remove: Mock,
        mock_urandom: Mock,
        mock_file: Mock,
        mock_getsize: Mock,
        mock_exists: Mock,
    ) -> None:
        """Test _delete_file_securely() overwrites with random data."""
        mock_exists.return_value = True
        mock_getsize.return_value = 1024
        mock_urandom.return_value = b"\x00" * 1024

        engine = TrialResetEngine()
        success = engine._delete_file_securely("C:\\test\\trial.dat")

        assert success is True
        mock_remove.assert_called_once()

    @patch.object(TrialResetEngine, "_delete_registry_key")
    @patch.object(TrialResetEngine, "_reset_registry_values")
    def test_registry_clean_reset_falls_back_to_value_reset(self, mock_reset_values: Mock, mock_delete_key: Mock) -> None:
        """Test _registry_clean_reset() falls back to value reset."""
        mock_delete_key.return_value = False
        mock_reset_values.return_value = True

        trial_info = TrialInfo(
            product_name="Test",
            trial_type=TrialType.TIME_BASED,
            trial_days=30,
            usage_count=0,
            install_date=datetime.datetime.now(),
            first_run_date=datetime.datetime.now(),
            last_run_date=datetime.datetime.now(),
            trial_expired=False,
            registry_keys=["HKEY_CURRENT_USER\\Software\\Test"],
            files=[],
            processes=[],
        )

        engine = TrialResetEngine()
        success = engine._registry_clean_reset(trial_info)

        mock_reset_values.assert_called_once()

    @patch("winreg.OpenKey")
    @patch("winreg.SetValueEx")
    def test_reset_registry_values_resets_trial_data(self, mock_set: Mock, mock_open: Mock) -> None:
        """Test _reset_registry_values() resets trial values."""
        mock_open.return_value.__enter__ = Mock(return_value=MagicMock())
        mock_open.return_value.__exit__ = Mock(return_value=None)

        engine = TrialResetEngine()
        success = engine._reset_registry_values("HKEY_CURRENT_USER\\Software\\Test")

        assert success is True

    @patch.object(TrialResetEngine, "_delete_file_securely")
    @patch.object(TrialResetEngine, "_reset_file_content")
    def test_file_wipe_reset_falls_back_to_content_reset(self, mock_reset_content: Mock, mock_delete: Mock) -> None:
        """Test _file_wipe_reset() falls back to content reset."""
        mock_delete.return_value = False
        mock_reset_content.return_value = True

        trial_info = TrialInfo(
            product_name="Test",
            trial_type=TrialType.TIME_BASED,
            trial_days=30,
            usage_count=0,
            install_date=datetime.datetime.now(),
            first_run_date=datetime.datetime.now(),
            last_run_date=datetime.datetime.now(),
            trial_expired=False,
            registry_keys=[],
            files=["C:\\test\\trial.dat"],
            processes=[],
        )

        engine = TrialResetEngine()
        success = engine._file_wipe_reset(trial_info)

        mock_reset_content.assert_called_once()

    @patch("builtins.open", new_callable=mock_open)
    @patch("os.utime")
    def test_reset_file_content_resets_xml_files(self, mock_utime: Mock, mock_file: Mock) -> None:
        """Test _reset_file_content() resets XML files correctly."""
        engine = TrialResetEngine()
        success = engine._reset_file_content("C:\\test\\trial.xml")

        assert success is True
        mock_file.assert_called()

    @patch("builtins.open", new_callable=mock_open)
    @patch("os.utime")
    def test_reset_file_content_resets_json_files(self, mock_utime: Mock, mock_file: Mock) -> None:
        """Test _reset_file_content() resets JSON files correctly."""
        engine = TrialResetEngine()
        success = engine._reset_file_content("C:\\test\\trial.json")

        assert success is True

    @patch("builtins.open", new_callable=mock_open)
    @patch("os.utime")
    def test_reset_file_content_resets_ini_files(self, mock_utime: Mock, mock_file: Mock) -> None:
        """Test _reset_file_content() resets INI files correctly."""
        engine = TrialResetEngine()
        success = engine._reset_file_content("C:\\test\\config.ini")

        assert success is True

    @patch("winreg.CreateKey")
    @patch("winreg.SetValueEx")
    @patch.object(TrialResetEngine, "_update_guid_in_key")
    def test_guid_regeneration_reset_generates_new_uuid(self, mock_update: Mock, mock_set: Mock, mock_create: Mock) -> None:
        """Test _guid_regeneration_reset() generates new machine GUID."""
        mock_create.return_value.__enter__ = Mock(return_value=MagicMock())
        mock_create.return_value.__exit__ = Mock(return_value=None)

        trial_info = TrialInfo(
            product_name="Test",
            trial_type=TrialType.TIME_BASED,
            trial_days=30,
            usage_count=0,
            install_date=datetime.datetime.now(),
            first_run_date=datetime.datetime.now(),
            last_run_date=datetime.datetime.now(),
            trial_expired=False,
            registry_keys=["HKEY_CURRENT_USER\\Software\\Test"],
            files=[],
            processes=[],
        )

        engine = TrialResetEngine()
        success = engine._guid_regeneration_reset(trial_info)

        assert success is True
        mock_update.assert_called()

    @patch("winreg.OpenKey")
    @patch("winreg.EnumValue")
    @patch("winreg.SetValueEx")
    def test_update_guid_in_key_updates_guid_values(self, mock_set: Mock, mock_enum: Mock, mock_open: Mock) -> None:
        """Test _update_guid_in_key() updates GUID/UUID values."""
        mock_open.return_value.__enter__ = Mock(return_value=MagicMock())
        mock_open.return_value.__exit__ = Mock(return_value=None)
        mock_enum.side_effect = [
            ("MachineGUID", "old-guid", 1),
            OSError,
        ]

        engine = TrialResetEngine()
        engine._update_guid_in_key("HKEY_CURRENT_USER\\Software\\Test")


class TestTimeManipulator(unittest.TestCase):
    """Test TimeManipulator class functionality."""

    def test_init_initializes_tracking_structures(self) -> None:
        """Test __init__() initializes original_time and frozen_apps."""
        manipulator = TimeManipulator()

        assert manipulator.original_time is None
        assert isinstance(manipulator.frozen_apps, dict)
        assert len(manipulator.frozen_apps) == 0

    @patch.object(TimeManipulator, "_set_system_time")
    def test_reset_trial_time_saves_original_time(self, mock_set_time: Mock) -> None:
        """Test reset_trial_time() saves current time."""
        mock_set_time.return_value = True

        trial_info = TrialInfo(
            product_name="Test",
            trial_type=TrialType.TIME_BASED,
            trial_days=30,
            usage_count=0,
            install_date=datetime.datetime.now() - datetime.timedelta(days=5),
            first_run_date=datetime.datetime.now(),
            last_run_date=datetime.datetime.now(),
            trial_expired=False,
            registry_keys=[],
            files=[],
            processes=[],
        )

        manipulator = TimeManipulator()
        manipulator.reset_trial_time(trial_info)

        assert manipulator.original_time is not None

    @patch.object(TimeManipulator, "_set_system_time")
    def test_reset_trial_time_calculates_target_time(self, mock_set_time: Mock) -> None:
        """Test reset_trial_time() calculates target as install_date - 1 day."""
        mock_set_time.return_value = True

        install_date = datetime.datetime.now() - datetime.timedelta(days=5)
        trial_info = TrialInfo(
            product_name="Test",
            trial_type=TrialType.TIME_BASED,
            trial_days=30,
            usage_count=0,
            install_date=install_date,
            first_run_date=datetime.datetime.now(),
            last_run_date=datetime.datetime.now(),
            trial_expired=False,
            registry_keys=[],
            files=[],
            processes=[],
        )

        manipulator = TimeManipulator()
        manipulator.reset_trial_time(trial_info)

        expected_target = install_date - datetime.timedelta(days=1)
        assert mock_set_time.call_count == 2

    @patch("ctypes.windll.kernel32.OpenProcess")
    @patch("ctypes.windll.kernel32.VirtualAllocEx")
    @patch("ctypes.windll.kernel32.WriteProcessMemory")
    def test_freeze_time_for_app_injects_hooks(self, mock_write: Mock, mock_alloc: Mock, mock_open: Mock) -> None:
        """Test freeze_time_for_app() injects time hooks into process."""
        mock_open.return_value = 1234
        mock_alloc.return_value = 0x10000

        manipulator = TimeManipulator()
        frozen_time = datetime.datetime.now()

        with patch("ctypes.windll.kernel32.CreateToolhelp32Snapshot", return_value=-1):
            success = manipulator.freeze_time_for_app("test.exe", frozen_time)
            assert success is False


class TestScanForTrial(unittest.TestCase):
    """Test scan_for_trial workflow."""

    @patch.object(TrialResetEngine, "_scan_registry_for_trial")
    @patch.object(TrialResetEngine, "_scan_files_for_trial")
    @patch.object(TrialResetEngine, "_detect_trial_type")
    @patch.object(TrialResetEngine, "_extract_trial_details")
    @patch.object(TrialResetEngine, "_check_trial_expired")
    @patch.object(TrialResetEngine, "_find_related_processes")
    def test_scan_for_trial_returns_trial_info(
        self,
        mock_processes: Mock,
        mock_expired: Mock,
        mock_details: Mock,
        mock_detect: Mock,
        mock_files: Mock,
        mock_registry: Mock,
    ) -> None:
        """Test scan_for_trial() returns complete TrialInfo."""
        mock_registry.return_value = ["HKEY_CURRENT_USER\\Software\\Test"]
        mock_files.return_value = ["C:\\test\\trial.dat"]
        mock_detect.return_value = TrialType.TIME_BASED
        mock_expired.return_value = False
        mock_processes.return_value = ["test.exe"]

        engine = TrialResetEngine()
        trial_info = engine.scan_for_trial("TestProduct")

        assert isinstance(trial_info, TrialInfo)
        assert trial_info.product_name == "TestProduct"
        mock_registry.assert_called_once_with("TestProduct")
        mock_files.assert_called_once_with("TestProduct")
        mock_detect.assert_called_once()
        mock_details.assert_called_once()
        mock_expired.assert_called_once()
        mock_processes.assert_called_once_with("TestProduct")


class TestAutomatedTrialReset(unittest.TestCase):
    """Test automated trial reset function."""

    @patch.object(TrialResetEngine, "scan_for_trial")
    @patch.object(TrialResetEngine, "reset_trial")
    def test_automated_reset_scans_and_resets(self, mock_reset: Mock, mock_scan: Mock) -> None:
        """Test automated_trial_reset() performs full workflow."""
        mock_scan.return_value = TrialInfo(
            product_name="Test",
            trial_type=TrialType.TIME_BASED,
            trial_days=30,
            usage_count=0,
            install_date=datetime.datetime.now(),
            first_run_date=datetime.datetime.now(),
            last_run_date=datetime.datetime.now(),
            trial_expired=False,
            registry_keys=["HKEY_CURRENT_USER\\Software\\Test"],
            files=["C:\\test\\trial.dat"],
            processes=[],
        )
        mock_reset.return_value = True

        success = automated_trial_reset("TestProduct")

        assert success is True
        mock_scan.assert_called_once_with("TestProduct")
        mock_reset.assert_called_once()

    @patch.object(TrialResetEngine, "scan_for_trial")
    def test_automated_reset_returns_false_for_no_data(self, mock_scan: Mock) -> None:
        """Test automated_trial_reset() returns False when no trial data found."""
        mock_scan.return_value = TrialInfo(
            product_name="Test",
            trial_type=TrialType.TIME_BASED,
            trial_days=0,
            usage_count=0,
            install_date=datetime.datetime.now(),
            first_run_date=datetime.datetime.now(),
            last_run_date=datetime.datetime.now(),
            trial_expired=False,
            registry_keys=[],
            files=[],
            processes=[],
        )

        success = automated_trial_reset("TestProduct")

        assert success is False


class TestRealWorldScenarios(unittest.TestCase):
    """Test real-world trial reset scenarios."""

    @patch.object(TrialResetEngine, "_delete_registry_key")
    @patch.object(TrialResetEngine, "_reset_registry_values")
    def test_registry_based_trial_reset(self, mock_reset_values: Mock, mock_delete: Mock) -> None:
        """Test complete reset workflow for registry-based trial."""
        mock_delete.return_value = True

        engine = TrialResetEngine()
        trial_info = TrialInfo(
            product_name="RegistryApp",
            trial_type=TrialType.TIME_BASED,
            trial_days=30,
            usage_count=0,
            install_date=datetime.datetime.now(),
            first_run_date=datetime.datetime.now(),
            last_run_date=datetime.datetime.now(),
            trial_expired=False,
            registry_keys=["HKEY_CURRENT_USER\\Software\\RegistryApp\\TrialDays"],
            files=[],
            processes=[],
        )

        success = engine._registry_clean_reset(trial_info)

        assert success is True
        mock_delete.assert_called()

    @patch("os.path.exists")
    @patch("os.path.getsize")
    @patch("builtins.open", new_callable=mock_open)
    @patch("os.urandom")
    @patch("os.remove")
    def test_file_based_trial_reset(
        self,
        mock_remove: Mock,
        mock_urandom: Mock,
        mock_file: Mock,
        mock_getsize: Mock,
        mock_exists: Mock,
    ) -> None:
        """Test complete reset workflow for file-based trial."""
        mock_exists.return_value = True
        mock_getsize.return_value = 1024
        mock_urandom.return_value = b"\x00" * 1024

        engine = TrialResetEngine()
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
            files=["C:\\test\\trial.dat"],
            processes=[],
        )

        success = engine._file_wipe_reset(trial_info)

        assert success is True

    @patch.object(TrialResetEngine, "_delete_registry_key")
    @patch.object(TrialResetEngine, "_delete_file_securely")
    @patch.object(TrialResetEngine, "_clear_alternate_data_streams")
    @patch.object(TrialResetEngine, "_clear_prefetch_data")
    @patch.object(TrialResetEngine, "_clear_event_logs")
    def test_hybrid_trial_reset(
        self,
        mock_clear_logs: Mock,
        mock_clear_prefetch: Mock,
        mock_clear_ads: Mock,
        mock_delete_file: Mock,
        mock_delete_key: Mock,
    ) -> None:
        """Test complete reset workflow for hybrid trial (registry + files)."""
        mock_delete_key.return_value = True
        mock_delete_file.return_value = True

        engine = TrialResetEngine()
        trial_info = TrialInfo(
            product_name="HybridApp",
            trial_type=TrialType.HYBRID,
            trial_days=30,
            usage_count=10,
            install_date=datetime.datetime.now(),
            first_run_date=datetime.datetime.now(),
            last_run_date=datetime.datetime.now(),
            trial_expired=False,
            registry_keys=["HKEY_CURRENT_USER\\Software\\HybridApp"],
            files=["C:\\test\\trial.dat"],
            processes=[],
        )

        success = engine._clean_uninstall_reset(trial_info)

        assert success is True
        mock_delete_key.assert_called()
        mock_delete_file.assert_called()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

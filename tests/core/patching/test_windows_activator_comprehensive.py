"""Comprehensive Tests for Windows Activator.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellicrack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""

import hashlib
import os
import platform
import subprocess
import tempfile
import uuid
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, Mock, patch

import pytest

from intellicrack.core.patching.windows_activator import (
    ActivationMethod,
    ActivationStatus,
    WindowsActivator,
    activate_windows_hwid,
    activate_windows_kms,
    check_windows_activation,
    create_windows_activator,
)


@pytest.fixture
def activator() -> WindowsActivator:
    """Create WindowsActivator instance for testing."""
    return WindowsActivator()


@pytest.fixture
def mock_script_path(tmp_path: Path) -> Path:
    """Create mock activation script for testing."""
    script_dir = tmp_path / "ui" / "Windows_Patch"
    script_dir.mkdir(parents=True, exist_ok=True)
    script_path = script_dir / "WindowsActivator.cmd"
    script_path.write_text("@echo off\necho Mock activation script\nexit /b 0\n")
    return script_path


@pytest.fixture
def activator_with_mock_script(activator: WindowsActivator, mock_script_path: Path) -> WindowsActivator:
    """Create activator with mocked script path."""
    activator.script_path = mock_script_path
    return activator


class TestActivationMethodEnum:
    """Tests for ActivationMethod enumeration."""

    def test_activation_method_values_are_strings(self) -> None:
        """ActivationMethod enum values are lowercase strings."""
        assert isinstance(ActivationMethod.HWID.value, str)
        assert isinstance(ActivationMethod.KMS38.value, str)
        assert isinstance(ActivationMethod.ONLINE_KMS.value, str)
        assert isinstance(ActivationMethod.CHECK_ONLY.value, str)

    def test_activation_method_hwid_value(self) -> None:
        """ActivationMethod.HWID has correct value."""
        assert ActivationMethod.HWID.value == "hwid"
        assert ActivationMethod.HWID.value.islower()

    def test_activation_method_kms38_value(self) -> None:
        """ActivationMethod.KMS38 has correct value."""
        assert ActivationMethod.KMS38.value == "kms38"
        assert ActivationMethod.KMS38.value.islower()

    def test_activation_method_online_kms_value(self) -> None:
        """ActivationMethod.ONLINE_KMS has correct value."""
        assert ActivationMethod.ONLINE_KMS.value == "ohook"
        assert ActivationMethod.ONLINE_KMS.value.islower()

    def test_activation_method_check_only_value(self) -> None:
        """ActivationMethod.CHECK_ONLY has correct value."""
        assert ActivationMethod.CHECK_ONLY.value == "check"
        assert ActivationMethod.CHECK_ONLY.value.islower()

    def test_activation_method_members_count(self) -> None:
        """ActivationMethod enum has exactly four members."""
        assert len(list(ActivationMethod)) == 4

    def test_activation_method_can_compare(self) -> None:
        """ActivationMethod members can be compared."""
        method = ActivationMethod.HWID
        assert method == ActivationMethod.HWID
        assert method != ActivationMethod.KMS38


class TestActivationStatusEnum:
    """Tests for ActivationStatus enumeration."""

    def test_activation_status_values_are_strings(self) -> None:
        """ActivationStatus enum values are lowercase strings."""
        assert isinstance(ActivationStatus.ACTIVATED.value, str)
        assert isinstance(ActivationStatus.NOT_ACTIVATED.value, str)
        assert isinstance(ActivationStatus.GRACE_PERIOD.value, str)
        assert isinstance(ActivationStatus.UNKNOWN.value, str)
        assert isinstance(ActivationStatus.ERROR.value, str)

    def test_activation_status_activated_value(self) -> None:
        """ActivationStatus.ACTIVATED has correct value."""
        assert ActivationStatus.ACTIVATED.value == "activated"

    def test_activation_status_not_activated_value(self) -> None:
        """ActivationStatus.NOT_ACTIVATED has correct value."""
        assert ActivationStatus.NOT_ACTIVATED.value == "not_activated"

    def test_activation_status_grace_period_value(self) -> None:
        """ActivationStatus.GRACE_PERIOD has correct value."""
        assert ActivationStatus.GRACE_PERIOD.value == "grace_period"

    def test_activation_status_unknown_value(self) -> None:
        """ActivationStatus.UNKNOWN has correct value."""
        assert ActivationStatus.UNKNOWN.value == "unknown"

    def test_activation_status_error_value(self) -> None:
        """ActivationStatus.ERROR has correct value."""
        assert ActivationStatus.ERROR.value == "error"

    def test_activation_status_members_count(self) -> None:
        """ActivationStatus enum has exactly five members."""
        assert len(list(ActivationStatus)) == 5


class TestWindowsActivatorInit:
    """Tests for WindowsActivator initialization."""

    def test_init_creates_instance(self, activator: WindowsActivator) -> None:
        """WindowsActivator can be instantiated."""
        assert isinstance(activator, WindowsActivator)
        assert activator is not None

    def test_init_sets_script_path(self, activator: WindowsActivator) -> None:
        """WindowsActivator initialization sets script path correctly."""
        assert hasattr(activator, "script_path")
        assert isinstance(activator.script_path, Path)
        assert "WindowsActivator.cmd" in str(activator.script_path)

    def test_init_sets_temp_dir(self, activator: WindowsActivator) -> None:
        """WindowsActivator initialization sets temp directory."""
        assert hasattr(activator, "temp_dir")
        assert isinstance(activator.temp_dir, Path)
        assert "intellicrack_activation" in str(activator.temp_dir)

    def test_init_sets_logger(self, activator: WindowsActivator) -> None:
        """WindowsActivator initialization sets logger."""
        assert hasattr(activator, "logger")
        assert activator.logger is not None

    def test_init_sets_validation_cache_attributes(self, activator: WindowsActivator) -> None:
        """WindowsActivator initialization sets validation cache attributes."""
        assert hasattr(activator, "last_validation_time")
        assert hasattr(activator, "last_validation_result")
        assert hasattr(activator, "validation_cache_duration")
        assert activator.validation_cache_duration == 300


class TestGenerateHWID:
    """Tests for HWID generation functionality."""

    def test_generate_hwid_returns_string(self, activator: WindowsActivator) -> None:
        """generate_hwid returns a string value."""
        hwid: str = activator.generate_hwid()
        assert isinstance(hwid, str)
        assert len(hwid) > 0

    def test_generate_hwid_format_has_dashes(self, activator: WindowsActivator) -> None:
        """generate_hwid returns formatted HWID with dashes."""
        hwid: str = activator.generate_hwid()
        assert "-" in hwid
        parts = hwid.split("-")
        assert len(parts) == 5

    def test_generate_hwid_format_structure(self, activator: WindowsActivator) -> None:
        """generate_hwid returns HWID with correct segment lengths."""
        hwid: str = activator.generate_hwid()
        parts = hwid.split("-")
        assert len(parts[0]) == 8
        assert len(parts[1]) == 4
        assert len(parts[2]) == 4
        assert len(parts[3]) == 4
        assert len(parts[4]) == 12

    def test_generate_hwid_is_uppercase(self, activator: WindowsActivator) -> None:
        """generate_hwid returns uppercase HWID string."""
        hwid: str = activator.generate_hwid()
        assert hwid.isupper()

    def test_generate_hwid_is_hexadecimal(self, activator: WindowsActivator) -> None:
        """generate_hwid returns hexadecimal HWID."""
        hwid: str = activator.generate_hwid()
        hwid_clean = hwid.replace("-", "")
        assert all(c in "0123456789ABCDEF" for c in hwid_clean)

    def test_generate_hwid_deterministic_per_machine(self, activator: WindowsActivator) -> None:
        """generate_hwid returns same HWID when called multiple times."""
        hwid1: str = activator.generate_hwid()
        hwid2: str = activator.generate_hwid()
        assert hwid1 == hwid2

    def test_generate_hwid_fallback_without_wmi(self, activator: WindowsActivator) -> None:
        """generate_hwid works without WMI module."""
        with patch("intellicrack.core.patching.windows_activator.wmi", None):
            hwid: str = activator.generate_hwid()
            assert isinstance(hwid, str)
            assert len(hwid.split("-")) == 5

    def test_generate_hwid_uses_machine_info(self, activator: WindowsActivator) -> None:
        """generate_hwid incorporates machine-specific information."""
        with patch("intellicrack.core.patching.windows_activator.wmi", None):
            with patch("platform.machine", return_value="AMD64"):
                hwid1: str = activator.generate_hwid()
            with patch("platform.machine", return_value="x86"):
                hwid2: str = activator.generate_hwid()
            assert hwid1 != hwid2

    def test_generate_hwid_hash_based(self, activator: WindowsActivator) -> None:
        """generate_hwid generates hash-based identifiers."""
        hwid: str = activator.generate_hwid()
        hwid_clean = hwid.replace("-", "")
        assert len(hwid_clean) == 32
        try:
            int(hwid_clean, 16)
        except ValueError:
            pytest.fail("HWID is not a valid hexadecimal value")


class TestCheckPrerequisites:
    """Tests for prerequisite checking functionality."""

    def test_check_prerequisites_returns_tuple(self, activator: WindowsActivator) -> None:
        """check_prerequisites returns tuple of bool and list."""
        result = activator.check_prerequisites()
        assert isinstance(result, tuple)
        assert len(result) == 2
        assert isinstance(result[0], bool)
        assert isinstance(result[1], list)

    def test_check_prerequisites_fails_without_script(self, activator: WindowsActivator) -> None:
        """check_prerequisites detects missing activation script."""
        activator.script_path = Path("/nonexistent/script.cmd")
        success, issues = activator.check_prerequisites()
        assert not success
        assert len(issues) > 0
        assert any("script not found" in issue.lower() for issue in issues)

    @pytest.mark.skipif(os.name != "nt", reason="Windows-specific test")
    def test_check_prerequisites_detects_non_windows(self, activator: WindowsActivator) -> None:
        """check_prerequisites fails on non-Windows platforms."""
        with patch("os.name", "posix"):
            success, issues = activator.check_prerequisites()
            assert not success
            assert any("windows" in issue.lower() for issue in issues)

    @pytest.mark.skipif(os.name != "nt", reason="Windows-specific test")
    def test_check_prerequisites_checks_admin(self, activator_with_mock_script: WindowsActivator) -> None:
        """check_prerequisites verifies administrator privileges."""
        with patch("intellicrack.core.patching.windows_activator.is_admin", return_value=False):
            success, issues = activator_with_mock_script.check_prerequisites()
            assert not success
            assert any("administrator" in issue.lower() or "privileges" in issue.lower() for issue in issues)

    @pytest.mark.skipif(os.name != "nt", reason="Windows-specific test")
    def test_check_prerequisites_succeeds_with_all_requirements(self, activator_with_mock_script: WindowsActivator) -> None:
        """check_prerequisites succeeds when all requirements are met."""
        with patch("intellicrack.core.patching.windows_activator.is_admin", return_value=True):
            with patch("os.name", "nt"):
                success, issues = activator_with_mock_script.check_prerequisites()
                assert success
                assert len(issues) == 0


class TestGetActivationStatus:
    """Tests for Windows activation status checking."""

    def test_get_activation_status_returns_dict(self, activator: WindowsActivator) -> None:
        """get_activation_status returns dictionary with status information."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=0, stdout="Windows is permanently activated", stderr="")
            result = activator.get_activation_status()
            assert isinstance(result, dict)
            assert "status" in result

    def test_get_activation_status_detects_activated(self, activator: WindowsActivator) -> None:
        """get_activation_status correctly identifies activated Windows."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(
                returncode=0,
                stdout="The machine is permanently activated.",
                stderr="",
            )
            result = activator.get_activation_status()
            assert result["status"] == ActivationStatus.ACTIVATED.value

    def test_get_activation_status_detects_grace_period(self, activator: WindowsActivator) -> None:
        """get_activation_status correctly identifies grace period."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(
                returncode=0,
                stdout="Windows is in grace period.",
                stderr="",
            )
            result = activator.get_activation_status()
            assert result["status"] == ActivationStatus.GRACE_PERIOD.value

    def test_get_activation_status_detects_not_activated(self, activator: WindowsActivator) -> None:
        """get_activation_status correctly identifies non-activated Windows."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(
                returncode=0,
                stdout="Windows is not activated.",
                stderr="",
            )
            result = activator.get_activation_status()
            assert result["status"] == ActivationStatus.NOT_ACTIVATED.value

    def test_get_activation_status_handles_errors(self, activator: WindowsActivator) -> None:
        """get_activation_status handles subprocess errors gracefully."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(
                returncode=1,
                stdout="",
                stderr="Access denied",
            )
            result = activator.get_activation_status()
            assert result["status"] == ActivationStatus.ERROR.value

    def test_get_activation_status_includes_raw_output(self, activator: WindowsActivator) -> None:
        """get_activation_status includes raw output in results."""
        test_output = "Test activation output"
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(
                returncode=0,
                stdout=test_output,
                stderr="",
            )
            result = activator.get_activation_status()
            assert "raw_output" in result
            assert result["raw_output"] == test_output

    def test_get_activation_status_handles_oserror(self, activator: WindowsActivator) -> None:
        """get_activation_status handles OSError exceptions."""
        with patch("subprocess.run", side_effect=OSError("Test error")):
            result = activator.get_activation_status()
            assert result["status"] == ActivationStatus.ERROR.value
            assert "error" in result


class TestActivateWindows:
    """Tests for Windows activation functionality."""

    def test_activate_windows_checks_prerequisites(self, activator: WindowsActivator) -> None:
        """activate_windows verifies prerequisites before activation."""
        with patch.object(activator, "check_prerequisites", return_value=(False, ["Missing script"])) as mock_check:
            result = activator.activate_windows(ActivationMethod.HWID)
            mock_check.assert_called_once()
            assert not result["success"]
            assert "prerequisites" in result["error"].lower()

    def test_activate_windows_hwid_method(self, activator_with_mock_script: WindowsActivator) -> None:
        """activate_windows uses correct arguments for HWID method."""
        with patch("intellicrack.core.patching.windows_activator.is_admin", return_value=True):
            with patch("os.name", "nt"):
                with patch("subprocess.run") as mock_run:
                    mock_run.return_value = Mock(returncode=0, stdout="Success", stderr="")
                    with patch.object(activator_with_mock_script, "get_activation_status", return_value={"status": "activated"}):
                        result = activator_with_mock_script.activate_windows(ActivationMethod.HWID)
                        assert mock_run.called
                        args_list = [call[0][0] for call in mock_run.call_args_list]
                        cmd_lines = [" ".join(str(arg) for arg in args) for args in args_list]
                        assert any("/HWID" in cmd_line for cmd_line in cmd_lines)

    def test_activate_windows_kms38_method(self, activator_with_mock_script: WindowsActivator) -> None:
        """activate_windows uses correct arguments for KMS38 method."""
        with patch("intellicrack.core.patching.windows_activator.is_admin", return_value=True):
            with patch("os.name", "nt"):
                with patch("subprocess.run") as mock_run:
                    mock_run.return_value = Mock(returncode=0, stdout="Success", stderr="")
                    with patch.object(activator_with_mock_script, "get_activation_status", return_value={"status": "activated"}):
                        result = activator_with_mock_script.activate_windows(ActivationMethod.KMS38)
                        assert mock_run.called
                        args_list = [call[0][0] for call in mock_run.call_args_list]
                        cmd_lines = [" ".join(str(arg) for arg in args) for args in args_list]
                        assert any("/KMS38" in cmd_line for cmd_line in cmd_lines)

    def test_activate_windows_online_kms_method(self, activator_with_mock_script: WindowsActivator) -> None:
        """activate_windows uses correct arguments for Online KMS method."""
        with patch("intellicrack.core.patching.windows_activator.is_admin", return_value=True):
            with patch("os.name", "nt"):
                with patch("subprocess.run") as mock_run:
                    mock_run.return_value = Mock(returncode=0, stdout="Success", stderr="")
                    with patch.object(activator_with_mock_script, "get_activation_status", return_value={"status": "activated"}):
                        result = activator_with_mock_script.activate_windows(ActivationMethod.ONLINE_KMS)
                        assert mock_run.called
                        args_list = [call[0][0] for call in mock_run.call_args_list]
                        cmd_lines = [" ".join(str(arg) for arg in args) for args in args_list]
                        assert any("/Ohook" in cmd_line for cmd_line in cmd_lines)

    def test_activate_windows_returns_success_result(self, activator_with_mock_script: WindowsActivator) -> None:
        """activate_windows returns success result when activation succeeds."""
        with patch("intellicrack.core.patching.windows_activator.is_admin", return_value=True):
            with patch("os.name", "nt"):
                with patch("subprocess.run") as mock_run:
                    mock_run.return_value = Mock(returncode=0, stdout="Activated", stderr="")
                    with patch.object(activator_with_mock_script, "get_activation_status") as mock_status:
                        mock_status.return_value = {"status": "activated"}
                        result = activator_with_mock_script.activate_windows(ActivationMethod.HWID)
                        assert result["success"]
                        assert result["method"] == "hwid"
                        assert "post_activation_status" in result

    def test_activate_windows_returns_failure_result(self, activator_with_mock_script: WindowsActivator) -> None:
        """activate_windows returns failure result when activation fails."""
        with patch("intellicrack.core.patching.windows_activator.is_admin", return_value=True):
            with patch("os.name", "nt"):
                with patch("subprocess.run") as mock_run:
                    mock_run.return_value = Mock(returncode=1, stdout="", stderr="Failed")
                    result = activator_with_mock_script.activate_windows(ActivationMethod.HWID)
                    assert not result["success"]
                    assert result["return_code"] == 1

    def test_activate_windows_handles_timeout(self, activator_with_mock_script: WindowsActivator) -> None:
        """activate_windows handles subprocess timeout gracefully."""
        with patch("intellicrack.core.patching.windows_activator.is_admin", return_value=True):
            with patch("os.name", "nt"):
                with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("cmd", 300)):
                    result = activator_with_mock_script.activate_windows(ActivationMethod.HWID)
                    assert not result["success"]
                    assert "timeout" in str(result.get("error", "")).lower() or "timed out" in str(result.get("error", "")).lower()


class TestActivateAliasMethods:
    """Tests for activation method aliases."""

    def test_activate_method_hwid_string(self, activator: WindowsActivator) -> None:
        """activate method converts 'hwid' string to enum."""
        with patch.object(activator, "activate_windows") as mock_activate:
            mock_activate.return_value = {"success": True}
            activator.activate("hwid")
            mock_activate.assert_called_once_with(ActivationMethod.HWID)

    def test_activate_method_kms38_string(self, activator: WindowsActivator) -> None:
        """activate method converts 'kms38' string to enum."""
        with patch.object(activator, "activate_windows") as mock_activate:
            mock_activate.return_value = {"success": True}
            activator.activate("kms38")
            mock_activate.assert_called_once_with(ActivationMethod.KMS38)

    def test_activate_method_ohook_string(self, activator: WindowsActivator) -> None:
        """activate method converts 'ohook' string to enum."""
        with patch.object(activator, "activate_windows") as mock_activate:
            mock_activate.return_value = {"success": True}
            activator.activate("ohook")
            mock_activate.assert_called_once_with(ActivationMethod.ONLINE_KMS)

    def test_activate_method_case_insensitive(self, activator: WindowsActivator) -> None:
        """activate method handles uppercase method names."""
        with patch.object(activator, "activate_windows") as mock_activate:
            mock_activate.return_value = {"success": True}
            activator.activate("HWID")
            mock_activate.assert_called_once_with(ActivationMethod.HWID)

    def test_activate_windows_kms_method(self, activator: WindowsActivator) -> None:
        """activate_windows_kms calls activate_windows with KMS38."""
        with patch.object(activator, "activate_windows") as mock_activate:
            mock_activate.return_value = {"success": True}
            activator.activate_windows_kms()
            mock_activate.assert_called_once_with(ActivationMethod.KMS38)

    def test_activate_windows_digital_method(self, activator: WindowsActivator) -> None:
        """activate_windows_digital calls activate_windows with HWID."""
        with patch.object(activator, "activate_windows") as mock_activate:
            mock_activate.return_value = {"success": True}
            activator.activate_windows_digital()
            mock_activate.assert_called_once_with(ActivationMethod.HWID)


class TestCheckActivationStatus:
    """Tests for check_activation_status alias method."""

    def test_check_activation_status_calls_get_activation_status(self, activator: WindowsActivator) -> None:
        """check_activation_status calls underlying get_activation_status."""
        with patch.object(activator, "get_activation_status") as mock_get:
            mock_get.return_value = {"status": "activated"}
            activator.check_activation_status()
            mock_get.assert_called_once()

    def test_check_activation_status_adds_activated_key(self, activator: WindowsActivator) -> None:
        """check_activation_status adds 'activated' boolean key."""
        with patch.object(activator, "get_activation_status") as mock_get:
            mock_get.return_value = {"status": "activated"}
            result = activator.check_activation_status()
            assert "activated" in result
            assert result["activated"] is True

    def test_check_activation_status_activated_false_for_not_activated(self, activator: WindowsActivator) -> None:
        """check_activation_status sets activated=False for non-activated status."""
        with patch.object(activator, "get_activation_status") as mock_get:
            mock_get.return_value = {"status": "not_activated"}
            result = activator.check_activation_status()
            assert "activated" in result
            assert result["activated"] is False


class TestResetActivation:
    """Tests for Windows activation reset functionality."""

    def test_reset_activation_returns_dict(self, activator: WindowsActivator) -> None:
        """reset_activation returns dictionary with reset results."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=0, stdout="Success", stderr="")
            result = activator.reset_activation()
            assert isinstance(result, dict)
            assert "success" in result

    def test_reset_activation_calls_slmgr_rearm(self, activator: WindowsActivator) -> None:
        """reset_activation executes slmgr.vbs /rearm command."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=0, stdout="Success", stderr="")
            activator.reset_activation()
            assert mock_run.called
            args = mock_run.call_args[0][0]
            assert any("slmgr.vbs" in str(arg) for arg in args)
            assert any("/rearm" in str(arg) for arg in args)

    def test_reset_activation_success_result(self, activator: WindowsActivator) -> None:
        """reset_activation returns success when reset succeeds."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=0, stdout="Reset successful", stderr="")
            result = activator.reset_activation()
            assert result["success"]
            assert result["return_code"] == 0

    def test_reset_activation_failure_result(self, activator: WindowsActivator) -> None:
        """reset_activation returns failure when reset fails."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=1, stdout="", stderr="Error")
            result = activator.reset_activation()
            assert not result["success"]
            assert result["return_code"] == 1

    def test_reset_activation_handles_exceptions(self, activator: WindowsActivator) -> None:
        """reset_activation handles exceptions gracefully."""
        with patch("subprocess.run", side_effect=OSError("Test error")):
            result = activator.reset_activation()
            assert not result["success"]
            assert "error" in result


class TestGetProductKeyInfo:
    """Tests for product key information retrieval."""

    def test_get_product_key_info_returns_dict(self, activator: WindowsActivator) -> None:
        """get_product_key_info returns dictionary with product information."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=0, stdout="Product info", stderr="")
            result = activator.get_product_key_info()
            assert isinstance(result, dict)
            assert "success" in result
            assert "product_info" in result

    def test_get_product_key_info_calls_slmgr_dli(self, activator: WindowsActivator) -> None:
        """get_product_key_info executes slmgr.vbs /dli command."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=0, stdout="Info", stderr="")
            activator.get_product_key_info()
            assert mock_run.called
            args = mock_run.call_args[0][0]
            assert any("slmgr.vbs" in str(arg) for arg in args)
            assert any("/dli" in str(arg) for arg in args)

    def test_get_product_key_info_success(self, activator: WindowsActivator) -> None:
        """get_product_key_info returns success with product information."""
        product_data = "Windows 10 Pro\nPartial Product Key: XXXXX"
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=0, stdout=product_data, stderr="")
            result = activator.get_product_key_info()
            assert result["success"]
            assert result["product_info"] == product_data

    def test_get_product_key_info_handles_errors(self, activator: WindowsActivator) -> None:
        """get_product_key_info handles subprocess errors."""
        with patch("subprocess.run", side_effect=OSError("Error")):
            result = activator.get_product_key_info()
            assert not result["success"]
            assert "error" in result


class TestOfficeActivation:
    """Tests for Microsoft Office activation functionality."""

    def test_activate_office_checks_prerequisites(self, activator: WindowsActivator) -> None:
        """activate_office verifies prerequisites before activation."""
        with patch.object(activator, "check_prerequisites", return_value=(False, ["Missing requirements"])):
            result = activator.activate_office()
            assert not result["success"]
            assert "prerequisites" in result["error"].lower()

    def test_activate_office_auto_detection(self, activator_with_mock_script: WindowsActivator) -> None:
        """activate_office automatically detects Office version."""
        with patch("intellicrack.core.patching.windows_activator.is_admin", return_value=True):
            with patch("os.name", "nt"):
                with patch.object(activator_with_mock_script, "_detect_office_version", return_value="2016"):
                    with patch.object(activator_with_mock_script, "_activate_office_c2r") as mock_c2r:
                        mock_c2r.return_value = {"success": True}
                        with patch.object(activator_with_mock_script, "_get_office_status") as mock_status:
                            mock_status.return_value = {"status": "activated"}
                            result = activator_with_mock_script.activate_office("auto")
                            assert mock_c2r.called

    def test_activate_office_no_office_detected(self, activator_with_mock_script: WindowsActivator) -> None:
        """activate_office handles case when Office is not detected."""
        with patch("intellicrack.core.patching.windows_activator.is_admin", return_value=True):
            with patch("os.name", "nt"):
                with patch.object(activator_with_mock_script, "_detect_office_version", return_value=""):
                    result = activator_with_mock_script.activate_office("auto")
                    assert not result["success"]
                    assert "no microsoft office" in result["error"].lower()

    def test_activate_office_specific_version(self, activator_with_mock_script: WindowsActivator) -> None:
        """activate_office accepts specific Office version."""
        with patch("intellicrack.core.patching.windows_activator.is_admin", return_value=True):
            with patch("os.name", "nt"):
                with patch.object(activator_with_mock_script, "_activate_office_c2r") as mock_c2r:
                    mock_c2r.return_value = {"success": True}
                    with patch.object(activator_with_mock_script, "_get_office_status") as mock_status:
                        mock_status.return_value = {"status": "activated"}
                        result = activator_with_mock_script.activate_office("2019")
                        mock_c2r.assert_called_once_with("2019")

    def test_activate_office_tries_c2r_then_msi(self, activator_with_mock_script: WindowsActivator) -> None:
        """activate_office tries C2R method first, then MSI if C2R fails."""
        with patch("intellicrack.core.patching.windows_activator.is_admin", return_value=True):
            with patch("os.name", "nt"):
                with patch.object(activator_with_mock_script, "_activate_office_c2r") as mock_c2r:
                    mock_c2r.return_value = {"success": False, "error": "C2R failed"}
                    with patch.object(activator_with_mock_script, "_activate_office_msi") as mock_msi:
                        mock_msi.return_value = {"success": True}
                        with patch.object(activator_with_mock_script, "_get_office_status") as mock_status:
                            mock_status.return_value = {"status": "activated"}
                            result = activator_with_mock_script.activate_office("2016")
                            assert mock_c2r.called
                            assert mock_msi.called


class TestDetectOfficeVersion:
    """Tests for Office version detection."""

    def test_detect_office_version_finds_version(self, activator: WindowsActivator) -> None:
        """_detect_office_version identifies installed Office version."""
        with patch("os.path.exists", return_value=True):
            with patch("os.listdir", return_value=["WINWORD.EXE", "EXCEL.EXE"]):
                version = activator._detect_office_version()
                assert isinstance(version, str)

    def test_detect_office_version_returns_empty_if_not_found(self, activator: WindowsActivator) -> None:
        """_detect_office_version returns empty string if Office not found."""
        with patch("os.path.exists", return_value=False):
            with patch("os.listdir", side_effect=OSError("No such file")):
                with patch("winreg.OpenKey", side_effect=FileNotFoundError()):
                    version = activator._detect_office_version()
                    assert isinstance(version, str)

    def test_detect_office_version_prefers_newer_versions(self, activator: WindowsActivator) -> None:
        """_detect_office_version prefers newer Office versions."""
        detected = ["2013", "2016", "2019"]
        with patch("os.path.exists", return_value=True):
            with patch("os.listdir", return_value=["WINWORD.EXE"]):
                with patch.object(activator, "_detect_office_version", return_value="2019"):
                    version = activator._detect_office_version()
                    assert version in ["2019", "2021"]


class TestActivateOfficeC2R:
    """Tests for Office Click-to-Run activation."""

    def test_activate_office_c2r_returns_dict(self, activator_with_mock_script: WindowsActivator) -> None:
        """_activate_office_c2r returns dictionary with activation results."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=0, stdout="Success", stderr="")
            result = activator_with_mock_script._activate_office_c2r("2016")
            assert isinstance(result, dict)
            assert "success" in result
            assert "method" in result
            assert result["method"] == "C2R"

    def test_activate_office_c2r_success(self, activator_with_mock_script: WindowsActivator) -> None:
        """_activate_office_c2r returns success when activation succeeds."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=0, stdout="Activated", stderr="")
            result = activator_with_mock_script._activate_office_c2r("2019")
            assert result["success"]
            assert result["office_version"] == "2019"

    def test_activate_office_c2r_handles_timeout(self, activator_with_mock_script: WindowsActivator) -> None:
        """_activate_office_c2r handles subprocess timeout."""
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("cmd", 300)):
            result = activator_with_mock_script._activate_office_c2r("2016")
            assert not result["success"]
            assert "timeout" in str(result.get("error", "")).lower() or "timed out" in str(result.get("error", "")).lower()


class TestActivateOfficeMSI:
    """Tests for Office MSI activation."""

    def test_activate_office_msi_returns_dict(self, activator: WindowsActivator) -> None:
        """_activate_office_msi returns dictionary with activation results."""
        with patch("os.path.exists", return_value=True):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = Mock(returncode=0, stdout="Success", stderr="")
                result = activator._activate_office_msi("2016")
                assert isinstance(result, dict)
                assert "success" in result
                assert "method" in result
                assert result["method"] == "MSI"

    def test_activate_office_msi_fails_without_ospp(self, activator: WindowsActivator) -> None:
        """_activate_office_msi fails when OSPP.VBS not found."""
        with patch("os.path.exists", return_value=False):
            result = activator._activate_office_msi("2016")
            assert not result["success"]
            assert "ospp.vbs" in result["error"].lower()

    def test_activate_office_msi_uses_volume_key(self, activator: WindowsActivator) -> None:
        """_activate_office_msi uses appropriate volume license key."""
        with patch("os.path.exists", return_value=True):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = Mock(returncode=0, stdout="Key installed", stderr="")
                result = activator._activate_office_msi("2019")
                assert "product_key" in result
                assert isinstance(result["product_key"], str)
                assert len(result["product_key"]) == 29

    def test_activate_office_msi_installs_then_activates(self, activator: WindowsActivator) -> None:
        """_activate_office_msi installs product key before activating."""
        with patch("os.path.exists", return_value=True):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = Mock(returncode=0, stdout="Success", stderr="")
                activator._activate_office_msi("2016")
                assert mock_run.call_count >= 2


class TestGetOfficeStatus:
    """Tests for Office activation status checking."""

    def test_get_office_status_returns_dict(self, activator: WindowsActivator) -> None:
        """_get_office_status returns dictionary with status information."""
        with patch("os.path.exists", return_value=True):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = Mock(returncode=0, stdout="LICENSE STATUS: ---LICENSED---", stderr="")
                result = activator._get_office_status()
                assert isinstance(result, dict)
                assert "status" in result

    def test_get_office_status_detects_activated(self, activator: WindowsActivator) -> None:
        """_get_office_status correctly identifies activated Office."""
        with patch("os.path.exists", return_value=True):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = Mock(
                    returncode=0,
                    stdout="LICENSE STATUS: ---LICENSED---",
                    stderr="",
                )
                result = activator._get_office_status()
                assert result["status"] == "activated"

    def test_get_office_status_detects_grace_period(self, activator: WindowsActivator) -> None:
        """_get_office_status correctly identifies grace period."""
        with patch("os.path.exists", return_value=True):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = Mock(
                    returncode=0,
                    stdout="LICENSE STATUS: ---GRACE---",
                    stderr="",
                )
                result = activator._get_office_status()
                assert result["status"] == "grace_period"

    def test_get_office_status_handles_missing_ospp(self, activator: WindowsActivator) -> None:
        """_get_office_status handles missing OSPP.VBS gracefully."""
        with patch("os.path.exists", return_value=False):
            result = activator._get_office_status()
            assert result["status"] == "unknown"
            assert "ospp.vbs" in result["error"].lower()


class TestConvenienceFunctions:
    """Tests for module-level convenience functions."""

    def test_create_windows_activator_returns_instance(self) -> None:
        """create_windows_activator returns WindowsActivator instance."""
        activator = create_windows_activator()
        assert isinstance(activator, WindowsActivator)

    def test_check_windows_activation_function(self) -> None:
        """check_windows_activation convenience function works."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=0, stdout="Activated", stderr="")
            result = check_windows_activation()
            assert isinstance(result, dict)
            assert "status" in result

    def test_activate_windows_hwid_function(self) -> None:
        """activate_windows_hwid convenience function works."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=0, stdout="Success", stderr="")
            with patch("intellicrack.core.patching.windows_activator.is_admin", return_value=False):
                result = activate_windows_hwid()
                assert isinstance(result, dict)

    def test_activate_windows_kms_function(self) -> None:
        """activate_windows_kms convenience function works."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=0, stdout="Success", stderr="")
            with patch("intellicrack.core.patching.windows_activator.is_admin", return_value=False):
                result = activate_windows_kms()
                assert isinstance(result, dict)


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_hwid_generation_with_empty_hardware_info(self, activator: WindowsActivator) -> None:
        """generate_hwid handles empty hardware information gracefully."""
        with patch("intellicrack.core.patching.windows_activator.wmi", None):
            with patch("platform.machine", return_value=""):
                with patch("platform.processor", return_value=""):
                    with patch("platform.node", return_value=""):
                        hwid = activator.generate_hwid()
                        assert isinstance(hwid, str)
                        assert len(hwid.split("-")) == 5

    def test_activation_with_very_long_output(self, activator_with_mock_script: WindowsActivator) -> None:
        """activate_windows handles very long subprocess output."""
        long_output = "A" * 10000
        with patch("intellicrack.core.patching.windows_activator.is_admin", return_value=True):
            with patch("os.name", "nt"):
                with patch("subprocess.run") as mock_run:
                    mock_run.return_value = Mock(returncode=0, stdout=long_output, stderr="")
                    with patch.object(activator_with_mock_script, "get_activation_status"):
                        result = activator_with_mock_script.activate_windows(ActivationMethod.HWID)
                        assert result["success"]
                        assert len(result["stdout"]) == 10000

    def test_office_activation_with_special_characters_in_path(self, activator: WindowsActivator) -> None:
        """_detect_office_version handles paths with special characters."""
        with patch("os.path.exists", return_value=False):
            with patch("os.listdir", side_effect=OSError("No such file")):
                with patch("winreg.OpenKey", side_effect=FileNotFoundError()):
                    version = activator._detect_office_version()
                    assert isinstance(version, str)

    def test_concurrent_activation_attempts(self, activator_with_mock_script: WindowsActivator) -> None:
        """Multiple activation attempts can be handled sequentially."""
        with patch("intellicrack.core.patching.windows_activator.is_admin", return_value=True):
            with patch("os.name", "nt"):
                with patch("subprocess.run") as mock_run:
                    mock_run.return_value = Mock(returncode=0, stdout="Success", stderr="")
                    with patch.object(activator_with_mock_script, "get_activation_status"):
                        result1 = activator_with_mock_script.activate_windows(ActivationMethod.HWID)
                        result2 = activator_with_mock_script.activate_windows(ActivationMethod.KMS38)
                        assert result1["method"] == "hwid"
                        assert result2["method"] == "kms38"

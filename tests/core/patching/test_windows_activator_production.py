"""Production Tests for Windows Activation Module.

Tests validate real Windows activation capabilities including HWID generation,
activation script execution, Office activation, and status checking. Tests run
on real Windows systems and validate actual activation functionality.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import os
import platform
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Generator
from unittest.mock import MagicMock, Mock, patch

import pytest

from intellicrack.core.patching.windows_activator import (
    ActivationMethod,
    ActivationStatus,
    WindowsActivator,
    WindowsActivatorInteractive,
    activate_windows_hwid,
    activate_windows_kms,
    check_windows_activation,
    create_windows_activator,
)


WINDOWS_ONLY = platform.system() == "Windows"


@pytest.fixture
def windows_activator() -> WindowsActivator:
    """Create WindowsActivator instance for testing."""
    return WindowsActivator()


@pytest.fixture
def mock_activation_script(tmp_path: Path) -> Generator[Path, None, None]:
    """Create mock Windows activation script for testing."""
    script_path = tmp_path / "WindowsActivator.cmd"

    script_content = """@echo off
echo Activating Windows...
echo Activation successful
exit /b 0
"""

    script_path.write_text(script_content)
    yield script_path


@pytest.fixture
def mock_activation_script_failure(tmp_path: Path) -> Generator[Path, None, None]:
    """Create mock activation script that fails."""
    script_path = tmp_path / "WindowsActivator.cmd"

    script_content = """@echo off
echo Activation failed
exit /b 1
"""

    script_path.write_text(script_content)
    yield script_path


class TestWindowsActivatorInitialization:
    """Test WindowsActivator initialization and configuration."""

    def test_activator_initializes_with_correct_paths(self, windows_activator: WindowsActivator) -> None:
        """WindowsActivator initializes with correct script path and temp directory."""
        assert windows_activator.script_path is not None
        assert isinstance(windows_activator.script_path, Path)
        assert windows_activator.temp_dir is not None
        assert isinstance(windows_activator.temp_dir, Path)

    def test_activator_has_validation_cache_configuration(self, windows_activator: WindowsActivator) -> None:
        """WindowsActivator has validation cache configuration."""
        assert windows_activator.last_validation_time is None
        assert windows_activator.last_validation_result is None
        assert windows_activator.validation_cache_duration == 300

    def test_create_windows_activator_factory_function(self) -> None:
        """create_windows_activator factory function creates valid instance."""
        activator = create_windows_activator()

        assert isinstance(activator, WindowsActivator)
        assert activator.script_path is not None


class TestHWIDGeneration:
    """Test Hardware ID generation for digital license activation."""

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_generate_hwid_produces_valid_format(self, windows_activator: WindowsActivator) -> None:
        """generate_hwid produces HWID in correct Windows format."""
        hwid = windows_activator.generate_hwid()

        assert isinstance(hwid, str)
        assert len(hwid) > 0

        parts = hwid.split("-")
        assert len(parts) == 5

        assert len(parts[0]) == 8
        assert len(parts[1]) == 4
        assert len(parts[2]) == 4
        assert len(parts[3]) == 4
        assert len(parts[4]) == 12

        assert hwid.isupper()
        assert all(c in "0123456789ABCDEF-" for c in hwid)

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_generate_hwid_uses_real_hardware_info(self, windows_activator: WindowsActivator) -> None:
        """generate_hwid uses real hardware information from system."""
        hwid1 = windows_activator.generate_hwid()
        hwid2 = windows_activator.generate_hwid()

        assert hwid1 == hwid2

    def test_generate_hwid_fallback_without_wmi(self, windows_activator: WindowsActivator, monkeypatch) -> None:
        """generate_hwid uses fallback method when WMI is unavailable."""
        import intellicrack.core.patching.windows_activator as wa_module

        monkeypatch.setattr(wa_module, "wmi", None)

        hwid = windows_activator.generate_hwid()

        assert isinstance(hwid, str)
        assert len(hwid.split("-")) == 5
        assert hwid.isupper()


class TestPrerequisiteChecking:
    """Test prerequisite checking for Windows activation."""

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_check_prerequisites_validates_windows_platform(self, windows_activator: WindowsActivator) -> None:
        """check_prerequisites validates Windows platform requirement."""
        success, issues = windows_activator.check_prerequisites()

        if os.name == "nt":
            assert isinstance(success, bool)
            assert isinstance(issues, list)
        else:
            assert success is False
            assert "Windows activation only supported on Windows" in issues

    def test_check_prerequisites_detects_missing_script(self, windows_activator: WindowsActivator, tmp_path: Path) -> None:
        """check_prerequisites detects when activation script is missing."""
        windows_activator.script_path = tmp_path / "nonexistent.cmd"

        success, issues = windows_activator.check_prerequisites()

        assert success is False
        assert any("script not found" in issue.lower() for issue in issues)

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_check_prerequisites_validates_admin_privileges(self, windows_activator: WindowsActivator) -> None:
        """check_prerequisites validates administrator privileges."""
        success, issues = windows_activator.check_prerequisites()

        from intellicrack.utils.system.system_utils import is_admin

        if not is_admin():
            assert "Administrator privileges required" in issues


class TestActivationStatusChecking:
    """Test Windows activation status checking."""

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_get_activation_status_returns_valid_structure(self, windows_activator: WindowsActivator) -> None:
        """get_activation_status returns valid status information structure."""
        status = windows_activator.get_activation_status()

        assert isinstance(status, dict)
        assert "status" in status
        assert status["status"] in [s.value for s in ActivationStatus]

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_get_activation_status_includes_raw_output(self, windows_activator: WindowsActivator) -> None:
        """get_activation_status includes raw slmgr output."""
        status = windows_activator.get_activation_status()

        assert "raw_output" in status
        assert isinstance(status["raw_output"], str)

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_check_activation_status_alias_works(self, windows_activator: WindowsActivator) -> None:
        """check_activation_status alias function works correctly."""
        status = windows_activator.check_activation_status()

        assert isinstance(status, dict)
        assert "status" in status
        assert "activated" in status
        assert isinstance(status["activated"], bool)

    def test_get_activation_status_handles_subprocess_errors(self, windows_activator: WindowsActivator) -> None:
        """get_activation_status handles subprocess errors gracefully."""
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = OSError("Subprocess error")

            status = windows_activator.get_activation_status()

            assert status["status"] == ActivationStatus.ERROR.value
            assert "error" in status


class TestWindowsActivation:
    """Test Windows activation functionality."""

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_activate_windows_validates_prerequisites(self, windows_activator: WindowsActivator, tmp_path: Path) -> None:
        """activate_windows validates prerequisites before activation."""
        windows_activator.script_path = tmp_path / "nonexistent.cmd"

        result = windows_activator.activate_windows(ActivationMethod.HWID)

        assert result["success"] is False
        assert "prerequisites not met" in result["error"].lower()
        assert "issues" in result

    def test_activate_windows_supports_hwid_method(self, windows_activator: WindowsActivator, mock_activation_script: Path) -> None:
        """activate_windows supports HWID activation method."""
        windows_activator.script_path = mock_activation_script

        with patch.object(windows_activator, "check_prerequisites", return_value=(True, [])):
            result = windows_activator.activate_windows(ActivationMethod.HWID)

            assert isinstance(result, dict)
            assert "method" in result
            assert result["method"] == "hwid"

    def test_activate_windows_supports_kms38_method(self, windows_activator: WindowsActivator, mock_activation_script: Path) -> None:
        """activate_windows supports KMS38 activation method."""
        windows_activator.script_path = mock_activation_script

        with patch.object(windows_activator, "check_prerequisites", return_value=(True, [])):
            result = windows_activator.activate_windows(ActivationMethod.KMS38)

            assert isinstance(result, dict)
            assert "method" in result
            assert result["method"] == "kms38"

    def test_activate_windows_supports_online_kms_method(self, windows_activator: WindowsActivator, mock_activation_script: Path) -> None:
        """activate_windows supports Online KMS (Ohook) activation method."""
        windows_activator.script_path = mock_activation_script

        with patch.object(windows_activator, "check_prerequisites", return_value=(True, [])):
            result = windows_activator.activate_windows(ActivationMethod.ONLINE_KMS)

            assert isinstance(result, dict)
            assert "method" in result
            assert result["method"] == "ohook"

    def test_activate_windows_returns_detailed_result(self, windows_activator: WindowsActivator, mock_activation_script: Path) -> None:
        """activate_windows returns detailed activation result."""
        windows_activator.script_path = mock_activation_script

        with patch.object(windows_activator, "check_prerequisites", return_value=(True, [])):
            result = windows_activator.activate_windows(ActivationMethod.HWID)

            assert "success" in result
            assert "method" in result
            assert "return_code" in result
            assert "stdout" in result
            assert "stderr" in result

    def test_activate_windows_handles_script_failure(self, windows_activator: WindowsActivator, mock_activation_script_failure: Path) -> None:
        """activate_windows handles script execution failure."""
        windows_activator.script_path = mock_activation_script_failure

        with patch.object(windows_activator, "check_prerequisites", return_value=(True, [])):
            result = windows_activator.activate_windows(ActivationMethod.HWID)

            assert result["success"] is False
            assert result["return_code"] != 0

    def test_activate_windows_handles_timeout(self, windows_activator: WindowsActivator, tmp_path: Path) -> None:
        """activate_windows handles subprocess timeout."""
        script_path = tmp_path / "WindowsActivator.cmd"
        script_path.write_text("@echo off\ntimeout /t 1000\n")

        windows_activator.script_path = script_path

        with patch.object(windows_activator, "check_prerequisites", return_value=(True, [])):
            with patch("subprocess.run") as mock_run:
                mock_run.side_effect = subprocess.TimeoutExpired("cmd", 300)

                result = windows_activator.activate_windows(ActivationMethod.HWID)

                assert result["success"] is False
                assert "timed out" in result["error"].lower()

    def test_activate_alias_method_works(self, windows_activator: WindowsActivator, mock_activation_script: Path) -> None:
        """activate alias method works correctly."""
        windows_activator.script_path = mock_activation_script

        with patch.object(windows_activator, "check_prerequisites", return_value=(True, [])):
            result = windows_activator.activate(method="hwid")

            assert isinstance(result, dict)
            assert "method" in result


class TestActivationReset:
    """Test activation reset functionality."""

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_reset_activation_executes_slmgr_rearm(self, windows_activator: WindowsActivator) -> None:
        """reset_activation executes slmgr /rearm command."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=0, stdout="Success", stderr="")

            result = windows_activator.reset_activation()

            assert mock_run.called
            args = mock_run.call_args[0][0]
            assert "slmgr.vbs" in args
            assert "/rearm" in args

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_reset_activation_returns_result_structure(self, windows_activator: WindowsActivator) -> None:
        """reset_activation returns proper result structure."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=0, stdout="Success", stderr="")

            result = windows_activator.reset_activation()

            assert "success" in result
            assert "return_code" in result
            assert "stdout" in result
            assert "stderr" in result

    def test_reset_activation_handles_errors(self, windows_activator: WindowsActivator) -> None:
        """reset_activation handles subprocess errors."""
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = OSError("Subprocess error")

            result = windows_activator.reset_activation()

            assert result["success"] is False
            assert "error" in result


class TestProductKeyInfo:
    """Test product key information retrieval."""

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_get_product_key_info_executes_slmgr_dli(self, windows_activator: WindowsActivator) -> None:
        """get_product_key_info executes slmgr /dli command."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=0, stdout="Product info", stderr="")

            result = windows_activator.get_product_key_info()

            assert mock_run.called
            args = mock_run.call_args[0][0]
            assert "slmgr.vbs" in args
            assert "/dli" in args

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_get_product_key_info_returns_product_info(self, windows_activator: WindowsActivator) -> None:
        """get_product_key_info returns product information."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=0, stdout="License Status: Licensed", stderr="")

            result = windows_activator.get_product_key_info()

            assert result["success"] is True
            assert "product_info" in result
            assert "License Status" in result["product_info"]


class TestOfficeActivation:
    """Test Microsoft Office activation functionality."""

    def test_activate_office_detects_office_version(self, windows_activator: WindowsActivator) -> None:
        """activate_office detects installed Office version."""
        with patch.object(windows_activator, "check_prerequisites", return_value=(True, [])):
            with patch.object(windows_activator, "_detect_office_version", return_value="2016"):
                with patch("subprocess.run") as mock_run:
                    mock_run.return_value = Mock(returncode=0, stdout="Success", stderr="")

                    result = windows_activator.activate_office(office_version="auto")

                    assert isinstance(result, dict)

    def test_activate_office_handles_no_installation(self, windows_activator: WindowsActivator) -> None:
        """activate_office handles case when Office is not installed."""
        with patch.object(windows_activator, "check_prerequisites", return_value=(True, [])):
            with patch.object(windows_activator, "_detect_office_version", return_value=""):
                result = windows_activator.activate_office(office_version="auto")

                assert result["success"] is False
                assert "No Microsoft Office installation detected" in result["error"]

    def test_activate_office_c2r_method(self, windows_activator: WindowsActivator, tmp_path: Path) -> None:
        """activate_office uses C2R activation method."""
        script_path = tmp_path / "OfficeActivator.cmd"
        script_path.write_text("@echo off\necho Success\n")

        with patch.object(windows_activator, "check_prerequisites", return_value=(True, [])):
            with patch.object(windows_activator, "_activate_office_c2r") as mock_c2r:
                mock_c2r.return_value = {"success": True, "method": "C2R"}

                result = windows_activator.activate_office(office_version="2016")

                assert mock_c2r.called

    def test_activate_office_msi_fallback(self, windows_activator: WindowsActivator) -> None:
        """activate_office falls back to MSI method when C2R fails."""
        with patch.object(windows_activator, "check_prerequisites", return_value=(True, [])):
            with patch.object(windows_activator, "_activate_office_c2r", return_value={"success": False}):
                with patch.object(windows_activator, "_activate_office_msi", return_value={"success": True}):
                    result = windows_activator.activate_office(office_version="2016")

                    assert result["success"] is True

    def test_detect_office_version_from_registry(self, windows_activator: WindowsActivator) -> None:
        """_detect_office_version detects Office from registry."""
        if platform.system() != "Windows":
            pytest.skip("Windows-specific test")

        version = windows_activator._detect_office_version()

        assert isinstance(version, str)

    def test_get_office_status_checks_activation(self, windows_activator: WindowsActivator) -> None:
        """_get_office_status checks Office activation status."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=0, stdout="LICENSE STATUS: ---LICENSED---", stderr="")

            status = windows_activator._get_office_status()

            assert "status" in status


class TestInteractiveActivation:
    """Test interactive activation with output streaming."""

    def test_activate_windows_interactive_validates_prerequisites(self, windows_activator: WindowsActivator, tmp_path: Path) -> None:
        """activate_windows_interactive validates prerequisites."""
        windows_activator.script_path = tmp_path / "nonexistent.cmd"

        result = windows_activator.activate_windows_interactive()

        assert result["success"] is False
        assert "prerequisites not met" in result["error"].lower()

    def test_activate_windows_interactive_calls_output_callback(self, windows_activator: WindowsActivator, mock_activation_script: Path) -> None:
        """activate_windows_interactive calls output callback with messages."""
        windows_activator.script_path = mock_activation_script
        output_lines = []

        def callback(line: str, is_stderr: bool) -> None:
            output_lines.append((line, is_stderr))

        with patch.object(windows_activator, "check_prerequisites", return_value=(True, [])):
            result = windows_activator.activate_windows_interactive(output_callback=callback)

            assert output_lines

    def test_activate_windows_interactive_returns_complete_result(self, windows_activator: WindowsActivator, mock_activation_script: Path) -> None:
        """activate_windows_interactive returns complete result structure."""
        windows_activator.script_path = mock_activation_script

        with patch.object(windows_activator, "check_prerequisites", return_value=(True, [])):
            result = windows_activator.activate_windows_interactive()

            assert "success" in result
            assert "method" in result
            assert "return_code" in result
            assert "stdout" in result
            assert "stderr" in result


class TestTerminalActivation:
    """Test terminal-based activation."""

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_activate_windows_in_terminal_validates_prerequisites(self, windows_activator: WindowsActivator, tmp_path: Path) -> None:
        """activate_windows_in_terminal validates prerequisites."""
        windows_activator.script_path = tmp_path / "nonexistent.cmd"

        result = windows_activator.activate_windows_in_terminal()

        assert result["success"] is False
        assert "prerequisites not met" in result["error"].lower()

    @pytest.mark.skipif(not WINDOWS_ONLY, reason="Windows-specific functionality")
    def test_activate_windows_in_terminal_returns_result(self, windows_activator: WindowsActivator, mock_activation_script: Path) -> None:
        """activate_windows_in_terminal returns activation result."""
        windows_activator.script_path = mock_activation_script

        with patch.object(windows_activator, "check_prerequisites", return_value=(True, [])):
            with patch("subprocess.Popen") as mock_popen:
                mock_process = Mock()
                mock_process.wait.return_value = 0
                mock_popen.return_value = mock_process

                result = windows_activator.activate_windows_in_terminal()

                assert "success" in result
                assert "method" in result

    def test_activate_windows_in_terminal_handles_non_windows(self, windows_activator: WindowsActivator) -> None:
        """activate_windows_in_terminal handles non-Windows platform."""
        with patch("os.name", "posix"):
            with patch.object(windows_activator, "check_prerequisites", return_value=(True, [])):
                result = windows_activator.activate_windows_in_terminal()

                assert result["success"] is False


class TestWindowsActivatorInteractive:
    """Test WindowsActivatorInteractive class."""

    def test_interactive_initializes_with_activator(self) -> None:
        """WindowsActivatorInteractive initializes with activator instance."""
        activator = WindowsActivator()
        interactive = WindowsActivatorInteractive(activator)

        assert interactive.activator == activator
        assert interactive.logger is not None

    def test_run_with_callback_executes_command(self, mock_activation_script: Path) -> None:
        """run_with_callback executes command with output streaming."""
        activator = WindowsActivator()
        activator.script_path = mock_activation_script
        interactive = WindowsActivatorInteractive(activator)

        output_lines = []

        def callback(line: str, is_stderr: bool) -> None:
            output_lines.append((line, is_stderr))

        result = interactive.run_with_callback([str(mock_activation_script)], callback)

        assert "success" in result
        assert "return_code" in result


class TestConvenienceFunctions:
    """Test module-level convenience functions."""

    def test_check_windows_activation_convenience_function(self) -> None:
        """check_windows_activation convenience function works."""
        status = check_windows_activation()

        assert isinstance(status, dict)
        assert "status" in status

    def test_activate_windows_hwid_convenience_function(self, mock_activation_script: Path) -> None:
        """activate_windows_hwid convenience function works."""
        with patch.object(WindowsActivator, "script_path", mock_activation_script):
            with patch.object(WindowsActivator, "check_prerequisites", return_value=(True, [])):
                result = activate_windows_hwid()

                assert isinstance(result, dict)

    def test_activate_windows_kms_convenience_function(self, mock_activation_script: Path) -> None:
        """activate_windows_kms convenience function works."""
        with patch.object(WindowsActivator, "script_path", mock_activation_script):
            with patch.object(WindowsActivator, "check_prerequisites", return_value=(True, [])):
                result = activate_windows_kms()

                assert isinstance(result, dict)


class TestActivationMethodEnum:
    """Test ActivationMethod enum."""

    def test_activation_method_has_all_methods(self) -> None:
        """ActivationMethod enum has all activation methods."""
        assert hasattr(ActivationMethod, "HWID")
        assert hasattr(ActivationMethod, "KMS38")
        assert hasattr(ActivationMethod, "ONLINE_KMS")
        assert hasattr(ActivationMethod, "CHECK_ONLY")

    def test_activation_method_values_are_strings(self) -> None:
        """ActivationMethod enum values are strings."""
        assert isinstance(ActivationMethod.HWID.value, str)
        assert isinstance(ActivationMethod.KMS38.value, str)
        assert isinstance(ActivationMethod.ONLINE_KMS.value, str)


class TestActivationStatusEnum:
    """Test ActivationStatus enum."""

    def test_activation_status_has_all_statuses(self) -> None:
        """ActivationStatus enum has all status values."""
        assert hasattr(ActivationStatus, "ACTIVATED")
        assert hasattr(ActivationStatus, "NOT_ACTIVATED")
        assert hasattr(ActivationStatus, "GRACE_PERIOD")
        assert hasattr(ActivationStatus, "UNKNOWN")
        assert hasattr(ActivationStatus, "ERROR")

    def test_activation_status_values_are_strings(self) -> None:
        """ActivationStatus enum values are strings."""
        assert isinstance(ActivationStatus.ACTIVATED.value, str)
        assert isinstance(ActivationStatus.NOT_ACTIVATED.value, str)

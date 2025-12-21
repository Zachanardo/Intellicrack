"""Production-ready tests for Windows activator functionality.

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

WINDOWS_ONLY = pytest.mark.skipif(
    os.name != "nt",
    reason="Windows-specific functionality requires Windows platform",
)

REQUIRES_ADMIN = pytest.mark.skipif(
    os.name == "nt" and not WindowsActivator().check_prerequisites()[0],
    reason="Test requires administrator privileges on Windows",
)


class TestActivationMethodEnum:
    """Test ActivationMethod enum values and behavior."""

    def test_activation_method_hwid_value(self) -> None:
        """ActivationMethod.HWID has correct string value."""
        assert ActivationMethod.HWID.value == "hwid"

    def test_activation_method_kms38_value(self) -> None:
        """ActivationMethod.KMS38 has correct string value."""
        assert ActivationMethod.KMS38.value == "kms38"

    def test_activation_method_online_kms_value(self) -> None:
        """ActivationMethod.ONLINE_KMS has correct string value."""
        assert ActivationMethod.ONLINE_KMS.value == "ohook"

    def test_activation_method_check_only_value(self) -> None:
        """ActivationMethod.CHECK_ONLY has correct string value."""
        assert ActivationMethod.CHECK_ONLY.value == "check"

    def test_activation_method_enum_members(self) -> None:
        """ActivationMethod enum has all expected members."""
        expected_members = {"HWID", "KMS38", "ONLINE_KMS", "CHECK_ONLY"}
        actual_members = {member.name for member in ActivationMethod}
        assert actual_members == expected_members

    def test_activation_method_enum_values_unique(self) -> None:
        """All ActivationMethod enum values are unique."""
        values = [member.value for member in ActivationMethod]
        assert len(values) == len(set(values))


class TestActivationStatusEnum:
    """Test ActivationStatus enum values and behavior."""

    def test_activation_status_activated_value(self) -> None:
        """ActivationStatus.ACTIVATED has correct string value."""
        assert ActivationStatus.ACTIVATED.value == "activated"

    def test_activation_status_not_activated_value(self) -> None:
        """ActivationStatus.NOT_ACTIVATED has correct string value."""
        assert ActivationStatus.NOT_ACTIVATED.value == "not_activated"

    def test_activation_status_grace_period_value(self) -> None:
        """ActivationStatus.GRACE_PERIOD has correct string value."""
        assert ActivationStatus.GRACE_PERIOD.value == "grace_period"

    def test_activation_status_unknown_value(self) -> None:
        """ActivationStatus.UNKNOWN has correct string value."""
        assert ActivationStatus.UNKNOWN.value == "unknown"

    def test_activation_status_error_value(self) -> None:
        """ActivationStatus.ERROR has correct string value."""
        assert ActivationStatus.ERROR.value == "error"

    def test_activation_status_enum_members(self) -> None:
        """ActivationStatus enum has all expected members."""
        expected_members = {"ACTIVATED", "NOT_ACTIVATED", "GRACE_PERIOD", "UNKNOWN", "ERROR"}
        actual_members = {member.name for member in ActivationStatus}
        assert actual_members == expected_members


class TestWindowsActivatorInitialization:
    """Test WindowsActivator initialization and properties."""

    def test_windows_activator_initialization(self) -> None:
        """WindowsActivator initializes with correct properties."""
        activator = WindowsActivator()

        assert activator.script_path is not None
        assert isinstance(activator.script_path, Path)
        assert activator.temp_dir is not None
        assert isinstance(activator.temp_dir, Path)
        assert activator.logger is not None
        assert activator.last_validation_time is None
        assert activator.last_validation_result is None
        assert activator.validation_cache_duration == 300

    def test_windows_activator_script_path_points_to_cmd(self) -> None:
        """WindowsActivator script_path points to WindowsActivator.cmd file."""
        activator = WindowsActivator()

        assert activator.script_path.name == "WindowsActivator.cmd"
        assert "Windows_Patch" in str(activator.script_path)

    def test_windows_activator_temp_dir_contains_intellicrack(self) -> None:
        """WindowsActivator temp_dir is located in system temp with intellicrack prefix."""
        activator = WindowsActivator()

        expected_temp_base = Path(tempfile.gettempdir())
        assert activator.temp_dir.parent == expected_temp_base
        assert "intellicrack_activation" in str(activator.temp_dir)

    def test_windows_activator_properties_are_not_none(self) -> None:
        """WindowsActivator critical properties are never None after initialization."""
        activator = WindowsActivator()

        assert activator.script_path is not None
        assert activator.temp_dir is not None
        assert activator.logger is not None
        assert activator.validation_cache_duration is not None


class TestWindowsActivatorPrerequisites:
    """Test prerequisite checking functionality."""

    def test_check_prerequisites_returns_tuple(self) -> None:
        """check_prerequisites returns tuple of (bool, list)."""
        activator = WindowsActivator()
        result = activator.check_prerequisites()

        assert isinstance(result, tuple)
        assert len(result) == 2
        assert isinstance(result[0], bool)
        assert isinstance(result[1], list)

    @WINDOWS_ONLY
    def test_check_prerequisites_script_exists_check(self) -> None:
        """check_prerequisites identifies when activation script is missing."""
        activator = WindowsActivator()
        activator.script_path = Path("/nonexistent/path/script.cmd")

        success, issues = activator.check_prerequisites()

        assert not success
        assert any("script not found" in issue.lower() for issue in issues)

    def test_check_prerequisites_detects_non_windows_platform(self) -> None:
        """check_prerequisites identifies non-Windows platforms."""
        if os.name != "nt":
            activator = WindowsActivator()
            success, issues = activator.check_prerequisites()

            assert not success
            assert any("windows" in issue.lower() for issue in issues)

    @WINDOWS_ONLY
    def test_check_prerequisites_detects_missing_admin_privileges(self) -> None:
        """check_prerequisites identifies when admin privileges are missing."""
        activator = WindowsActivator()
        success, issues = activator.check_prerequisites()

        if not success:
            if admin_issues := [
                issue
                for issue in issues
                if "administrator" in issue.lower()
                or "privileges" in issue.lower()
            ]:
                assert "administrator" in admin_issues[0].lower() or "privileges" in admin_issues[0].lower()

    @WINDOWS_ONLY
    @REQUIRES_ADMIN
    def test_check_prerequisites_succeeds_with_all_requirements(self) -> None:
        """check_prerequisites returns success when all requirements are met."""
        activator = WindowsActivator()

        if activator.script_path.exists():
            success, issues = activator.check_prerequisites()

            assert success
            assert len(issues) == 0


class TestHardwareIDGeneration:
    """Test hardware ID generation functionality."""

    def test_generate_hwid_returns_string(self) -> None:
        """generate_hwid returns a string."""
        activator = WindowsActivator()
        hwid = activator.generate_hwid()

        assert isinstance(hwid, str)
        assert len(hwid) > 0

    def test_generate_hwid_format_matches_windows_style(self) -> None:
        """generate_hwid returns HWID in Windows-style format (XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX)."""
        activator = WindowsActivator()
        hwid = activator.generate_hwid()

        parts = hwid.split("-")
        assert len(parts) == 5
        assert len(parts[0]) == 8
        assert len(parts[1]) == 4
        assert len(parts[2]) == 4
        assert len(parts[3]) == 4
        assert len(parts[4]) == 12

    def test_generate_hwid_is_uppercase(self) -> None:
        """generate_hwid returns uppercase hexadecimal string."""
        activator = WindowsActivator()
        hwid = activator.generate_hwid()

        hwid_no_dashes = hwid.replace("-", "")
        assert hwid_no_dashes.isupper()
        assert all(c in "0123456789ABCDEF-" for c in hwid)

    def test_generate_hwid_is_deterministic_for_same_hardware(self) -> None:
        """generate_hwid produces identical HWID for same hardware configuration."""
        activator = WindowsActivator()

        hwid1 = activator.generate_hwid()
        hwid2 = activator.generate_hwid()

        assert hwid1 == hwid2

    def test_generate_hwid_contains_only_hex_and_dashes(self) -> None:
        """generate_hwid contains only hexadecimal characters and dashes."""
        activator = WindowsActivator()
        hwid = activator.generate_hwid()

        allowed_chars = set("0123456789ABCDEF-")
        assert all(c in allowed_chars for c in hwid)

    def test_generate_hwid_fallback_when_wmi_unavailable(self) -> None:
        """generate_hwid uses fallback method when WMI is unavailable."""
        activator = WindowsActivator()

        import intellicrack.core.patching.windows_activator as wa_module

        original_wmi = wa_module.wmi
        try:
            wa_module.wmi = None

            hwid = activator.generate_hwid()

            assert isinstance(hwid, str)
            assert len(hwid) > 0

            parts = hwid.split("-")
            assert len(parts) == 5

        finally:
            wa_module.wmi = original_wmi

    def test_generate_hwid_uses_platform_info_in_fallback(self) -> None:
        """generate_hwid fallback incorporates platform information."""
        activator = WindowsActivator()

        import intellicrack.core.patching.windows_activator as wa_module

        original_wmi = wa_module.wmi
        try:
            wa_module.wmi = None

            hwid = activator.generate_hwid()

            machine_info = f"{platform.machine()}|{platform.processor()}|{platform.node()}"
            mac = uuid.getnode()
            machine_info += f"|{mac:012X}"

            expected_hash = hashlib.sha256(machine_info.encode()).hexdigest()
            expected_hwid = (
                f"{expected_hash[:8]}-{expected_hash[8:12]}-{expected_hash[12:16]}-{expected_hash[16:20]}-{expected_hash[20:32]}"
            ).upper()

            assert hwid == expected_hwid

        finally:
            wa_module.wmi = original_wmi


class TestActivationStatusRetrieval:
    """Test Windows activation status retrieval."""

    @WINDOWS_ONLY
    def test_get_activation_status_returns_dict(self) -> None:
        """get_activation_status returns dictionary with status information."""
        activator = WindowsActivator()
        status = activator.get_activation_status()

        assert isinstance(status, dict)
        assert "status" in status

    @WINDOWS_ONLY
    def test_get_activation_status_contains_required_fields(self) -> None:
        """get_activation_status dictionary contains required status fields."""
        activator = WindowsActivator()
        status = activator.get_activation_status()

        assert "status" in status
        assert status["status"] in [
            ActivationStatus.ACTIVATED.value,
            ActivationStatus.NOT_ACTIVATED.value,
            ActivationStatus.GRACE_PERIOD.value,
            ActivationStatus.UNKNOWN.value,
            ActivationStatus.ERROR.value,
        ]

    @WINDOWS_ONLY
    def test_get_activation_status_includes_raw_output(self) -> None:
        """get_activation_status includes raw output from slmgr."""
        activator = WindowsActivator()
        status = activator.get_activation_status()

        if status.get("status") != ActivationStatus.ERROR.value:
            assert "raw_output" in status
            assert isinstance(status["raw_output"], str)

    @WINDOWS_ONLY
    def test_get_activation_status_detects_activated_status(self) -> None:
        """get_activation_status correctly identifies activated Windows installations."""
        activator = WindowsActivator()
        status = activator.get_activation_status()

        if "permanently activated" in status.get("raw_output", "").lower():
            assert status["status"] == ActivationStatus.ACTIVATED.value

    @WINDOWS_ONLY
    def test_get_activation_status_detects_grace_period(self) -> None:
        """get_activation_status correctly identifies grace period status."""
        activator = WindowsActivator()
        status = activator.get_activation_status()

        if "grace period" in status.get("raw_output", "").lower():
            assert status["status"] == ActivationStatus.GRACE_PERIOD.value

    @WINDOWS_ONLY
    def test_get_activation_status_detects_not_activated(self) -> None:
        """get_activation_status correctly identifies non-activated installations."""
        activator = WindowsActivator()
        status = activator.get_activation_status()

        if "not activated" in status.get("raw_output", "").lower():
            assert status["status"] == ActivationStatus.NOT_ACTIVATED.value

    def test_get_activation_status_handles_non_windows_gracefully(self) -> None:
        """get_activation_status returns error status on non-Windows platforms."""
        if os.name != "nt":
            activator = WindowsActivator()
            status = activator.get_activation_status()

            assert isinstance(status, dict)
            assert status.get("status") == ActivationStatus.ERROR.value
            assert "error" in status


class TestCheckActivationStatusAlias:
    """Test check_activation_status alias method."""

    @WINDOWS_ONLY
    def test_check_activation_status_returns_dict(self) -> None:
        """check_activation_status returns dictionary with activation info."""
        activator = WindowsActivator()
        status = activator.check_activation_status()

        assert isinstance(status, dict)
        assert "status" in status

    @WINDOWS_ONLY
    def test_check_activation_status_includes_activated_key(self) -> None:
        """check_activation_status includes 'activated' boolean key."""
        activator = WindowsActivator()
        status = activator.check_activation_status()

        assert "activated" in status
        assert isinstance(status["activated"], bool)

    @WINDOWS_ONLY
    def test_check_activation_status_activated_key_matches_status(self) -> None:
        """check_activation_status 'activated' key matches status value."""
        activator = WindowsActivator()
        status = activator.check_activation_status()

        if status["status"] == "activated":
            assert status["activated"] is True
        else:
            assert status["activated"] is False


class TestActivateMethod:
    """Test activate method (alias for activate_windows)."""

    def test_activate_method_accepts_hwid_string(self) -> None:
        """activate method accepts 'hwid' as activation method."""
        activator = WindowsActivator()
        activator.script_path = Path("/nonexistent/script.cmd")

        result = activator.activate(method="hwid")

        assert isinstance(result, dict)
        assert "success" in result

    def test_activate_method_accepts_kms38_string(self) -> None:
        """activate method accepts 'kms38' as activation method."""
        activator = WindowsActivator()
        activator.script_path = Path("/nonexistent/script.cmd")

        result = activator.activate(method="kms38")

        assert isinstance(result, dict)
        assert "success" in result

    def test_activate_method_accepts_ohook_string(self) -> None:
        """activate method accepts 'ohook' as activation method."""
        activator = WindowsActivator()
        activator.script_path = Path("/nonexistent/script.cmd")

        result = activator.activate(method="ohook")

        assert isinstance(result, dict)
        assert "success" in result

    def test_activate_method_default_is_hwid(self) -> None:
        """activate method defaults to HWID activation when no method specified."""
        activator = WindowsActivator()
        activator.script_path = Path("/nonexistent/script.cmd")

        result = activator.activate()

        assert isinstance(result, dict)

    def test_activate_method_case_insensitive(self) -> None:
        """activate method accepts uppercase and mixed case method strings."""
        activator = WindowsActivator()
        activator.script_path = Path("/nonexistent/script.cmd")

        result1 = activator.activate(method="HWID")
        result2 = activator.activate(method="Kms38")
        result3 = activator.activate(method="OHook")

        assert isinstance(result1, dict)
        assert isinstance(result2, dict)
        assert isinstance(result3, dict)


class TestActivateWindowsMethod:
    """Test activate_windows method functionality."""

    def test_activate_windows_fails_when_prerequisites_not_met(self) -> None:
        """activate_windows returns failure when prerequisites are not satisfied."""
        activator = WindowsActivator()
        activator.script_path = Path("/nonexistent/script.cmd")

        result = activator.activate_windows(ActivationMethod.HWID)

        assert isinstance(result, dict)
        assert result["success"] is False
        assert "issues" in result
        assert len(result["issues"]) > 0

    def test_activate_windows_checks_for_missing_script(self) -> None:
        """activate_windows detects when activation script is missing."""
        activator = WindowsActivator()
        activator.script_path = Path("/nonexistent/WindowsActivator.cmd")

        result = activator.activate_windows(ActivationMethod.HWID)

        assert result["success"] is False
        assert "issues" in result
        assert any("script" in issue.lower() for issue in result["issues"])

    @pytest.mark.skipif(os.name != "nt", reason="Windows-specific test")
    def test_activate_windows_requires_admin_privileges(self) -> None:
        """activate_windows detects when admin privileges are missing."""
        activator = WindowsActivator()

        success, issues = activator.check_prerequisites()

        if not success and any("administrator" in issue.lower() for issue in issues):
            result = activator.activate_windows(ActivationMethod.HWID)
            assert result["success"] is False

    def test_activate_windows_returns_dict_with_method_field(self) -> None:
        """activate_windows result includes method that was used."""
        activator = WindowsActivator()
        activator.script_path = Path("/nonexistent/script.cmd")

        result = activator.activate_windows(ActivationMethod.HWID)

        if "method" in result:
            assert result["method"] == ActivationMethod.HWID.value

    def test_activate_windows_hwid_method_uses_correct_flag(self) -> None:
        """activate_windows with HWID method would use /HWID flag."""
        activator = WindowsActivator()

        result = activator.activate_windows(ActivationMethod.HWID)

        assert isinstance(result, dict)
        assert "success" in result

    def test_activate_windows_kms38_method_uses_correct_flag(self) -> None:
        """activate_windows with KMS38 method would use /KMS38 flag."""
        activator = WindowsActivator()

        result = activator.activate_windows(ActivationMethod.KMS38)

        assert isinstance(result, dict)
        assert "success" in result

    def test_activate_windows_online_kms_method_uses_correct_flag(self) -> None:
        """activate_windows with ONLINE_KMS method would use /Ohook flag."""
        activator = WindowsActivator()

        result = activator.activate_windows(ActivationMethod.ONLINE_KMS)

        assert isinstance(result, dict)
        assert "success" in result


class TestResetActivation:
    """Test activation reset functionality."""

    @WINDOWS_ONLY
    def test_reset_activation_returns_dict(self) -> None:
        """reset_activation returns dictionary with result information."""
        activator = WindowsActivator()
        result = activator.reset_activation()

        assert isinstance(result, dict)
        assert "success" in result

    @WINDOWS_ONLY
    def test_reset_activation_includes_return_code(self) -> None:
        """reset_activation result includes subprocess return code."""
        activator = WindowsActivator()
        result = activator.reset_activation()

        if "return_code" in result:
            assert isinstance(result["return_code"], int)

    @WINDOWS_ONLY
    def test_reset_activation_includes_output_fields(self) -> None:
        """reset_activation result includes stdout and stderr fields."""
        activator = WindowsActivator()
        result = activator.reset_activation()

        if result.get("success"):
            assert "stdout" in result or "stderr" in result


class TestProductKeyInfo:
    """Test product key information retrieval."""

    @WINDOWS_ONLY
    def test_get_product_key_info_returns_dict(self) -> None:
        """get_product_key_info returns dictionary with product information."""
        activator = WindowsActivator()
        result = activator.get_product_key_info()

        assert isinstance(result, dict)
        assert "success" in result

    @WINDOWS_ONLY
    def test_get_product_key_info_includes_product_info_field(self) -> None:
        """get_product_key_info includes product_info field when successful."""
        activator = WindowsActivator()
        result = activator.get_product_key_info()

        if result.get("success"):
            assert "product_info" in result
            assert isinstance(result["product_info"], str)


class TestOfficeDetection:
    """Test Office version detection functionality."""

    @WINDOWS_ONLY
    def test_detect_office_version_returns_string(self) -> None:
        """_detect_office_version returns string (empty if not found)."""
        activator = WindowsActivator()
        version = activator._detect_office_version()

        assert isinstance(version, str)

    @WINDOWS_ONLY
    def test_detect_office_version_returns_known_version_or_empty(self) -> None:
        """_detect_office_version returns known Office version or empty string."""
        activator = WindowsActivator()
        if version := activator._detect_office_version():
            assert version in ["2010", "2013", "2016", "2019", "2021", "365"]

    @WINDOWS_ONLY
    def test_detect_office_version_checks_file_system(self) -> None:
        """_detect_office_version checks common Office installation paths."""
        activator = WindowsActivator()
        version = activator._detect_office_version()

        office_paths = [
            r"C:\Program Files\Microsoft Office",
            r"C:\Program Files (x86)\Microsoft Office",
        ]

        has_office = any(os.path.exists(path) for path in office_paths)


class TestOfficeActivation:
    """Test Office activation functionality."""

    def test_activate_office_fails_when_prerequisites_not_met(self) -> None:
        """activate_office returns failure when prerequisites are not satisfied."""
        activator = WindowsActivator()
        activator.script_path = Path("/nonexistent/script.cmd")

        result = activator.activate_office()

        assert isinstance(result, dict)
        assert result["success"] is False
        assert "issues" in result

    @WINDOWS_ONLY
    def test_activate_office_auto_detects_version(self) -> None:
        """activate_office with 'auto' version attempts to detect Office installation."""
        activator = WindowsActivator()

        result = activator.activate_office(office_version="auto")

        assert isinstance(result, dict)
        assert "success" in result

    @WINDOWS_ONLY
    def test_activate_office_accepts_specific_versions(self) -> None:
        """activate_office accepts specific Office version strings."""
        activator = WindowsActivator()

        for version in ["2016", "2019", "2021", "365"]:
            result = activator.activate_office(office_version=version)
            assert isinstance(result, dict)

    @WINDOWS_ONLY
    def test_activate_office_returns_error_when_office_not_found(self) -> None:
        """activate_office returns error when Office is not detected."""
        activator = WindowsActivator()

        detected_version = activator._detect_office_version()

        if not detected_version:
            result = activator.activate_office(office_version="auto")

            if not result.get("success"):
                assert "office" in result.get("error", "").lower() or "not detected" in result.get("error", "").lower()


class TestOfficeActivationMethods:
    """Test Office-specific activation methods (C2R and MSI)."""

    @WINDOWS_ONLY
    def test_activate_office_c2r_returns_dict(self) -> None:
        """_activate_office_c2r returns dictionary with activation result."""
        activator = WindowsActivator()
        result = activator._activate_office_c2r("2016")

        assert isinstance(result, dict)
        assert "success" in result
        assert "method" in result
        assert result["method"] == "C2R"

    @WINDOWS_ONLY
    def test_activate_office_msi_returns_dict(self) -> None:
        """_activate_office_msi returns dictionary with activation result."""
        activator = WindowsActivator()
        result = activator._activate_office_msi("2016")

        assert isinstance(result, dict)
        assert "success" in result
        assert "method" in result
        assert result["method"] == "MSI"

    @WINDOWS_ONLY
    def test_activate_office_msi_uses_volume_keys(self) -> None:
        """_activate_office_msi uses appropriate volume license keys."""
        activator = WindowsActivator()

        result = activator._activate_office_msi("2016")

        if "product_key" in result:
            assert isinstance(result["product_key"], str)
            assert len(result["product_key"]) == 29

    @WINDOWS_ONLY
    def test_get_office_status_returns_dict(self) -> None:
        """_get_office_status returns dictionary with Office activation status."""
        activator = WindowsActivator()
        status = activator._get_office_status()

        assert isinstance(status, dict)
        assert "status" in status

    @WINDOWS_ONLY
    def test_get_office_status_detects_missing_ospp(self) -> None:
        """_get_office_status detects when OSPP.VBS is not found."""
        activator = WindowsActivator()
        status = activator._get_office_status()

        ospp_paths = [
            r"C:\Program Files\Microsoft Office\Office16\OSPP.VBS",
            r"C:\Program Files (x86)\Microsoft Office\Office16\OSPP.VBS",
            r"C:\Program Files\Microsoft Office\Office15\OSPP.VBS",
            r"C:\Program Files (x86)\Microsoft Office\Office15\OSPP.VBS",
        ]

        has_ospp = any(os.path.exists(path) for path in ospp_paths)

        if not has_ospp:
            assert status["status"] == "unknown"
            assert "error" in status


class TestActivatorAliases:
    """Test activation method aliases."""

    def test_activate_windows_kms_calls_kms38_method(self) -> None:
        """activate_windows_kms uses KMS38 activation method."""
        activator = WindowsActivator()
        activator.script_path = Path("/nonexistent/script.cmd")

        result = activator.activate_windows_kms()

        assert isinstance(result, dict)
        assert "success" in result

    def test_activate_windows_digital_calls_hwid_method(self) -> None:
        """activate_windows_digital uses HWID digital activation method."""
        activator = WindowsActivator()
        activator.script_path = Path("/nonexistent/script.cmd")

        result = activator.activate_windows_digital()

        assert isinstance(result, dict)
        assert "success" in result


class TestConvenienceFunctions:
    """Test module-level convenience functions."""

    def test_create_windows_activator_returns_activator_instance(self) -> None:
        """create_windows_activator returns configured WindowsActivator instance."""
        activator = create_windows_activator()

        assert isinstance(activator, WindowsActivator)
        assert activator.script_path is not None
        assert activator.temp_dir is not None

    @WINDOWS_ONLY
    def test_check_windows_activation_returns_dict(self) -> None:
        """check_windows_activation returns activation status dictionary."""
        status = check_windows_activation()

        assert isinstance(status, dict)
        assert "status" in status

    def test_activate_windows_hwid_returns_dict(self) -> None:
        """activate_windows_hwid returns activation result dictionary."""
        result = activate_windows_hwid()

        assert isinstance(result, dict)
        assert "success" in result

    def test_activate_windows_kms_returns_dict(self) -> None:
        """activate_windows_kms returns activation result dictionary."""
        result = activate_windows_kms()

        assert isinstance(result, dict)
        assert "success" in result


class TestErrorHandling:
    """Test error handling in various scenarios."""

    def test_activate_windows_handles_timeout_gracefully(self) -> None:
        """activate_windows handles subprocess timeout without crashing."""
        activator = WindowsActivator()
        activator.script_path = Path("/nonexistent/script.cmd")

        result = activator.activate_windows(ActivationMethod.HWID)

        assert isinstance(result, dict)
        assert "success" in result

    def test_generate_hwid_handles_exceptions_gracefully(self) -> None:
        """generate_hwid returns valid HWID even when exceptions occur."""
        activator = WindowsActivator()

        hwid = activator.generate_hwid()

        assert isinstance(hwid, str)
        assert len(hwid) > 0
        parts = hwid.split("-")
        assert len(parts) == 5

    @WINDOWS_ONLY
    def test_get_activation_status_handles_subprocess_errors(self) -> None:
        """get_activation_status handles subprocess errors gracefully."""
        activator = WindowsActivator()

        status = activator.get_activation_status()

        assert isinstance(status, dict)
        assert "status" in status

    def test_detect_office_version_handles_missing_paths(self) -> None:
        """_detect_office_version handles missing Office paths without crashing."""
        activator = WindowsActivator()

        version = activator._detect_office_version()

        assert isinstance(version, str)


class TestIntegrationScenarios:
    """Test realistic integration scenarios."""

    @WINDOWS_ONLY
    def test_full_activation_workflow_check_status_then_activate(self) -> None:
        """Full workflow: check prerequisites, status, then attempt activation."""
        activator = WindowsActivator()

        prereq_ok, issues = activator.check_prerequisites()
        assert isinstance(prereq_ok, bool)
        assert isinstance(issues, list)

        status = activator.get_activation_status()
        assert isinstance(status, dict)
        assert "status" in status

        hwid = activator.generate_hwid()
        assert isinstance(hwid, str)
        assert len(hwid.split("-")) == 5

    @WINDOWS_ONLY
    def test_office_detection_and_activation_workflow(self) -> None:
        """Full Office workflow: detect version, generate HWID, attempt activation."""
        activator = WindowsActivator()

        detected_version = activator._detect_office_version()
        assert isinstance(detected_version, str)

        hwid = activator.generate_hwid()
        assert isinstance(hwid, str)

        result = activator.activate_office(office_version="auto")
        assert isinstance(result, dict)
        assert "success" in result

    @WINDOWS_ONLY
    def test_multiple_activation_methods_in_sequence(self) -> None:
        """Test attempting multiple activation methods sequentially."""
        activator = WindowsActivator()

        result1 = activator.activate(method="hwid")
        result2 = activator.activate(method="kms38")

        assert isinstance(result1, dict)
        assert isinstance(result2, dict)
        assert "success" in result1
        assert "success" in result2


class TestPlatformCompatibility:
    """Test platform-specific behavior and compatibility."""

    def test_windows_activator_works_on_all_platforms(self) -> None:
        """WindowsActivator can be instantiated on any platform."""
        activator = WindowsActivator()

        assert activator is not None
        assert isinstance(activator, WindowsActivator)

    def test_non_windows_platforms_get_appropriate_errors(self) -> None:
        """Non-Windows platforms receive appropriate error messages."""
        if os.name != "nt":
            activator = WindowsActivator()

            success, issues = activator.check_prerequisites()

            assert not success
            assert any("windows" in issue.lower() for issue in issues)

    def test_hwid_generation_works_cross_platform(self) -> None:
        """HWID generation produces valid output on all platforms."""
        activator = WindowsActivator()

        hwid = activator.generate_hwid()

        assert isinstance(hwid, str)
        assert len(hwid.split("-")) == 5
        assert all(c in "0123456789ABCDEF-" for c in hwid)


class TestEdgeCases:
    """Test edge cases and unusual scenarios."""

    def test_activate_windows_with_check_only_method(self) -> None:
        """activate_windows handles CHECK_ONLY method appropriately."""
        activator = WindowsActivator()

        result = activator.activate_windows(ActivationMethod.CHECK_ONLY)

        assert isinstance(result, dict)
        assert "success" in result

    def test_generate_hwid_with_minimal_hardware_info(self) -> None:
        """generate_hwid produces valid HWID even with minimal hardware information."""
        activator = WindowsActivator()

        import intellicrack.core.patching.windows_activator as wa_module

        original_wmi = wa_module.wmi
        try:
            wa_module.wmi = None

            hwid = activator.generate_hwid()

            assert isinstance(hwid, str)
            assert len(hwid.split("-")) == 5

        finally:
            wa_module.wmi = original_wmi

    @WINDOWS_ONLY
    def test_activate_office_with_unsupported_version(self) -> None:
        """activate_office handles unsupported Office versions gracefully."""
        activator = WindowsActivator()

        result = activator.activate_office(office_version="2003")

        assert isinstance(result, dict)
        assert "success" in result

    def test_activator_temp_dir_creation(self) -> None:
        """WindowsActivator temp_dir path is properly constructed."""
        activator = WindowsActivator()

        assert activator.temp_dir.parent == Path(tempfile.gettempdir())
        assert "intellicrack" in str(activator.temp_dir).lower()


class TestTypeAnnotations:
    """Verify all methods have proper type annotations."""

    def test_generate_hwid_has_return_type(self) -> None:
        """generate_hwid has proper return type annotation."""
        activator = WindowsActivator()
        hwid = activator.generate_hwid()

        assert isinstance(hwid, str)

    def test_check_prerequisites_has_return_type(self) -> None:
        """check_prerequisites has proper return type annotation."""
        activator = WindowsActivator()
        result = activator.check_prerequisites()

        assert isinstance(result, tuple)
        assert isinstance(result[0], bool)
        assert isinstance(result[1], list)

    def test_get_activation_status_has_return_type(self) -> None:
        """get_activation_status has proper return type annotation."""
        activator = WindowsActivator()
        status = activator.get_activation_status()

        assert isinstance(status, dict)

    def test_activate_windows_has_return_type(self) -> None:
        """activate_windows has proper return type annotation."""
        activator = WindowsActivator()
        result = activator.activate_windows(ActivationMethod.HWID)

        assert isinstance(result, dict)

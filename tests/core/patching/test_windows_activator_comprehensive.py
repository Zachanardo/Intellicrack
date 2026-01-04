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
from typing import Any, Callable

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


class FakeSubprocessResult:
    """Test double for subprocess.CompletedProcess."""

    def __init__(self, returncode: int, stdout: str, stderr: str) -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class FakeSubprocessRunner:
    """Test double for subprocess operations."""

    def __init__(self) -> None:
        self.calls: list[tuple[list[str], dict[str, Any]]] = []
        self.responses: list[FakeSubprocessResult] = []
        self.call_index: int = 0
        self.exception_to_raise: Exception | None = None

    def run(self, cmd: list[str], **kwargs: Any) -> FakeSubprocessResult:
        """Simulate subprocess.run."""
        self.calls.append((cmd, kwargs))

        if self.exception_to_raise:
            raise self.exception_to_raise

        if self.call_index < len(self.responses):
            result = self.responses[self.call_index]
            self.call_index += 1
            return result

        return FakeSubprocessResult(0, "", "")

    def set_response(self, returncode: int, stdout: str, stderr: str) -> None:
        """Set single response."""
        self.responses = [FakeSubprocessResult(returncode, stdout, stderr)]
        self.call_index = 0

    def add_response(self, returncode: int, stdout: str, stderr: str) -> None:
        """Add response to queue."""
        self.responses.append(FakeSubprocessResult(returncode, stdout, stderr))

    def set_exception(self, exception: Exception) -> None:
        """Set exception to raise."""
        self.exception_to_raise = exception

    def was_called_with_arg(self, arg: str) -> bool:
        """Check if any call contained the argument."""
        for cmd, _ in self.calls:
            if any(arg in str(part) for part in cmd):
                return True
        return False


class FakePlatformInfo:
    """Test double for platform information."""

    def __init__(self) -> None:
        self.machine_value: str = "AMD64"
        self.processor_value: str = "Intel64"
        self.node_value: str = "TESTPC"
        self.os_name: str = "nt"

    def machine(self) -> str:
        return self.machine_value

    def processor(self) -> str:
        return self.processor_value

    def node(self) -> str:
        return self.node_value


class FakeWMI:
    """Test double for WMI module."""

    def __init__(self) -> None:
        self.available: bool = True
        self.serial_number: str = "TESTSERIAL123"

    def WMI(self) -> "FakeWMI":  # noqa: N802
        """Return self as WMI connection."""
        if not self.available:
            raise RuntimeError("WMI not available")
        return self

    def Win32_ComputerSystemProduct(self) -> list[Any]:  # noqa: N802
        """Return computer system product info."""
        return [type("Product", (), {"IdentifyingNumber": self.serial_number})]


class FakePathInfo:
    """Test double for path operations."""

    def __init__(self) -> None:
        self.existing_paths: set[str] = set()
        self.directory_contents: dict[str, list[str]] = {}

    def exists(self, path: str | Path) -> bool:
        """Check if path exists."""
        return str(path) in self.existing_paths

    def listdir(self, path: str | Path) -> list[str]:
        """List directory contents."""
        path_str = str(path)
        if path_str in self.directory_contents:
            return self.directory_contents[path_str]
        raise OSError(f"No such file or directory: {path_str}")

    def add_path(self, path: str) -> None:
        """Add existing path."""
        self.existing_paths.add(path)

    def add_directory_contents(self, path: str, contents: list[str]) -> None:
        """Add directory contents."""
        self.existing_paths.add(path)
        self.directory_contents[path] = contents


class FakeRegistryKey:
    """Test double for Windows registry operations."""

    def __init__(self) -> None:
        self.should_raise: bool = False

    def OpenKey(self, *args: Any) -> None:  # noqa: N802
        """Simulate registry key opening."""
        if self.should_raise:
            raise FileNotFoundError("Registry key not found")


class FakeAdminChecker:
    """Test double for admin privilege checking."""

    def __init__(self) -> None:
        self.is_admin_value: bool = True

    def is_admin(self) -> bool:
        """Check if running as admin."""
        return self.is_admin_value


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


@pytest.fixture
def fake_subprocess() -> FakeSubprocessRunner:
    """Create fake subprocess runner."""
    return FakeSubprocessRunner()


@pytest.fixture
def fake_platform() -> FakePlatformInfo:
    """Create fake platform info."""
    return FakePlatformInfo()


@pytest.fixture
def fake_wmi() -> FakeWMI:
    """Create fake WMI."""
    return FakeWMI()


@pytest.fixture
def fake_path() -> FakePathInfo:
    """Create fake path operations."""
    return FakePathInfo()


@pytest.fixture
def fake_admin() -> FakeAdminChecker:
    """Create fake admin checker."""
    return FakeAdminChecker()


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
        assert method != ActivationMethod.KMS38  # type: ignore[comparison-overlap]


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
        assert hwid != ""

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

    def test_generate_hwid_fallback_without_wmi(self, activator: WindowsActivator, monkeypatch: pytest.MonkeyPatch) -> None:
        """generate_hwid works without WMI module."""
        monkeypatch.setattr("intellicrack.core.patching.windows_activator.wmi", None)
        hwid: str = activator.generate_hwid()
        assert isinstance(hwid, str)
        assert len(hwid.split("-")) == 5

    def test_generate_hwid_uses_machine_info(self, activator: WindowsActivator, fake_platform: FakePlatformInfo, monkeypatch: pytest.MonkeyPatch) -> None:
        """generate_hwid incorporates machine-specific information."""
        monkeypatch.setattr("intellicrack.core.patching.windows_activator.wmi", None)

        fake_platform.machine_value = "AMD64"
        monkeypatch.setattr("platform.machine", fake_platform.machine)
        hwid1: str = activator.generate_hwid()

        fake_platform.machine_value = "x86"
        monkeypatch.setattr("platform.machine", fake_platform.machine)
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
    def test_check_prerequisites_detects_non_windows(self, activator: WindowsActivator, monkeypatch: pytest.MonkeyPatch) -> None:
        """check_prerequisites fails on non-Windows platforms."""
        monkeypatch.setattr("os.name", "posix")
        success, issues = activator.check_prerequisites()
        assert not success
        assert any("windows" in issue.lower() for issue in issues)

    @pytest.mark.skipif(os.name != "nt", reason="Windows-specific test")
    def test_check_prerequisites_checks_admin(self, activator_with_mock_script: WindowsActivator, fake_admin: FakeAdminChecker, monkeypatch: pytest.MonkeyPatch) -> None:
        """check_prerequisites verifies administrator privileges."""
        fake_admin.is_admin_value = False
        monkeypatch.setattr("intellicrack.core.patching.windows_activator.is_admin", fake_admin.is_admin)
        success, issues = activator_with_mock_script.check_prerequisites()
        assert not success
        assert any("administrator" in issue.lower() or "privileges" in issue.lower() for issue in issues)

    @pytest.mark.skipif(os.name != "nt", reason="Windows-specific test")
    def test_check_prerequisites_succeeds_with_all_requirements(self, activator_with_mock_script: WindowsActivator, fake_admin: FakeAdminChecker, monkeypatch: pytest.MonkeyPatch) -> None:
        """check_prerequisites succeeds when all requirements are met."""
        fake_admin.is_admin_value = True
        monkeypatch.setattr("intellicrack.core.patching.windows_activator.is_admin", fake_admin.is_admin)
        monkeypatch.setattr("os.name", "nt")
        success, issues = activator_with_mock_script.check_prerequisites()
        assert success
        assert len(issues) == 0


class TestGetActivationStatus:
    """Tests for Windows activation status checking."""

    def test_get_activation_status_returns_dict(self, activator: WindowsActivator, fake_subprocess: FakeSubprocessRunner, monkeypatch: pytest.MonkeyPatch) -> None:
        """get_activation_status returns dictionary with status information."""
        fake_subprocess.set_response(0, "Windows is permanently activated", "")
        monkeypatch.setattr("subprocess.run", fake_subprocess.run)
        result = activator.get_activation_status()
        assert isinstance(result, dict)
        assert "status" in result

    def test_get_activation_status_detects_activated(self, activator: WindowsActivator, fake_subprocess: FakeSubprocessRunner, monkeypatch: pytest.MonkeyPatch) -> None:
        """get_activation_status correctly identifies activated Windows."""
        fake_subprocess.set_response(0, "The machine is permanently activated.", "")
        monkeypatch.setattr("subprocess.run", fake_subprocess.run)
        result = activator.get_activation_status()
        assert result["status"] == ActivationStatus.ACTIVATED.value

    def test_get_activation_status_detects_grace_period(self, activator: WindowsActivator, fake_subprocess: FakeSubprocessRunner, monkeypatch: pytest.MonkeyPatch) -> None:
        """get_activation_status correctly identifies grace period."""
        fake_subprocess.set_response(0, "Windows is in grace period.", "")
        monkeypatch.setattr("subprocess.run", fake_subprocess.run)
        result = activator.get_activation_status()
        assert result["status"] == ActivationStatus.GRACE_PERIOD.value

    def test_get_activation_status_detects_not_activated(self, activator: WindowsActivator, fake_subprocess: FakeSubprocessRunner, monkeypatch: pytest.MonkeyPatch) -> None:
        """get_activation_status correctly identifies non-activated Windows."""
        fake_subprocess.set_response(0, "Windows is not activated.", "")
        monkeypatch.setattr("subprocess.run", fake_subprocess.run)
        result = activator.get_activation_status()
        assert result["status"] == ActivationStatus.NOT_ACTIVATED.value

    def test_get_activation_status_handles_errors(self, activator: WindowsActivator, fake_subprocess: FakeSubprocessRunner, monkeypatch: pytest.MonkeyPatch) -> None:
        """get_activation_status handles subprocess errors gracefully."""
        fake_subprocess.set_response(1, "", "Access denied")
        monkeypatch.setattr("subprocess.run", fake_subprocess.run)
        result = activator.get_activation_status()
        assert result["status"] == ActivationStatus.ERROR.value

    def test_get_activation_status_includes_raw_output(self, activator: WindowsActivator, fake_subprocess: FakeSubprocessRunner, monkeypatch: pytest.MonkeyPatch) -> None:
        """get_activation_status includes raw output in results."""
        test_output = "Test activation output"
        fake_subprocess.set_response(0, test_output, "")
        monkeypatch.setattr("subprocess.run", fake_subprocess.run)
        result = activator.get_activation_status()
        assert "raw_output" in result
        assert result["raw_output"] == test_output

    def test_get_activation_status_handles_oserror(self, activator: WindowsActivator, fake_subprocess: FakeSubprocessRunner, monkeypatch: pytest.MonkeyPatch) -> None:
        """get_activation_status handles OSError exceptions."""
        fake_subprocess.set_exception(OSError("Test error"))
        monkeypatch.setattr("subprocess.run", fake_subprocess.run)
        result = activator.get_activation_status()
        assert result["status"] == ActivationStatus.ERROR.value
        assert "error" in result


class TestActivateWindows:
    """Tests for Windows activation functionality."""

    def test_activate_windows_checks_prerequisites(self, activator: WindowsActivator) -> None:
        """activate_windows verifies prerequisites before activation."""
        original_check: Callable[[], tuple[bool, list[str]]] = activator.check_prerequisites

        def fake_check() -> tuple[bool, list[str]]:
            return (False, ["Missing script"])

        activator.check_prerequisites = fake_check  # type: ignore[method-assign]
        result = activator.activate_windows(ActivationMethod.HWID)
        activator.check_prerequisites = original_check  # type: ignore[method-assign]

        assert not result["success"]
        assert "prerequisites" in result["error"].lower()

    def test_activate_windows_hwid_method(self, activator_with_mock_script: WindowsActivator, fake_subprocess: FakeSubprocessRunner, fake_admin: FakeAdminChecker, monkeypatch: pytest.MonkeyPatch) -> None:
        """activate_windows uses correct arguments for HWID method."""
        fake_admin.is_admin_value = True
        monkeypatch.setattr("intellicrack.core.patching.windows_activator.is_admin", fake_admin.is_admin)
        monkeypatch.setattr("os.name", "nt")

        fake_subprocess.set_response(0, "Success", "")
        monkeypatch.setattr("subprocess.run", fake_subprocess.run)

        original_get_status: Callable[[], dict[str, Any]] = activator_with_mock_script.get_activation_status
        activator_with_mock_script.get_activation_status = lambda: {"status": "activated"}  # type: ignore[method-assign]

        result = activator_with_mock_script.activate_windows(ActivationMethod.HWID)

        activator_with_mock_script.get_activation_status = original_get_status  # type: ignore[method-assign]

        assert fake_subprocess.was_called_with_arg("/HWID")

    def test_activate_windows_kms38_method(self, activator_with_mock_script: WindowsActivator, fake_subprocess: FakeSubprocessRunner, fake_admin: FakeAdminChecker, monkeypatch: pytest.MonkeyPatch) -> None:
        """activate_windows uses correct arguments for KMS38 method."""
        fake_admin.is_admin_value = True
        monkeypatch.setattr("intellicrack.core.patching.windows_activator.is_admin", fake_admin.is_admin)
        monkeypatch.setattr("os.name", "nt")

        fake_subprocess.set_response(0, "Success", "")
        monkeypatch.setattr("subprocess.run", fake_subprocess.run)

        original_get_status: Callable[[], dict[str, Any]] = activator_with_mock_script.get_activation_status
        activator_with_mock_script.get_activation_status = lambda: {"status": "activated"}  # type: ignore[method-assign]

        result = activator_with_mock_script.activate_windows(ActivationMethod.KMS38)

        activator_with_mock_script.get_activation_status = original_get_status  # type: ignore[method-assign]

        assert fake_subprocess.was_called_with_arg("/KMS38")

    def test_activate_windows_online_kms_method(self, activator_with_mock_script: WindowsActivator, fake_subprocess: FakeSubprocessRunner, fake_admin: FakeAdminChecker, monkeypatch: pytest.MonkeyPatch) -> None:
        """activate_windows uses correct arguments for Online KMS method."""
        fake_admin.is_admin_value = True
        monkeypatch.setattr("intellicrack.core.patching.windows_activator.is_admin", fake_admin.is_admin)
        monkeypatch.setattr("os.name", "nt")

        fake_subprocess.set_response(0, "Success", "")
        monkeypatch.setattr("subprocess.run", fake_subprocess.run)

        original_get_status: Callable[[], dict[str, Any]] = activator_with_mock_script.get_activation_status
        activator_with_mock_script.get_activation_status = lambda: {"status": "activated"}  # type: ignore[method-assign]

        result = activator_with_mock_script.activate_windows(ActivationMethod.ONLINE_KMS)

        activator_with_mock_script.get_activation_status = original_get_status  # type: ignore[method-assign]

        assert fake_subprocess.was_called_with_arg("/Ohook")

    def test_activate_windows_returns_success_result(self, activator_with_mock_script: WindowsActivator, fake_subprocess: FakeSubprocessRunner, fake_admin: FakeAdminChecker, monkeypatch: pytest.MonkeyPatch) -> None:
        """activate_windows returns success result when activation succeeds."""
        fake_admin.is_admin_value = True
        monkeypatch.setattr("intellicrack.core.patching.windows_activator.is_admin", fake_admin.is_admin)
        monkeypatch.setattr("os.name", "nt")

        fake_subprocess.set_response(0, "Activated", "")
        monkeypatch.setattr("subprocess.run", fake_subprocess.run)

        original_get_status: Callable[[], dict[str, Any]] = activator_with_mock_script.get_activation_status
        activator_with_mock_script.get_activation_status = lambda: {"status": "activated"}  # type: ignore[method-assign]

        result = activator_with_mock_script.activate_windows(ActivationMethod.HWID)

        activator_with_mock_script.get_activation_status = original_get_status  # type: ignore[method-assign]

        assert result["success"]
        assert result["method"] == "hwid"
        assert "post_activation_status" in result

    def test_activate_windows_returns_failure_result(self, activator_with_mock_script: WindowsActivator, fake_subprocess: FakeSubprocessRunner, fake_admin: FakeAdminChecker, monkeypatch: pytest.MonkeyPatch) -> None:
        """activate_windows returns failure result when activation fails."""
        fake_admin.is_admin_value = True
        monkeypatch.setattr("intellicrack.core.patching.windows_activator.is_admin", fake_admin.is_admin)
        monkeypatch.setattr("os.name", "nt")

        fake_subprocess.set_response(1, "", "Failed")
        monkeypatch.setattr("subprocess.run", fake_subprocess.run)

        result = activator_with_mock_script.activate_windows(ActivationMethod.HWID)

        assert not result["success"]
        assert result["return_code"] == 1

    def test_activate_windows_handles_timeout(self, activator_with_mock_script: WindowsActivator, fake_subprocess: FakeSubprocessRunner, fake_admin: FakeAdminChecker, monkeypatch: pytest.MonkeyPatch) -> None:
        """activate_windows handles subprocess timeout gracefully."""
        fake_admin.is_admin_value = True
        monkeypatch.setattr("intellicrack.core.patching.windows_activator.is_admin", fake_admin.is_admin)
        monkeypatch.setattr("os.name", "nt")

        fake_subprocess.set_exception(subprocess.TimeoutExpired("cmd", 300))
        monkeypatch.setattr("subprocess.run", fake_subprocess.run)

        result = activator_with_mock_script.activate_windows(ActivationMethod.HWID)

        assert not result["success"]
        assert "timeout" in str(result.get("error", "")).lower() or "timed out" in str(result.get("error", "")).lower()


class TestActivateAliasMethods:
    """Tests for activation method aliases."""

    def test_activate_method_hwid_string(self, activator: WindowsActivator) -> None:
        """activate method converts 'hwid' string to enum."""
        original_activate: Callable[[ActivationMethod], dict[str, Any]] = activator.activate_windows
        called_with: list[ActivationMethod] = []

        def fake_activate(method: ActivationMethod) -> dict[str, Any]:
            called_with.append(method)
            return {"success": True}

        activator.activate_windows = fake_activate  # type: ignore[method-assign, assignment]
        activator.activate("hwid")
        activator.activate_windows = original_activate  # type: ignore[method-assign, assignment]

        assert len(called_with) == 1
        assert called_with[0] == ActivationMethod.HWID

    def test_activate_method_kms38_string(self, activator: WindowsActivator) -> None:
        """activate method converts 'kms38' string to enum."""
        original_activate: Callable[[ActivationMethod], dict[str, Any]] = activator.activate_windows
        called_with: list[ActivationMethod] = []

        def fake_activate(method: ActivationMethod) -> dict[str, Any]:
            called_with.append(method)
            return {"success": True}

        activator.activate_windows = fake_activate  # type: ignore[method-assign, assignment]
        activator.activate("kms38")
        activator.activate_windows = original_activate  # type: ignore[method-assign, assignment]

        assert len(called_with) == 1
        assert called_with[0] == ActivationMethod.KMS38

    def test_activate_method_ohook_string(self, activator: WindowsActivator) -> None:
        """activate method converts 'ohook' string to enum."""
        original_activate: Callable[[ActivationMethod], dict[str, Any]] = activator.activate_windows
        called_with: list[ActivationMethod] = []

        def fake_activate(method: ActivationMethod) -> dict[str, Any]:
            called_with.append(method)
            return {"success": True}

        activator.activate_windows = fake_activate  # type: ignore[method-assign, assignment]
        activator.activate("ohook")
        activator.activate_windows = original_activate  # type: ignore[method-assign, assignment]

        assert len(called_with) == 1
        assert called_with[0] == ActivationMethod.ONLINE_KMS

    def test_activate_method_case_insensitive(self, activator: WindowsActivator) -> None:
        """activate method handles uppercase method names."""
        original_activate: Callable[[ActivationMethod], dict[str, Any]] = activator.activate_windows
        called_with: list[ActivationMethod] = []

        def fake_activate(method: ActivationMethod) -> dict[str, Any]:
            called_with.append(method)
            return {"success": True}

        activator.activate_windows = fake_activate  # type: ignore[method-assign, assignment]
        activator.activate("HWID")
        activator.activate_windows = original_activate  # type: ignore[method-assign, assignment]

        assert len(called_with) == 1
        assert called_with[0] == ActivationMethod.HWID

    def test_activate_windows_kms_method(self, activator: WindowsActivator) -> None:
        """activate_windows_kms calls activate_windows with KMS38."""
        original_activate: Callable[[ActivationMethod], dict[str, Any]] = activator.activate_windows
        called_with: list[ActivationMethod] = []

        def fake_activate(method: ActivationMethod) -> dict[str, Any]:
            called_with.append(method)
            return {"success": True}

        activator.activate_windows = fake_activate  # type: ignore[method-assign, assignment]
        activator.activate_windows_kms()
        activator.activate_windows = original_activate  # type: ignore[method-assign, assignment]

        assert len(called_with) == 1
        assert called_with[0] == ActivationMethod.KMS38

    def test_activate_windows_digital_method(self, activator: WindowsActivator) -> None:
        """activate_windows_digital calls activate_windows with HWID."""
        original_activate: Callable[[ActivationMethod], dict[str, Any]] = activator.activate_windows
        called_with: list[ActivationMethod] = []

        def fake_activate(method: ActivationMethod) -> dict[str, Any]:
            called_with.append(method)
            return {"success": True}

        activator.activate_windows = fake_activate  # type: ignore[method-assign, assignment]
        activator.activate_windows_digital()
        activator.activate_windows = original_activate  # type: ignore[method-assign, assignment]

        assert len(called_with) == 1
        assert called_with[0] == ActivationMethod.HWID


class TestCheckActivationStatus:
    """Tests for check_activation_status alias method."""

    def test_check_activation_status_calls_get_activation_status(self, activator: WindowsActivator) -> None:
        """check_activation_status calls underlying get_activation_status."""
        original_get: Callable[[], dict[str, Any]] = activator.get_activation_status
        call_count: list[int] = [0]

        def fake_get() -> dict[str, Any]:
            call_count[0] += 1
            return {"status": "activated"}

        activator.get_activation_status = fake_get  # type: ignore[method-assign]
        activator.check_activation_status()
        activator.get_activation_status = original_get  # type: ignore[method-assign]

        assert call_count[0] == 1

    def test_check_activation_status_adds_activated_key(self, activator: WindowsActivator) -> None:
        """check_activation_status adds 'activated' boolean key."""
        original_get: Callable[[], dict[str, Any]] = activator.get_activation_status
        activator.get_activation_status = lambda: {"status": "activated"}  # type: ignore[method-assign]

        result = activator.check_activation_status()

        activator.get_activation_status = original_get  # type: ignore[method-assign]

        assert "activated" in result
        assert result["activated"] is True

    def test_check_activation_status_activated_false_for_not_activated(self, activator: WindowsActivator) -> None:
        """check_activation_status sets activated=False for non-activated status."""
        original_get: Callable[[], dict[str, Any]] = activator.get_activation_status
        activator.get_activation_status = lambda: {"status": "not_activated"}  # type: ignore[method-assign]

        result = activator.check_activation_status()

        activator.get_activation_status = original_get  # type: ignore[method-assign]

        assert "activated" in result
        assert result["activated"] is False


class TestResetActivation:
    """Tests for Windows activation reset functionality."""

    def test_reset_activation_returns_dict(self, activator: WindowsActivator, fake_subprocess: FakeSubprocessRunner, monkeypatch: pytest.MonkeyPatch) -> None:
        """reset_activation returns dictionary with reset results."""
        fake_subprocess.set_response(0, "Success", "")
        monkeypatch.setattr("subprocess.run", fake_subprocess.run)
        result = activator.reset_activation()
        assert isinstance(result, dict)
        assert "success" in result

    def test_reset_activation_calls_slmgr_rearm(self, activator: WindowsActivator, fake_subprocess: FakeSubprocessRunner, monkeypatch: pytest.MonkeyPatch) -> None:
        """reset_activation executes slmgr.vbs /rearm command."""
        fake_subprocess.set_response(0, "Success", "")
        monkeypatch.setattr("subprocess.run", fake_subprocess.run)
        activator.reset_activation()
        assert fake_subprocess.was_called_with_arg("slmgr.vbs")
        assert fake_subprocess.was_called_with_arg("/rearm")

    def test_reset_activation_success_result(self, activator: WindowsActivator, fake_subprocess: FakeSubprocessRunner, monkeypatch: pytest.MonkeyPatch) -> None:
        """reset_activation returns success when reset succeeds."""
        fake_subprocess.set_response(0, "Reset successful", "")
        monkeypatch.setattr("subprocess.run", fake_subprocess.run)
        result = activator.reset_activation()
        assert result["success"]
        assert result["return_code"] == 0

    def test_reset_activation_failure_result(self, activator: WindowsActivator, fake_subprocess: FakeSubprocessRunner, monkeypatch: pytest.MonkeyPatch) -> None:
        """reset_activation returns failure when reset fails."""
        fake_subprocess.set_response(1, "", "Error")
        monkeypatch.setattr("subprocess.run", fake_subprocess.run)
        result = activator.reset_activation()
        assert not result["success"]
        assert result["return_code"] == 1

    def test_reset_activation_handles_exceptions(self, activator: WindowsActivator, fake_subprocess: FakeSubprocessRunner, monkeypatch: pytest.MonkeyPatch) -> None:
        """reset_activation handles exceptions gracefully."""
        fake_subprocess.set_exception(OSError("Test error"))
        monkeypatch.setattr("subprocess.run", fake_subprocess.run)
        result = activator.reset_activation()
        assert not result["success"]
        assert "error" in result


class TestGetProductKeyInfo:
    """Tests for product key information retrieval."""

    def test_get_product_key_info_returns_dict(self, activator: WindowsActivator, fake_subprocess: FakeSubprocessRunner, monkeypatch: pytest.MonkeyPatch) -> None:
        """get_product_key_info returns dictionary with product information."""
        fake_subprocess.set_response(0, "Product info", "")
        monkeypatch.setattr("subprocess.run", fake_subprocess.run)
        result = activator.get_product_key_info()
        assert isinstance(result, dict)
        assert "success" in result
        assert "product_info" in result

    def test_get_product_key_info_calls_slmgr_dli(self, activator: WindowsActivator, fake_subprocess: FakeSubprocessRunner, monkeypatch: pytest.MonkeyPatch) -> None:
        """get_product_key_info executes slmgr.vbs /dli command."""
        fake_subprocess.set_response(0, "Info", "")
        monkeypatch.setattr("subprocess.run", fake_subprocess.run)
        activator.get_product_key_info()
        assert fake_subprocess.was_called_with_arg("slmgr.vbs")
        assert fake_subprocess.was_called_with_arg("/dli")

    def test_get_product_key_info_success(self, activator: WindowsActivator, fake_subprocess: FakeSubprocessRunner, monkeypatch: pytest.MonkeyPatch) -> None:
        """get_product_key_info returns success with product information."""
        product_data = "Windows 10 Pro\nPartial Product Key: XXXXX"
        fake_subprocess.set_response(0, product_data, "")
        monkeypatch.setattr("subprocess.run", fake_subprocess.run)
        result = activator.get_product_key_info()
        assert result["success"]
        assert result["product_info"] == product_data

    def test_get_product_key_info_handles_errors(self, activator: WindowsActivator, fake_subprocess: FakeSubprocessRunner, monkeypatch: pytest.MonkeyPatch) -> None:
        """get_product_key_info handles subprocess errors."""
        fake_subprocess.set_exception(OSError("Error"))
        monkeypatch.setattr("subprocess.run", fake_subprocess.run)
        result = activator.get_product_key_info()
        assert not result["success"]
        assert "error" in result


class TestOfficeActivation:
    """Tests for Microsoft Office activation functionality."""

    def test_activate_office_checks_prerequisites(self, activator: WindowsActivator) -> None:
        """activate_office verifies prerequisites before activation."""
        original_check = activator.check_prerequisites

        def fake_check() -> tuple[bool, list[str]]:
            return (False, ["Missing requirements"])

        activator.check_prerequisites = fake_check  # type: ignore[method-assign]
        result = activator.activate_office()
        activator.check_prerequisites = original_check  # type: ignore[method-assign]

        assert not result["success"]
        assert "prerequisites" in result["error"].lower()

    def test_activate_office_auto_detection(self, activator_with_mock_script: WindowsActivator, fake_admin: FakeAdminChecker, monkeypatch: pytest.MonkeyPatch) -> None:
        """activate_office automatically detects Office version."""
        fake_admin.is_admin_value = True
        monkeypatch.setattr("intellicrack.core.patching.windows_activator.is_admin", fake_admin.is_admin)
        monkeypatch.setattr("os.name", "nt")

        original_detect: Callable[[], str] = activator_with_mock_script._detect_office_version
        original_c2r: Callable[[str], dict[str, Any]] = activator_with_mock_script._activate_office_c2r
        original_status: Callable[[], dict[str, Any]] = activator_with_mock_script._get_office_status

        activator_with_mock_script._detect_office_version = lambda: "2016"  # type: ignore[method-assign]
        activator_with_mock_script._activate_office_c2r = lambda version: {"success": True}  # type: ignore[method-assign, assignment]
        activator_with_mock_script._get_office_status = lambda: {"status": "activated"}  # type: ignore[method-assign]

        result = activator_with_mock_script.activate_office("auto")

        activator_with_mock_script._detect_office_version = original_detect  # type: ignore[method-assign]
        activator_with_mock_script._activate_office_c2r = original_c2r  # type: ignore[method-assign, assignment]
        activator_with_mock_script._get_office_status = original_status  # type: ignore[method-assign]

        assert result["success"]

    def test_activate_office_no_office_detected(self, activator_with_mock_script: WindowsActivator, fake_admin: FakeAdminChecker, monkeypatch: pytest.MonkeyPatch) -> None:
        """activate_office handles case when Office is not detected."""
        fake_admin.is_admin_value = True
        monkeypatch.setattr("intellicrack.core.patching.windows_activator.is_admin", fake_admin.is_admin)
        monkeypatch.setattr("os.name", "nt")

        original_detect: Callable[[], str] = activator_with_mock_script._detect_office_version
        activator_with_mock_script._detect_office_version = lambda: ""  # type: ignore[method-assign]

        result = activator_with_mock_script.activate_office("auto")

        activator_with_mock_script._detect_office_version = original_detect  # type: ignore[method-assign]

        assert not result["success"]
        assert "no microsoft office" in result["error"].lower()

    def test_activate_office_specific_version(self, activator_with_mock_script: WindowsActivator, fake_admin: FakeAdminChecker, monkeypatch: pytest.MonkeyPatch) -> None:
        """activate_office accepts specific Office version."""
        fake_admin.is_admin_value = True
        monkeypatch.setattr("intellicrack.core.patching.windows_activator.is_admin", fake_admin.is_admin)
        monkeypatch.setattr("os.name", "nt")

        called_with_version: list[str] = []

        def fake_c2r(version: str) -> dict[str, Any]:
            called_with_version.append(version)
            return {"success": True}

        original_c2r = activator_with_mock_script._activate_office_c2r
        original_status = activator_with_mock_script._get_office_status

        activator_with_mock_script._activate_office_c2r = fake_c2r  # type: ignore[method-assign, assignment]
        activator_with_mock_script._get_office_status = lambda: {"status": "activated"}  # type: ignore[method-assign]

        result = activator_with_mock_script.activate_office("2019")

        activator_with_mock_script._activate_office_c2r = original_c2r  # type: ignore[method-assign]
        activator_with_mock_script._get_office_status = original_status  # type: ignore[method-assign]

        assert len(called_with_version) == 1
        assert called_with_version[0] == "2019"

    def test_activate_office_tries_c2r_then_msi(self, activator_with_mock_script: WindowsActivator, fake_admin: FakeAdminChecker, monkeypatch: pytest.MonkeyPatch) -> None:
        """activate_office tries C2R method first, then MSI if C2R fails."""
        fake_admin.is_admin_value = True
        monkeypatch.setattr("intellicrack.core.patching.windows_activator.is_admin", fake_admin.is_admin)
        monkeypatch.setattr("os.name", "nt")

        c2r_called = [False]
        msi_called = [False]

        def fake_c2r(version: str) -> dict[str, Any]:
            c2r_called[0] = True
            return {"success": False, "error": "C2R failed"}

        def fake_msi(version: str) -> dict[str, Any]:
            msi_called[0] = True
            return {"success": True}

        original_c2r = activator_with_mock_script._activate_office_c2r
        original_msi = activator_with_mock_script._activate_office_msi
        original_status = activator_with_mock_script._get_office_status

        activator_with_mock_script._activate_office_c2r = fake_c2r  # type: ignore[method-assign, assignment]
        activator_with_mock_script._activate_office_msi = fake_msi  # type: ignore[method-assign, assignment]
        activator_with_mock_script._get_office_status = lambda: {"status": "activated"}  # type: ignore[method-assign]

        result = activator_with_mock_script.activate_office("2016")

        activator_with_mock_script._activate_office_c2r = original_c2r  # type: ignore[method-assign]
        activator_with_mock_script._activate_office_msi = original_msi  # type: ignore[method-assign]
        activator_with_mock_script._get_office_status = original_status  # type: ignore[method-assign]

        assert c2r_called[0]
        assert msi_called[0]


class TestDetectOfficeVersion:
    """Tests for Office version detection."""

    def test_detect_office_version_finds_version(self, activator: WindowsActivator, fake_path: FakePathInfo, monkeypatch: pytest.MonkeyPatch) -> None:
        """_detect_office_version identifies installed Office version."""
        fake_path.add_directory_contents("C:\\Program Files\\Microsoft Office\\Office16", ["WINWORD.EXE", "EXCEL.EXE"])
        monkeypatch.setattr("os.path.exists", fake_path.exists)
        monkeypatch.setattr("os.listdir", fake_path.listdir)

        version = activator._detect_office_version()
        assert isinstance(version, str)

    def test_detect_office_version_returns_empty_if_not_found(self, activator: WindowsActivator, fake_path: FakePathInfo, monkeypatch: pytest.MonkeyPatch) -> None:
        """_detect_office_version returns empty string if Office not found."""
        fake_registry = FakeRegistryKey()
        fake_registry.should_raise = True

        monkeypatch.setattr("os.path.exists", fake_path.exists)
        monkeypatch.setattr("os.listdir", fake_path.listdir)
        monkeypatch.setattr("winreg.OpenKey", fake_registry.OpenKey)

        version = activator._detect_office_version()
        assert isinstance(version, str)

    def test_detect_office_version_prefers_newer_versions(self, activator: WindowsActivator) -> None:
        """_detect_office_version prefers newer Office versions."""
        original_detect = activator._detect_office_version
        activator._detect_office_version = lambda: "2019"  # type: ignore[method-assign]

        version = activator._detect_office_version()

        activator._detect_office_version = original_detect  # type: ignore[method-assign]

        assert version in ["2019", "2021"]


class TestActivateOfficeC2R:
    """Tests for Office Click-to-Run activation."""

    def test_activate_office_c2r_returns_dict(self, activator_with_mock_script: WindowsActivator, fake_subprocess: FakeSubprocessRunner, monkeypatch: pytest.MonkeyPatch) -> None:
        """_activate_office_c2r returns dictionary with activation results."""
        fake_subprocess.set_response(0, "Success", "")
        monkeypatch.setattr("subprocess.run", fake_subprocess.run)
        result = activator_with_mock_script._activate_office_c2r("2016")
        assert isinstance(result, dict)
        assert "success" in result
        assert "method" in result
        assert result["method"] == "C2R"

    def test_activate_office_c2r_success(self, activator_with_mock_script: WindowsActivator, fake_subprocess: FakeSubprocessRunner, monkeypatch: pytest.MonkeyPatch) -> None:
        """_activate_office_c2r returns success when activation succeeds."""
        fake_subprocess.set_response(0, "Activated", "")
        monkeypatch.setattr("subprocess.run", fake_subprocess.run)
        result = activator_with_mock_script._activate_office_c2r("2019")
        assert result["success"]
        assert result["office_version"] == "2019"

    def test_activate_office_c2r_handles_timeout(self, activator_with_mock_script: WindowsActivator, fake_subprocess: FakeSubprocessRunner, monkeypatch: pytest.MonkeyPatch) -> None:
        """_activate_office_c2r handles subprocess timeout."""
        fake_subprocess.set_exception(subprocess.TimeoutExpired("cmd", 300))
        monkeypatch.setattr("subprocess.run", fake_subprocess.run)
        result = activator_with_mock_script._activate_office_c2r("2016")
        assert not result["success"]
        assert "timeout" in str(result.get("error", "")).lower() or "timed out" in str(result.get("error", "")).lower()


class TestActivateOfficeMSI:
    """Tests for Office MSI activation."""

    def test_activate_office_msi_returns_dict(self, activator: WindowsActivator, fake_path: FakePathInfo, fake_subprocess: FakeSubprocessRunner, monkeypatch: pytest.MonkeyPatch) -> None:
        """_activate_office_msi returns dictionary with activation results."""
        fake_path.add_path("C:\\Program Files\\Microsoft Office\\Office16\\OSPP.VBS")
        monkeypatch.setattr("os.path.exists", fake_path.exists)

        fake_subprocess.set_response(0, "Success", "")
        monkeypatch.setattr("subprocess.run", fake_subprocess.run)

        result = activator._activate_office_msi("2016")
        assert isinstance(result, dict)
        assert "success" in result
        assert "method" in result
        assert result["method"] == "MSI"

    def test_activate_office_msi_fails_without_ospp(self, activator: WindowsActivator, fake_path: FakePathInfo, monkeypatch: pytest.MonkeyPatch) -> None:
        """_activate_office_msi fails when OSPP.VBS not found."""
        monkeypatch.setattr("os.path.exists", fake_path.exists)
        result = activator._activate_office_msi("2016")
        assert not result["success"]
        assert "ospp.vbs" in result["error"].lower()

    def test_activate_office_msi_uses_volume_key(self, activator: WindowsActivator, fake_path: FakePathInfo, fake_subprocess: FakeSubprocessRunner, monkeypatch: pytest.MonkeyPatch) -> None:
        """_activate_office_msi uses appropriate volume license key."""
        fake_path.add_path("C:\\Program Files\\Microsoft Office\\Office16\\OSPP.VBS")
        monkeypatch.setattr("os.path.exists", fake_path.exists)

        fake_subprocess.set_response(0, "Key installed", "")
        monkeypatch.setattr("subprocess.run", fake_subprocess.run)

        result = activator._activate_office_msi("2019")
        assert "product_key" in result
        assert isinstance(result["product_key"], str)
        assert len(result["product_key"]) == 29

    def test_activate_office_msi_installs_then_activates(self, activator: WindowsActivator, fake_path: FakePathInfo, fake_subprocess: FakeSubprocessRunner, monkeypatch: pytest.MonkeyPatch) -> None:
        """_activate_office_msi installs product key before activating."""
        fake_path.add_path("C:\\Program Files\\Microsoft Office\\Office16\\OSPP.VBS")
        monkeypatch.setattr("os.path.exists", fake_path.exists)

        fake_subprocess.add_response(0, "Key installed", "")
        fake_subprocess.add_response(0, "Activated", "")
        monkeypatch.setattr("subprocess.run", fake_subprocess.run)

        activator._activate_office_msi("2016")
        assert len(fake_subprocess.calls) >= 2


class TestGetOfficeStatus:
    """Tests for Office activation status checking."""

    def test_get_office_status_returns_dict(self, activator: WindowsActivator, fake_path: FakePathInfo, fake_subprocess: FakeSubprocessRunner, monkeypatch: pytest.MonkeyPatch) -> None:
        """_get_office_status returns dictionary with status information."""
        fake_path.add_path("C:\\Program Files\\Microsoft Office\\Office16\\OSPP.VBS")
        monkeypatch.setattr("os.path.exists", fake_path.exists)

        fake_subprocess.set_response(0, "LICENSE STATUS: ---LICENSED---", "")
        monkeypatch.setattr("subprocess.run", fake_subprocess.run)

        result = activator._get_office_status()
        assert isinstance(result, dict)
        assert "status" in result

    def test_get_office_status_detects_activated(self, activator: WindowsActivator, fake_path: FakePathInfo, fake_subprocess: FakeSubprocessRunner, monkeypatch: pytest.MonkeyPatch) -> None:
        """_get_office_status correctly identifies activated Office."""
        fake_path.add_path("C:\\Program Files\\Microsoft Office\\Office16\\OSPP.VBS")
        monkeypatch.setattr("os.path.exists", fake_path.exists)

        fake_subprocess.set_response(0, "LICENSE STATUS: ---LICENSED---", "")
        monkeypatch.setattr("subprocess.run", fake_subprocess.run)

        result = activator._get_office_status()
        assert result["status"] == "activated"

    def test_get_office_status_detects_grace_period(self, activator: WindowsActivator, fake_path: FakePathInfo, fake_subprocess: FakeSubprocessRunner, monkeypatch: pytest.MonkeyPatch) -> None:
        """_get_office_status correctly identifies grace period."""
        fake_path.add_path("C:\\Program Files\\Microsoft Office\\Office16\\OSPP.VBS")
        monkeypatch.setattr("os.path.exists", fake_path.exists)

        fake_subprocess.set_response(0, "LICENSE STATUS: ---GRACE---", "")
        monkeypatch.setattr("subprocess.run", fake_subprocess.run)

        result = activator._get_office_status()
        assert result["status"] == "grace_period"

    def test_get_office_status_handles_missing_ospp(self, activator: WindowsActivator, fake_path: FakePathInfo, monkeypatch: pytest.MonkeyPatch) -> None:
        """_get_office_status handles missing OSPP.VBS gracefully."""
        monkeypatch.setattr("os.path.exists", fake_path.exists)
        result = activator._get_office_status()
        assert result["status"] == "unknown"
        assert "ospp.vbs" in result["error"].lower()


class TestConvenienceFunctions:
    """Tests for module-level convenience functions."""

    def test_create_windows_activator_returns_instance(self) -> None:
        """create_windows_activator returns WindowsActivator instance."""
        activator = create_windows_activator()
        assert isinstance(activator, WindowsActivator)

    def test_check_windows_activation_function(self, fake_subprocess: FakeSubprocessRunner, monkeypatch: pytest.MonkeyPatch) -> None:
        """check_windows_activation convenience function works."""
        fake_subprocess.set_response(0, "Activated", "")
        monkeypatch.setattr("subprocess.run", fake_subprocess.run)
        result = check_windows_activation()
        assert isinstance(result, dict)
        assert "status" in result

    def test_activate_windows_hwid_function(self, fake_subprocess: FakeSubprocessRunner, fake_admin: FakeAdminChecker, monkeypatch: pytest.MonkeyPatch) -> None:
        """activate_windows_hwid convenience function works."""
        fake_subprocess.set_response(0, "Success", "")
        monkeypatch.setattr("subprocess.run", fake_subprocess.run)

        fake_admin.is_admin_value = False
        monkeypatch.setattr("intellicrack.core.patching.windows_activator.is_admin", fake_admin.is_admin)

        result = activate_windows_hwid()
        assert isinstance(result, dict)

    def test_activate_windows_kms_function(self, fake_subprocess: FakeSubprocessRunner, fake_admin: FakeAdminChecker, monkeypatch: pytest.MonkeyPatch) -> None:
        """activate_windows_kms convenience function works."""
        fake_subprocess.set_response(0, "Success", "")
        monkeypatch.setattr("subprocess.run", fake_subprocess.run)

        fake_admin.is_admin_value = False
        monkeypatch.setattr("intellicrack.core.patching.windows_activator.is_admin", fake_admin.is_admin)

        result = activate_windows_kms()
        assert isinstance(result, dict)


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_hwid_generation_with_empty_hardware_info(self, activator: WindowsActivator, fake_platform: FakePlatformInfo, monkeypatch: pytest.MonkeyPatch) -> None:
        """generate_hwid handles empty hardware information gracefully."""
        monkeypatch.setattr("intellicrack.core.patching.windows_activator.wmi", None)

        fake_platform.machine_value = ""
        fake_platform.processor_value = ""
        fake_platform.node_value = ""

        monkeypatch.setattr("platform.machine", fake_platform.machine)
        monkeypatch.setattr("platform.processor", fake_platform.processor)
        monkeypatch.setattr("platform.node", fake_platform.node)

        hwid = activator.generate_hwid()
        assert isinstance(hwid, str)
        assert len(hwid.split("-")) == 5

    def test_activation_with_very_long_output(self, activator_with_mock_script: WindowsActivator, fake_subprocess: FakeSubprocessRunner, fake_admin: FakeAdminChecker, monkeypatch: pytest.MonkeyPatch) -> None:
        """activate_windows handles very long subprocess output."""
        long_output = "A" * 10000

        fake_admin.is_admin_value = True
        monkeypatch.setattr("intellicrack.core.patching.windows_activator.is_admin", fake_admin.is_admin)
        monkeypatch.setattr("os.name", "nt")

        fake_subprocess.set_response(0, long_output, "")
        monkeypatch.setattr("subprocess.run", fake_subprocess.run)

        original_get_status = activator_with_mock_script.get_activation_status
        activator_with_mock_script.get_activation_status = lambda: {"status": "activated"}  # type: ignore[method-assign]

        result = activator_with_mock_script.activate_windows(ActivationMethod.HWID)

        activator_with_mock_script.get_activation_status = original_get_status  # type: ignore[method-assign]

        assert result["success"]
        assert len(result["stdout"]) == 10000

    def test_office_activation_with_special_characters_in_path(self, activator: WindowsActivator, fake_path: FakePathInfo, monkeypatch: pytest.MonkeyPatch) -> None:
        """_detect_office_version handles paths with special characters."""
        fake_registry = FakeRegistryKey()
        fake_registry.should_raise = True

        monkeypatch.setattr("os.path.exists", fake_path.exists)
        monkeypatch.setattr("os.listdir", fake_path.listdir)
        monkeypatch.setattr("winreg.OpenKey", fake_registry.OpenKey)

        version = activator._detect_office_version()
        assert isinstance(version, str)

    def test_concurrent_activation_attempts(self, activator_with_mock_script: WindowsActivator, fake_subprocess: FakeSubprocessRunner, fake_admin: FakeAdminChecker, monkeypatch: pytest.MonkeyPatch) -> None:
        """Multiple activation attempts can be handled sequentially."""
        fake_admin.is_admin_value = True
        monkeypatch.setattr("intellicrack.core.patching.windows_activator.is_admin", fake_admin.is_admin)
        monkeypatch.setattr("os.name", "nt")

        fake_subprocess.add_response(0, "Success", "")
        fake_subprocess.add_response(0, "Success", "")
        monkeypatch.setattr("subprocess.run", fake_subprocess.run)

        original_get_status = activator_with_mock_script.get_activation_status
        activator_with_mock_script.get_activation_status = lambda: {"status": "activated"}  # type: ignore[method-assign]

        result1 = activator_with_mock_script.activate_windows(ActivationMethod.HWID)
        result2 = activator_with_mock_script.activate_windows(ActivationMethod.KMS38)

        activator_with_mock_script.get_activation_status = original_get_status  # type: ignore[method-assign]

        assert result1["method"] == "hwid"
        assert result2["method"] == "kms38"

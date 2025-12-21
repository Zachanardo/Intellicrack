"""Production tests for os_detection_mixin.py.

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

import sys

import pytest

from intellicrack.utils.system.os_detection_mixin import OSDetectionMixin


class TestClass(OSDetectionMixin):
    """Test class using OSDetectionMixin."""

    pass


class TestOSDetectionMixin:
    """Test OSDetectionMixin provides OS detection to classes."""

    def test_mixin_detect_os_returns_valid_os(self) -> None:
        """Mixin _detect_os returns valid operating system."""
        test_obj: TestClass = TestClass()
        detected_os: str = test_obj._detect_os()

        assert detected_os in ["windows", "linux", "unknown"]

    def test_mixin_detect_target_os_returns_valid_os(self) -> None:
        """Mixin _detect_target_os returns valid operating system."""
        test_obj: TestClass = TestClass()
        target_os: str = test_obj._detect_target_os()

        assert target_os in ["windows", "linux", "unknown"]

    def test_mixin_detect_os_matches_detect_target_os(self) -> None:
        """_detect_os and _detect_target_os return same value."""
        test_obj: TestClass = TestClass()

        os_result: str = test_obj._detect_os()
        target_result: str = test_obj._detect_target_os()

        assert os_result == target_result

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-only test")
    def test_mixin_is_windows_true_on_windows(self) -> None:
        """Mixin _is_windows returns True on Windows platform."""
        test_obj: TestClass = TestClass()

        assert test_obj._is_windows() is True

    @pytest.mark.skipif(sys.platform == "win32", reason="Non-Windows test")
    def test_mixin_is_windows_false_on_linux(self) -> None:
        """Mixin _is_windows returns False on non-Windows platform."""
        test_obj: TestClass = TestClass()

        assert test_obj._is_windows() is False

    @pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux-only test")
    def test_mixin_is_linux_true_on_linux(self) -> None:
        """Mixin _is_linux returns True on Linux platform."""
        test_obj: TestClass = TestClass()

        assert test_obj._is_linux() is True

    @pytest.mark.skipif(sys.platform.startswith("linux"), reason="Non-Linux test")
    def test_mixin_is_linux_false_on_windows(self) -> None:
        """Mixin _is_linux returns False on non-Linux platform."""
        test_obj: TestClass = TestClass()

        if sys.platform == "win32":
            assert test_obj._is_linux() is False

    def test_mixin_detect_platform_public_method(self) -> None:
        """Mixin detect_platform provides public access to OS detection."""
        test_obj: TestClass = TestClass()
        platform: str = test_obj.detect_platform()

        assert platform in ["windows", "linux", "unknown"]

    def test_mixin_detect_platform_matches_private_detect_os(self) -> None:
        """Public detect_platform matches private _detect_os."""
        test_obj: TestClass = TestClass()

        public: str = test_obj.detect_platform()
        private: str = test_obj._detect_os()

        assert public == private

    def test_mixin_windows_and_linux_mutually_exclusive(self) -> None:
        """_is_windows and _is_linux are mutually exclusive."""
        test_obj: TestClass = TestClass()

        is_win: bool = test_obj._is_windows()
        is_lin: bool = test_obj._is_linux()

        assert not (is_win and is_lin)


class TestMixinConsistency:
    """Test consistency of mixin methods across multiple instances."""

    def test_mixin_consistent_across_instances(self) -> None:
        """Multiple instances return same OS detection results."""
        obj1: TestClass = TestClass()
        obj2: TestClass = TestClass()
        obj3: TestClass = TestClass()

        assert obj1._detect_os() == obj2._detect_os() == obj3._detect_os()

    def test_mixin_consistent_multiple_calls(self) -> None:
        """Multiple calls on same instance return consistent results."""
        test_obj: TestClass = TestClass()

        result1: str = test_obj._detect_os()
        result2: str = test_obj._detect_os()
        result3: str = test_obj._detect_os()

        assert result1 == result2 == result3

    def test_mixin_windows_check_consistent(self) -> None:
        """_is_windows returns consistent results across calls."""
        test_obj: TestClass = TestClass()

        check1: bool = test_obj._is_windows()
        check2: bool = test_obj._is_windows()
        check3: bool = test_obj._is_windows()

        assert check1 == check2 == check3

    def test_mixin_linux_check_consistent(self) -> None:
        """_is_linux returns consistent results across calls."""
        test_obj: TestClass = TestClass()

        check1: bool = test_obj._is_linux()
        check2: bool = test_obj._is_linux()
        check3: bool = test_obj._is_linux()

        assert check1 == check2 == check3


class TestMixinIntegration:
    """Integration tests for OSDetectionMixin with real classes."""

    def test_mixin_os_detection_matches_system(self) -> None:
        """Mixin OS detection matches actual system platform."""
        test_obj: TestClass = TestClass()
        detected: str = test_obj._detect_os()

        if sys.platform == "win32":
            assert detected == "windows"
        elif sys.platform.startswith("linux") or sys.platform == "darwin":
            assert detected == "linux"

    def test_mixin_boolean_checks_match_detection(self) -> None:
        """Boolean methods match string detection result."""
        test_obj: TestClass = TestClass()
        detected: str = test_obj._detect_os()

        if detected == "windows":
            assert test_obj._is_windows() is True
            assert test_obj._is_linux() is False
        elif detected == "linux":
            assert test_obj._is_windows() is False
            assert test_obj._is_linux() is True

    def test_mixin_public_private_consistency(self) -> None:
        """Public and private methods return consistent results."""
        test_obj: TestClass = TestClass()

        public_platform: str = test_obj.detect_platform()
        private_os: str = test_obj._detect_os()
        private_target: str = test_obj._detect_target_os()

        assert public_platform == private_os == private_target


class TestMultipleInheritance:
    """Test OSDetectionMixin with multiple inheritance scenarios."""

    class MultipleInheritanceClass(OSDetectionMixin):
        """Class with additional methods alongside mixin."""

        def custom_method(self) -> str:
            return "custom"

        def get_os_info(self) -> dict[str, bool | str]:
            return {
                "os": self._detect_os(),
                "is_windows": self._is_windows(),
                "is_linux": self._is_linux(),
            }

    def test_mixin_coexists_with_custom_methods(self) -> None:
        """Mixin methods work alongside custom class methods."""
        obj: TestMultipleInheritance.MultipleInheritanceClass = (
            self.MultipleInheritanceClass()
        )

        assert obj.custom_method() == "custom"
        assert obj._detect_os() in ["windows", "linux", "unknown"]

    def test_mixin_custom_integration_method(self) -> None:
        """Custom method using mixin returns valid OS info."""
        obj: TestMultipleInheritance.MultipleInheritanceClass = (
            self.MultipleInheritanceClass()
        )
        info: dict[str, bool | str] = obj.get_os_info()

        assert "os" in info
        assert "is_windows" in info
        assert "is_linux" in info
        assert info["os"] in ["windows", "linux", "unknown"]
        assert isinstance(info["is_windows"], bool)
        assert isinstance(info["is_linux"], bool)

    def test_mixin_integration_method_consistency(self) -> None:
        """Custom method results match direct mixin calls."""
        obj: TestMultipleInheritance.MultipleInheritanceClass = (
            self.MultipleInheritanceClass()
        )
        info: dict[str, bool | str] = obj.get_os_info()

        assert info["os"] == obj._detect_os()
        assert info["is_windows"] == obj._is_windows()
        assert info["is_linux"] == obj._is_linux()

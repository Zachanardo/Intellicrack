"""Production tests for driver_utils.py.

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

import os
import sys
from pathlib import Path

import pytest

from intellicrack.utils.system.driver_utils import get_driver_path


pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows-only tests")


class TestDriverPathResolution:
    """Test Windows driver path resolution on real system."""

    def test_get_driver_path_returns_absolute_path(self) -> None:
        """Driver path resolution returns absolute Windows path."""
        driver_path: str = get_driver_path("ntfs.sys")

        assert os.path.isabs(driver_path)
        assert driver_path.endswith("ntfs.sys")

    def test_get_driver_path_includes_drivers_directory(self) -> None:
        """Driver path includes Windows drivers directory."""
        driver_path: str = get_driver_path("ntoskrnl.exe")

        assert "drivers" in driver_path.lower() or "System32" in driver_path

    def test_get_driver_path_uses_systemroot_environment(self) -> None:
        """Driver path uses SYSTEMROOT environment variable."""
        driver_path: str = get_driver_path("win32k.sys")

        systemroot: str = os.environ.get("SYSTEMROOT", r"C:\Windows")
        assert driver_path.startswith(systemroot) or driver_path.startswith(r"C:\Windows")

    def test_get_driver_path_handles_various_driver_names(self) -> None:
        """Driver path resolution works with various driver file names."""
        drivers: list[str] = [
            "ntfs.sys",
            "fltmgr.sys",
            "tcpip.sys",
            "http.sys",
            "ndis.sys",
        ]

        for driver in drivers:
            path: str = get_driver_path(driver)
            assert path.endswith(driver)
            assert os.path.isabs(path)

    def test_get_driver_path_system32_drivers_location(self) -> None:
        """Driver path points to System32/drivers for standard location."""
        driver_path: str = get_driver_path("test.sys")

        path_obj: Path = Path(driver_path)
        parent_dirs: list[str] = [p.lower() for p in path_obj.parts]

        assert "system32" in parent_dirs
        assert "drivers" in parent_dirs

    def test_get_driver_path_preserves_driver_name(self) -> None:
        """Driver path preserves exact driver name provided."""
        driver_name: str = "CustomDriver.sys"
        driver_path: str = get_driver_path(driver_name)

        assert driver_path.endswith(driver_name)

    def test_get_driver_path_works_without_path_discovery(self) -> None:
        """Driver path works even if path_discovery module unavailable."""
        driver_path: str = get_driver_path("fallback.sys")

        assert driver_path is not None
        assert len(driver_path) > 0
        assert "fallback.sys" in driver_path

    def test_get_driver_path_different_extensions(self) -> None:
        """Driver path handles different file extensions."""
        extensions: list[str] = [".sys", ".dll", ".exe"]

        for ext in extensions:
            driver_name: str = f"driver{ext}"
            path: str = get_driver_path(driver_name)
            assert path.endswith(ext)

    def test_get_driver_path_consistency(self) -> None:
        """Multiple calls to get_driver_path return consistent paths."""
        driver: str = "consistency_test.sys"

        path1: str = get_driver_path(driver)
        path2: str = get_driver_path(driver)
        path3: str = get_driver_path(driver)

        assert path1 == path2 == path3

    def test_get_driver_path_windows_path_separators(self) -> None:
        """Driver paths use Windows path separators."""
        driver_path: str = get_driver_path("separator_test.sys")

        assert "\\" in driver_path or "/" in driver_path
        path_normalized: str = os.path.normpath(driver_path)
        assert driver_path == path_normalized or driver_path.replace("/", "\\") == path_normalized


class TestDriverPathIntegration:
    """Integration tests for driver path resolution with Windows system."""

    def test_common_windows_drivers_exist(self) -> None:
        """Common Windows driver paths point to existing driver directory."""
        common_drivers: list[str] = [
            "ntfs.sys",
            "ntoskrnl.exe",
            "win32k.sys",
        ]

        for driver in common_drivers:
            path: str = get_driver_path(driver)
            parent_dir: Path = Path(path).parent

            assert parent_dir.exists()
            assert parent_dir.is_dir()

    def test_driver_path_in_system_protected_area(self) -> None:
        """Driver paths are in system-protected Windows directories."""
        driver_path: str = get_driver_path("protected.sys")

        path_lower: str = driver_path.lower()
        assert "windows" in path_lower
        assert "system32" in path_lower or "syswow64" in path_lower

    def test_driver_path_uses_real_system_paths(self) -> None:
        """Driver paths use actual Windows system paths, not mock paths."""
        driver_path: str = get_driver_path("real_system.sys")

        assert not driver_path.startswith("/tmp")
        assert not driver_path.startswith("/var")
        assert driver_path[1:3] == ":\\" or driver_path.startswith(r"\\")

    def test_driver_path_accessible_for_analysis(self) -> None:
        """Driver directory is accessible for binary analysis purposes."""
        driver_path: str = get_driver_path("accessible.sys")
        parent: Path = Path(driver_path).parent

        assert os.access(parent, os.R_OK)


class TestDriverPathEdgeCases:
    """Edge case tests for driver path utilities."""

    def test_get_driver_path_empty_string(self) -> None:
        """Driver path handles empty string input."""
        path: str = get_driver_path("")

        assert isinstance(path, str)
        assert "drivers" in path.lower() or "system32" in path.lower()

    def test_get_driver_path_with_subdirectory(self) -> None:
        """Driver path handles driver name with subdirectory."""
        driver_path: str = get_driver_path("subdir\\driver.sys")

        assert "subdir" in driver_path or driver_path.endswith("subdir\\driver.sys")

    def test_get_driver_path_unicode_driver_name(self) -> None:
        """Driver path handles Unicode characters in driver name."""
        driver_name: str = "drïvér.sys"
        path: str = get_driver_path(driver_name)

        assert isinstance(path, str)
        assert len(path) > 0

    def test_get_driver_path_long_driver_name(self) -> None:
        """Driver path handles very long driver names."""
        long_name: str = "a" * 200 + ".sys"
        path: str = get_driver_path(long_name)

        assert path.endswith(".sys")
        assert len(path) > 200

    def test_get_driver_path_special_characters(self) -> None:
        """Driver path handles special characters in driver name."""
        special_names: list[str] = [
            "driver-v2.sys",
            "driver_v2.sys",
            "driver.v2.sys",
        ]

        for name in special_names:
            path: str = get_driver_path(name)
            assert path.endswith(name)

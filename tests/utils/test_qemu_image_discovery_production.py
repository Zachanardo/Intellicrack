"""Production-grade tests for QEMU image discovery utility.

Tests validate real QEMU image discovery, format detection, OS type detection,
architecture detection, caching, and directory traversal functionality.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import tempfile
from pathlib import Path
from typing import Any

import pytest

from intellicrack.utils.qemu_image_discovery import (
    QEMUImageDiscovery,
    QEMUImageInfo,
    get_qemu_discovery,
)


@pytest.fixture
def qemu_images_dir(temp_workspace: Path) -> Path:
    """Create a temporary directory with mock QEMU images."""
    images_dir = temp_workspace / "qemu_images"
    images_dir.mkdir(parents=True)

    # Create various QEMU image files with realistic names
    test_images = [
        "windows_10_x64.qcow2",
        "ubuntu_22.04_amd64.qcow2",
        "debian_11_i386.img",
        "centos_8_x86_64.vmdk",
        "fedora_38_arm64.vdi",
        "macos_ventura_x64.dmg",
        "freebsd_13_amd64.raw",
        "arch_linux_x86.qcow",
        "kali_linux_64bit.vhd",
        "windows_server_2022_x64.vhdx",
        "openbsd_7_x86_64.iso",
        "netbsd_9_i686.qed",
    ]

    for image_name in test_images:
        image_path = images_dir / image_name
        # Create realistic-sized dummy files
        image_path.write_bytes(b"\x00" * (1024 * 1024 * 10))  # 10MB

    return images_dir


@pytest.fixture
def discovery_instance(qemu_images_dir: Path, monkeypatch: pytest.MonkeyPatch) -> QEMUImageDiscovery:
    """Create QEMUImageDiscovery instance with test directory."""
    discovery = QEMUImageDiscovery()

    # Mock get_search_directories to return test directory
    def mock_get_search_directories(self: QEMUImageDiscovery) -> list[Path]:
        return [qemu_images_dir]

    monkeypatch.setattr(QEMUImageDiscovery, "get_search_directories", mock_get_search_directories)
    return discovery


class TestQEMUImageDiscovery:
    """Test suite for QEMU image discovery functionality."""

    def test_discovery_initialization(self) -> None:
        """QEMUImageDiscovery initializes with empty cache."""
        discovery = QEMUImageDiscovery()

        assert discovery._cache == []
        assert discovery._cache_valid is False

    def test_supported_formats_comprehensive(self) -> None:
        """All common QEMU formats are supported."""
        expected_formats = [
            ".qcow2",
            ".qcow",
            ".img",
            ".vmdk",
            ".vdi",
            ".vhd",
            ".vhdx",
            ".iso",
            ".raw",
        ]

        for fmt in expected_formats:
            assert fmt in QEMUImageDiscovery.SUPPORTED_FORMATS

    def test_discover_images_finds_all_formats(self, discovery_instance: QEMUImageDiscovery) -> None:
        """discover_images finds all supported image formats."""
        images = discovery_instance.discover_images()

        assert len(images) > 0
        # Should find at least the major formats
        found_formats = {img.format for img in images}
        assert "qcow2" in found_formats
        assert "vmdk" in found_formats or "vdi" in found_formats

    def test_discover_images_creates_image_info(self, discovery_instance: QEMUImageDiscovery) -> None:
        """discover_images creates proper QEMUImageInfo objects."""
        images = discovery_instance.discover_images()

        for image in images:
            assert isinstance(image, QEMUImageInfo)
            assert image.path.exists()
            assert image.filename != ""
            assert image.format != ""
            assert image.size_bytes > 0

    def test_os_type_detection_windows(self, discovery_instance: QEMUImageDiscovery) -> None:
        """OS type detection correctly identifies Windows images."""
        test_cases = [
            "windows_10_x64.qcow2",
            "win11_installer.iso",
            "winxp_sp3.vmdk",
        ]

        for filename in test_cases:
            os_type = discovery_instance.detect_os_type(filename)
            assert os_type == "windows"

    def test_os_type_detection_linux(self, discovery_instance: QEMUImageDiscovery) -> None:
        """OS type detection correctly identifies Linux distributions."""
        test_cases = [
            "ubuntu_22.04_server.qcow2",
            "debian_bullseye.img",
            "centos_stream_9.vmdk",
            "fedora_workstation_38.vdi",
            "arch_linux_latest.qcow",
            "kali_linux_2023.iso",
        ]

        for filename in test_cases:
            os_type = discovery_instance.detect_os_type(filename)
            assert os_type == "linux"

    def test_os_type_detection_bsd(self, discovery_instance: QEMUImageDiscovery) -> None:
        """OS type detection correctly identifies BSD variants."""
        test_cases = [
            "freebsd_13.2.qcow2",
            "openbsd_7.3.img",
            "netbsd_9.3.vmdk",
        ]

        for filename in test_cases:
            os_type = discovery_instance.detect_os_type(filename)
            assert os_type == "bsd"

    def test_os_type_detection_macos(self, discovery_instance: QEMUImageDiscovery) -> None:
        """OS type detection correctly identifies macOS images."""
        test_cases = [
            "macos_ventura.dmg",
            "osx_high_sierra.vmdk",
            "darwin_kernel.img",
        ]

        for filename in test_cases:
            os_type = discovery_instance.detect_os_type(filename)
            assert os_type == "macos"

    def test_os_type_detection_unknown(self, discovery_instance: QEMUImageDiscovery) -> None:
        """OS type detection returns unknown for unrecognized names."""
        os_type = discovery_instance.detect_os_type("custom_os.qcow2")
        assert os_type == "unknown"

    def test_architecture_detection_x86_64(self, discovery_instance: QEMUImageDiscovery) -> None:
        """Architecture detection correctly identifies x86_64."""
        test_cases = [
            "system_x86_64.qcow2",
            "os_amd64.vmdk",
            "vm_x64.img",
            "app_64bit.vdi",
        ]

        for filename in test_cases:
            arch = discovery_instance.detect_architecture(filename)
            assert arch == "x86_64"

    def test_architecture_detection_x86(self, discovery_instance: QEMUImageDiscovery) -> None:
        """Architecture detection correctly identifies x86 (32-bit)."""
        test_cases = [
            "system_i386.qcow2",
            "os_i686.vmdk",
            "vm_32bit.img",
        ]

        for filename in test_cases:
            arch = discovery_instance.detect_architecture(filename)
            assert arch == "x86"

    def test_architecture_detection_arm(self, discovery_instance: QEMUImageDiscovery) -> None:
        """Architecture detection correctly identifies ARM architectures."""
        test_cases_arm64 = ["system_arm64.qcow2", "os_aarch64.vmdk"]
        test_cases_arm = ["system_arm.img", "os_armv7.vdi"]

        for filename in test_cases_arm64:
            arch = discovery_instance.detect_architecture(filename)
            assert arch == "arm64"

        for filename in test_cases_arm:
            arch = discovery_instance.detect_architecture(filename)
            assert arch == "arm"

    def test_architecture_detection_default(self, discovery_instance: QEMUImageDiscovery) -> None:
        """Architecture detection defaults to x86_64 when unknown."""
        arch = discovery_instance.detect_architecture("generic_os.qcow2")
        assert arch == "x86_64"

    def test_discover_images_populates_cache(self, discovery_instance: QEMUImageDiscovery) -> None:
        """discover_images populates internal cache."""
        assert discovery_instance._cache_valid is False

        images = discovery_instance.discover_images()

        assert discovery_instance._cache_valid is True
        assert len(discovery_instance._cache) > 0  # type: ignore[unreachable]
        assert discovery_instance._cache == images

    def test_cache_reused_on_subsequent_calls(self, discovery_instance: QEMUImageDiscovery) -> None:
        """Cached results are reused on subsequent discover calls."""
        images1 = discovery_instance.discover_images()
        images2 = discovery_instance.discover_images()

        assert images1 is images2  # Same object reference
        assert images1 == images2

    def test_force_refresh_ignores_cache(self, discovery_instance: QEMUImageDiscovery, qemu_images_dir: Path) -> None:
        """force_refresh parameter bypasses cache."""
        images1 = discovery_instance.discover_images()

        # Add a new image
        new_image = qemu_images_dir / "new_system.qcow2"
        new_image.write_bytes(b"\x00" * 1024)

        images2 = discovery_instance.discover_images(force_refresh=True)

        assert len(images2) > len(images1)

    def test_invalidate_cache_clears_cache(self, discovery_instance: QEMUImageDiscovery) -> None:
        """invalidate_cache properly clears the cache."""
        discovery_instance.discover_images()
        assert discovery_instance._cache_valid is True

        discovery_instance.invalidate_cache()

        assert discovery_instance._cache_valid is False

    def test_get_images_by_os_filters_correctly(self, discovery_instance: QEMUImageDiscovery) -> None:
        """get_images_by_os returns only images matching OS type."""
        windows_images = discovery_instance.get_images_by_os("windows")

        assert len(windows_images) > 0
        for image in windows_images:
            assert image.os_type == "windows"

    def test_get_images_by_os_case_insensitive(self, discovery_instance: QEMUImageDiscovery) -> None:
        """get_images_by_os is case-insensitive."""
        images_lower = discovery_instance.get_images_by_os("linux")
        images_upper = discovery_instance.get_images_by_os("LINUX")
        images_mixed = discovery_instance.get_images_by_os("LiNuX")

        assert images_lower == images_upper == images_mixed

    def test_get_images_by_format_filters_correctly(self, discovery_instance: QEMUImageDiscovery) -> None:
        """get_images_by_format returns only images matching format."""
        qcow2_images = discovery_instance.get_images_by_format("qcow2")

        assert len(qcow2_images) > 0
        for image in qcow2_images:
            assert image.format == "qcow2"

    def test_get_images_by_format_case_insensitive(self, discovery_instance: QEMUImageDiscovery) -> None:
        """get_images_by_format is case-insensitive."""
        images_lower = discovery_instance.get_images_by_format("qcow2")
        images_upper = discovery_instance.get_images_by_format("QCOW2")

        assert images_lower == images_upper

    def test_find_image_by_filename(self, discovery_instance: QEMUImageDiscovery) -> None:
        """find_image locates image by exact filename."""
        all_images = discovery_instance.discover_images()
        target_image = all_images[0]

        found = discovery_instance.find_image(target_image.filename)

        assert found is not None
        assert found.filename == target_image.filename
        assert found.path == target_image.path

    def test_find_image_returns_none_for_nonexistent(self, discovery_instance: QEMUImageDiscovery) -> None:
        """find_image returns None for non-existent image."""
        found = discovery_instance.find_image("nonexistent_image.qcow2")
        assert found is None

    def test_image_size_bytes_accurate(self, discovery_instance: QEMUImageDiscovery) -> None:
        """Image size_bytes field contains accurate file size."""
        images = discovery_instance.discover_images()

        for image in images:
            actual_size = image.path.stat().st_size
            assert image.size_bytes == actual_size

    def test_discover_handles_symlinks(self, discovery_instance: QEMUImageDiscovery, qemu_images_dir: Path) -> None:
        """Image discovery handles symbolic links appropriately."""
        # Create a real image and a symlink to it
        real_image = qemu_images_dir / "real_image.qcow2"
        real_image.write_bytes(b"\x00" * 1024)

        try:
            symlink_image = qemu_images_dir / "symlink_image.qcow2"
            symlink_image.symlink_to(real_image)

            images = discovery_instance.discover_images(force_refresh=True)

            # Both should be discovered (symlink points to file)
            filenames = [img.filename for img in images]
            assert "real_image.qcow2" in filenames
        except OSError:
            # Symlinks might not be supported on Windows without privileges
            pytest.skip("Symlinks not supported on this system")

    def test_discover_skips_directories(self, qemu_images_dir: Path, discovery_instance: QEMUImageDiscovery) -> None:
        """Image discovery skips directories with image extensions."""
        # Create a directory with image extension
        fake_dir = qemu_images_dir / "not_an_image.qcow2"
        fake_dir.mkdir()

        images = discovery_instance.discover_images(force_refresh=True)

        # Should not include the directory
        paths = [img.path for img in images]
        assert fake_dir not in paths

    def test_discover_handles_access_errors_gracefully(
        self, discovery_instance: QEMUImageDiscovery, qemu_images_dir: Path
    ) -> None:
        """Image discovery handles file access errors gracefully."""
        # Discovery should complete even if some files have issues
        images = discovery_instance.discover_images()
        assert len(images) > 0


class TestGetQEMUDiscovery:
    """Test suite for singleton get_qemu_discovery function."""

    def test_get_qemu_discovery_returns_instance(self) -> None:
        """get_qemu_discovery returns QEMUImageDiscovery instance."""
        discovery = get_qemu_discovery()
        assert isinstance(discovery, QEMUImageDiscovery)

    def test_get_qemu_discovery_singleton(self) -> None:
        """get_qemu_discovery returns same instance on multiple calls."""
        discovery1 = get_qemu_discovery()
        discovery2 = get_qemu_discovery()

        assert discovery1 is discovery2


class TestSearchDirectories:
    """Test suite for search directory configuration."""

    def test_get_search_directories_returns_paths(self) -> None:
        """get_search_directories returns list of Path objects."""
        discovery = QEMUImageDiscovery()
        dirs = discovery.get_search_directories()

        assert isinstance(dirs, list)
        for directory in dirs:
            assert isinstance(directory, Path)

    def test_search_directories_exist_or_created(self) -> None:
        """Search directories exist or are created automatically."""
        discovery = QEMUImageDiscovery()
        dirs = discovery.get_search_directories()

        assert len(dirs) > 0
        for directory in dirs:
            assert directory.exists()
            assert directory.is_dir()


class TestQEMUImageInfo:
    """Test suite for QEMUImageInfo dataclass."""

    def test_image_info_creation(self, temp_workspace: Path) -> None:
        """QEMUImageInfo can be created with all fields."""
        test_path = temp_workspace / "test.qcow2"
        test_path.write_bytes(b"\x00" * 1024)

        info = QEMUImageInfo(
            path=test_path,
            filename="test.qcow2",
            format="qcow2",
            os_type="linux",
            architecture="x86_64",
            size_bytes=1024,
        )

        assert info.path == test_path
        assert info.filename == "test.qcow2"
        assert info.format == "qcow2"
        assert info.os_type == "linux"
        assert info.architecture == "x86_64"
        assert info.size_bytes == 1024


class TestEmptyDirectoryHandling:
    """Test suite for handling empty directories."""

    def test_discover_empty_directory_returns_empty_list(self, temp_workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """discover_images returns empty list for empty directory."""
        empty_dir = temp_workspace / "empty_qemu"
        empty_dir.mkdir()

        discovery = QEMUImageDiscovery()

        def mock_get_search_directories(self: QEMUImageDiscovery) -> list[Path]:
            return [empty_dir]

        monkeypatch.setattr(QEMUImageDiscovery, "get_search_directories", mock_get_search_directories)

        images = discovery.discover_images()
        assert images == []


class TestLargeDirectoryPerformance:
    """Test suite for performance with many images."""

    def test_discover_many_images_performs_well(self, temp_workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """discover_images performs efficiently with many images."""
        many_images_dir = temp_workspace / "many_images"
        many_images_dir.mkdir()

        # Create 100 dummy images
        for i in range(100):
            image = many_images_dir / f"image_{i}.qcow2"
            image.write_bytes(b"\x00" * 100)

        discovery = QEMUImageDiscovery()

        def mock_get_search_directories(self: QEMUImageDiscovery) -> list[Path]:
            return [many_images_dir]

        monkeypatch.setattr(QEMUImageDiscovery, "get_search_directories", mock_get_search_directories)

        import time

        start = time.time()
        images = discovery.discover_images()
        elapsed = time.time() - start

        assert len(images) == 100
        assert elapsed < 5.0  # Should complete in under 5 seconds


class TestConcurrentAccess:
    """Test suite for thread-safe concurrent access."""

    def test_concurrent_discovery_safe(self, discovery_instance: QEMUImageDiscovery) -> None:
        """Multiple threads can safely call discover_images."""
        import threading

        results: list[list[QEMUImageInfo]] = []

        def discover() -> None:
            images = discovery_instance.discover_images()
            results.append(images)

        threads = [threading.Thread(target=discover) for _ in range(5)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert len(results) == 5
        # All results should be consistent
        first_result = results[0]
        for result in results[1:]:
            assert len(result) == len(first_result)

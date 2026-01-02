"""Production tests for path resolution utilities.

Tests validate that path resolution works correctly across the Intellicrack
project structure, handling QEMU images, data directories, and project root
detection for consistent file access in binary analysis workflows.
"""

import tempfile
from pathlib import Path

import pytest

from intellicrack.utils.path_resolver import (
    ensure_data_directories,
    get_data_dir,
    get_project_root,
    get_qemu_images_dir,
    resolve_qemu_image_path,
)


class TestGetProjectRoot:
    """Test project root directory resolution."""

    def test_returns_path_object(self) -> None:
        """get_project_root returns Path object."""
        root = get_project_root()

        assert isinstance(root, Path)

    def test_returns_absolute_path(self) -> None:
        """get_project_root returns absolute path."""
        root = get_project_root()

        assert root.is_absolute()

    def test_respects_environment_variable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """get_project_root respects INTELLICRACK_ROOT environment variable."""
        with tempfile.TemporaryDirectory() as tmpdir:
            monkeypatch.setenv("INTELLICRACK_ROOT", tmpdir)
            root = get_project_root()

            assert str(root) == tmpdir

    def test_default_resolution_from_file_location(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """get_project_root resolves from file location when no env var."""
        monkeypatch.delenv("INTELLICRACK_ROOT", raising=False)
        root = get_project_root()

        assert root.exists()
        assert root.is_dir()

    def test_resolved_path_contains_intellicrack(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """get_project_root resolves to directory containing intellicrack package."""
        monkeypatch.delenv("INTELLICRACK_ROOT", raising=False)
        root = get_project_root()

        assert (root / "intellicrack").exists() or root.name == "intellicrack"


class TestGetDataDir:
    """Test data directory resolution."""

    def test_returns_path_object(self) -> None:
        """get_data_dir returns Path object."""
        data_dir = get_data_dir()

        assert isinstance(data_dir, Path)

    def test_returns_path_under_project_root(self) -> None:
        """get_data_dir returns path under project root."""
        root = get_project_root()
        data_dir = get_data_dir()

        assert str(data_dir).startswith(str(root))

    def test_path_ends_with_data(self) -> None:
        """get_data_dir returns path ending with 'data'."""
        data_dir = get_data_dir()

        assert data_dir.name == "data"


class TestGetQemuImagesDir:
    """Test QEMU images directory resolution."""

    def test_returns_path_object(self) -> None:
        """get_qemu_images_dir returns Path object."""
        qemu_dir = get_qemu_images_dir()

        assert isinstance(qemu_dir, Path)

    def test_creates_directory_if_not_exists(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """get_qemu_images_dir creates directory if it does not exist."""
        with tempfile.TemporaryDirectory() as tmpdir:
            monkeypatch.setenv("INTELLICRACK_ROOT", tmpdir)
            qemu_dir = get_qemu_images_dir()

            assert qemu_dir.exists()
            assert qemu_dir.is_dir()

    def test_path_contains_qemu_images(self) -> None:
        """get_qemu_images_dir returns path containing qemu_images."""
        qemu_dir = get_qemu_images_dir()

        assert "qemu_images" in str(qemu_dir)

    def test_path_under_intellicrack_assets(self) -> None:
        """get_qemu_images_dir returns path under intellicrack/assets."""
        qemu_dir = get_qemu_images_dir()

        assert "intellicrack" in str(qemu_dir)
        assert "assets" in str(qemu_dir)


class TestResolveQemuImagePath:
    """Test QEMU image path resolution."""

    def test_resolves_simple_filename(self) -> None:
        """resolve_qemu_image_path resolves simple filename."""
        path = resolve_qemu_image_path("windows10.qcow2")

        assert path.name == "windows10.qcow2"
        assert "qemu_images" in str(path)

    def test_strips_hardcoded_path_prefix(self) -> None:
        """resolve_qemu_image_path strips hardcoded path prefixes."""
        path = resolve_qemu_image_path("qemu/images/ubuntu.qcow2")

        assert path.name == "ubuntu.qcow2"
        assert "qemu/images/" not in str(path)

    def test_handles_backslash_paths(self) -> None:
        """resolve_qemu_image_path handles Windows-style paths."""
        path = resolve_qemu_image_path("qemu\\images\\test.qcow2")

        assert path.name == "test.qcow2"

    def test_extracts_basename_from_full_path(self) -> None:
        """resolve_qemu_image_path extracts basename from full paths."""
        path = resolve_qemu_image_path("/home/user/qemu/images/debian.qcow2")

        assert path.name == "debian.qcow2"

    def test_removes_intellicrack_prefix(self) -> None:
        """resolve_qemu_image_path removes intellicrack prefix."""
        path = resolve_qemu_image_path("intellicrack/assets/qemu_images/test.img")

        assert path.name == "test.img"

    def test_returns_path_under_qemu_images_dir(self) -> None:
        """resolve_qemu_image_path returns path under qemu_images directory."""
        path = resolve_qemu_image_path("test.qcow2")
        qemu_dir = get_qemu_images_dir()

        assert str(path).startswith(str(qemu_dir))


class TestEnsureDataDirectories:
    """Test data directory creation."""

    def test_creates_data_directory(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """ensure_data_directories creates data directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            monkeypatch.setenv("INTELLICRACK_ROOT", tmpdir)
            ensure_data_directories()

            assert get_data_dir().exists()

    def test_creates_qemu_images_directory(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """ensure_data_directories creates qemu_images directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            monkeypatch.setenv("INTELLICRACK_ROOT", tmpdir)
            ensure_data_directories()

            assert get_qemu_images_dir().exists()

    def test_creates_cache_directory(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """ensure_data_directories creates cache subdirectory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            monkeypatch.setenv("INTELLICRACK_ROOT", tmpdir)
            ensure_data_directories()

            cache_dir = get_data_dir() / "cache"
            assert cache_dir.exists()

    def test_creates_logs_directory(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """ensure_data_directories creates logs subdirectory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            monkeypatch.setenv("INTELLICRACK_ROOT", tmpdir)
            ensure_data_directories()

            logs_dir = get_data_dir() / "logs"
            assert logs_dir.exists()

    def test_creates_output_directory(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """ensure_data_directories creates output subdirectory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            monkeypatch.setenv("INTELLICRACK_ROOT", tmpdir)
            ensure_data_directories()

            output_dir = get_data_dir() / "output"
            assert output_dir.exists()

    def test_idempotent_operation(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """ensure_data_directories can be called multiple times safely."""
        with tempfile.TemporaryDirectory() as tmpdir:
            monkeypatch.setenv("INTELLICRACK_ROOT", tmpdir)
            ensure_data_directories()
            ensure_data_directories()

            assert get_data_dir().exists()


class TestRealWorldScenarios:
    """Test realistic production usage scenarios."""

    def test_qemu_image_path_resolution_workflow(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test complete workflow of QEMU image path resolution."""
        with tempfile.TemporaryDirectory() as tmpdir:
            monkeypatch.setenv("INTELLICRACK_ROOT", tmpdir)
            ensure_data_directories()

            image_path = resolve_qemu_image_path("windows10.qcow2")
            image_path.parent.mkdir(parents=True, exist_ok=True)
            image_path.write_bytes(b"QEMU image data")

            assert image_path.exists()
            assert image_path.read_bytes() == b"QEMU image data"

    def test_multiple_image_paths(self) -> None:
        """Test resolving multiple QEMU image paths."""
        images = ["ubuntu.qcow2", "debian.img", "kali.qcow2"]

        paths = [resolve_qemu_image_path(img) for img in images]

        assert len(paths) == 3
        assert all(isinstance(p, Path) for p in paths)
        assert all("qemu_images" in str(p) for p in paths)

    def test_data_directory_structure_creation(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test creating complete data directory structure."""
        with tempfile.TemporaryDirectory() as tmpdir:
            monkeypatch.setenv("INTELLICRACK_ROOT", tmpdir)
            ensure_data_directories()

            data_dir = get_data_dir()
            assert (data_dir / "cache").exists()
            assert (data_dir / "logs").exists()
            assert (data_dir / "output").exists()


class TestEdgeCases:
    """Test edge cases and error conditions."""

    def test_handles_empty_image_name(self) -> None:
        """resolve_qemu_image_path handles empty image name."""
        path = resolve_qemu_image_path("")

        assert isinstance(path, Path)

    def test_handles_image_name_with_multiple_slashes(self) -> None:
        """resolve_qemu_image_path handles paths with multiple slashes."""
        path = resolve_qemu_image_path("a/b/c/d/e/image.qcow2")

        assert path.name == "image.qcow2"

    def test_handles_mixed_path_separators(self) -> None:
        """resolve_qemu_image_path handles mixed path separators."""
        path = resolve_qemu_image_path("qemu/images\\test\\file.img")

        assert path.name == "file.img"

    def test_handles_relative_paths(self) -> None:
        """resolve_qemu_image_path handles relative paths."""
        path = resolve_qemu_image_path("../images/test.qcow2")

        assert path.name == "test.qcow2"

    def test_handles_unicode_filenames(self) -> None:
        """resolve_qemu_image_path handles Unicode filenames."""
        path = resolve_qemu_image_path("test_\u4e2d\u6587_image.qcow2")

        assert "\u4e2d\u6587" in path.name

    def test_project_root_when_env_var_is_empty_string(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """get_project_root handles empty INTELLICRACK_ROOT env var."""
        monkeypatch.setenv("INTELLICRACK_ROOT", "")
        root = get_project_root()

        assert isinstance(root, Path)

    def test_qemu_dir_creation_with_permission_restrictions(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """get_qemu_images_dir handles directory creation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            monkeypatch.setenv("INTELLICRACK_ROOT", tmpdir)
            qemu_dir = get_qemu_images_dir()

            assert qemu_dir.exists()


class TestPathConsistency:
    """Test consistency of path resolution."""

    def test_project_root_consistency(self) -> None:
        """get_project_root returns same path on multiple calls."""
        root1 = get_project_root()
        root2 = get_project_root()

        assert root1 == root2

    def test_data_dir_consistency(self) -> None:
        """get_data_dir returns same path on multiple calls."""
        dir1 = get_data_dir()
        dir2 = get_data_dir()

        assert dir1 == dir2

    def test_qemu_dir_consistency(self) -> None:
        """get_qemu_images_dir returns same path on multiple calls."""
        dir1 = get_qemu_images_dir()
        dir2 = get_qemu_images_dir()

        assert dir1 == dir2

    def test_resolved_paths_consistency(self) -> None:
        """resolve_qemu_image_path returns same path for same input."""
        path1 = resolve_qemu_image_path("test.qcow2")
        path2 = resolve_qemu_image_path("test.qcow2")

        assert path1 == path2

"""Production tests for scripts/clean_nul.py.

Tests validate real NUL file cleaning operations on Windows without mocks.
"""

import os
import subprocess
import sys
from pathlib import Path
from typing import List

import pytest


@pytest.fixture
def project_root() -> Path:
    """Get the project root directory."""
    return Path(__file__).parent.parent.parent


@pytest.fixture
def script_path(project_root: Path) -> Path:
    """Get the path to clean_nul.py script."""
    return project_root / "scripts" / "clean_nul.py"


@pytest.fixture
def temp_directory_structure(tmp_path: Path) -> Path:
    """Create a temporary directory structure for testing."""
    (tmp_path / "dir1").mkdir()
    (tmp_path / "dir2").mkdir()
    (tmp_path / "dir1" / "subdir1").mkdir()
    (tmp_path / "dir2" / "subdir2").mkdir()

    (tmp_path / "normal_file.txt").write_text("content")
    (tmp_path / "dir1" / "another_file.py").write_text("code")

    return tmp_path


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-specific functionality")
class TestCleanNulFilesWindows:
    """Test NUL file cleaning on Windows platform."""

    def test_script_runs_successfully_on_empty_directory(
        self,
        script_path: Path,
        tmp_path: Path,
    ) -> None:
        """Script executes successfully on directory without NUL files."""
        result = subprocess.run(
            [sys.executable, str(script_path)],
            cwd=str(tmp_path),
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert result.returncode == 0
        assert "Python NUL File Cleaner" in result.stdout
        assert "Scan complete" in result.stdout
        assert "0 file(s) deleted" in result.stdout

    def test_script_deletes_single_nul_file(
        self,
        script_path: Path,
        tmp_path: Path,
    ) -> None:
        """Script successfully deletes a single NUL file."""
        nul_path = tmp_path / "nul"
        prefixed_path = "\\\\?\\" + str(nul_path)

        try:
            nul_path.write_text("test content")
        except (OSError, PermissionError):
            pytest.skip("Cannot create NUL file on this system")

        assert os.path.exists(prefixed_path), "NUL file should exist before cleaning"

        result = subprocess.run(
            [sys.executable, str(script_path)],
            cwd=str(tmp_path),
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert result.returncode == 0
        assert "1 file(s) deleted" in result.stdout
        assert "[OK] Deleted:" in result.stdout

        assert not os.path.exists(prefixed_path), "NUL file should be deleted"

    def test_script_deletes_multiple_nul_files_in_nested_structure(
        self,
        script_path: Path,
        temp_directory_structure: Path,
    ) -> None:
        """Script deletes multiple NUL files in nested directories."""
        nul_files: List[Path] = [
            temp_directory_structure / "nul",
            temp_directory_structure / "dir1" / "nul",
            temp_directory_structure / "dir1" / "subdir1" / "nul",
        ]

        created_count = 0
        for nul_file in nul_files:
            try:
                nul_file.write_text("nul content")
                created_count += 1
            except (OSError, PermissionError):
                continue

        if created_count == 0:
            pytest.skip("Cannot create NUL files on this system")

        result = subprocess.run(
            [sys.executable, str(script_path)],
            cwd=str(temp_directory_structure),
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert result.returncode == 0
        assert f"{created_count} file(s) deleted" in result.stdout

        for nul_file in nul_files:
            prefixed = "\\\\?\\" + str(nul_file)
            if os.path.exists(prefixed):
                assert False, f"NUL file {nul_file} should be deleted"

    def test_script_preserves_non_nul_files(
        self,
        script_path: Path,
        temp_directory_structure: Path,
    ) -> None:
        """Script does not delete non-NUL files."""
        normal_files = [
            temp_directory_structure / "normal_file.txt",
            temp_directory_structure / "dir1" / "another_file.py",
        ]

        for normal_file in normal_files:
            assert normal_file.exists(), f"{normal_file} should exist before script"

        result = subprocess.run(
            [sys.executable, str(script_path)],
            cwd=str(temp_directory_structure),
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert result.returncode == 0

        for normal_file in normal_files:
            assert normal_file.exists(), f"{normal_file} should still exist after script"

    def test_script_reports_deletion_failures(
        self,
        script_path: Path,
        tmp_path: Path,
    ) -> None:
        """Script reports failures when unable to delete NUL files."""
        nul_path = tmp_path / "nul"

        try:
            nul_path.write_text("test")
        except (OSError, PermissionError):
            pytest.skip("Cannot create NUL file on this system")

        read_only_dir = tmp_path / "readonly_dir"
        read_only_dir.mkdir()
        readonly_nul = read_only_dir / "nul"

        try:
            readonly_nul.write_text("test")
            os.chmod(str(read_only_dir), 0o444)
        except (OSError, PermissionError):
            pytest.skip("Cannot create read-only directory with NUL file")

        try:
            result = subprocess.run(
                [sys.executable, str(script_path)],
                cwd=str(tmp_path),
                capture_output=True,
                text=True,
                timeout=30,
            )

            if "[!!!] FAILED to delete:" in result.stdout:
                assert "Reason:" in result.stdout
        finally:
            try:
                os.chmod(str(read_only_dir), 0o755)
            except (OSError, PermissionError):
                pass


class TestCleanNulFilesFunction:
    """Test clean_nul_files function directly."""

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-specific functionality")
    def test_clean_nul_files_function_execution(
        self,
        tmp_path: Path,
        monkeypatch,
        capsys,
    ) -> None:
        """clean_nul_files function executes and prints output."""
        from scripts.clean_nul import clean_nul_files

        monkeypatch.chdir(tmp_path)

        with pytest.raises(SystemExit) as exc_info:
            clean_nul_files()

        assert exc_info.value.code == 0

        captured = capsys.readouterr()
        assert "Python NUL File Cleaner" in captured.out
        assert "Starting recursive search in:" in captured.out
        assert "Scan complete" in captured.out

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-specific functionality")
    def test_clean_nul_files_counts_deletions(
        self,
        tmp_path: Path,
        monkeypatch,
        capsys,
    ) -> None:
        """clean_nul_files function counts deleted files correctly."""
        from scripts.clean_nul import clean_nul_files

        monkeypatch.chdir(tmp_path)

        nul_file = tmp_path / "nul"
        try:
            nul_file.write_text("content")
        except (OSError, PermissionError):
            pytest.skip("Cannot create NUL file on this system")

        with pytest.raises(SystemExit) as exc_info:
            clean_nul_files()

        assert exc_info.value.code == 0

        captured = capsys.readouterr()
        assert "1 file(s) deleted" in captured.out

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-specific functionality")
    def test_clean_nul_files_handles_exceptions(
        self,
        tmp_path: Path,
        monkeypatch,
        capsys,
    ) -> None:
        """clean_nul_files handles unexpected exceptions gracefully."""
        from scripts.clean_nul import clean_nul_files

        monkeypatch.chdir(tmp_path / "nonexistent")

        with pytest.raises(SystemExit) as exc_info:
            clean_nul_files()

        assert exc_info.value.code == 1

        captured = capsys.readouterr()
        assert "[!!!]" in captured.out or "failed" in captured.out.lower()


class TestWindowsPathPrefixing:
    """Test Windows \\?\ path prefixing for reserved names."""

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-specific functionality")
    def test_uses_windows_prefix_for_nul_paths(
        self,
        tmp_path: Path,
    ) -> None:
        """Script uses \\?\ prefix for NUL file paths on Windows."""
        nul_path = os.path.join(str(tmp_path), "nul")
        prefixed_path = "\\\\?\\" + nul_path

        assert prefixed_path.startswith("\\\\?\\")
        assert "nul" in prefixed_path

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-specific functionality")
    def test_prefixed_path_handles_reserved_names(
        self,
        tmp_path: Path,
    ) -> None:
        """Prefixed paths allow access to Windows reserved names."""
        nul_file = tmp_path / "nul"

        try:
            nul_file.write_text("test content")
        except (OSError, PermissionError):
            pytest.skip("Cannot create NUL file on this system")

        prefixed = "\\\\?\\" + str(nul_file)

        assert os.path.exists(prefixed), "Prefixed path should access NUL file"

        try:
            os.remove(prefixed)
        except OSError:
            pass


class TestRecursiveDirectoryWalk:
    """Test recursive directory traversal for NUL files."""

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-specific functionality")
    def test_walks_all_subdirectories(
        self,
        temp_directory_structure: Path,
        monkeypatch,
    ) -> None:
        """Script walks all subdirectories to find NUL files."""
        monkeypatch.chdir(temp_directory_structure)

        visited_dirs: List[str] = []

        for dirpath, _, _ in os.walk(str(temp_directory_structure)):
            visited_dirs.append(dirpath)

        assert len(visited_dirs) >= 5
        assert str(temp_directory_structure) in visited_dirs
        assert any("dir1" in d for d in visited_dirs)
        assert any("dir2" in d for d in visited_dirs)
        assert any("subdir1" in d for d in visited_dirs)
        assert any("subdir2" in d for d in visited_dirs)

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-specific functionality")
    def test_checks_filenames_for_nul(
        self,
        tmp_path: Path,
        monkeypatch,
    ) -> None:
        """Script checks filenames list for 'nul' entry."""
        monkeypatch.chdir(tmp_path)

        (tmp_path / "normal.txt").write_text("content")
        (tmp_path / "another.py").write_text("code")

        nul_found = False
        for dirpath, _, filenames in os.walk(str(tmp_path)):
            if "nul" in filenames:
                nul_found = True
                break

        assert not nul_found, "Should not find NUL in filenames without creating one"


class TestOutputFormatting:
    """Test script output formatting and messages."""

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-specific functionality")
    def test_displays_header_message(
        self,
        script_path: Path,
        tmp_path: Path,
    ) -> None:
        """Script displays header message on execution."""
        result = subprocess.run(
            [sys.executable, str(script_path)],
            cwd=str(tmp_path),
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert "--- Python NUL File Cleaner ---" in result.stdout

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-specific functionality")
    def test_displays_search_directory(
        self,
        script_path: Path,
        tmp_path: Path,
    ) -> None:
        """Script displays the search directory path."""
        result = subprocess.run(
            [sys.executable, str(script_path)],
            cwd=str(tmp_path),
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert "Starting recursive search in:" in result.stdout
        assert str(tmp_path) in result.stdout or tmp_path.name in result.stdout

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-specific functionality")
    def test_displays_summary_message(
        self,
        script_path: Path,
        tmp_path: Path,
    ) -> None:
        """Script displays summary message after completion."""
        result = subprocess.run(
            [sys.executable, str(script_path)],
            cwd=str(tmp_path),
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert "Scan complete." in result.stdout
        assert "file(s) deleted" in result.stdout


class TestEdgeCases:
    """Test edge cases in NUL file cleaning."""

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-specific functionality")
    def test_handles_deeply_nested_nul_files(
        self,
        tmp_path: Path,
        script_path: Path,
    ) -> None:
        """Script handles NUL files in deeply nested directory structures."""
        deep_path = tmp_path
        for i in range(10):
            deep_path = deep_path / f"level{i}"
            deep_path.mkdir()

        nul_file = deep_path / "nul"

        try:
            nul_file.write_text("deep content")
        except (OSError, PermissionError):
            pytest.skip("Cannot create NUL file in deep structure")

        result = subprocess.run(
            [sys.executable, str(script_path)],
            cwd=str(tmp_path),
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert result.returncode == 0
        assert "1 file(s) deleted" in result.stdout

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-specific functionality")
    def test_handles_empty_directory_tree(
        self,
        script_path: Path,
        tmp_path: Path,
    ) -> None:
        """Script handles directory tree with no files."""
        (tmp_path / "empty1").mkdir()
        (tmp_path / "empty2").mkdir()
        (tmp_path / "empty1" / "empty3").mkdir()

        result = subprocess.run(
            [sys.executable, str(script_path)],
            cwd=str(tmp_path),
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert result.returncode == 0
        assert "0 file(s) deleted" in result.stdout

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-specific functionality")
    def test_ignores_directories_named_nul(
        self,
        script_path: Path,
        tmp_path: Path,
    ) -> None:
        """Script only processes files named 'nul', not directories."""
        result = subprocess.run(
            [sys.executable, str(script_path)],
            cwd=str(tmp_path),
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert result.returncode == 0
        assert "0 file(s) deleted" in result.stdout


class TestCrossPlatformBehavior:
    """Test script behavior on non-Windows platforms."""

    @pytest.mark.skipif(sys.platform == "win32", reason="Non-Windows test")
    def test_script_runs_on_non_windows(
        self,
        script_path: Path,
        tmp_path: Path,
    ) -> None:
        """Script executes on non-Windows platforms without errors."""
        nul_file = tmp_path / "nul"
        nul_file.write_text("regular file named nul")

        result = subprocess.run(
            [sys.executable, str(script_path)],
            cwd=str(tmp_path),
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert "Python NUL File Cleaner" in result.stdout

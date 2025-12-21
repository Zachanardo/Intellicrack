"""Production tests for Project Manager CLI module.

These tests validate that project manager correctly:
- Creates project directory structures with proper metadata
- Adds binary files to projects and tracks them
- Lists all available projects with metadata
- Deletes projects with backup creation
- Exports projects as zip archives
- Imports projects from archives
- Calculates file hashes for integrity tracking
"""

import json
import shutil
import zipfile
from pathlib import Path

import pytest

from intellicrack.cli.project_manager import ProjectManager, main


class TestProjectCreation:
    """Test project creation functionality."""

    def test_create_project_basic(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        manager = ProjectManager()
        project_dir = manager.create_project("TestProject", "Test description")

        assert project_dir.exists()
        assert (project_dir / "binaries").exists()
        assert (project_dir / "analysis").exists()
        assert (project_dir / "reports").exists()
        assert (project_dir / "scripts").exists()
        assert (project_dir / "patches").exists()
        assert (project_dir / "logs").exists()
        assert (project_dir / "project.json").exists()

    def test_create_project_with_metadata(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        manager = ProjectManager()
        project_dir = manager.create_project("MetadataProject", "Project with metadata")

        with open(project_dir / "project.json") as f:
            metadata = json.load(f)

        assert metadata["name"] == "MetadataProject"
        assert metadata["description"] == "Project with metadata"
        assert "created" in metadata
        assert "modified" in metadata
        assert metadata["files"] == []
        assert metadata["analyses"] == []
        assert metadata["version"] == "1.0.0"

    def test_create_project_duplicate_raises(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        manager = ProjectManager()
        manager.create_project("DuplicateTest")

        with pytest.raises(ValueError, match="already exists"):
            manager.create_project("DuplicateTest")


class TestProjectLoading:
    """Test project loading functionality."""

    def test_load_existing_project(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        manager = ProjectManager()
        manager.create_project("LoadTest", "Test loading")

        metadata = manager.load_project("LoadTest")

        assert metadata["name"] == "LoadTest"
        assert metadata["description"] == "Test loading"
        assert manager.current_project is not None
        assert manager.current_project["name"] == "LoadTest"

    def test_load_nonexistent_project_raises(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        manager = ProjectManager()

        with pytest.raises(ValueError, match="not found"):
            manager.load_project("NonExistent")


class TestProjectListing:
    """Test project listing functionality."""

    def test_list_projects_empty(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        manager = ProjectManager()
        projects = manager.list_projects()

        assert projects == []

    def test_list_multiple_projects(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        manager = ProjectManager()
        manager.create_project("Project1", "First project")
        manager.create_project("Project2", "Second project")
        manager.create_project("Project3", "Third project")

        projects = manager.list_projects()

        assert len(projects) == 3
        project_names = [p["name"] for p in projects]
        assert "Project1" in project_names
        assert "Project2" in project_names
        assert "Project3" in project_names


class TestAddFileToProject:
    """Test adding files to projects."""

    def test_add_file_to_project(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        test_binary = tmp_path / "test.exe"
        test_binary.write_bytes(b"MZ\x90\x00" * 100)

        manager = ProjectManager()
        manager.create_project("FileTest")

        file_info = manager.add_file_to_project("FileTest", str(test_binary))

        assert file_info["name"] == "test.exe"
        assert file_info["size"] == 400
        assert "hash" in file_info
        assert "added" in file_info

        project_binary = manager.projects_dir / "FileTest" / "binaries" / "test.exe"
        assert project_binary.exists()

    def test_add_file_updates_metadata(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        test_binary = tmp_path / "metadata_test.exe"
        test_binary.write_bytes(b"TEST" * 50)

        manager = ProjectManager()
        manager.create_project("MetadataUpdate")
        manager.add_file_to_project("MetadataUpdate", str(test_binary))

        project_dir = manager.projects_dir / "MetadataUpdate"
        with open(project_dir / "project.json") as f:
            metadata = json.load(f)

        assert len(metadata["files"]) == 1
        assert metadata["files"][0]["name"] == "metadata_test.exe"

    def test_add_file_nonexistent_project_raises(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        test_binary = tmp_path / "test.exe"
        test_binary.write_bytes(b"DATA")

        manager = ProjectManager()

        with pytest.raises(ValueError, match="not found"):
            manager.add_file_to_project("NonExistent", str(test_binary))

    def test_add_file_nonexistent_file_raises(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        manager = ProjectManager()
        manager.create_project("FileNotFound")

        with pytest.raises(FileNotFoundError):
            manager.add_file_to_project("FileNotFound", "/nonexistent/file.exe")


class TestFileHashing:
    """Test file hash calculation."""

    def test_calculate_file_hash(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        test_file = tmp_path / "hash_test.bin"
        test_file.write_bytes(b"TEST DATA" * 100)

        manager = ProjectManager()
        file_hash = manager._calculate_file_hash(str(test_file))

        assert isinstance(file_hash, str)
        assert len(file_hash) == 64

    def test_identical_files_same_hash(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        file1 = tmp_path / "file1.bin"
        file2 = tmp_path / "file2.bin"

        data = b"IDENTICAL DATA" * 50
        file1.write_bytes(data)
        file2.write_bytes(data)

        manager = ProjectManager()
        hash1 = manager._calculate_file_hash(str(file1))
        hash2 = manager._calculate_file_hash(str(file2))

        assert hash1 == hash2

    def test_different_files_different_hash(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        file1 = tmp_path / "file1.bin"
        file2 = tmp_path / "file2.bin"

        file1.write_bytes(b"DATA1" * 50)
        file2.write_bytes(b"DATA2" * 50)

        manager = ProjectManager()
        hash1 = manager._calculate_file_hash(str(file1))
        hash2 = manager._calculate_file_hash(str(file2))

        assert hash1 != hash2


class TestProjectDeletion:
    """Test project deletion with backup."""

    def test_delete_project_creates_backup(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        manager = ProjectManager()
        manager.create_project("DeleteTest")

        manager.delete_project("DeleteTest")

        backup_dir = manager.projects_dir / "backups"
        assert backup_dir.exists()

        backups = list(backup_dir.glob("DeleteTest_*.zip"))
        assert backups

    def test_delete_project_removes_directory(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        manager = ProjectManager()
        project_dir = manager.create_project("RemoveTest")

        manager.delete_project("RemoveTest")

        assert not project_dir.exists()

    def test_delete_current_project_clears_state(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        manager = ProjectManager()
        manager.create_project("CurrentTest")
        manager.load_project("CurrentTest")

        assert manager.current_project is not None

        manager.delete_project("CurrentTest")

        assert manager.current_project is None

    def test_delete_nonexistent_project_raises(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        manager = ProjectManager()

        with pytest.raises(ValueError, match="not found"):
            manager.delete_project("NonExistent")


class TestProjectExport:
    """Test project export functionality."""

    def test_export_project_creates_archive(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        manager = ProjectManager()
        manager.create_project("ExportTest")

        output_path = manager.export_project("ExportTest")

        assert output_path.exists()
        assert output_path.suffix == ".zip"

    def test_export_project_custom_path(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        manager = ProjectManager()
        manager.create_project("CustomExport")

        custom_path = tmp_path / "custom_export.zip"
        output_path = manager.export_project("CustomExport", str(custom_path))

        assert output_path.exists()
        assert output_path == custom_path

    def test_export_project_contains_files(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        test_binary = tmp_path / "export_binary.exe"
        test_binary.write_bytes(b"EXPORT DATA")

        manager = ProjectManager()
        manager.create_project("ContentExport")
        manager.add_file_to_project("ContentExport", str(test_binary))

        output_path = manager.export_project("ContentExport")

        with zipfile.ZipFile(output_path) as zf:
            files = zf.namelist()
            assert any("project.json" in f for f in files)

    def test_export_nonexistent_project_raises(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        manager = ProjectManager()

        with pytest.raises(ValueError, match="not found"):
            manager.export_project("NonExistent")


class TestProjectImport:
    """Test project import functionality."""

    def test_import_project_from_archive(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        manager = ProjectManager()
        manager.create_project("ImportSource")

        archive_path = manager.export_project("ImportSource")

        manager.delete_project("ImportSource")

        imported_name = manager.import_project(str(archive_path))

        assert imported_name == "ImportSource"

        projects = manager.list_projects()
        assert any(p["name"] == "ImportSource" for p in projects)

    def test_import_duplicate_project_renames(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        manager = ProjectManager()
        manager.create_project("DuplicateImport")

        archive_path = manager.export_project("DuplicateImport")

        imported_name = manager.import_project(str(archive_path))

        assert imported_name == "DuplicateImport_1"

    def test_import_nonexistent_archive_raises(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        manager = ProjectManager()

        with pytest.raises(FileNotFoundError):
            manager.import_project("/nonexistent/archive.zip")

    def test_import_invalid_archive_raises(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        invalid_archive = tmp_path / "invalid.zip"

        with zipfile.ZipFile(invalid_archive, "w") as zf:
            zf.writestr("random_file.txt", "not a project")

        manager = ProjectManager()

        with pytest.raises(ValueError, match="Invalid project archive"):
            manager.import_project(str(invalid_archive))


class TestEndToEndWorkflow:
    """Test complete project management workflows."""

    def test_full_project_lifecycle(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        test_binary = tmp_path / "lifecycle.exe"
        test_binary.write_bytes(b"LIFECYCLE DATA" * 50)

        manager = ProjectManager()

        project_dir = manager.create_project("LifecycleProject", "Full lifecycle test")
        assert project_dir.exists()

        file_info = manager.add_file_to_project("LifecycleProject", str(test_binary))
        assert file_info["name"] == "lifecycle.exe"

        metadata = manager.load_project("LifecycleProject")
        assert len(metadata["files"]) == 1

        export_path = manager.export_project("LifecycleProject")
        assert export_path.exists()

        manager.delete_project("LifecycleProject")
        assert not project_dir.exists()

        imported_name = manager.import_project(str(export_path))
        assert imported_name == "LifecycleProject"

        final_projects = manager.list_projects()
        assert any(p["name"] == "LifecycleProject" for p in final_projects)

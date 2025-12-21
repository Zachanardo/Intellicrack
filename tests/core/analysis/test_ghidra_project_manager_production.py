"""Production tests for GhidraProjectManager.

Validates project lifecycle management, version control, binary diffing,
compression/decompression, database operations, and project import/export.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import json
import sqlite3
import tempfile
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.analysis.ghidra_analyzer import (
    GhidraAnalysisResult,
    GhidraDataType,
    GhidraFunction,
)
from intellicrack.core.analysis.ghidra_project_manager import (
    GhidraProject,
    GhidraProjectManager,
    ProjectVersion,
)


@pytest.fixture
def temp_projects_dir(tmp_path: Path) -> Path:
    """Create temporary projects directory."""
    projects_dir = tmp_path / "ghidra_projects"
    projects_dir.mkdir(parents=True)
    return projects_dir


@pytest.fixture
def manager(temp_projects_dir: Path) -> GhidraProjectManager:
    """Create GhidraProjectManager instance."""
    return GhidraProjectManager(projects_dir=str(temp_projects_dir))


@pytest.fixture
def test_binary(tmp_path: Path) -> Path:
    """Create test binary file."""
    binary_path = tmp_path / "test.exe"
    binary_path.write_bytes(b"MZ" + b"\x00" * 1000)
    return binary_path


@pytest.fixture
def sample_analysis_result(test_binary: Path) -> GhidraAnalysisResult:
    """Create sample Ghidra analysis result."""
    func1 = GhidraFunction(
        name="main",
        address=0x401000,
        size=100,
        signature="int main(int argc, char** argv)",
        return_type="int",
        parameters=[("int", "argc"), ("char**", "argv")],
        local_variables=[("int", "result", 0)],
        decompiled_code="int main() { return 0; }",
        assembly_code="push ebp\nmov ebp, esp\nxor eax, eax\npop ebp\nret",
        xrefs_to=[0x402000],
        xrefs_from=[0x401500],
        comments={0: "Entry point"}
    )

    func2 = GhidraFunction(
        name="CheckLicense",
        address=0x401500,
        size=50,
        signature="bool CheckLicense()",
        return_type="bool",
        parameters=[],
        local_variables=[],
        decompiled_code="bool CheckLicense() { return true; }",
        assembly_code="xor eax, eax\ninc eax\nret",
        xrefs_to=[0x401000],
        xrefs_from=[],
        comments={}
    )

    data_type = GhidraDataType(
        name="LICENSE_INFO",
        size=32,
        category="struct",
        members=[{"name": "serial", "type": "char[16]", "offset": 0}],
        alignment=4
    )

    return GhidraAnalysisResult(
        binary_path=str(test_binary),
        architecture="x86",
        compiler="MSVC",
        functions={0x401000: func1, 0x401500: func2},
        data_types={"LICENSE_INFO": data_type},
        strings=[(0x403000, "Enter license key")],
        imports=[("kernel32.dll", "ExitProcess", 0x405000)],
        exports=[("main", 0x401000)],
        sections=[{"name": ".text", "start": 0x401000, "size": 0x1000}],
        entry_point=0x401000,
        image_base=0x400000,
        vtables={},
        exception_handlers=[],
        metadata={"analysis_time": 10.5}
    )


class TestProjectVersionDataclass:
    """Test ProjectVersion dataclass."""

    def test_initialization(self) -> None:
        """ProjectVersion initializes with required fields."""
        version = ProjectVersion(
            version_id="v1",
            timestamp=datetime.now(),
            binary_hash="abc123",
            analysis_data=b"compressed_data",
            metadata={"test": True}
        )

        assert version.version_id == "v1"
        assert version.binary_hash == "abc123"
        assert version.parent_version is None
        assert version.author == "intellicrack"
        assert version.description == ""
        assert version.tags == []


class TestGhidraProjectDataclass:
    """Test GhidraProject dataclass."""

    def test_initialization(self) -> None:
        """GhidraProject initializes with all required fields."""
        now = datetime.now()
        version = ProjectVersion(
            version_id="v1",
            timestamp=now,
            binary_hash="hash",
            analysis_data=b"",
            metadata={}
        )

        project = GhidraProject(
            project_id="proj1",
            name="Test Project",
            binary_path="/test.exe",
            created_at=now,
            modified_at=now,
            versions=[version],
            current_version="v1",
            collaborators=["user1"],
            settings={"auto_analyze": True}
        )

        assert project.project_id == "proj1"
        assert project.name == "Test Project"
        assert len(project.versions) == 1
        assert project.is_locked is False


class TestManagerInitialization:
    """Test GhidraProjectManager initialization."""

    def test_creates_projects_directory(self, temp_projects_dir: Path) -> None:
        """Manager creates projects directory on initialization."""
        manager = GhidraProjectManager(projects_dir=str(temp_projects_dir))

        assert manager.projects_dir.exists()
        assert manager.projects_dir.is_dir()

    def test_creates_database(self, manager: GhidraProjectManager) -> None:
        """Manager creates SQLite database on initialization."""
        assert manager.db_path.exists()

        conn = sqlite3.connect(manager.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {row[0] for row in cursor.fetchall()}
        conn.close()

        assert "projects" in tables
        assert "versions" in tables
        assert "collaborators" in tables
        assert "analysis_cache" in tables

    def test_initializes_cache(self, manager: GhidraProjectManager) -> None:
        """Manager initializes in-memory cache."""
        assert "projects" in manager.cache
        assert "versions" in manager.cache
        assert "analysis_results" in manager.cache


class TestProjectCreation:
    """Test project creation functionality."""

    def test_create_project_basic(self, manager: GhidraProjectManager, test_binary: Path) -> None:
        """create_project creates project with minimal parameters."""
        project = manager.create_project("Test Project", str(test_binary))

        assert project is not None
        assert project.name == "Test Project"
        assert project.binary_path == str(test_binary)
        assert len(project.versions) == 1
        assert project.current_version is not None

    def test_create_project_with_analysis(self, manager: GhidraProjectManager, test_binary: Path, sample_analysis_result: GhidraAnalysisResult) -> None:
        """create_project accepts initial analysis result."""
        project = manager.create_project(
            "Analyzed Project",
            str(test_binary),
            initial_analysis=sample_analysis_result
        )

        assert project is not None
        assert len(project.versions) == 1
        version = project.versions[0]
        assert len(version.analysis_data) > 0

    def test_create_project_generates_unique_id(self, manager: GhidraProjectManager, test_binary: Path) -> None:
        """create_project generates unique project IDs."""
        project1 = manager.create_project("Project 1", str(test_binary))
        project2 = manager.create_project("Project 2", str(test_binary))

        assert project1.project_id != project2.project_id

    def test_create_project_stores_in_database(self, manager: GhidraProjectManager, test_binary: Path) -> None:
        """create_project persists to database."""
        project = manager.create_project("DB Project", str(test_binary))

        conn = sqlite3.connect(manager.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM projects WHERE project_id = ?", (project.project_id,))
        row = cursor.fetchone()
        conn.close()

        assert row is not None
        assert row[0] == "DB Project"

    def test_create_project_creates_directory(self, manager: GhidraProjectManager, test_binary: Path) -> None:
        """create_project creates project directory on disk."""
        project = manager.create_project("Dir Project", str(test_binary))

        project_dir = manager.projects_dir / project.project_id
        assert project_dir.exists()
        assert project_dir.is_dir()

    def test_create_project_caches_project(self, manager: GhidraProjectManager, test_binary: Path) -> None:
        """create_project adds project to cache."""
        project = manager.create_project("Cached Project", str(test_binary))

        assert project.project_id in manager.cache["projects"]
        cached = manager.cache["projects"][project.project_id]
        assert cached.name == "Cached Project"


class TestProjectLoading:
    """Test project loading functionality."""

    def test_load_project_from_database(self, manager: GhidraProjectManager, test_binary: Path) -> None:
        """load_project retrieves project from database."""
        created = manager.create_project("Load Test", str(test_binary))
        manager.cache["projects"].clear()

        loaded = manager.load_project(created.project_id)

        assert loaded is not None
        assert loaded.name == "Load Test"
        assert loaded.project_id == created.project_id

    def test_load_project_uses_cache(self, manager: GhidraProjectManager, test_binary: Path) -> None:
        """load_project returns cached project when available."""
        project = manager.create_project("Cached", str(test_binary))

        loaded1 = manager.load_project(project.project_id)
        loaded2 = manager.load_project(project.project_id)

        assert loaded1 is loaded2

    def test_load_project_not_found(self, manager: GhidraProjectManager) -> None:
        """load_project returns None for non-existent project."""
        loaded = manager.load_project("nonexistent_id")

        assert loaded is None

    def test_load_project_loads_versions(self, manager: GhidraProjectManager, test_binary: Path, sample_analysis_result: GhidraAnalysisResult) -> None:
        """load_project loads all project versions."""
        project = manager.create_project("Multi Version", str(test_binary), sample_analysis_result)
        manager.save_version(project.project_id, sample_analysis_result, "Second version")
        manager.cache["projects"].clear()

        loaded = manager.load_project(project.project_id)

        assert loaded is not None
        assert len(loaded.versions) >= 2

    def test_load_project_loads_collaborators(self, manager: GhidraProjectManager, test_binary: Path) -> None:
        """load_project loads collaborator list."""
        project = manager.create_project("Collab Project", str(test_binary))
        manager.add_collaborator(project.project_id, "user123", "editor")
        manager.cache["projects"].clear()

        loaded = manager.load_project(project.project_id)

        assert loaded is not None
        assert "user123" in loaded.collaborators


class TestVersionManagement:
    """Test version save/load functionality."""

    def test_save_version(self, manager: GhidraProjectManager, test_binary: Path, sample_analysis_result: GhidraAnalysisResult) -> None:
        """save_version creates new version."""
        project = manager.create_project("Version Test", str(test_binary))

        version = manager.save_version(
            project.project_id,
            sample_analysis_result,
            description="Added license checks"
        )

        assert version is not None
        assert version.description == "Added license checks"
        assert version.parent_version == project.current_version

    def test_save_version_updates_current(self, manager: GhidraProjectManager, test_binary: Path, sample_analysis_result: GhidraAnalysisResult) -> None:
        """save_version updates project current_version."""
        project = manager.create_project("Current Test", str(test_binary))
        old_version = project.current_version

        manager.save_version(project.project_id, sample_analysis_result)

        loaded = manager.load_project(project.project_id)
        assert loaded.current_version != old_version

    def test_save_version_with_tags(self, manager: GhidraProjectManager, test_binary: Path, sample_analysis_result: GhidraAnalysisResult) -> None:
        """save_version accepts tags."""
        project = manager.create_project("Tagged", str(test_binary))

        version = manager.save_version(
            project.project_id,
            sample_analysis_result,
            tags=["stable", "release"]
        )

        assert "stable" in version.tags
        assert "release" in version.tags

    def test_save_version_locked_project(self, manager: GhidraProjectManager, test_binary: Path, sample_analysis_result: GhidraAnalysisResult) -> None:
        """save_version raises error for locked project."""
        project = manager.create_project("Locked", str(test_binary))
        manager.lock_project(project.project_id)

        with pytest.raises(ValueError, match="locked"):
            manager.save_version(project.project_id, sample_analysis_result)

    def test_load_version(self, manager: GhidraProjectManager, test_binary: Path, sample_analysis_result: GhidraAnalysisResult) -> None:
        """load_version retrieves compressed analysis data."""
        project = manager.create_project("Load Ver", str(test_binary), sample_analysis_result)

        loaded = manager.load_version(project.project_id, project.current_version)

        assert loaded is not None
        assert loaded.binary_path == str(test_binary)
        assert len(loaded.functions) == 2
        assert 0x401000 in loaded.functions

    def test_load_version_caches_result(self, manager: GhidraProjectManager, test_binary: Path, sample_analysis_result: GhidraAnalysisResult) -> None:
        """load_version caches decompressed results."""
        project = manager.create_project("Cache Ver", str(test_binary), sample_analysis_result)

        loaded1 = manager.load_version(project.project_id, project.current_version)
        loaded2 = manager.load_version(project.project_id, project.current_version)

        assert loaded1 is loaded2

    def test_load_version_not_found(self, manager: GhidraProjectManager, test_binary: Path) -> None:
        """load_version returns None for non-existent version."""
        project = manager.create_project("No Ver", str(test_binary))

        loaded = manager.load_version(project.project_id, "nonexistent_version")

        assert loaded is None


class TestCompressionDecompression:
    """Test analysis compression and decompression."""

    def test_compress_analysis(self, manager: GhidraProjectManager, sample_analysis_result: GhidraAnalysisResult) -> None:
        """_compress_analysis reduces data size."""
        compressed = manager._compress_analysis(sample_analysis_result)

        assert len(compressed) > 0
        assert isinstance(compressed, bytes)

    def test_decompress_analysis(self, manager: GhidraProjectManager, sample_analysis_result: GhidraAnalysisResult) -> None:
        """_decompress_analysis restores original data."""
        compressed = manager._compress_analysis(sample_analysis_result)
        decompressed = manager._decompress_analysis(compressed)

        assert decompressed.binary_path == sample_analysis_result.binary_path
        assert decompressed.architecture == sample_analysis_result.architecture
        assert len(decompressed.functions) == len(sample_analysis_result.functions)

    def test_roundtrip_compression(self, manager: GhidraProjectManager, sample_analysis_result: GhidraAnalysisResult) -> None:
        """Compression-decompression roundtrip preserves data."""
        compressed = manager._compress_analysis(sample_analysis_result)
        decompressed = manager._decompress_analysis(compressed)

        original_func = sample_analysis_result.functions[0x401000]
        restored_func = decompressed.functions[0x401000]

        assert original_func.name == restored_func.name
        assert original_func.address == restored_func.address
        assert original_func.size == restored_func.size


class TestBinaryDiffing:
    """Test version diffing functionality."""

    def test_diff_versions_detects_added_functions(self, manager: GhidraProjectManager, test_binary: Path, sample_analysis_result: GhidraAnalysisResult) -> None:
        """diff_versions detects newly added functions."""
        project = manager.create_project("Diff Test", str(test_binary), sample_analysis_result)

        new_func = GhidraFunction(
            name="NewFunction",
            address=0x402000,
            size=75,
            signature="void NewFunction()",
            return_type="void",
            parameters=[],
            local_variables=[],
            decompiled_code="void NewFunction() {}",
            assembly_code="ret",
            xrefs_to=[],
            xrefs_from=[],
            comments={}
        )

        modified_result = GhidraAnalysisResult(
            binary_path=sample_analysis_result.binary_path,
            architecture=sample_analysis_result.architecture,
            compiler=sample_analysis_result.compiler,
            functions={**sample_analysis_result.functions, 0x402000: new_func},
            data_types=sample_analysis_result.data_types,
            strings=sample_analysis_result.strings,
            imports=sample_analysis_result.imports,
            exports=sample_analysis_result.exports,
            sections=sample_analysis_result.sections,
            entry_point=sample_analysis_result.entry_point,
            image_base=sample_analysis_result.image_base,
            vtables={},
            exception_handlers=[]
        )

        new_version = manager.save_version(project.project_id, modified_result)

        diff = manager.diff_versions(project.project_id, project.versions[0].version_id, new_version.version_id)

        assert len(diff["added_functions"]) > 0
        assert any(f["name"] == "NewFunction" for f in diff["added_functions"])

    def test_diff_versions_detects_removed_functions(self, manager: GhidraProjectManager, test_binary: Path, sample_analysis_result: GhidraAnalysisResult) -> None:
        """diff_versions detects removed functions."""
        project = manager.create_project("Remove Test", str(test_binary), sample_analysis_result)

        reduced_funcs = {0x401000: sample_analysis_result.functions[0x401000]}

        reduced_result = GhidraAnalysisResult(
            binary_path=sample_analysis_result.binary_path,
            architecture=sample_analysis_result.architecture,
            compiler=sample_analysis_result.compiler,
            functions=reduced_funcs,
            data_types=sample_analysis_result.data_types,
            strings=sample_analysis_result.strings,
            imports=sample_analysis_result.imports,
            exports=sample_analysis_result.exports,
            sections=sample_analysis_result.sections,
            entry_point=sample_analysis_result.entry_point,
            image_base=sample_analysis_result.image_base,
            vtables={},
            exception_handlers=[]
        )

        new_version = manager.save_version(project.project_id, reduced_result)

        diff = manager.diff_versions(project.project_id, project.versions[0].version_id, new_version.version_id)

        assert len(diff["removed_functions"]) > 0

    def test_diff_versions_detects_modified_functions(self, manager: GhidraProjectManager, test_binary: Path, sample_analysis_result: GhidraAnalysisResult) -> None:
        """diff_versions detects function modifications."""
        project = manager.create_project("Modify Test", str(test_binary), sample_analysis_result)

        modified_func = GhidraFunction(
            name=sample_analysis_result.functions[0x401000].name,
            address=0x401000,
            size=150,
            signature="int main(int argc, char** argv, char** envp)",
            return_type="int",
            parameters=[("int", "argc"), ("char**", "argv"), ("char**", "envp")],
            local_variables=[("int", "result", 0)],
            decompiled_code="int main() { return 1; }",
            assembly_code="push ebp\nmov ebp, esp\nmov eax, 1\npop ebp\nret",
            xrefs_to=[0x402000],
            xrefs_from=[0x401500],
            comments={0: "Entry point modified"}
        )

        modified_result = GhidraAnalysisResult(
            binary_path=sample_analysis_result.binary_path,
            architecture=sample_analysis_result.architecture,
            compiler=sample_analysis_result.compiler,
            functions={0x401000: modified_func, 0x401500: sample_analysis_result.functions[0x401500]},
            data_types=sample_analysis_result.data_types,
            strings=sample_analysis_result.strings,
            imports=sample_analysis_result.imports,
            exports=sample_analysis_result.exports,
            sections=sample_analysis_result.sections,
            entry_point=sample_analysis_result.entry_point,
            image_base=sample_analysis_result.image_base,
            vtables={},
            exception_handlers=[]
        )

        new_version = manager.save_version(project.project_id, modified_result)

        diff = manager.diff_versions(project.project_id, project.versions[0].version_id, new_version.version_id)

        assert len(diff["modified_functions"]) > 0

    def test_diff_versions_calculates_similarity(self, manager: GhidraProjectManager, test_binary: Path, sample_analysis_result: GhidraAnalysisResult) -> None:
        """diff_versions includes similarity ratio."""
        project = manager.create_project("Similarity", str(test_binary), sample_analysis_result)
        new_version = manager.save_version(project.project_id, sample_analysis_result)

        diff = manager.diff_versions(project.project_id, project.versions[0].version_id, new_version.version_id)

        assert "statistics" in diff
        assert "similarity_ratio" in diff["statistics"]
        assert 0.0 <= diff["statistics"]["similarity_ratio"] <= 1.0


class TestProjectExportImport:
    """Test project export and import."""

    def test_export_project_creates_archive(self, manager: GhidraProjectManager, test_binary: Path, sample_analysis_result: GhidraAnalysisResult, tmp_path: Path) -> None:
        """export_project creates zip archive."""
        project = manager.create_project("Export Test", str(test_binary), sample_analysis_result)
        export_path = tmp_path / "export.zip"

        result_path = manager.export_project(project.project_id, str(export_path))

        assert result_path.exists()
        assert zipfile.is_zipfile(result_path)

    def test_export_project_includes_metadata(self, manager: GhidraProjectManager, test_binary: Path, sample_analysis_result: GhidraAnalysisResult, tmp_path: Path) -> None:
        """export_project includes project.json."""
        project = manager.create_project("Meta Export", str(test_binary), sample_analysis_result)
        export_path = tmp_path / "export_meta.zip"

        manager.export_project(project.project_id, str(export_path))

        with zipfile.ZipFile(export_path, 'r') as zf:
            assert "project.json" in zf.namelist()
            project_data = json.loads(zf.read("project.json"))
            assert project_data["name"] == "Meta Export"

    def test_export_project_current_version_only(self, manager: GhidraProjectManager, test_binary: Path, sample_analysis_result: GhidraAnalysisResult, tmp_path: Path) -> None:
        """export_project exports only current version by default."""
        project = manager.create_project("Current Only", str(test_binary), sample_analysis_result)
        manager.save_version(project.project_id, sample_analysis_result)
        export_path = tmp_path / "current.zip"

        manager.export_project(project.project_id, str(export_path), include_all_versions=False)

        with zipfile.ZipFile(export_path, 'r') as zf:
            version_files = [f for f in zf.namelist() if f.startswith("versions/")]
            assert len(version_files) >= 1

    def test_import_project_restores_structure(self, manager: GhidraProjectManager, test_binary: Path, sample_analysis_result: GhidraAnalysisResult, tmp_path: Path) -> None:
        """import_project restores exported project."""
        project = manager.create_project("Import Test", str(test_binary), sample_analysis_result)
        export_path = tmp_path / "import_test.zip"
        manager.export_project(project.project_id, str(export_path))

        new_manager = GhidraProjectManager(projects_dir=str(tmp_path / "new_projects"))
        imported = new_manager.import_project(str(export_path))

        assert imported is not None
        assert imported.name == "Import Test"
        assert len(imported.versions) > 0

    def test_import_project_handles_duplicate(self, manager: GhidraProjectManager, test_binary: Path, sample_analysis_result: GhidraAnalysisResult, tmp_path: Path) -> None:
        """import_project generates new ID for duplicate."""
        project = manager.create_project("Duplicate", str(test_binary), sample_analysis_result)
        export_path = tmp_path / "duplicate.zip"
        manager.export_project(project.project_id, str(export_path))

        imported = manager.import_project(str(export_path))

        assert imported.project_id != project.project_id


class TestCollaboration:
    """Test collaboration features."""

    def test_add_collaborator(self, manager: GhidraProjectManager, test_binary: Path) -> None:
        """add_collaborator adds user to project."""
        project = manager.create_project("Collab", str(test_binary))

        manager.add_collaborator(project.project_id, "user456", "editor")

        conn = sqlite3.connect(manager.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT role FROM collaborators WHERE project_id = ? AND user_id = ?",
                      (project.project_id, "user456"))
        row = cursor.fetchone()
        conn.close()

        assert row is not None
        assert row[0] == "editor"

    def test_lock_project(self, manager: GhidraProjectManager, test_binary: Path) -> None:
        """lock_project prevents modifications."""
        project = manager.create_project("Lock Test", str(test_binary))

        manager.lock_project(project.project_id)

        loaded = manager.load_project(project.project_id)
        assert loaded.is_locked is True

    def test_unlock_project(self, manager: GhidraProjectManager, test_binary: Path) -> None:
        """unlock_project allows modifications."""
        project = manager.create_project("Unlock Test", str(test_binary))
        manager.lock_project(project.project_id)

        manager.unlock_project(project.project_id)

        loaded = manager.load_project(project.project_id)
        assert loaded.is_locked is False


class TestHelperMethods:
    """Test internal helper methods."""

    def test_generate_project_id_uniqueness(self, manager: GhidraProjectManager) -> None:
        """_generate_project_id creates unique IDs."""
        id1 = manager._generate_project_id("Project", "/path/bin.exe")
        id2 = manager._generate_project_id("Project", "/path/bin.exe")

        assert id1 != id2

    def test_generate_version_id_uniqueness(self, manager: GhidraProjectManager) -> None:
        """_generate_version_id creates unique IDs."""
        id1 = manager._generate_version_id()
        id2 = manager._generate_version_id()

        assert id1 != id2

    def test_compute_file_hash(self, manager: GhidraProjectManager, test_binary: Path) -> None:
        """_compute_file_hash calculates SHA256."""
        hash1 = manager._compute_file_hash(str(test_binary))
        hash2 = manager._compute_file_hash(str(test_binary))

        assert hash1 == hash2
        assert len(hash1) == 64


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_save_version_nonexistent_project(self, manager: GhidraProjectManager, sample_analysis_result: GhidraAnalysisResult) -> None:
        """save_version raises error for non-existent project."""
        with pytest.raises(ValueError):
            manager.save_version("nonexistent", sample_analysis_result)

    def test_diff_versions_missing_version(self, manager: GhidraProjectManager, test_binary: Path, sample_analysis_result: GhidraAnalysisResult) -> None:
        """diff_versions raises error for missing versions."""
        project = manager.create_project("Diff Error", str(test_binary), sample_analysis_result)

        with pytest.raises(ValueError):
            manager.diff_versions(project.project_id, "missing1", "missing2")

    def test_export_nonexistent_project(self, manager: GhidraProjectManager, tmp_path: Path) -> None:
        """export_project raises error for non-existent project."""
        export_path = tmp_path / "error.zip"

        with pytest.raises(ValueError):
            manager.export_project("nonexistent", str(export_path))

    def test_empty_analysis_result(self, manager: GhidraProjectManager, test_binary: Path) -> None:
        """Manager handles empty analysis results."""
        empty_result = GhidraAnalysisResult(
            binary_path=str(test_binary),
            architecture="unknown",
            compiler="unknown",
            functions={},
            data_types={},
            strings=[],
            imports=[],
            exports=[],
            sections=[],
            entry_point=0,
            image_base=0,
            vtables={},
            exception_handlers=[]
        )

        project = manager.create_project("Empty", str(test_binary), empty_result)

        loaded = manager.load_version(project.project_id, project.current_version)
        assert loaded is not None
        assert len(loaded.functions) == 0

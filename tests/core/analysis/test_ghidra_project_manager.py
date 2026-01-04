"""Production tests for Ghidra Project Manager.

Tests validate real project management, versioning, diffing, and collaboration features.
All tests verify actual filesystem operations, database transactions, and compression.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import hashlib
import json
import shutil
import sqlite3
import tempfile
import time
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Any, Generator

import lz4.frame
import msgpack
import pytest

from intellicrack.core.analysis.ghidra_analyzer import GhidraAnalysisResult, GhidraDataType, GhidraFunction
from intellicrack.core.analysis.ghidra_project_manager import GhidraProject, GhidraProjectManager, ProjectVersion


@pytest.fixture
def temp_projects_dir() -> Generator[Path, None, None]:
    """Create temporary directory for projects."""
    temp_dir: Path = Path(tempfile.mkdtemp())
    yield temp_dir
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def project_manager(temp_projects_dir: Path) -> GhidraProjectManager:
    """Create project manager with temporary directory."""
    return GhidraProjectManager(str(temp_projects_dir))


@pytest.fixture
def sample_binary(tmp_path: Path) -> Path:
    """Create sample binary file."""
    binary_path: Path = tmp_path / "sample.exe"
    binary_path.write_bytes(b"MZ\x90\x00" + b"\x00" * 1000)
    return binary_path


@pytest.fixture
def sample_analysis_result(sample_binary: Path) -> GhidraAnalysisResult:
    """Create sample analysis result."""
    functions: dict[int, GhidraFunction] = {
        0x401000: GhidraFunction(  # type: ignore[call-arg]
            address=0x401000,
            name="main",
            size=256,
            signature="int main(int argc, char** argv)",
            return_type="int",
            parameters=["argc: int", "argv: char**"],  # type: ignore[list-item]
            decompiled_code="int main(int argc, char** argv) {\n    return 0;\n}",
            basic_blocks=[],
            call_graph=[],
            xrefs=[],
        ),
        0x401100: GhidraFunction(  # type: ignore[call-arg]
            address=0x401100,
            name="CheckLicense",
            size=128,
            signature="BOOL CheckLicense()",
            return_type="BOOL",
            parameters=[],
            decompiled_code="BOOL CheckLicense() {\n    return TRUE;\n}",
            basic_blocks=[],
            call_graph=[],
            xrefs=[],
        ),
    }

    data_types: dict[str, GhidraDataType] = {
        "LICENSE_INFO": GhidraDataType(  # type: ignore[call-arg]
            name="LICENSE_INFO",
            size=64,
            kind="struct",
            fields={"serial": "char[32]", "expiry": "DWORD"},
        ),
    }

    return GhidraAnalysisResult(
        binary_path=str(sample_binary),
        architecture="x86:LE:32:default",
        compiler="Visual Studio",
        functions=functions,
        data_types=data_types,
        strings=[(0x402000, "License check failed"), (0x402020, "Valid license")],
        imports=[("KERNEL32.dll", "GetTickCount", 0x403000)],
        exports=[("CheckLicense", 0x401100)],
        sections=[{"name": ".text", "start": 0x401000, "size": 0x1000}],
        entry_point=0x401000,
        image_base=0x400000,
        vtables=[],  # type: ignore[arg-type]
        exception_handlers=[],
        metadata={"analyzed": True},
    )


def test_project_manager_initialization(temp_projects_dir: Path) -> None:
    """Project manager initializes with database and directory structure."""
    manager: GhidraProjectManager = GhidraProjectManager(str(temp_projects_dir))

    assert manager.projects_dir.exists()
    assert manager.db_path.exists()

    conn: sqlite3.Connection = sqlite3.connect(manager.db_path)
    cursor: sqlite3.Cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    rows: list[Any] = cursor.fetchall()
    tables: set[Any] = {row[0] for row in rows}
    conn.close()

    assert "projects" in tables
    assert "versions" in tables
    assert "collaborators" in tables
    assert "analysis_cache" in tables


def test_create_project_without_analysis(project_manager: GhidraProjectManager, sample_binary: Path) -> None:
    """Creating project without initial analysis creates valid project with empty version."""
    project = project_manager.create_project("Test Project", str(sample_binary), initial_analysis=None)

    assert project.name == "Test Project"
    assert project.binary_path == str(sample_binary)
    assert len(project.versions) == 1
    assert project.current_version == project.versions[0].version_id
    assert project.versions[0].description == "Initial project creation"

    loaded_project = project_manager.load_project(project.project_id)
    assert loaded_project is not None
    assert loaded_project.project_id == project.project_id


def test_create_project_with_analysis(project_manager: GhidraProjectManager, sample_binary: Path, sample_analysis_result: GhidraAnalysisResult) -> None:
    """Creating project with analysis compresses and stores analysis data."""
    project = project_manager.create_project("Analyzed Project", str(sample_binary), initial_analysis=sample_analysis_result)

    assert len(project.versions) == 1
    version = project.versions[0]
    assert len(version.analysis_data) > 0

    loaded_analysis = project_manager.load_version(project.project_id, version.version_id)
    assert loaded_analysis is not None
    assert loaded_analysis.binary_path == str(sample_binary)
    assert len(loaded_analysis.functions) == 2
    assert 0x401000 in loaded_analysis.functions
    assert loaded_analysis.functions[0x401000].name == "main"


def test_compression_decompression_accuracy(project_manager: GhidraProjectManager, sample_analysis_result: GhidraAnalysisResult) -> None:
    """Compression and decompression preserves all analysis data accurately."""
    compressed: bytes = project_manager._compress_analysis(sample_analysis_result)

    assert isinstance(compressed, bytes)
    assert len(compressed) > 0
    assert len(compressed) < len(str(sample_analysis_result))

    decompressed: GhidraAnalysisResult = project_manager._decompress_analysis(compressed)

    assert decompressed.binary_path == sample_analysis_result.binary_path
    assert decompressed.architecture == sample_analysis_result.architecture
    assert decompressed.compiler == sample_analysis_result.compiler
    assert len(decompressed.functions) == len(sample_analysis_result.functions)
    assert len(decompressed.data_types) == len(sample_analysis_result.data_types)
    assert decompressed.strings == sample_analysis_result.strings
    assert decompressed.imports == sample_analysis_result.imports


def test_save_new_version(project_manager: GhidraProjectManager, sample_binary: Path, sample_analysis_result: GhidraAnalysisResult) -> None:
    """Saving new version creates versioned analysis with proper parent tracking."""
    project = project_manager.create_project("Versioned Project", str(sample_binary), initial_analysis=sample_analysis_result)
    initial_version = project.current_version

    modified_analysis = GhidraAnalysisResult(
        binary_path=sample_analysis_result.binary_path,
        architecture=sample_analysis_result.architecture,
        compiler=sample_analysis_result.compiler,
        functions={**sample_analysis_result.functions, 0x401200: GhidraFunction(  # type: ignore[call-arg]
            address=0x401200,
            name="NewFunction",
            size=64,
            signature="void NewFunction()",
            return_type="void",
            parameters=[],
            decompiled_code="void NewFunction() {}",
            basic_blocks=[],
            call_graph=[],
            xrefs=[],
        )},
        data_types=sample_analysis_result.data_types,
        strings=sample_analysis_result.strings,
        imports=sample_analysis_result.imports,
        exports=sample_analysis_result.exports,
        sections=sample_analysis_result.sections,
        entry_point=sample_analysis_result.entry_point,
        image_base=sample_analysis_result.image_base,
        vtables=[],  # type: ignore[arg-type]
        exception_handlers=[],
        metadata={},
    )

    new_version = project_manager.save_version(
        project.project_id,
        modified_analysis,
        description="Added NewFunction",
        tags=["enhancement", "v2"],
    )

    assert new_version.parent_version == initial_version
    assert new_version.description == "Added NewFunction"
    assert new_version.tags == ["enhancement", "v2"]

    reloaded_project = project_manager.load_project(project.project_id)
    assert reloaded_project is not None
    assert len(reloaded_project.versions) == 2
    assert reloaded_project.current_version == new_version.version_id


def test_locked_project_prevents_modifications(project_manager: GhidraProjectManager, sample_binary: Path, sample_analysis_result: GhidraAnalysisResult) -> None:
    """Locked project raises error when attempting to save new version."""
    project = project_manager.create_project("Locked Project", str(sample_binary), initial_analysis=sample_analysis_result)
    project_manager.lock_project(project.project_id)

    with pytest.raises(ValueError, match="locked"):
        project_manager.save_version(project.project_id, sample_analysis_result, description="Should fail")


def test_unlock_project_allows_modifications(project_manager: GhidraProjectManager, sample_binary: Path, sample_analysis_result: GhidraAnalysisResult) -> None:
    """Unlocking project after locking allows modifications again."""
    project = project_manager.create_project("Unlockable Project", str(sample_binary), initial_analysis=sample_analysis_result)
    project_manager.lock_project(project.project_id)
    project_manager.unlock_project(project.project_id)

    new_version = project_manager.save_version(project.project_id, sample_analysis_result, description="After unlock")
    assert new_version.description == "After unlock"


def test_diff_versions_detects_added_functions(project_manager: GhidraProjectManager, sample_binary: Path, sample_analysis_result: GhidraAnalysisResult) -> None:
    """Version diffing correctly identifies added functions."""
    project = project_manager.create_project("Diff Project", str(sample_binary), initial_analysis=sample_analysis_result)
    v1 = project.current_version

    modified_analysis = GhidraAnalysisResult(
        binary_path=sample_analysis_result.binary_path,
        architecture=sample_analysis_result.architecture,
        compiler=sample_analysis_result.compiler,
        functions={**sample_analysis_result.functions, 0x401300: GhidraFunction(  # type: ignore[call-arg]
            address=0x401300,
            name="ValidateLicense",
            size=192,
            signature="BOOL ValidateLicense(char* serial)",
            return_type="BOOL",
            parameters=["serial: char*"],  # type: ignore[list-item]
            decompiled_code="BOOL ValidateLicense(char* serial) {\n    return FALSE;\n}",
            basic_blocks=[],
            call_graph=[],
            xrefs=[],
        )},
        data_types=sample_analysis_result.data_types,
        strings=sample_analysis_result.strings,
        imports=sample_analysis_result.imports,
        exports=sample_analysis_result.exports,
        sections=sample_analysis_result.sections,
        entry_point=sample_analysis_result.entry_point,
        image_base=sample_analysis_result.image_base,
        vtables=[],  # type: ignore[arg-type]
        exception_handlers=[],
        metadata={},
    )
    v2 = project_manager.save_version(project.project_id, modified_analysis).version_id

    diff = project_manager.diff_versions(project.project_id, v1, v2)

    assert len(diff["added_functions"]) == 1
    assert diff["added_functions"][0]["name"] == "ValidateLicense"
    assert diff["added_functions"][0]["address"] == hex(0x401300)
    assert len(diff["removed_functions"]) == 0


def test_diff_versions_detects_removed_functions(project_manager: GhidraProjectManager, sample_binary: Path, sample_analysis_result: GhidraAnalysisResult) -> None:
    """Version diffing correctly identifies removed functions."""
    project = project_manager.create_project("Diff Project 2", str(sample_binary), initial_analysis=sample_analysis_result)
    v1 = project.current_version

    modified_funcs: dict[int, GhidraFunction] = {k: v for k, v in sample_analysis_result.functions.items() if k != 0x401100}
    modified_analysis = GhidraAnalysisResult(
        binary_path=sample_analysis_result.binary_path,
        architecture=sample_analysis_result.architecture,
        compiler=sample_analysis_result.compiler,
        functions=modified_funcs,
        data_types=sample_analysis_result.data_types,
        strings=sample_analysis_result.strings,
        imports=sample_analysis_result.imports,
        exports=sample_analysis_result.exports,
        sections=sample_analysis_result.sections,
        entry_point=sample_analysis_result.entry_point,
        image_base=sample_analysis_result.image_base,
        vtables=[],  # type: ignore[arg-type]
        exception_handlers=[],
        metadata={},
    )
    v2 = project_manager.save_version(project.project_id, modified_analysis).version_id

    diff = project_manager.diff_versions(project.project_id, v1, v2)

    assert len(diff["removed_functions"]) == 1
    assert diff["removed_functions"][0]["name"] == "CheckLicense"
    assert len(diff["added_functions"]) == 0


def test_diff_versions_detects_modified_functions(project_manager: GhidraProjectManager, sample_binary: Path, sample_analysis_result: GhidraAnalysisResult) -> None:
    """Version diffing correctly identifies modified functions with code changes."""
    project = project_manager.create_project("Diff Project 3", str(sample_binary), initial_analysis=sample_analysis_result)
    v1 = project.current_version

    modified_funcs: dict[int, GhidraFunction] = dict(sample_analysis_result.functions)
    modified_funcs[0x401100] = GhidraFunction(  # type: ignore[call-arg]
        address=0x401100,
        name="CheckLicense",
        size=256,
        signature="BOOL CheckLicense()",
        return_type="BOOL",
        parameters=[],
        decompiled_code="BOOL CheckLicense() {\n    // Modified\n    return FALSE;\n}",
        basic_blocks=[],
        call_graph=[],
        xrefs=[],
    )

    modified_analysis = GhidraAnalysisResult(
        binary_path=sample_analysis_result.binary_path,
        architecture=sample_analysis_result.architecture,
        compiler=sample_analysis_result.compiler,
        functions=modified_funcs,
        data_types=sample_analysis_result.data_types,
        strings=sample_analysis_result.strings,
        imports=sample_analysis_result.imports,
        exports=sample_analysis_result.exports,
        sections=sample_analysis_result.sections,
        entry_point=sample_analysis_result.entry_point,
        image_base=sample_analysis_result.image_base,
        vtables=[],  # type: ignore[arg-type]
        exception_handlers=[],
        metadata={},
    )
    v2 = project_manager.save_version(project.project_id, modified_analysis).version_id

    diff = project_manager.diff_versions(project.project_id, v1, v2)

    assert len(diff["modified_functions"]) == 1
    assert diff["modified_functions"][0]["name"] == "CheckLicense"
    assert "code_diff" in diff["modified_functions"][0]["changes"]
    assert "size" in diff["modified_functions"][0]["changes"]


def test_export_project_current_version_only(project_manager: GhidraProjectManager, sample_binary: Path, sample_analysis_result: GhidraAnalysisResult, tmp_path: Path) -> None:
    """Exporting project with current version only creates valid archive."""
    project = project_manager.create_project("Export Project", str(sample_binary), initial_analysis=sample_analysis_result)
    export_path = tmp_path / "export.zip"

    exported = project_manager.export_project(project.project_id, str(export_path), include_all_versions=False)

    assert exported.exists()
    assert zipfile.is_zipfile(exported)

    with zipfile.ZipFile(exported, "r") as zipf:
        assert "project.json" in zipf.namelist()
        version_files: list[str] = [f for f in zipf.namelist() if f.startswith("versions/") and f.endswith(".dat")]
        assert len(version_files) == 1


def test_export_import_project_roundtrip(project_manager: GhidraProjectManager, sample_binary: Path, sample_analysis_result: GhidraAnalysisResult, tmp_path: Path) -> None:
    """Exporting and importing project preserves all data."""
    original_project = project_manager.create_project("Roundtrip Project", str(sample_binary), initial_analysis=sample_analysis_result)
    project_manager.save_version(original_project.project_id, sample_analysis_result, description="V2", tags=["test"])

    export_path = tmp_path / "roundtrip.zip"
    project_manager.export_project(original_project.project_id, str(export_path), include_all_versions=True)

    new_manager = GhidraProjectManager(str(tmp_path / "new_projects"))
    imported_project = new_manager.import_project(str(export_path))

    assert imported_project.name == original_project.name
    assert len(imported_project.versions) == len(original_project.versions)

    for orig_ver, imp_ver in zip(original_project.versions, imported_project.versions, strict=True):
        assert orig_ver.description == imp_ver.description
        assert orig_ver.tags == imp_ver.tags


def test_add_collaborator(project_manager: GhidraProjectManager, sample_binary: Path) -> None:
    """Adding collaborator stores user association."""
    project = project_manager.create_project("Collaborative Project", str(sample_binary))
    project_manager.add_collaborator(project.project_id, "user123", "editor")

    reloaded = project_manager.load_project(project.project_id)
    assert reloaded is not None
    assert "user123" in reloaded.collaborators


def test_project_cache_performance(project_manager: GhidraProjectManager, sample_binary: Path, sample_analysis_result: GhidraAnalysisResult) -> None:
    """Cached projects load faster on subsequent accesses."""
    project = project_manager.create_project("Cached Project", str(sample_binary), initial_analysis=sample_analysis_result)

    start: float = time.perf_counter()
    project_manager.load_project(project.project_id)
    first_load: float = time.perf_counter() - start

    start = time.perf_counter()
    project_manager.load_project(project.project_id)
    cached_load: float = time.perf_counter() - start

    assert cached_load < first_load


def test_similarity_calculation(project_manager: GhidraProjectManager, sample_binary: Path, sample_analysis_result: GhidraAnalysisResult) -> None:
    """Similarity calculation between identical versions returns 1.0."""
    project = project_manager.create_project("Similarity Project", str(sample_binary), initial_analysis=sample_analysis_result)
    v1 = project.current_version
    v2 = project_manager.save_version(project.project_id, sample_analysis_result, description="Identical").version_id

    diff = project_manager.diff_versions(project.project_id, v1, v2)

    assert diff["statistics"]["similarity_ratio"] == 1.0


def test_nonexistent_project_returns_none(project_manager: GhidraProjectManager) -> None:
    """Loading nonexistent project returns None."""
    result = project_manager.load_project("nonexistent_id")
    assert result is None


def test_binary_hash_calculation(project_manager: GhidraProjectManager, sample_binary: Path) -> None:
    """Binary hash is calculated correctly and stored in versions."""
    project = project_manager.create_project("Hash Project", str(sample_binary))

    expected_hash: str = hashlib.sha256(sample_binary.read_bytes()).hexdigest()

    assert project.versions[0].binary_hash == expected_hash


def test_version_metadata_storage(project_manager: GhidraProjectManager, sample_binary: Path, sample_analysis_result: GhidraAnalysisResult) -> None:
    """Version metadata including function counts is stored correctly."""
    project = project_manager.create_project("Metadata Project", str(sample_binary), initial_analysis=sample_analysis_result)
    version = project_manager.save_version(project.project_id, sample_analysis_result, description="Metadata test")

    assert version.metadata["functions_count"] == len(sample_analysis_result.functions)


def test_database_consistency_after_operations(project_manager: GhidraProjectManager, sample_binary: Path, sample_analysis_result: GhidraAnalysisResult) -> None:
    """Database remains consistent after multiple operations."""
    project = project_manager.create_project("Consistency Project", str(sample_binary), initial_analysis=sample_analysis_result)
    project_manager.save_version(project.project_id, sample_analysis_result, description="V2")
    project_manager.lock_project(project.project_id)
    project_manager.unlock_project(project.project_id)
    project_manager.add_collaborator(project.project_id, "user456", "viewer")

    conn = sqlite3.connect(project_manager.db_path)
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM projects WHERE project_id = ?", (project.project_id,))
    projects_row = cursor.fetchone()
    assert projects_row is not None
    assert projects_row[0] == 1

    cursor.execute("SELECT COUNT(*) FROM versions WHERE project_id = ?", (project.project_id,))
    versions_row = cursor.fetchone()
    assert versions_row is not None
    assert versions_row[0] == 2

    cursor.execute("SELECT COUNT(*) FROM collaborators WHERE project_id = ?", (project.project_id,))
    collaborators_row = cursor.fetchone()
    assert collaborators_row is not None
    assert collaborators_row[0] == 1

    conn.close()


def test_large_analysis_compression_efficiency(project_manager: GhidraProjectManager) -> None:
    """Large analysis results compress efficiently."""
    large_functions: dict[int, GhidraFunction] = {}
    for i in range(1000):
        addr = 0x400000 + (i * 0x100)
        large_functions[addr] = GhidraFunction(  # type: ignore[call-arg]
            address=addr,
            name=f"Function_{i}",
            size=256,
            signature=f"void Function_{i}()",
            return_type="void",
            parameters=[],
            decompiled_code=f"void Function_{i}() {{\n" + "    // Code\n" * 50 + "}",
            basic_blocks=[],
            call_graph=[],
            xrefs=[],
        )

    large_analysis = GhidraAnalysisResult(
        binary_path="/tmp/large.exe",
        architecture="x86:LE:64:default",
        compiler="GCC",
        functions=large_functions,
        data_types={},
        strings=[],
        imports=[],
        exports=[],
        sections=[],
        entry_point=0x400000,
        image_base=0x400000,
        vtables=[],  # type: ignore[arg-type]
        exception_handlers=[],
        metadata={},
    )

    compressed: bytes = project_manager._compress_analysis(large_analysis)
    decompressed: GhidraAnalysisResult = project_manager._decompress_analysis(compressed)

    assert len(decompressed.functions) == 1000
    packed_bytes: bytes = msgpack.packb(large_analysis.__dict__, use_bin_type=True)
    compression_ratio: float = len(compressed) / len(packed_bytes)
    assert compression_ratio < 0.8

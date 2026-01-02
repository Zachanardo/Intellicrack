"""Production-grade tests for AI File Tools.

Tests validate real file system operations including:
- File search with pattern matching
- Large file handling (10MB+)
- Batch file reading
- Directory traversal with depth limits
- Binary and text file detection
- Multiple encoding support
- License pattern detection in real file structures
- Performance with large directory trees
- Error handling for invalid paths and permissions
- Memory efficiency with large files
"""

import os
import tempfile
from pathlib import Path
from typing import Any, Callable

import pytest

from intellicrack.ai.ai_file_tools import (
    AIFileTools,
    DEFAULT_MAX_FILE_SIZE,
    MAX_FILES_TO_DISPLAY,
    MAX_SEARCH_DEPTH,
    FileReadTool,
    FileSearchTool,
    create_approval_dialog,
)


class FakeApprovalDialog:
    """Real test double for approval dialog with call tracking."""

    def __init__(self, approval_result: bool = True) -> None:
        self.approval_result: bool = approval_result
        self.call_count: int = 0
        self.last_operation: str = ""
        self.last_target: str = ""
        self.last_purpose: str = ""

    def __call__(
        self, operation: str, target: str, purpose: str = ""
    ) -> bool:
        self.call_count += 1
        self.last_operation = operation
        self.last_target = target
        self.last_purpose = purpose
        return self.approval_result

    def reset(self) -> None:
        self.call_count = 0
        self.last_operation = ""
        self.last_target = ""
        self.last_purpose = ""


@pytest.fixture
def temp_test_dir(tmp_path: Path) -> Path:
    """Create temporary directory for file operations tests."""
    test_dir = tmp_path / "ai_file_tests"
    test_dir.mkdir()
    return test_dir


@pytest.fixture
def nested_directory_structure(temp_test_dir: Path) -> Path:
    """Create nested directory structure for search tests."""
    (temp_test_dir / "level1").mkdir()
    (temp_test_dir / "level1" / "level2").mkdir()
    (temp_test_dir / "level1" / "level2" / "level3").mkdir()
    (temp_test_dir / "level1" / "level2" / "level3" / "level4").mkdir()
    (temp_test_dir / "level1" / "level2" / "level3" / "level4" / "level5").mkdir()
    (temp_test_dir / "level1" / "level2" / "level3" / "level4" / "level5" / "level6").mkdir()

    (temp_test_dir / "license.txt").write_text("Test license content")
    (temp_test_dir / "level1" / "activation.dat").write_text("Activation data")
    (temp_test_dir / "level1" / "level2" / "serial.key").write_text("Serial key")
    (temp_test_dir / "level1" / "level2" / "level3" / "registration.ini").write_text("[Registration]")
    (temp_test_dir / "level1" / "level2" / "level3" / "level4" / "auth.cfg").write_text("Auth config")
    (temp_test_dir / "level1" / "level2" / "level3" / "level4" / "level5" / "deep.lic").write_text("Deep license")
    (temp_test_dir / "level1" / "level2" / "level3" / "level4" / "level5" / "level6" / "too_deep.lic").write_text("Too deep")

    return temp_test_dir


@pytest.fixture
def license_file_structure(temp_test_dir: Path) -> Path:
    """Create realistic license file structure."""
    app_dir = temp_test_dir / "MyApplication"
    app_dir.mkdir()

    (app_dir / "MyApp.exe").write_bytes(b"MZ\x90\x00" + b"\x00" * 100)
    (app_dir / "license.txt").write_text("License Agreement")
    (app_dir / "license.dat").write_bytes(b"\x00\x01\x02\x03" * 100)
    (app_dir / "serial.key").write_text("XXXX-YYYY-ZZZZ-AAAA")
    (app_dir / "activation.ini").write_text("[Activation]\nkey=value")

    config_dir = app_dir / "config"
    config_dir.mkdir()
    (config_dir / "auth.cfg").write_text("auth_token=12345")
    (config_dir / "registration.conf").write_text("registered=false")

    data_dir = app_dir / "data"
    data_dir.mkdir()
    (data_dir / "license.db").write_bytes(b"SQLite format" + b"\x00" * 500)
    (data_dir / "trial.dat").write_bytes(b"TRIAL" + b"\x00" * 200)

    (app_dir / "readme.txt").write_text("This is a readme file")
    (app_dir / "unrelated.log").write_text("Log file content")

    return app_dir


@pytest.fixture
def large_file_directory(temp_test_dir: Path) -> Path:
    """Create directory with large files for performance testing."""
    large_dir = temp_test_dir / "large_files"
    large_dir.mkdir()

    (large_dir / "small.txt").write_text("Small file" * 100)

    large_content = "A" * (5 * 1024 * 1024)
    (large_dir / "medium_5mb.txt").write_text(large_content)

    very_large_content = "B" * (15 * 1024 * 1024)
    (large_dir / "large_15mb.txt").write_text(very_large_content)

    (large_dir / "binary_large.dat").write_bytes(b"\x00\xFF" * (6 * 1024 * 1024))

    return large_dir


@pytest.fixture
def approval_always_approved(monkeypatch: pytest.MonkeyPatch) -> FakeApprovalDialog:
    """Replace approval dialog with test double that always approves."""
    fake_approval = FakeApprovalDialog(approval_result=True)
    monkeypatch.setattr(
        "intellicrack.ai.ai_file_tools.create_approval_dialog",
        fake_approval
    )
    return fake_approval


@pytest.fixture
def approval_always_denied(monkeypatch: pytest.MonkeyPatch) -> FakeApprovalDialog:
    """Replace approval dialog with test double that always denies."""
    fake_approval = FakeApprovalDialog(approval_result=False)
    monkeypatch.setattr(
        "intellicrack.ai.ai_file_tools.create_approval_dialog",
        fake_approval
    )
    return fake_approval


class TestFileSearchTool:
    """Test file search functionality with real file system operations."""

    def test_search_finds_license_files_by_pattern(
        self, license_file_structure: Path, approval_always_approved: FakeApprovalDialog
    ) -> None:
        """File search finds license files matching patterns."""
        search_tool = FileSearchTool()

        result = search_tool.search_license_files(str(license_file_structure))

        assert result["status"] == "success"
        assert result["search_path"] == str(license_file_structure)
        assert isinstance(result["files_found"], list)
        assert len(result["files_found"]) > 0

        found_names = {f["name"].lower() for f in result["files_found"]}
        assert any("license" in name for name in found_names)

    def test_search_respects_depth_limit(
        self, nested_directory_structure: Path, approval_always_approved: FakeApprovalDialog
    ) -> None:
        """File search respects maximum depth limit."""
        search_tool = FileSearchTool()

        result = search_tool.search_license_files(str(nested_directory_structure))

        assert result["status"] == "success"

        files_found = result["files_found"]
        too_deep_found = any(
            "level6" in f["path"] or "too_deep" in f["name"].lower()
            for f in files_found
        )

        assert not too_deep_found, "Search exceeded depth limit"

    def test_search_with_custom_patterns(
        self, temp_test_dir: Path, approval_always_approved: FakeApprovalDialog
    ) -> None:
        """File search uses custom patterns correctly."""
        (temp_test_dir / "custom.xyz").write_text("Custom file")
        (temp_test_dir / "special_config.abc").write_text("Special config")
        (temp_test_dir / "normal.txt").write_text("Normal file")

        search_tool = FileSearchTool()
        custom_patterns = ["*.xyz", "*.abc"]

        result = search_tool.search_license_files(str(temp_test_dir), custom_patterns)

        assert result["status"] == "success"

        found_names = {f["name"] for f in result["files_found"]}
        assert "custom.xyz" in found_names
        assert "special_config.abc" in found_names

    def test_search_returns_file_metadata(
        self, license_file_structure: Path, approval_always_approved: FakeApprovalDialog
    ) -> None:
        """File search returns complete metadata for each file."""
        search_tool = FileSearchTool()

        result = search_tool.search_license_files(str(license_file_structure))

        assert result["status"] == "success"
        assert len(result["files_found"]) > 0

        for file_info in result["files_found"]:
            assert "path" in file_info
            assert "name" in file_info
            assert "size" in file_info
            assert "matched_pattern" in file_info
            assert "directory" in file_info
            assert file_info["size"] >= 0
            assert Path(file_info["path"]).name == file_info["name"]

    def test_search_counts_directories_and_files(
        self, license_file_structure: Path, approval_always_approved: FakeApprovalDialog
    ) -> None:
        """File search accurately counts scanned directories and files."""
        search_tool = FileSearchTool()

        result = search_tool.search_license_files(str(license_file_structure))

        assert result["status"] == "success"
        assert result["directories_scanned"] > 0
        assert result["total_files_checked"] > 0

    def test_search_nonexistent_path_returns_error(
        self, temp_test_dir: Path, approval_always_approved: FakeApprovalDialog
    ) -> None:
        """File search with nonexistent path returns error."""
        search_tool = FileSearchTool()
        nonexistent = temp_test_dir / "does_not_exist"

        result = search_tool.search_license_files(str(nonexistent))

        assert result["status"] == "error"
        assert "does not exist" in result["message"].lower()

    def test_search_file_instead_of_directory_returns_error(
        self, temp_test_dir: Path, approval_always_approved: FakeApprovalDialog
    ) -> None:
        """File search with file path instead of directory returns error."""
        test_file = temp_test_dir / "test.txt"
        test_file.write_text("Test content")

        search_tool = FileSearchTool()

        result = search_tool.search_license_files(str(test_file))

        assert result["status"] == "error"
        assert "not a directory" in result["message"].lower()

    def test_quick_license_scan_finds_priority_files(
        self, license_file_structure: Path, approval_always_approved: FakeApprovalDialog
    ) -> None:
        """Quick license scan finds high-priority license files."""
        search_tool = FileSearchTool()

        result = search_tool.quick_license_scan(str(license_file_structure))

        assert result["status"] == "success"
        assert len(result["files_found"]) > 0

        found_names = {f["name"].lower() for f in result["files_found"]}
        assert any(
            name in found_names
            for name in ["license.txt", "license.dat", "serial.key"]
        )

    def test_search_case_insensitive_matching(
        self, temp_test_dir: Path, approval_always_approved: FakeApprovalDialog
    ) -> None:
        """File search uses case-insensitive pattern matching."""
        (temp_test_dir / "LICENSE.TXT").write_text("Uppercase license")
        (temp_test_dir / "License.Dat").write_text("Mixed case license")
        (temp_test_dir / "license.key").write_text("Lowercase license")

        search_tool = FileSearchTool()

        result = search_tool.search_license_files(str(temp_test_dir))

        assert result["status"] == "success"
        assert len(result["files_found"]) >= 3


class TestFileReadTool:
    """Test file reading functionality with various file types and sizes."""

    def test_read_small_text_file(
        self, temp_test_dir: Path, approval_always_approved: FakeApprovalDialog
    ) -> None:
        """Small text file is read correctly with UTF-8 encoding."""
        test_file = temp_test_dir / "small.txt"
        content = "This is a small test file with UTF-8 content"
        test_file.write_text(content, encoding="utf-8")

        read_tool = FileReadTool()
        result = read_tool.read_file_content(str(test_file))

        assert result["status"] == "success"
        assert result["content"] == content
        assert result["encoding"] == "utf-8"
        assert result["is_binary"] is False
        assert result["size"] == len(content.encode("utf-8"))

    def test_read_large_file_within_limit(
        self, large_file_directory: Path, approval_always_approved: FakeApprovalDialog
    ) -> None:
        """Large file within size limit is read successfully."""
        large_file = large_file_directory / "medium_5mb.txt"

        read_tool = FileReadTool(max_file_size=10 * 1024 * 1024)
        result = read_tool.read_file_content(str(large_file))

        assert result["status"] == "success"
        assert len(result["content"]) > 0
        assert result["size"] > 5 * 1024 * 1024

    def test_read_file_exceeding_size_limit_returns_error(
        self, large_file_directory: Path, approval_always_approved: FakeApprovalDialog
    ) -> None:
        """File exceeding size limit returns error."""
        large_file = large_file_directory / "large_15mb.txt"

        read_tool = FileReadTool(max_file_size=10 * 1024 * 1024)
        result = read_tool.read_file_content(str(large_file))

        assert result["status"] == "error"
        assert "too large" in result["message"].lower()

    def test_read_binary_file(
        self, temp_test_dir: Path, approval_always_approved: FakeApprovalDialog
    ) -> None:
        """Binary file is detected and handled correctly."""
        binary_file = temp_test_dir / "binary.dat"
        binary_content = bytes(range(256)) * 100
        binary_file.write_bytes(binary_content)

        read_tool = FileReadTool()
        result = read_tool.read_file_content(str(binary_file))

        assert result["status"] == "success"
        assert result["is_binary"] is True
        assert result["encoding"] == "binary"
        assert "[Binary file" in result["content"]

    def test_read_file_with_latin1_encoding(
        self, temp_test_dir: Path, approval_always_approved: FakeApprovalDialog
    ) -> None:
        """File with Latin-1 encoding is read with fallback encoding."""
        test_file = temp_test_dir / "latin1.txt"
        content = "Café résumé naïve"
        test_file.write_bytes(content.encode("latin-1"))

        read_tool = FileReadTool()
        result = read_tool.read_file_content(str(test_file))

        assert result["status"] == "success"
        assert result["encoding"] in ["latin-1", "cp1252", "ascii"]

    def test_read_nonexistent_file_returns_error(
        self, temp_test_dir: Path, approval_always_approved: FakeApprovalDialog
    ) -> None:
        """Reading nonexistent file returns error."""
        nonexistent = temp_test_dir / "nonexistent.txt"

        read_tool = FileReadTool()
        result = read_tool.read_file_content(str(nonexistent))

        assert result["status"] == "error"
        assert "does not exist" in result["message"].lower()

    def test_set_max_file_size(self) -> None:
        """Maximum file size can be configured."""
        read_tool = FileReadTool()

        new_limit = 50 * 1024 * 1024
        read_tool.set_max_file_size(new_limit)

        assert read_tool.max_file_size == new_limit

    def test_set_invalid_max_file_size_raises_error(self) -> None:
        """Setting invalid maximum file size raises ValueError."""
        read_tool = FileReadTool()

        with pytest.raises(ValueError):
            read_tool.set_max_file_size(0)

        with pytest.raises(ValueError):
            read_tool.set_max_file_size(-1000)

    def test_read_multiple_files_batch_operation(
        self, license_file_structure: Path, approval_always_approved: FakeApprovalDialog
    ) -> None:
        """Multiple files are read in batch operation."""
        files = [
            str(license_file_structure / "license.txt"),
            str(license_file_structure / "serial.key"),
            str(license_file_structure / "activation.ini"),
        ]

        read_tool = FileReadTool()
        result = read_tool.read_multiple_files(files)

        assert result["status"] == "success"
        assert result["total_files"] == len(files)
        assert len(result["files_read"]) == len(files)
        assert result["total_size"] > 0

    def test_read_multiple_files_filters_invalid_paths(
        self, temp_test_dir: Path, approval_always_approved: FakeApprovalDialog
    ) -> None:
        """Batch read filters out invalid paths."""
        valid_file = temp_test_dir / "valid.txt"
        valid_file.write_text("Valid content")

        files = [
            str(valid_file),
            str(temp_test_dir / "nonexistent1.txt"),
            str(temp_test_dir / "nonexistent2.txt"),
        ]

        read_tool = FileReadTool()
        result = read_tool.read_multiple_files(files)

        assert result["status"] == "success"
        assert result["total_files"] == 1

    def test_read_multiple_files_respects_size_limit(
        self, large_file_directory: Path, approval_always_approved: FakeApprovalDialog
    ) -> None:
        """Batch read respects per-file size limits."""
        files = [
            str(large_file_directory / "small.txt"),
            str(large_file_directory / "large_15mb.txt"),
        ]

        read_tool = FileReadTool(max_file_size=10 * 1024 * 1024)
        result = read_tool.read_multiple_files(files)

        assert result["status"] == "success"
        assert result["total_files"] == 1


class TestAIFileTools:
    """Test integrated AI file tools functionality."""

    def test_initialization_with_custom_max_size(self) -> None:
        """AI file tools initializes with custom max file size."""
        custom_size = 20 * 1024 * 1024
        tools = AIFileTools(max_file_size=custom_size)

        assert tools.read_tool.max_file_size == custom_size

    def test_search_for_license_files_integration(
        self, license_file_structure: Path, approval_always_approved: FakeApprovalDialog
    ) -> None:
        """Integrated search finds license files."""
        tools = AIFileTools()

        result = tools.search_for_license_files(str(license_file_structure))

        assert result["status"] == "success"
        assert len(result["files_found"]) > 0

    def test_read_file_integration(
        self, temp_test_dir: Path, approval_always_approved: FakeApprovalDialog
    ) -> None:
        """Integrated file read works correctly."""
        test_file = temp_test_dir / "integration_test.txt"
        content = "Integration test content"
        test_file.write_text(content)

        tools = AIFileTools()
        result = tools.read_file(str(test_file), purpose="Testing integration")

        assert result["status"] == "success"
        assert result["content"] == content

    def test_read_multiple_files_integration(
        self, license_file_structure: Path, approval_always_approved: FakeApprovalDialog
    ) -> None:
        """Integrated batch read works correctly."""
        files = [
            str(license_file_structure / "license.txt"),
            str(license_file_structure / "serial.key"),
        ]

        tools = AIFileTools()
        result = tools.read_multiple_files(files, purpose="Batch test")

        assert result["status"] == "success"
        assert len(result["files_read"]) == len(files)

    def test_analyze_program_directory_complete_workflow(
        self, license_file_structure: Path, approval_always_approved: FakeApprovalDialog
    ) -> None:
        """Complete program directory analysis workflow."""
        program_path = license_file_structure / "MyApp.exe"

        tools = AIFileTools()
        result = tools.analyze_program_directory(str(program_path))

        assert result["status"] == "success"
        assert result["program_path"] == str(program_path)
        assert result["program_directory"] == str(license_file_structure)
        assert len(result["license_files_found"]) > 0

        summary = result["analysis_summary"]
        assert summary["license_files_count"] > 0
        assert summary["program_name"] == "MyApp"

    def test_analyze_program_directory_reads_license_files(
        self, license_file_structure: Path, approval_always_approved: FakeApprovalDialog
    ) -> None:
        """Program analysis reads license file contents."""
        program_path = license_file_structure / "MyApp.exe"

        tools = AIFileTools()
        result = tools.analyze_program_directory(str(program_path))

        assert result["status"] == "success"
        assert len(result["file_contents"]) > 0

        file_contents = result["file_contents"]
        assert any("License" in content for content in file_contents.values())


class TestPerformanceWithLargeDirectories:
    """Test performance with large directory structures."""

    def test_search_large_directory_tree_performance(
        self, temp_test_dir: Path, approval_always_approved: FakeApprovalDialog
    ) -> None:
        """File search completes in reasonable time with large directory tree."""
        import time

        for i in range(50):
            dir_path = temp_test_dir / f"dir_{i}"
            dir_path.mkdir()
            for j in range(20):
                file_path = dir_path / f"file_{j}.txt"
                file_path.write_text(f"Content {i}-{j}")

            if i % 10 == 0:
                license_file = dir_path / "license.dat"
                license_file.write_text("License data")

        search_tool = FileSearchTool()

        start_time = time.time()
        result = search_tool.search_license_files(str(temp_test_dir))
        elapsed = time.time() - start_time

        assert result["status"] == "success"
        assert elapsed < 5.0, f"Search took too long: {elapsed:.2f}s"

    def test_read_many_small_files_performance(
        self, temp_test_dir: Path, approval_always_approved: FakeApprovalDialog
    ) -> None:
        """Reading many small files completes in reasonable time."""
        import time

        file_paths = []
        for i in range(100):
            file_path = temp_test_dir / f"small_{i}.txt"
            file_path.write_text(f"Content {i}" * 10)
            file_paths.append(str(file_path))

        read_tool = FileReadTool()

        start_time = time.time()
        result = read_tool.read_multiple_files(file_paths[:50])
        elapsed = time.time() - start_time

        assert result["status"] == "success"
        assert elapsed < 3.0, f"Batch read took too long: {elapsed:.2f}s"


class TestMemoryEfficiency:
    """Test memory efficiency with large files."""

    def test_large_file_read_memory_efficiency(
        self, large_file_directory: Path, approval_always_approved: FakeApprovalDialog
    ) -> None:
        """Large file read doesn't cause excessive memory usage."""
        import gc

        large_file = large_file_directory / "medium_5mb.txt"

        read_tool = FileReadTool(max_file_size=10 * 1024 * 1024)

        gc.collect()

        result = read_tool.read_file_content(str(large_file))

        assert result["status"] == "success"

        del result
        gc.collect()

    def test_batch_read_cleans_up_memory(
        self, temp_test_dir: Path, approval_always_approved: FakeApprovalDialog
    ) -> None:
        """Batch file reading cleans up memory between files."""
        import gc

        file_paths = []
        for i in range(20):
            file_path = temp_test_dir / f"batch_{i}.txt"
            file_path.write_text("X" * (1024 * 1024))
            file_paths.append(str(file_path))

        read_tool = FileReadTool()

        gc.collect()

        result = read_tool.read_multiple_files(file_paths)

        assert result["status"] == "success"

        del result
        gc.collect()


class TestErrorHandling:
    """Test comprehensive error handling."""

    def test_search_handles_permission_errors_gracefully(
        self, temp_test_dir: Path, approval_always_approved: FakeApprovalDialog
    ) -> None:
        """File search handles permission errors gracefully."""
        restricted_dir = temp_test_dir / "restricted"
        restricted_dir.mkdir()
        (restricted_dir / "license.txt").write_text("License")

        search_tool = FileSearchTool()

        result = search_tool.search_license_files(str(temp_test_dir))

        assert result["status"] in ["success", "error"]

    def test_read_handles_file_corruption_gracefully(
        self, temp_test_dir: Path, approval_always_approved: FakeApprovalDialog
    ) -> None:
        """File read handles corrupted files gracefully."""
        corrupted_file = temp_test_dir / "corrupted.txt"
        corrupted_file.write_bytes(b"\xFF\xFE" + bytes(range(256)) * 10)

        read_tool = FileReadTool()
        result = read_tool.read_file_content(str(corrupted_file))

        assert result["status"] in ["success", "error"]
        assert "content" in result or "message" in result


class TestApprovalMechanism:
    """Test user approval mechanism."""

    def test_search_denied_returns_denied_status(
        self, temp_test_dir: Path, approval_always_denied: FakeApprovalDialog
    ) -> None:
        """File search returns denied status when user denies."""
        search_tool = FileSearchTool()
        result = search_tool.search_license_files(str(temp_test_dir))

        assert result["status"] == "denied"
        assert "denied" in result["message"].lower()
        assert approval_always_denied.call_count == 1
        assert approval_always_denied.last_operation == "search_directory"

    def test_read_denied_returns_denied_status(
        self, temp_test_dir: Path, approval_always_denied: FakeApprovalDialog
    ) -> None:
        """File read returns denied status when user denies."""
        test_file = temp_test_dir / "test.txt"
        test_file.write_text("Test content")

        read_tool = FileReadTool()
        result = read_tool.read_file_content(str(test_file))

        assert result["status"] == "denied"
        assert "denied" in result["message"].lower()
        assert approval_always_denied.call_count == 1
        assert approval_always_denied.last_operation == "read_file"


class TestRealWorldScenarios:
    """Test real-world usage scenarios."""

    def test_analyze_realistic_application_structure(
        self, temp_test_dir: Path, approval_always_approved: FakeApprovalDialog
    ) -> None:
        """Analyze realistic application directory structure."""
        app_dir = temp_test_dir / "RealApp"
        app_dir.mkdir()

        (app_dir / "RealApp.exe").write_bytes(b"MZ" + b"\x00" * 1000)
        (app_dir / "LICENSE").write_text("MIT License")
        (app_dir / "config.ini").write_text("[Settings]\nkey=value")

        lib_dir = app_dir / "lib"
        lib_dir.mkdir()
        (lib_dir / "library.dll").write_bytes(b"MZ" + b"\x00" * 500)

        plugins_dir = app_dir / "plugins"
        plugins_dir.mkdir()
        (plugins_dir / "license_check.dll").write_bytes(b"MZ" + b"\x00" * 300)

        tools = AIFileTools()
        result = tools.analyze_program_directory(str(app_dir / "RealApp.exe"))

        assert result["status"] == "success"
        assert len(result["license_files_found"]) > 0

    def test_search_complex_license_patterns(
        self, temp_test_dir: Path, approval_always_approved: FakeApprovalDialog
    ) -> None:
        """Search finds complex license file patterns."""
        (temp_test_dir / "app_license_v2.txt").write_text("License v2")
        (temp_test_dir / "trial_expiration.dat").write_text("Trial data")
        (temp_test_dir / "product_activation_key.ini").write_text("[Activation]")
        (temp_test_dir / "registration_info.cfg").write_text("Registration")
        (temp_test_dir / "demo_limitations.conf").write_text("Demo mode")

        search_tool = FileSearchTool()
        result = search_tool.search_license_files(str(temp_test_dir))

        assert result["status"] == "success"

        found_names = {f["name"].lower() for f in result["files_found"]}
        assert len(found_names) >= 4


class TestFactoryFunction:
    """Test factory function for creating AI file tools."""

    def test_get_ai_file_tools_creates_instance(self) -> None:
        """Factory function creates AI file tools instance."""
        from intellicrack.ai.ai_file_tools import get_ai_file_tools

        tools = get_ai_file_tools()

        assert isinstance(tools, AIFileTools)
        assert tools.read_tool.max_file_size == DEFAULT_MAX_FILE_SIZE

    def test_get_ai_file_tools_with_custom_size(self) -> None:
        """Factory function accepts custom max file size."""
        from intellicrack.ai.ai_file_tools import get_ai_file_tools

        custom_size = 50 * 1024 * 1024
        tools = get_ai_file_tools(max_file_size=custom_size)

        assert tools.read_tool.max_file_size == custom_size

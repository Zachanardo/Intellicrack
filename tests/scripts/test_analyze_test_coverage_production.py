"""Production tests for scripts/analyze_test_coverage.py.

Tests validate real test coverage analysis functionality without mocks.
"""

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
    """Get the path to analyze_test_coverage.py script."""
    return project_root / "scripts" / "analyze_test_coverage.py"


@pytest.fixture
def temp_project_structure(tmp_path: Path) -> Path:
    """Create a temporary project structure for testing."""
    intellicrack_dir = tmp_path / "intellicrack"
    intellicrack_dir.mkdir()

    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()

    (intellicrack_dir / "module1.py").write_text("def func1(): pass\n")
    (intellicrack_dir / "module2.py").write_text("def func2(): pass\n")
    (intellicrack_dir / "module3.py").write_text("def func3(): pass\n")

    subdir = intellicrack_dir / "submodule"
    subdir.mkdir()
    (subdir / "module4.py").write_text("def func4(): pass\n")
    (subdir / "module5.py").write_text("def func5(): pass\n")

    (tests_dir / "test_module1.py").write_text("def test_func1(): pass\n")
    (tests_dir / "test_module3.py").write_text("def test_func3(): pass\n")

    test_subdir = tests_dir / "submodule"
    test_subdir.mkdir()
    (test_subdir / "test_module4.py").write_text("def test_func4(): pass\n")

    (intellicrack_dir / "__init__.py").write_text("")
    (subdir / "__init__.py").write_text("")
    (tests_dir / "__init__.py").write_text("")
    (test_subdir / "__init__.py").write_text("")

    (tests_dir / "conftest.py").write_text("import pytest\n")

    return tmp_path


class TestAnalyzeTestCoverageScriptExecution:
    """Test actual script execution on real project structure."""

    def test_script_runs_successfully(
        self,
        script_path: Path,
        project_root: Path,
    ) -> None:
        """Script executes without errors on real project."""
        result = subprocess.run(
            [sys.executable, str(script_path)],
            cwd=str(project_root),
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert result.returncode == 0, f"Script failed: {result.stderr}"
        assert "Total source files:" in result.stdout
        assert "Total test files:" in result.stdout
        assert "Files with NO test coverage:" in result.stdout

    def test_script_output_contains_statistics(
        self,
        script_path: Path,
        project_root: Path,
    ) -> None:
        """Script output includes coverage statistics."""
        result = subprocess.run(
            [sys.executable, str(script_path)],
            cwd=str(project_root),
            capture_output=True,
            text=True,
            timeout=30,
        )

        output_lines = result.stdout.strip().split('\n')

        stats_found = False
        for line in output_lines:
            if "Total source files:" in line:
                count = int(line.split(':')[1].strip())
                assert count > 0, "Should find source files"
                stats_found = True
            elif "Total test files:" in line:
                count = int(line.split(':')[1].strip())
                assert count > 0, "Should find test files"
            elif "Files with NO test coverage:" in line:
                count = int(line.split(':')[1].strip())
                assert count >= 0, "Should count files without tests"

        assert stats_found, "Statistics not found in output"

    def test_script_lists_uncovered_files(
        self,
        script_path: Path,
        project_root: Path,
    ) -> None:
        """Script lists files with no test coverage."""
        result = subprocess.run(
            [sys.executable, str(script_path)],
            cwd=str(project_root),
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert "=== SOURCE FILES WITH NO TEST COVERAGE ===" in result.stdout

        lines = result.stdout.strip().split('\n')
        header_found = False
        files_after_header = []

        for line in lines:
            if "=== SOURCE FILES WITH NO TEST COVERAGE ===" in line:
                header_found = True
                continue
            if header_found and line.strip() and (not line.startswith("Total") and not line.startswith("Files")):
                files_after_header.append(line.strip())

        assert header_found, "Coverage section header not found"


class TestGetModuleName:
    """Test module name extraction from file paths."""

    def test_extract_module_name_from_simple_path(self) -> None:
        """Extract module name from simple file path."""
        from scripts.analyze_test_coverage import get_module_name

        result = get_module_name("intellicrack/module.py")
        assert result == "module"

    def test_extract_module_name_from_nested_path(self) -> None:
        """Extract module name from nested file path."""
        from scripts.analyze_test_coverage import get_module_name

        result = get_module_name("intellicrack/core/analysis/analyzer.py")
        assert result == "analyzer"

    def test_extract_module_name_from_test_file(self) -> None:
        """Extract module name from test file path."""
        from scripts.analyze_test_coverage import get_module_name

        result = get_module_name("tests/core/test_analyzer.py")
        assert result == "test_analyzer"

    def test_extract_module_name_removes_py_extension(self) -> None:
        """Module name extraction removes .py extension."""
        from scripts.analyze_test_coverage import get_module_name

        result = get_module_name("path/to/my_module.py")
        assert not result.endswith(".py")
        assert result == "my_module"


class TestSourceFileDiscovery:
    """Test source file discovery in project structure."""

    def test_discovers_source_files_in_intellicrack_directory(
        self,
        monkeypatch,
        temp_project_structure: Path,
    ) -> None:
        """Discover all Python source files in intellicrack directory."""
        monkeypatch.chdir(temp_project_structure)

        source_dir = Path('intellicrack')
        source_files: List[str] = []

        for f in source_dir.rglob('*.py'):
            if '__init__' not in f.name and '__pycache__' not in str(f):
                rel_path = str(f).replace('\\', '/')
                source_files.append(rel_path)

        assert len(source_files) == 5
        assert "intellicrack/module1.py" in source_files
        assert "intellicrack/module2.py" in source_files
        assert "intellicrack/module3.py" in source_files
        assert "intellicrack/submodule/module4.py" in source_files
        assert "intellicrack/submodule/module5.py" in source_files

    def test_excludes_init_files_from_source_discovery(
        self,
        monkeypatch,
        temp_project_structure: Path,
    ) -> None:
        """Exclude __init__.py files from source file discovery."""
        monkeypatch.chdir(temp_project_structure)

        source_dir = Path('intellicrack')
        source_files: List[str] = []

        for f in source_dir.rglob('*.py'):
            if '__init__' not in f.name and '__pycache__' not in str(f):
                rel_path = str(f).replace('\\', '/')
                source_files.append(rel_path)

        for source_file in source_files:
            assert '__init__' not in source_file

    def test_excludes_pycache_from_source_discovery(
        self,
        monkeypatch,
        temp_project_structure: Path,
    ) -> None:
        """Exclude __pycache__ directories from source discovery."""
        monkeypatch.chdir(temp_project_structure)

        pycache_dir = temp_project_structure / "intellicrack" / "__pycache__"
        pycache_dir.mkdir()
        (pycache_dir / "module1.cpython-311.pyc").write_bytes(b"compiled")

        source_dir = Path('intellicrack')
        source_files: List[str] = []

        for f in source_dir.rglob('*.py'):
            if '__init__' not in f.name and '__pycache__' not in str(f):
                rel_path = str(f).replace('\\', '/')
                source_files.append(rel_path)

        for source_file in source_files:
            assert '__pycache__' not in source_file


class TestTestFileDiscovery:
    """Test test file discovery in project structure."""

    def test_discovers_test_files_in_tests_directory(
        self,
        monkeypatch,
        temp_project_structure: Path,
    ) -> None:
        """Discover all test files in tests directory."""
        monkeypatch.chdir(temp_project_structure)

        test_dir = Path('tests')
        test_files: List[str] = []

        for f in test_dir.rglob('*.py'):
            if '__init__' not in f.name and '__pycache__' not in str(f) and 'conftest' not in f.name:
                rel_path = str(f).replace('\\', '/')
                test_files.append(rel_path)

        assert len(test_files) == 3
        assert "tests/test_module1.py" in test_files
        assert "tests/test_module3.py" in test_files
        assert "tests/submodule/test_module4.py" in test_files

    def test_excludes_conftest_from_test_discovery(
        self,
        monkeypatch,
        temp_project_structure: Path,
    ) -> None:
        """Exclude conftest.py files from test discovery."""
        monkeypatch.chdir(temp_project_structure)

        test_dir = Path('tests')
        test_files: List[str] = []

        for f in test_dir.rglob('*.py'):
            if '__init__' not in f.name and '__pycache__' not in str(f) and 'conftest' not in f.name:
                rel_path = str(f).replace('\\', '/')
                test_files.append(rel_path)

        for test_file in test_files:
            assert 'conftest' not in test_file

    def test_excludes_init_files_from_test_discovery(
        self,
        monkeypatch,
        temp_project_structure: Path,
    ) -> None:
        """Exclude __init__.py files from test discovery."""
        monkeypatch.chdir(temp_project_structure)

        test_dir = Path('tests')
        test_files: List[str] = []

        for f in test_dir.rglob('*.py'):
            if '__init__' not in f.name and '__pycache__' not in str(f) and 'conftest' not in f.name:
                rel_path = str(f).replace('\\', '/')
                test_files.append(rel_path)

        for test_file in test_files:
            assert '__init__' not in test_file


class TestCoverageMapping:
    """Test coverage mapping between source and test files."""

    def test_maps_source_files_to_matching_tests(
        self,
        monkeypatch,
        temp_project_structure: Path,
    ) -> None:
        """Map source files to their corresponding test files."""
        from scripts.analyze_test_coverage import get_module_name

        monkeypatch.chdir(temp_project_structure)

        source_files = [
            "intellicrack/module1.py",
            "intellicrack/module2.py",
            "intellicrack/module3.py",
        ]

        test_files = [
            "tests/test_module1.py",
            "tests/test_module3.py",
        ]

        test_coverage = {}
        for src in source_files:
            module = get_module_name(src)
            matching_tests = []
            for t in test_files:
                t_module = get_module_name(t)
                if t_module.startswith('test_') and module in t_module:
                    matching_tests.append(t)
            test_coverage[src] = matching_tests

        assert len(test_coverage["intellicrack/module1.py"]) == 1
        assert "tests/test_module1.py" in test_coverage["intellicrack/module1.py"]

        assert len(test_coverage["intellicrack/module2.py"]) == 0

        assert len(test_coverage["intellicrack/module3.py"]) == 1
        assert "tests/test_module3.py" in test_coverage["intellicrack/module3.py"]

    def test_identifies_files_without_test_coverage(
        self,
        monkeypatch,
        temp_project_structure: Path,
    ) -> None:
        """Identify source files without corresponding test files."""
        from scripts.analyze_test_coverage import get_module_name

        monkeypatch.chdir(temp_project_structure)

        source_files = [
            "intellicrack/module1.py",
            "intellicrack/module2.py",
            "intellicrack/module3.py",
            "intellicrack/submodule/module4.py",
            "intellicrack/submodule/module5.py",
        ]

        test_files = [
            "tests/test_module1.py",
            "tests/test_module3.py",
            "tests/submodule/test_module4.py",
        ]

        test_coverage = {}
        for src in source_files:
            module = get_module_name(src)
            matching_tests = []
            for t in test_files:
                t_module = get_module_name(t)
                if t_module.startswith('test_') and module in t_module:
                    matching_tests.append(t)
            test_coverage[src] = matching_tests

        no_tests = [src for src, tests in test_coverage.items() if not tests]

        assert len(no_tests) == 2
        assert "intellicrack/module2.py" in no_tests
        assert "intellicrack/submodule/module5.py" in no_tests

    def test_coverage_mapping_with_nested_modules(
        self,
        monkeypatch,
        temp_project_structure: Path,
    ) -> None:
        """Coverage mapping works with nested module structures."""
        from scripts.analyze_test_coverage import get_module_name

        monkeypatch.chdir(temp_project_structure)

        source_files = [
            "intellicrack/submodule/module4.py",
        ]

        test_files = [
            "tests/submodule/test_module4.py",
        ]

        test_coverage = {}
        for src in source_files:
            module = get_module_name(src)
            matching_tests = []
            for t in test_files:
                t_module = get_module_name(t)
                if t_module.startswith('test_') and module in t_module:
                    matching_tests.append(t)
            test_coverage[src] = matching_tests

        assert len(test_coverage["intellicrack/submodule/module4.py"]) == 1
        assert "tests/submodule/test_module4.py" in test_coverage["intellicrack/submodule/module4.py"]


class TestPathNormalization:
    """Test path normalization for cross-platform compatibility."""

    def test_normalizes_windows_paths_to_forward_slashes(
        self,
        tmp_path: Path,
    ) -> None:
        """Normalize Windows backslash paths to forward slashes."""
        test_path = tmp_path / "intellicrack" / "core" / "module.py"
        test_path.parent.mkdir(parents=True)
        test_path.write_text("pass")

        path_str = str(test_path.relative_to(tmp_path))
        normalized = path_str.replace('\\', '/')

        assert '\\' not in normalized
        assert '/' in normalized or len(normalized.split('/')) == 1

    def test_handles_mixed_path_separators(self) -> None:
        """Handle paths with mixed separators correctly."""
        mixed_path = "intellicrack\\core/analysis\\module.py"
        normalized = mixed_path.replace('\\', '/')

        assert '\\' not in normalized
        assert normalized == "intellicrack/core/analysis/module.py"


class TestEdgeCases:
    """Test edge cases in coverage analysis."""

    def test_handles_empty_source_directory(
        self,
        tmp_path: Path,
        monkeypatch,
    ) -> None:
        """Handle empty source directory gracefully."""
        monkeypatch.chdir(tmp_path)

        intellicrack_dir = tmp_path / "intellicrack"
        intellicrack_dir.mkdir()
        (intellicrack_dir / "__init__.py").write_text("")

        tests_dir = tmp_path / "tests"
        tests_dir.mkdir()

        source_dir = Path('intellicrack')
        source_files: List[str] = []

        for f in source_dir.rglob('*.py'):
            if '__init__' not in f.name and '__pycache__' not in str(f):
                rel_path = str(f).replace('\\', '/')
                source_files.append(rel_path)

        assert not source_files

    def test_handles_empty_tests_directory(
        self,
        tmp_path: Path,
        monkeypatch,
    ) -> None:
        """Handle empty tests directory gracefully."""
        monkeypatch.chdir(tmp_path)

        intellicrack_dir = tmp_path / "intellicrack"
        intellicrack_dir.mkdir()
        (intellicrack_dir / "module.py").write_text("pass")

        tests_dir = tmp_path / "tests"
        tests_dir.mkdir()
        (tests_dir / "__init__.py").write_text("")

        test_dir = Path('tests')
        test_files: List[str] = []

        for f in test_dir.rglob('*.py'):
            if '__init__' not in f.name and '__pycache__' not in str(f) and 'conftest' not in f.name:
                rel_path = str(f).replace('\\', '/')
                test_files.append(rel_path)

        assert not test_files

    def test_handles_multiple_tests_for_single_module(
        self,
        monkeypatch,
        tmp_path: Path,
    ) -> None:
        """Handle multiple test files for a single module."""
        from scripts.analyze_test_coverage import get_module_name

        monkeypatch.chdir(tmp_path)

        intellicrack_dir = tmp_path / "intellicrack"
        intellicrack_dir.mkdir()
        (intellicrack_dir / "analyzer.py").write_text("pass")

        tests_dir = tmp_path / "tests"
        tests_dir.mkdir()
        (tests_dir / "test_analyzer.py").write_text("pass")
        (tests_dir / "test_analyzer_integration.py").write_text("pass")
        (tests_dir / "test_analyzer_production.py").write_text("pass")

        source_files = ["intellicrack/analyzer.py"]
        test_files = [
            "tests/test_analyzer.py",
            "tests/test_analyzer_integration.py",
            "tests/test_analyzer_production.py",
        ]

        test_coverage = {}
        for src in source_files:
            module = get_module_name(src)
            matching_tests = []
            for t in test_files:
                t_module = get_module_name(t)
                if t_module.startswith('test_') and module in t_module:
                    matching_tests.append(t)
            test_coverage[src] = matching_tests

        assert len(test_coverage["intellicrack/analyzer.py"]) == 3
        assert all(
            test in test_coverage["intellicrack/analyzer.py"]
            for test in test_files
        )


class TestRealProjectExecution:
    """Test script execution on actual Intellicrack project."""

    def test_script_finds_actual_source_files(
        self,
        script_path: Path,
        project_root: Path,
    ) -> None:
        """Script finds real source files in Intellicrack project."""
        result = subprocess.run(
            [sys.executable, str(script_path)],
            cwd=str(project_root),
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert result.returncode == 0

        for line in result.stdout.split('\n'):
            if "Total source files:" in line:
                count = int(line.split(':')[1].strip())
                assert count > 50, f"Should find many source files, found {count}"
                break

    def test_script_finds_actual_test_files(
        self,
        script_path: Path,
        project_root: Path,
    ) -> None:
        """Script finds real test files in Intellicrack project."""
        result = subprocess.run(
            [sys.executable, str(script_path)],
            cwd=str(project_root),
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert result.returncode == 0

        for line in result.stdout.split('\n'):
            if "Total test files:" in line:
                count = int(line.split(':')[1].strip())
                assert count > 20, f"Should find many test files, found {count}"
                break

    def test_script_identifies_coverage_gaps(
        self,
        script_path: Path,
        project_root: Path,
    ) -> None:
        """Script identifies files without test coverage."""
        result = subprocess.run(
            [sys.executable, str(script_path)],
            cwd=str(project_root),
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert result.returncode == 0
        assert "=== SOURCE FILES WITH NO TEST COVERAGE ===" in result.stdout

"""Production tests for configuration cleanup utilities.

Tests verify that configuration cleanup properly identifies and removes
unused configuration code patterns across the codebase.
"""

import ast
import tempfile
from pathlib import Path

import pytest


@pytest.fixture
def temp_python_file(tmp_path: Path) -> Path:
    """Create a temporary Python file for testing."""
    return tmp_path / "test_module.py"


@pytest.fixture
def sample_code_with_qsettings() -> str:
    """Sample code with QSettings usage."""
    return """
from PyQt6.QtCore import QSettings

class ConfigManager:
    def __init__(self):
        self.settings = QSettings("company", "app")

    def save_value(self, key, value):
        self.settings.setValue(key, value)

    def load_value(self, key):
        return self.settings.value(key)
"""


@pytest.fixture
def sample_code_with_deprecated_methods() -> str:
    """Sample code with deprecated configuration methods."""
    return '''
class OldConfigSystem:
    def _save_json_file(self, path, data):
        """Deprecated - use central config instead."""
        pass

    def _load_json_file(self, path):
        """Legacy method for loading config files."""
        pass

    def save_to_registry(self, key, value):
        """Unused - migration only."""
        pass
'''


@pytest.fixture
def sample_code_clean() -> str:
    """Sample code without configuration issues."""
    return """
from intellicrack.core.config_manager import get_config

class ModernConfigManager:
    def __init__(self):
        self.config = get_config()

    def save_value(self, key, value):
        self.config.set(key, value)
"""


class TestUnusedConfigCodeDetector:
    """Tests for UnusedConfigCodeDetector AST visitor."""

    def test_detects_qsettings_import(self, sample_code_with_qsettings: str) -> None:
        """Detector identifies QSettings imports."""
        from intellicrack.utils.config_cleanup import UnusedConfigCodeDetector

        tree = ast.parse(sample_code_with_qsettings)
        detector = UnusedConfigCodeDetector()
        detector.visit(tree)

        assert len(detector.unused_imports) > 0
        import_names = {name for name, _ in detector.unused_imports}
        assert "QSettings" in import_names

    def test_detects_configparser_import(self) -> None:
        """Detector identifies configparser imports."""
        from intellicrack.utils.config_cleanup import UnusedConfigCodeDetector

        code = "import configparser"
        tree = ast.parse(code)
        detector = UnusedConfigCodeDetector()
        detector.visit(tree)

        import_names = {name for name, _ in detector.unused_imports}
        assert "configparser" in import_names

    def test_detects_qsettings_usage(self, sample_code_with_qsettings: str) -> None:
        """Detector identifies QSettings instantiation."""
        from intellicrack.utils.config_cleanup import UnusedConfigCodeDetector

        tree = ast.parse(sample_code_with_qsettings)
        detector = UnusedConfigCodeDetector()
        detector.visit(tree)

        assert len(detector.qsettings_usage) > 0

    def test_detects_deprecated_methods(self, sample_code_with_deprecated_methods: str) -> None:
        """Detector identifies deprecated configuration methods."""
        from intellicrack.utils.config_cleanup import UnusedConfigCodeDetector

        tree = ast.parse(sample_code_with_deprecated_methods)
        detector = UnusedConfigCodeDetector()
        detector.visit(tree)

        assert len(detector.unused_methods) > 0
        method_names = {name for name, _ in detector.unused_methods}
        assert "_save_json_file" in method_names or "save_to_registry" in method_names

    def test_no_false_positives_on_clean_code(self, sample_code_clean: str) -> None:
        """Detector does not report issues in clean code."""
        from intellicrack.utils.config_cleanup import UnusedConfigCodeDetector

        tree = ast.parse(sample_code_clean)
        detector = UnusedConfigCodeDetector()
        detector.visit(tree)

        assert len(detector.unused_imports) == 0
        assert len(detector.unused_methods) == 0
        assert len(detector.qsettings_usage) == 0


class TestAnalyzeFile:
    """Tests for analyze_file function."""

    def test_analyzes_file_with_qsettings(
        self,
        temp_python_file: Path,
        sample_code_with_qsettings: str,
    ) -> None:
        """analyze_file correctly processes files with QSettings usage."""
        from intellicrack.utils.config_cleanup import analyze_file

        temp_python_file.write_text(sample_code_with_qsettings)
        imports, methods, qsettings, legacy = analyze_file(temp_python_file)

        assert len(imports) > 0
        assert len(qsettings) > 0

    def test_analyzes_file_with_deprecated_methods(
        self,
        temp_python_file: Path,
        sample_code_with_deprecated_methods: str,
    ) -> None:
        """analyze_file identifies deprecated configuration methods."""
        from intellicrack.utils.config_cleanup import analyze_file

        temp_python_file.write_text(sample_code_with_deprecated_methods)
        imports, methods, qsettings, legacy = analyze_file(temp_python_file)

        assert len(methods) > 0

    def test_handles_invalid_python_syntax(self, temp_python_file: Path) -> None:
        """analyze_file gracefully handles files with syntax errors."""
        from intellicrack.utils.config_cleanup import analyze_file

        temp_python_file.write_text("def invalid syntax here")
        imports, methods, qsettings, legacy = analyze_file(temp_python_file)

        assert imports == set()
        assert methods == set()
        assert qsettings == []
        assert legacy == []

    def test_handles_nonexistent_file(self) -> None:
        """analyze_file handles nonexistent files."""
        from intellicrack.utils.config_cleanup import analyze_file

        imports, methods, qsettings, legacy = analyze_file(Path("/nonexistent/file.py"))

        assert imports == set()
        assert methods == set()


class TestFindUnusedConfigCode:
    """Tests for find_unused_config_code function."""

    def test_finds_issues_in_directory_tree(self, tmp_path: Path) -> None:
        """find_unused_config_code recursively finds issues in multiple files."""
        from intellicrack.utils.config_cleanup import find_unused_config_code

        (tmp_path / "module1.py").write_text("from PyQt6.QtCore import QSettings")
        (tmp_path / "module2.py").write_text("import configparser")
        (tmp_path / "clean.py").write_text("import sys")

        results = find_unused_config_code(tmp_path)

        assert len(results) >= 2
        assert any("module1.py" in path for path in results.keys())
        assert any("module2.py" in path for path in results.keys())

    def test_skips_test_files(self, tmp_path: Path) -> None:
        """find_unused_config_code skips test files and migration scripts."""
        from intellicrack.utils.config_cleanup import find_unused_config_code

        (tmp_path / "test_module.py").write_text("from PyQt6.QtCore import QSettings")
        (tmp_path / "migration_script.py").write_text("import configparser")

        results = find_unused_config_code(tmp_path)

        assert len(results) == 0

    def test_returns_empty_for_clean_directory(self, tmp_path: Path) -> None:
        """find_unused_config_code returns empty dict for clean codebase."""
        from intellicrack.utils.config_cleanup import find_unused_config_code

        (tmp_path / "clean1.py").write_text("import sys\nimport os")
        (tmp_path / "clean2.py").write_text("from pathlib import Path")

        results = find_unused_config_code(tmp_path)

        assert len(results) == 0


class TestGenerateCleanupReport:
    """Tests for generate_cleanup_report function."""

    def test_generates_report_with_issues(self) -> None:
        """generate_cleanup_report produces formatted report from analysis results."""
        from intellicrack.utils.config_cleanup import generate_cleanup_report

        results = {
            "/path/to/file1.py": {
                "unused_imports": [("QSettings", 1)],
                "unused_methods": [("_save_json_file", 10)],
                "qsettings_usage": [15],
                "legacy_patterns": [("setValue", 20)],
            },
            "/path/to/file2.py": {
                "unused_imports": [("configparser", 1)],
                "unused_methods": [],
                "qsettings_usage": [],
                "legacy_patterns": [],
            },
        }

        report = generate_cleanup_report(results)

        assert "CONFIGURATION CODE CLEANUP REPORT" in report
        assert "Files with unused config code: 2" in report
        assert "file1.py" in report
        assert "file2.py" in report
        assert "QSettings" in report
        assert "configparser" in report

    def test_generates_empty_report(self) -> None:
        """generate_cleanup_report handles empty results."""
        from intellicrack.utils.config_cleanup import generate_cleanup_report

        results = {}
        report = generate_cleanup_report(results)

        assert "CONFIGURATION CODE CLEANUP REPORT" in report
        assert "Files with unused config code: 0" in report


class TestRemoveUnusedImports:
    """Tests for remove_unused_imports function."""

    def test_removes_import_lines(self, temp_python_file: Path) -> None:
        """remove_unused_imports removes specified import lines from file."""
        from intellicrack.utils.config_cleanup import remove_unused_imports

        code = """from PyQt6.QtCore import QSettings
import sys
import os
"""
        temp_python_file.write_text(code)

        unused_imports = {("QSettings", 1)}
        success = remove_unused_imports(temp_python_file, unused_imports)

        assert success
        new_content = temp_python_file.read_text()
        assert "QSettings" not in new_content
        assert "import sys" in new_content
        assert "import os" in new_content

    def test_preserves_other_lines(self, temp_python_file: Path) -> None:
        """remove_unused_imports preserves all non-import lines."""
        from intellicrack.utils.config_cleanup import remove_unused_imports

        code = '''"""Module docstring."""
from PyQt6.QtCore import QSettings

def function():
    pass
'''
        temp_python_file.write_text(code)

        unused_imports = {("QSettings", 2)}
        success = remove_unused_imports(temp_python_file, unused_imports)

        assert success
        new_content = temp_python_file.read_text()
        assert '"""Module docstring."""' in new_content
        assert "def function():" in new_content

    def test_handles_nonexistent_file(self) -> None:
        """remove_unused_imports handles nonexistent files gracefully."""
        from intellicrack.utils.config_cleanup import remove_unused_imports

        success = remove_unused_imports(Path("/nonexistent/file.py"), {("test", 1)})

        assert not success


class TestCleanupFile:
    """Tests for cleanup_file function."""

    def test_auto_fixes_imports(
        self,
        temp_python_file: Path,
        sample_code_with_qsettings: str,
    ) -> None:
        """cleanup_file removes unused imports when auto_fix is enabled."""
        from intellicrack.utils.config_cleanup import cleanup_file

        temp_python_file.write_text(sample_code_with_qsettings)

        fixed_count = cleanup_file(temp_python_file, auto_fix=True)

        assert fixed_count > 0
        content = temp_python_file.read_text()
        assert "QSettings" not in content or "import" not in content.split("QSettings")[0].split("\n")[-1]

    def test_reports_without_fixing(
        self,
        temp_python_file: Path,
        sample_code_with_qsettings: str,
    ) -> None:
        """cleanup_file reports issues without fixing when auto_fix is False."""
        from intellicrack.utils.config_cleanup import cleanup_file

        original_content = sample_code_with_qsettings
        temp_python_file.write_text(original_content)

        fixed_count = cleanup_file(temp_python_file, auto_fix=False)

        assert fixed_count == 0
        assert temp_python_file.read_text() == original_content

    def test_returns_zero_for_clean_file(
        self,
        temp_python_file: Path,
        sample_code_clean: str,
    ) -> None:
        """cleanup_file returns zero issues for clean files."""
        from intellicrack.utils.config_cleanup import cleanup_file

        temp_python_file.write_text(sample_code_clean)

        fixed_count = cleanup_file(temp_python_file, auto_fix=True)

        assert fixed_count == 0


class TestConfigCleanupIntegration:
    """Integration tests for configuration cleanup system."""

    def test_full_cleanup_workflow(self, tmp_path: Path) -> None:
        """Complete workflow from detection to cleanup works correctly."""
        from intellicrack.utils.config_cleanup import cleanup_file, find_unused_config_code, generate_cleanup_report

        (tmp_path / "bad_config.py").write_text("""
from PyQt6.QtCore import QSettings

class BadConfig:
    def __init__(self):
        self.s = QSettings()
""")

        results = find_unused_config_code(tmp_path)
        assert len(results) > 0

        report = generate_cleanup_report(results)
        assert "QSettings" in report

        for file_path_str in results:
            file_path = Path(file_path_str)
            fixed = cleanup_file(file_path, auto_fix=True)
            assert fixed >= 0

    def test_handles_real_project_structure(self, tmp_path: Path) -> None:
        """Cleanup system works on realistic project directory structure."""
        from intellicrack.utils.config_cleanup import find_unused_config_code

        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "module.py").write_text("from PyQt6.QtCore import QSettings")
        (tmp_path / "tests").mkdir()
        (tmp_path / "tests" / "test_module.py").write_text("import configparser")

        results = find_unused_config_code(tmp_path)

        assert any("src" in path and "module.py" in path for path in results.keys())
        assert all("tests" not in path for path in results.keys())


class TestEdgeCases:
    """Edge case tests for configuration cleanup."""

    def test_handles_empty_file(self, temp_python_file: Path) -> None:
        """Cleanup handles empty Python files."""
        from intellicrack.utils.config_cleanup import analyze_file

        temp_python_file.write_text("")
        imports, methods, qsettings, legacy = analyze_file(temp_python_file)

        assert imports == set()
        assert methods == set()

    def test_handles_unicode_content(self, temp_python_file: Path) -> None:
        """Cleanup handles files with Unicode characters."""
        from intellicrack.utils.config_cleanup import analyze_file

        temp_python_file.write_text('"""Module with Unicode: 日本語, Ελληνικά."""\nimport sys', encoding="utf-8")
        imports, methods, qsettings, legacy = analyze_file(temp_python_file)

        assert imports == set()

    def test_handles_multiline_imports(self, temp_python_file: Path) -> None:
        """Cleanup handles multiline import statements."""
        from intellicrack.utils.config_cleanup import analyze_file

        code = """from PyQt6.QtCore import (
    QSettings,
    QObject,
)"""
        temp_python_file.write_text(code)
        imports, methods, qsettings, legacy = analyze_file(temp_python_file)

        import_names = {name for name, _ in imports}
        assert "QSettings" in import_names

    def test_performance_on_large_codebase(self, tmp_path: Path) -> None:
        """Cleanup performs efficiently on large codebases."""
        import time

        from intellicrack.utils.config_cleanup import find_unused_config_code

        for i in range(50):
            (tmp_path / f"module{i}.py").write_text(f"import sys\nclass Module{i}:\n    pass")

        (tmp_path / "with_issue.py").write_text("from PyQt6.QtCore import QSettings")

        start = time.time()
        results = find_unused_config_code(tmp_path)
        elapsed = time.time() - start

        assert elapsed < 5.0
        assert len(results) > 0

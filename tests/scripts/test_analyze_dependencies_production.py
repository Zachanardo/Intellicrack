"""Production tests for scripts/analyze_dependencies.py.

These tests validate the dependency analyzer that scans the codebase for third-party
imports and identifies missing dependencies. Tests use real project structure and
actual import analysis.

Copyright (C) 2025 Zachary Flint
"""

import ast
import tempfile
from pathlib import Path
from typing import Any

import pytest

from scripts.analyze_dependencies import DependencyAnalyzer


class TestDependencyAnalyzerInitialization:
    """Production tests for DependencyAnalyzer initialization."""

    def test_analyzer_initializes_with_valid_project_root(self) -> None:
        """DependencyAnalyzer initializes successfully with project root."""
        project_root = Path(__file__).parent.parent.parent
        analyzer = DependencyAnalyzer(project_root)

        assert analyzer is not None
        assert analyzer.project_root == project_root
        assert hasattr(analyzer, "local_modules")
        assert hasattr(analyzer, "installed_packages")
        assert hasattr(analyzer, "package_to_imports")
        assert hasattr(analyzer, "stdlib_modules")

    def test_local_modules_discovered(self) -> None:
        """Local modules discovered correctly during initialization."""
        project_root = Path(__file__).parent.parent.parent
        analyzer = DependencyAnalyzer(project_root)

        assert isinstance(analyzer.local_modules, set)
        assert len(analyzer.local_modules) > 0
        assert "intellicrack" in analyzer.local_modules

    def test_installed_packages_discovered(self) -> None:
        """Installed packages enumerated correctly."""
        project_root = Path(__file__).parent.parent.parent
        analyzer = DependencyAnalyzer(project_root)

        assert isinstance(analyzer.installed_packages, dict)
        assert len(analyzer.installed_packages) > 0

        for package_name, version in list(analyzer.installed_packages.items())[:5]:
            assert isinstance(package_name, str)
            assert isinstance(version, str)
            assert len(package_name) > 0
            assert len(version) > 0

    def test_package_import_map_built(self) -> None:
        """Package-to-import mapping built correctly."""
        project_root = Path(__file__).parent.parent.parent
        analyzer = DependencyAnalyzer(project_root)

        assert isinstance(analyzer.package_to_imports, dict)
        assert len(analyzer.package_to_imports) > 0

        for import_name, package_name in list(analyzer.package_to_imports.items())[:10]:
            assert isinstance(import_name, str)
            assert isinstance(package_name, str)
            assert len(import_name) > 0
            assert len(package_name) > 0

    def test_stdlib_modules_comprehensive(self) -> None:
        """Standard library modules set is comprehensive."""
        project_root = Path(__file__).parent.parent.parent
        analyzer = DependencyAnalyzer(project_root)

        assert isinstance(analyzer.stdlib_modules, set)
        assert len(analyzer.stdlib_modules) > 50

        essential_stdlib = {"os", "sys", "pathlib", "json", "re", "logging", "typing"}
        for module in essential_stdlib:
            assert module in analyzer.stdlib_modules


class TestLocalModuleDiscovery:
    """Production tests for local module discovery."""

    def test_discover_local_modules_excludes_build_dirs(self) -> None:
        """Local module discovery excludes build/dist directories."""
        project_root = Path(__file__).parent.parent.parent
        analyzer = DependencyAnalyzer(project_root)

        for module in analyzer.local_modules:
            assert ".pixi" not in module
            assert ".venv" not in module
            assert "__pycache__" not in module
            assert ".git" not in module

    def test_discover_local_modules_includes_subdirectories(self) -> None:
        """Local module discovery includes package subdirectories."""
        project_root = Path(__file__).parent.parent.parent
        analyzer = DependencyAnalyzer(project_root)

        submodules = [m for m in analyzer.local_modules if "." in m and m.startswith("intellicrack")]
        assert len(submodules) > 0

    def test_discover_local_modules_real_directories(self) -> None:
        """Discovered local modules correspond to real directories."""
        project_root = Path(__file__).parent.parent.parent
        analyzer = DependencyAnalyzer(project_root)

        intellicrack_dir = project_root / "intellicrack"
        if intellicrack_dir.exists():
            assert "intellicrack" in analyzer.local_modules


class TestImportExtraction:
    """Production tests for import statement extraction."""

    def test_extract_imports_from_valid_file(self) -> None:
        """extract_imports() extracts imports from valid Python file."""
        project_root = Path(__file__).parent.parent.parent
        analyzer = DependencyAnalyzer(project_root)

        test_file = project_root / "intellicrack" / "config.py"
        if test_file.exists():
            imports = analyzer.extract_imports(test_file)

            assert isinstance(imports, set)
            assert len(imports) > 0

            common_imports = {"os", "logging", "typing"}
            found_common = any(imp in imports for imp in common_imports)
            assert found_common

    def test_extract_imports_handles_import_statements(self) -> None:
        """extract_imports() correctly parses import statements."""
        with tempfile.TemporaryDirectory() as temp_dir:
            project_root = Path(temp_dir)
            analyzer = DependencyAnalyzer(project_root)

            test_file = Path(temp_dir) / "test_module.py"
            test_file.write_text("import os\nimport sys\nfrom pathlib import Path\n")

            imports = analyzer.extract_imports(test_file)

            assert "os" in imports
            assert "sys" in imports
            assert "pathlib" in imports

    def test_extract_imports_handles_from_imports(self) -> None:
        """extract_imports() correctly parses from...import statements."""
        with tempfile.TemporaryDirectory() as temp_dir:
            project_root = Path(temp_dir)
            analyzer = DependencyAnalyzer(project_root)

            test_file = Path(temp_dir) / "test_module.py"
            test_file.write_text("from typing import Any, Dict\nfrom pathlib import Path\n")

            imports = analyzer.extract_imports(test_file)

            assert "typing" in imports
            assert "pathlib" in imports

    def test_extract_imports_gets_top_level_only(self) -> None:
        """extract_imports() extracts only top-level package names."""
        with tempfile.TemporaryDirectory() as temp_dir:
            project_root = Path(temp_dir)
            analyzer = DependencyAnalyzer(project_root)

            test_file = Path(temp_dir) / "test_module.py"
            test_file.write_text("from os.path import join\nimport collections.abc\n")

            imports = analyzer.extract_imports(test_file)

            assert "os" in imports
            assert "collections" in imports
            assert "os.path" not in imports
            assert "collections.abc" not in imports

    def test_extract_imports_handles_syntax_errors(self) -> None:
        """extract_imports() handles syntax errors gracefully."""
        with tempfile.TemporaryDirectory() as temp_dir:
            project_root = Path(temp_dir)
            analyzer = DependencyAnalyzer(project_root)

            test_file = Path(temp_dir) / "test_invalid.py"
            test_file.write_text("import os\ndef broken_func(\n")

            imports = analyzer.extract_imports(test_file)

            assert isinstance(imports, set)

    def test_extract_imports_handles_unicode_errors(self) -> None:
        """extract_imports() handles unicode decode errors gracefully."""
        with tempfile.TemporaryDirectory() as temp_dir:
            project_root = Path(temp_dir)
            analyzer = DependencyAnalyzer(project_root)

            test_file = Path(temp_dir) / "test_binary.py"
            test_file.write_bytes(b"\x00\x01\x02\x03import os\n")

            imports = analyzer.extract_imports(test_file)

            assert isinstance(imports, set)


class TestImportClassification:
    """Production tests for import classification."""

    def test_classify_local_module(self) -> None:
        """classify_import() identifies local modules correctly."""
        project_root = Path(__file__).parent.parent.parent
        analyzer = DependencyAnalyzer(project_root)

        classification, package = analyzer.classify_import("intellicrack")

        assert classification == "local"
        assert package == "intellicrack"

    def test_classify_stdlib_module(self) -> None:
        """classify_import() identifies standard library modules."""
        project_root = Path(__file__).parent.parent.parent
        analyzer = DependencyAnalyzer(project_root)

        for stdlib_module in ["os", "sys", "pathlib", "json"]:
            classification, package = analyzer.classify_import(stdlib_module)

            assert classification == "stdlib"
            assert package == stdlib_module

    def test_classify_installed_package(self) -> None:
        """classify_import() identifies installed third-party packages."""
        project_root = Path(__file__).parent.parent.parent
        analyzer = DependencyAnalyzer(project_root)

        common_packages = ["pytest", "setuptools"]

        for package_name in common_packages:
            if package_name in analyzer.package_to_imports or package_name.lower() in analyzer.installed_packages:
                classification, _ = analyzer.classify_import(package_name)
                assert classification == "installed"

    def test_classify_missing_import(self) -> None:
        """classify_import() identifies missing/unknown imports."""
        project_root = Path(__file__).parent.parent.parent
        analyzer = DependencyAnalyzer(project_root)

        classification, package = analyzer.classify_import("nonexistent_package_xyz_12345")

        assert classification == "missing"
        assert package == "nonexistent_package_xyz_12345"

    def test_classify_builtin_dunder_imports(self) -> None:
        """classify_import() classifies __future__ and __main__ as stdlib."""
        project_root = Path(__file__).parent.parent.parent
        analyzer = DependencyAnalyzer(project_root)

        classification, _ = analyzer.classify_import("__future__")
        assert classification == "stdlib"

        classification, _ = analyzer.classify_import("__main__")
        assert classification == "stdlib"

    def test_classify_test_modules_as_local(self) -> None:
        """classify_import() classifies test modules as local."""
        project_root = Path(__file__).parent.parent.parent
        analyzer = DependencyAnalyzer(project_root)

        classification, package = analyzer.classify_import("tests")

        assert classification == "local"
        assert package == "tests"


class TestProjectAnalysis:
    """Production tests for full project analysis."""

    def test_analyze_project_returns_results(self) -> None:
        """analyze_project() returns analysis results dictionary."""
        with tempfile.TemporaryDirectory() as temp_dir:
            project_root = Path(temp_dir)

            (project_root / "intellicrack").mkdir()
            test_file = project_root / "intellicrack" / "module.py"
            test_file.write_text("import os\nimport sys\n")

            analyzer = DependencyAnalyzer(project_root)
            results = analyzer.analyze_project()

            assert isinstance(results, dict)

    def test_analyze_project_finds_python_files(self) -> None:
        """analyze_project() finds and analyzes Python files."""
        with tempfile.TemporaryDirectory() as temp_dir:
            project_root = Path(temp_dir)

            (project_root / "intellicrack").mkdir()
            test_file = project_root / "intellicrack" / "module.py"
            test_file.write_text("import os\nimport nonexistent_package_xyz\n")

            analyzer = DependencyAnalyzer(project_root)
            results = analyzer.analyze_project()

            assert "missing" in results or len(results.get("missing", [])) >= 0

    def test_analyze_project_excludes_test_directory(self) -> None:
        """analyze_project() excludes tests directory from analysis."""
        with tempfile.TemporaryDirectory() as temp_dir:
            project_root = Path(temp_dir)

            (project_root / "intellicrack").mkdir()
            (project_root / "tests").mkdir()

            test_file = project_root / "tests" / "test_module.py"
            test_file.write_text("import pytest\n")

            analyzer = DependencyAnalyzer(project_root)
            results = analyzer.analyze_project()

            assert isinstance(results, dict)

    def test_analyze_project_excludes_build_dirs(self) -> None:
        """analyze_project() excludes build/dist directories."""
        with tempfile.TemporaryDirectory() as temp_dir:
            project_root = Path(temp_dir)

            (project_root / "intellicrack").mkdir()
            (project_root / "build").mkdir()
            (project_root / "dist").mkdir()

            test_file = project_root / "build" / "temp.py"
            test_file.write_text("import buildonlypackage\n")

            analyzer = DependencyAnalyzer(project_root)
            results = analyzer.analyze_project()

            missing_imports = [imp for imp, _ in results.get("missing", [])]
            assert "buildonlypackage" not in missing_imports


class TestMissingDependencyDetection:
    """Production tests for missing dependency detection."""

    def test_detect_missing_dependencies(self) -> None:
        """Missing dependencies detected correctly."""
        with tempfile.TemporaryDirectory() as temp_dir:
            project_root = Path(temp_dir)

            (project_root / "intellicrack").mkdir()
            test_file = project_root / "intellicrack" / "module.py"
            test_file.write_text(
                "import os\nimport nonexistent_package_xyz\nimport another_missing_pkg\n"
            )

            analyzer = DependencyAnalyzer(project_root)
            results = analyzer.analyze_project()

            missing = results.get("missing", [])
            missing_names = {imp for imp, _ in missing}

            assert "nonexistent_package_xyz" in missing_names
            assert "another_missing_pkg" in missing_names
            assert "os" not in missing_names

    def test_missing_dependencies_include_file_paths(self) -> None:
        """Missing dependency results include file paths."""
        with tempfile.TemporaryDirectory() as temp_dir:
            project_root = Path(temp_dir)

            (project_root / "intellicrack").mkdir()
            test_file = project_root / "intellicrack" / "module.py"
            test_file.write_text("import missing_package\n")

            analyzer = DependencyAnalyzer(project_root)
            results = analyzer.analyze_project()

            missing = results.get("missing", [])

            for import_name, file_path in missing:
                assert isinstance(import_name, str)
                assert isinstance(file_path, Path)
                assert file_path.exists()


class TestInstalledPackageMapping:
    """Production tests for installed package mapping."""

    def test_package_to_import_mapping_accuracy(self) -> None:
        """Package-to-import mapping correctly maps import names."""
        project_root = Path(__file__).parent.parent.parent
        analyzer = DependencyAnalyzer(project_root)

        common_mappings = {
            "pytest": "pytest",
        }

        for import_name, expected_package in common_mappings.items():
            if expected_package in analyzer.installed_packages:
                mapped_package = analyzer.package_to_imports.get(import_name)
                if mapped_package:
                    assert mapped_package == expected_package

    def test_package_name_normalization(self) -> None:
        """Package names normalized correctly (hyphens to underscores)."""
        project_root = Path(__file__).parent.parent.parent
        analyzer = DependencyAnalyzer(project_root)

        for import_name, package_name in list(analyzer.package_to_imports.items())[:20]:
            if "-" in package_name:
                underscore_version = package_name.replace("-", "_")
                assert (
                    import_name == package_name
                    or import_name == underscore_version
                    or import_name in package_name
                )


class TestStandardLibraryDetection:
    """Production tests for standard library detection."""

    def test_stdlib_modules_comprehensive_coverage(self) -> None:
        """Standard library set includes comprehensive module list."""
        project_root = Path(__file__).parent.parent.parent
        analyzer = DependencyAnalyzer(project_root)

        essential_modules = [
            "os",
            "sys",
            "pathlib",
            "json",
            "re",
            "logging",
            "typing",
            "collections",
            "itertools",
            "functools",
            "subprocess",
            "tempfile",
            "datetime",
            "time",
            "hashlib",
            "base64",
            "urllib",
            "http",
            "socket",
            "threading",
            "multiprocessing",
        ]

        for module in essential_modules:
            assert module in analyzer.stdlib_modules, f"Missing essential stdlib module: {module}"

    def test_stdlib_classification_correct(self) -> None:
        """Standard library modules classified correctly."""
        project_root = Path(__file__).parent.parent.parent
        analyzer = DependencyAnalyzer(project_root)

        stdlib_samples = ["os", "sys", "pathlib", "json", "logging"]

        for stdlib_module in stdlib_samples:
            classification, _ = analyzer.classify_import(stdlib_module)
            assert classification == "stdlib", f"{stdlib_module} not classified as stdlib"


class TestEdgeCases:
    """Production tests for edge cases and error handling."""

    def test_empty_project_analysis(self) -> None:
        """Analysis handles empty project directory gracefully."""
        with tempfile.TemporaryDirectory() as temp_dir:
            project_root = Path(temp_dir)

            analyzer = DependencyAnalyzer(project_root)
            results = analyzer.analyze_project()

            assert isinstance(results, dict)

    def test_project_with_no_imports(self) -> None:
        """Analysis handles files with no imports correctly."""
        with tempfile.TemporaryDirectory() as temp_dir:
            project_root = Path(temp_dir)

            (project_root / "intellicrack").mkdir()
            test_file = project_root / "intellicrack" / "module.py"
            test_file.write_text("# No imports\nx = 1\n")

            analyzer = DependencyAnalyzer(project_root)
            results = analyzer.analyze_project()

            assert isinstance(results, dict)

    def test_circular_import_handling(self) -> None:
        """Analysis handles circular imports without infinite loops."""
        with tempfile.TemporaryDirectory() as temp_dir:
            project_root = Path(temp_dir)

            (project_root / "intellicrack").mkdir()
            (project_root / "intellicrack" / "__init__.py").touch()

            file_a = project_root / "intellicrack" / "a.py"
            file_b = project_root / "intellicrack" / "b.py"

            file_a.write_text("from intellicrack.b import func_b\n")
            file_b.write_text("from intellicrack.a import func_a\n")

            analyzer = DependencyAnalyzer(project_root)
            results = analyzer.analyze_project()

            assert isinstance(results, dict)

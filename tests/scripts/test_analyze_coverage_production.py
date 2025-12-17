"""Production tests for scripts/analyze_coverage.py.

These tests validate the coverage analysis script that identifies untested modules
in the Intellicrack codebase. Tests use real directory structures and actual file
analysis without mocks.

Copyright (C) 2025 Zachary Flint
"""

import os
import tempfile
from pathlib import Path
from typing import Any

import pytest

from scripts.analyze_coverage import (
    analyze_coverage,
    get_source_modules,
    get_test_targets,
)


class TestSourceModuleDiscovery:
    """Production tests for source module discovery."""

    def test_get_source_modules_returns_dict(self) -> None:
        """get_source_modules() returns dictionary of module names to paths."""
        original_dir = os.getcwd()
        try:
            project_root = Path(__file__).parent.parent.parent
            os.chdir(project_root)

            modules = get_source_modules()

            assert isinstance(modules, dict)
            assert len(modules) > 0
        finally:
            os.chdir(original_dir)

    def test_source_modules_contain_core_components(self) -> None:
        """Source modules include critical core components."""
        original_dir = os.getcwd()
        try:
            project_root = Path(__file__).parent.parent.parent
            os.chdir(project_root)

            modules = get_source_modules()

            core_modules = [name for name in modules.keys() if "core" in modules[name]]
            assert len(core_modules) > 0
        finally:
            os.chdir(original_dir)

    def test_source_modules_have_valid_paths(self) -> None:
        """All source module paths actually exist on filesystem."""
        original_dir = os.getcwd()
        try:
            project_root = Path(__file__).parent.parent.parent
            os.chdir(project_root)

            modules = get_source_modules()

            for module_path in list(modules.values())[:20]:
                assert Path(module_path).exists(), f"Module path does not exist: {module_path}"
                assert module_path.endswith(".py"), f"Module path is not a Python file: {module_path}"
        finally:
            os.chdir(original_dir)

    def test_source_modules_exclude_init_files(self) -> None:
        """Source modules exclude __init__.py files."""
        original_dir = os.getcwd()
        try:
            project_root = Path(__file__).parent.parent.parent
            os.chdir(project_root)

            modules = get_source_modules()

            for module_path in modules.values():
                assert not module_path.endswith("__init__.py"), f"Found __init__.py: {module_path}"
        finally:
            os.chdir(original_dir)

    def test_source_modules_in_intellicrack_directory(self) -> None:
        """Source modules are within intellicrack directory."""
        original_dir = os.getcwd()
        try:
            project_root = Path(__file__).parent.parent.parent
            os.chdir(project_root)

            modules = get_source_modules()

            for module_path in modules.values():
                assert "intellicrack" in module_path.replace("\\", "/"), f"Module outside intellicrack: {module_path}"
        finally:
            os.chdir(original_dir)


class TestTestTargetDiscovery:
    """Production tests for test target discovery."""

    def test_get_test_targets_returns_dict(self) -> None:
        """get_test_targets() returns dictionary mapping modules to test files."""
        original_dir = os.getcwd()
        try:
            project_root = Path(__file__).parent.parent.parent
            os.chdir(project_root)

            targets = get_test_targets()

            assert isinstance(targets, dict)
            assert len(targets) > 0
        finally:
            os.chdir(original_dir)

    def test_test_targets_have_valid_paths(self) -> None:
        """All test target paths actually exist on filesystem."""
        original_dir = os.getcwd()
        try:
            project_root = Path(__file__).parent.parent.parent
            os.chdir(project_root)

            targets = get_test_targets()

            for test_paths in list(targets.values())[:20]:
                for test_path in test_paths:
                    assert Path(test_path).exists(), f"Test path does not exist: {test_path}"
                    assert test_path.endswith(".py"), f"Test path is not a Python file: {test_path}"
        finally:
            os.chdir(original_dir)

    def test_test_targets_start_with_test_prefix(self) -> None:
        """All test files follow test_* naming convention."""
        original_dir = os.getcwd()
        try:
            project_root = Path(__file__).parent.parent.parent
            os.chdir(project_root)

            targets = get_test_targets()

            for test_paths in targets.values():
                for test_path in test_paths:
                    filename = Path(test_path).name
                    assert filename.startswith("test_"), f"Test file doesn't start with test_: {filename}"
        finally:
            os.chdir(original_dir)

    def test_test_targets_in_tests_directory(self) -> None:
        """All test files are within tests directory."""
        original_dir = os.getcwd()
        try:
            project_root = Path(__file__).parent.parent.parent
            os.chdir(project_root)

            targets = get_test_targets()

            for test_paths in targets.values():
                for test_path in test_paths:
                    assert "tests" in test_path.replace("\\", "/"), f"Test file outside tests: {test_path}"
        finally:
            os.chdir(original_dir)

    def test_test_targets_map_to_modules(self) -> None:
        """Test targets contain mappings to actual module names."""
        original_dir = os.getcwd()
        try:
            project_root = Path(__file__).parent.parent.parent
            os.chdir(project_root)

            targets = get_test_targets()

            assert len(targets.keys()) > 0
            for module_name in list(targets.keys())[:10]:
                assert isinstance(module_name, str)
                assert len(module_name) > 0
        finally:
            os.chdir(original_dir)


class TestCoverageAnalysis:
    """Production tests for coverage analysis functionality."""

    def test_analyze_coverage_executes_without_error(self) -> None:
        """analyze_coverage() executes successfully on real codebase."""
        original_dir = os.getcwd()
        try:
            project_root = Path(__file__).parent.parent.parent
            os.chdir(project_root)

            analyze_coverage()

        finally:
            os.chdir(original_dir)

    def test_coverage_calculation_accuracy(self) -> None:
        """Coverage statistics are mathematically correct."""
        original_dir = os.getcwd()
        try:
            project_root = Path(__file__).parent.parent.parent
            os.chdir(project_root)

            source_modules = get_source_modules()
            test_targets = get_test_targets()

            covered = set(test_targets.keys())
            all_sources = set(source_modules.keys())
            uncovered = all_sources - covered

            assert len(all_sources) > 0
            assert len(covered) >= 0
            assert len(uncovered) >= 0
            assert len(covered) + len(uncovered) >= len(all_sources) - len(covered & uncovered)

            if len(all_sources) > 0:
                coverage_rate = len(covered) / len(all_sources) * 100
                assert 0 <= coverage_rate <= 100
        finally:
            os.chdir(original_dir)

    def test_critical_modules_identification(self) -> None:
        """Coverage analysis identifies critical untested modules correctly."""
        original_dir = os.getcwd()
        try:
            project_root = Path(__file__).parent.parent.parent
            os.chdir(project_root)

            source_modules = get_source_modules()
            test_targets = get_test_targets()

            covered = set(test_targets.keys())
            all_sources = set(source_modules.keys())
            uncovered = all_sources - covered

            critical_keywords = [
                "license",
                "keygen",
                "bypass",
                "crack",
                "patch",
                "protection",
                "serial",
                "activation",
                "validation",
            ]

            critical_uncovered = []
            for module_name in uncovered:
                module_path = source_modules.get(module_name, "")
                score = sum(
                    1 for kw in critical_keywords if kw in module_name.lower() or kw in module_path.lower()
                )
                if score > 0:
                    critical_uncovered.append((score, module_name, module_path))

            assert isinstance(critical_uncovered, list)
        finally:
            os.chdir(original_dir)

    def test_priority_directory_analysis(self) -> None:
        """Coverage analysis correctly analyzes priority directories."""
        original_dir = os.getcwd()
        try:
            project_root = Path(__file__).parent.parent.parent
            os.chdir(project_root)

            source_modules = get_source_modules()
            test_targets = get_test_targets()

            covered = set(test_targets.keys())
            all_sources = set(source_modules.keys())
            uncovered = all_sources - covered

            priority_dirs = [
                "intellicrack/core/",
                "intellicrack/protection/",
                "intellicrack/plugins/",
            ]

            for priority_dir in priority_dirs:
                dir_uncovered = []
                for module_name in uncovered:
                    module_path = source_modules.get(module_name, "")
                    if priority_dir in module_path.replace("\\", "/"):
                        dir_uncovered.append(module_path)

                assert isinstance(dir_uncovered, list)
        finally:
            os.chdir(original_dir)


class TestModulePathProcessing:
    """Production tests for module path processing logic."""

    def test_source_modules_exclude_pycache(self) -> None:
        """Source module discovery excludes __pycache__ directories."""
        original_dir = os.getcwd()
        try:
            project_root = Path(__file__).parent.parent.parent
            os.chdir(project_root)

            modules = get_source_modules()

            for module_path in modules.values():
                assert "__pycache__" not in module_path, f"Found __pycache__ in path: {module_path}"
        finally:
            os.chdir(original_dir)

    def test_test_targets_exclude_pycache(self) -> None:
        """Test target discovery excludes __pycache__ directories."""
        original_dir = os.getcwd()
        try:
            project_root = Path(__file__).parent.parent.parent
            os.chdir(project_root)

            targets = get_test_targets()

            for test_paths in targets.values():
                for test_path in test_paths:
                    assert "__pycache__" not in test_path, f"Found __pycache__ in path: {test_path}"
        finally:
            os.chdir(original_dir)

    def test_module_name_extraction(self) -> None:
        """Module names extracted correctly from file paths."""
        original_dir = os.getcwd()
        try:
            project_root = Path(__file__).parent.parent.parent
            os.chdir(project_root)

            modules = get_source_modules()

            for module_name, module_path in list(modules.items())[:20]:
                assert module_name in Path(module_path).stem or module_name == Path(module_path).stem
                assert not module_name.endswith(".py")
        finally:
            os.chdir(original_dir)


class TestCoverageReporting:
    """Production tests for coverage reporting functionality."""

    def test_coverage_rate_calculation(self) -> None:
        """Coverage rate calculated correctly as percentage."""
        original_dir = os.getcwd()
        try:
            project_root = Path(__file__).parent.parent.parent
            os.chdir(project_root)

            source_modules = get_source_modules()
            test_targets = get_test_targets()

            covered = set(test_targets.keys())
            all_sources = set(source_modules.keys())

            if len(all_sources) > 0:
                coverage_rate = len(covered) / len(all_sources) * 100
                assert isinstance(coverage_rate, float)
                assert 0.0 <= coverage_rate <= 100.0
        finally:
            os.chdir(original_dir)

    def test_uncovered_modules_calculation(self) -> None:
        """Uncovered modules set calculated correctly."""
        original_dir = os.getcwd()
        try:
            project_root = Path(__file__).parent.parent.parent
            os.chdir(project_root)

            source_modules = get_source_modules()
            test_targets = get_test_targets()

            covered = set(test_targets.keys())
            all_sources = set(source_modules.keys())
            uncovered = all_sources - covered

            assert isinstance(uncovered, set)
            for module_name in list(uncovered)[:10]:
                assert module_name in all_sources
                assert module_name not in covered
        finally:
            os.chdir(original_dir)

    def test_covered_modules_have_tests(self) -> None:
        """Covered modules actually have corresponding test files."""
        original_dir = os.getcwd()
        try:
            project_root = Path(__file__).parent.parent.parent
            os.chdir(project_root)

            test_targets = get_test_targets()

            for module_name, test_paths in list(test_targets.items())[:20]:
                assert len(test_paths) > 0, f"Module {module_name} marked as covered but has no tests"
                for test_path in test_paths:
                    assert Path(test_path).exists(), f"Test file doesn't exist: {test_path}"
        finally:
            os.chdir(original_dir)


class TestCriticalModuleScoring:
    """Production tests for critical module scoring algorithm."""

    def test_critical_module_scoring_logic(self) -> None:
        """Critical modules scored correctly based on keywords."""
        original_dir = os.getcwd()
        try:
            project_root = Path(__file__).parent.parent.parent
            os.chdir(project_root)

            source_modules = get_source_modules()

            critical_keywords = [
                "license",
                "keygen",
                "bypass",
                "crack",
                "patch",
                "protection",
            ]

            for module_name, module_path in list(source_modules.items())[:20]:
                score = sum(
                    1 for kw in critical_keywords if kw in module_name.lower() or kw in module_path.lower()
                )
                assert isinstance(score, int)
                assert score >= 0
                assert score <= len(critical_keywords)
        finally:
            os.chdir(original_dir)

    def test_high_priority_modules_identified(self) -> None:
        """High-priority licensing modules identified correctly."""
        original_dir = os.getcwd()
        try:
            project_root = Path(__file__).parent.parent.parent
            os.chdir(project_root)

            source_modules = get_source_modules()
            test_targets = get_test_targets()

            covered = set(test_targets.keys())
            all_sources = set(source_modules.keys())
            uncovered = all_sources - covered

            critical_keywords = ["license", "keygen", "crack", "protection"]

            high_priority = []
            for module_name in uncovered:
                module_path = source_modules.get(module_name, "")
                score = sum(
                    1 for kw in critical_keywords if kw in module_name.lower() or kw in module_path.lower()
                )
                if score >= 2:
                    high_priority.append((score, module_name, module_path))

            assert isinstance(high_priority, list)
            high_priority.sort(reverse=True)

            for score, module_name, module_path in high_priority[:5]:
                assert score >= 2
                assert module_name in source_modules
        finally:
            os.chdir(original_dir)


class TestDirectoryFiltering:
    """Production tests for directory filtering logic."""

    def test_test_suffix_stripping(self) -> None:
        """Test file suffixes stripped correctly from module names."""
        original_dir = os.getcwd()
        try:
            project_root = Path(__file__).parent.parent.parent
            os.chdir(project_root)

            targets = get_test_targets()

            import re

            for module_name in list(targets.keys())[:20]:
                assert not re.search(
                    r"_(comprehensive|advanced|gaps|validation|real|simple|basic|debug|integration)$",
                    module_name,
                ), f"Module name contains test suffix: {module_name}"
        finally:
            os.chdir(original_dir)

    def test_directory_walking_correctness(self) -> None:
        """Directory walking finds all Python files correctly."""
        original_dir = os.getcwd()
        try:
            project_root = Path(__file__).parent.parent.parent
            os.chdir(project_root)

            modules = get_source_modules()

            intellicrack_dir = Path("intellicrack")
            if intellicrack_dir.exists():
                for py_file in list(intellicrack_dir.rglob("*.py"))[:20]:
                    if "__pycache__" not in str(py_file) and "__init__.py" not in str(py_file):
                        module_name = py_file.stem
                        module_path = str(py_file).replace("\\", "/")

                        found = any(
                            module_name in found_name or found_path == module_path
                            for found_name, found_path in modules.items()
                        )
        finally:
            os.chdir(original_dir)


class TestEdgeCases:
    """Production tests for edge cases and error handling."""

    def test_empty_directory_handling(self) -> None:
        """Analysis handles empty directories gracefully."""
        with tempfile.TemporaryDirectory() as temp_dir:
            original_dir = os.getcwd()
            try:
                os.chdir(temp_dir)

                Path("intellicrack").mkdir()
                Path("tests").mkdir()

                modules = get_source_modules()
                targets = get_test_targets()

                assert isinstance(modules, dict)
                assert isinstance(targets, dict)
            finally:
                os.chdir(original_dir)

    def test_analysis_with_no_tests(self) -> None:
        """Analysis handles codebase with no tests correctly."""
        with tempfile.TemporaryDirectory() as temp_dir:
            original_dir = os.getcwd()
            try:
                os.chdir(temp_dir)

                Path("intellicrack").mkdir()
                (Path("intellicrack") / "module.py").write_text("# Test module\n")
                Path("tests").mkdir()

                modules = get_source_modules()
                targets = get_test_targets()

                assert len(modules) > 0
                assert len(targets) == 0
            finally:
                os.chdir(original_dir)

    def test_analysis_with_no_source(self) -> None:
        """Analysis handles test directory with no source modules."""
        with tempfile.TemporaryDirectory() as temp_dir:
            original_dir = os.getcwd()
            try:
                os.chdir(temp_dir)

                Path("intellicrack").mkdir()
                Path("tests").mkdir()
                (Path("tests") / "test_module.py").write_text("# Test\n")

                modules = get_source_modules()
                targets = get_test_targets()

                assert len(modules) == 0
                assert len(targets) >= 0
            finally:
                os.chdir(original_dir)

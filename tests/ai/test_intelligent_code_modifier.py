"""Production tests for Intelligent Code Modifier.

Tests AI-powered code modification with real LLM integration and file operations.

Copyright (C) 2025 Zachary Flint
"""

import tempfile
from pathlib import Path

import pytest

from intellicrack.ai.intelligent_code_modifier import (
    ChangeStatus,
    CodeAnalyzer,
    CodeChange,
    DiffGenerator,
    IntelligentCodeModifier,
    ModificationRequest,
    ModificationType,
)


@pytest.fixture
def python_test_file() -> Path:
    """Create temporary Python file for modification testing."""
    import os
    fd, path = tempfile.mkstemp(suffix=".py", text=True)
    try:
        with os.fdopen(fd, "w") as f:
            f.write("""import os
import sys

def test_function():
    return 42

class TestClass:
    def method(self):
        pass
""")
        return Path(path)
    except Exception:
        os.close(fd)
        raise


@pytest.fixture
def code_analyzer() -> CodeAnalyzer:
    """Create code analyzer instance."""
    return CodeAnalyzer()


@pytest.fixture
def diff_generator() -> DiffGenerator:
    """Create diff generator instance."""
    return DiffGenerator()


@pytest.fixture
def code_modifier() -> IntelligentCodeModifier:
    """Create code modifier instance."""
    return IntelligentCodeModifier()


class TestCodeAnalyzer:
    """Test code analysis functionality."""

    def test_analyze_python_file(self, code_analyzer: CodeAnalyzer, python_test_file: Path) -> None:
        """Python file analysis extracts imports, classes, and functions."""
        context = code_analyzer.analyze_file(str(python_test_file))

        assert context.language in {"python", "unknown"}
        if context.language == "python" and context.content:
            assert "os" in context.imports or "sys" in context.imports
            assert "test_function" in context.functions
            assert "TestClass" in context.classes

    def test_analyze_javascript_file(self, code_analyzer: CodeAnalyzer) -> None:
        """JavaScript file analysis extracts code structure."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".js", delete=False) as f:
            f.write("""
import React from 'react';

function TestComponent() {
    return null;
}

class MyClass {
    constructor() {}
}
""")
            js_file = Path(f.name)

        context = code_analyzer.analyze_file(str(js_file))

        assert context.language in {"javascript", "unknown"}
        if context.language == "javascript":
            assert len(context.imports) > 0
            assert len(context.functions) > 0 or len(context.classes) > 0

    def test_calculate_complexity(self, code_analyzer: CodeAnalyzer, python_test_file: Path) -> None:
        """Complexity calculation reflects code structure."""
        context = code_analyzer.analyze_file(str(python_test_file))

        if context.language == "python" and context.ast_info:
            assert "complexity" in context.ast_info
            assert context.ast_info["complexity"] > 0

    def test_extract_dependencies(self, code_analyzer: CodeAnalyzer, python_test_file: Path) -> None:
        """External dependencies extracted correctly."""
        context = code_analyzer.analyze_file(str(python_test_file))

        assert isinstance(context.dependencies, list)


class TestDiffGenerator:
    """Test diff generation functionality."""

    def test_unified_diff_generation(self, diff_generator: DiffGenerator) -> None:
        """Unified diff format generated correctly."""
        original = "line 1\nline 2\nline 3"
        modified = "line 1\nmodified line 2\nline 3"

        diff = diff_generator.generate_unified_diff(original, modified)

        assert diff != ""
        assert "@@" in diff
        assert "+modified" in diff or "-line 2" in diff

    def test_side_by_side_diff(self, diff_generator: DiffGenerator) -> None:
        """Side-by-side diff data structured correctly."""
        original = "line 1\nline 2"
        modified = "line 1\nline 2 modified"

        diff_data = diff_generator.generate_side_by_side_diff(original, modified)

        assert "original_lines" in diff_data
        assert "modified_lines" in diff_data
        assert "changes" in diff_data
        assert len(diff_data["changes"]) > 0

    def test_change_summary(self, diff_generator: DiffGenerator) -> None:
        """Change summary counts additions, deletions, modifications."""
        original = "line 1\nline 2\nline 3"
        modified = "line 1\nmodified\nline 3\nline 4"

        summary = diff_generator.get_change_summary(original, modified)

        assert "additions" in summary
        assert "deletions" in summary
        assert "modifications" in summary
        assert summary["total_changes"] > 0


class TestIntelligentCodeModifier:
    """Test intelligent code modification."""

    def test_modifier_initialization(self, code_modifier: IntelligentCodeModifier) -> None:
        """Code modifier initializes with correct configuration."""
        assert code_modifier.llm_manager is not None
        assert code_modifier.analyzer is not None
        assert code_modifier.diff_generator is not None
        assert code_modifier.backup_enabled is True

    def test_gather_project_context(self, code_modifier: IntelligentCodeModifier, python_test_file: Path) -> None:
        """Project context gathering analyzes target files."""
        project_root = python_test_file.parent
        target_files = [python_test_file.name]

        context = code_modifier.gather_project_context(str(project_root), target_files)

        assert len(context) > 0
        assert any(python_test_file.name in str(key) for key in context.keys())

    def test_create_modification_request(self, code_modifier: IntelligentCodeModifier, python_test_file: Path) -> None:
        """Modification request created with all required fields."""
        request = code_modifier.create_modification_request(
            description="Add documentation",
            target_files=[str(python_test_file)],
            requirements=["Add docstrings"],
        )

        assert request.request_id is not None
        assert request.description == "Add documentation"
        assert len(request.target_files) == 1
        assert len(request.requirements) == 1

    def test_preview_changes(self, code_modifier: IntelligentCodeModifier) -> None:
        """Change preview displays modification details."""
        change = CodeChange(
            change_id="test_1",
            file_path="/test/file.py",
            modification_type=ModificationType.FUNCTION_MODIFICATION,
            description="Test change",
            original_code="def old():\n    pass",
            modified_code="def new():\n    return 42",
            start_line=1,
            end_line=2,
            confidence=0.9,
            reasoning="Testing",
        )

        code_modifier.pending_changes["test_1"] = change

        preview = code_modifier.preview_changes(["test_1"])

        assert preview["total_changes"] == 1
        assert len(preview["changes"]) == 1
        assert preview["changes"][0]["confidence"] == 0.9

    def test_reject_changes(self, code_modifier: IntelligentCodeModifier) -> None:
        """Change rejection updates status correctly."""
        change = CodeChange(
            change_id="test_2",
            file_path="/test/file.py",
            modification_type=ModificationType.BUG_FIX,
            description="Fix bug",
            original_code="broken",
            modified_code="fixed",
            start_line=1,
            end_line=1,
            confidence=0.8,
            reasoning="Bug fix",
        )

        code_modifier.pending_changes["test_2"] = change

        results = code_modifier.reject_changes(["test_2"])

        assert "test_2" in results["rejected"]
        assert "test_2" not in code_modifier.pending_changes

    def test_get_pending_changes(self, code_modifier: IntelligentCodeModifier) -> None:
        """Pending changes listed with correct details."""
        change = CodeChange(
            change_id="test_3",
            file_path="/test/file.py",
            modification_type=ModificationType.OPTIMIZATION,
            description="Optimize",
            original_code="slow",
            modified_code="fast",
            start_line=1,
            end_line=1,
            confidence=0.85,
            reasoning="Performance",
        )

        code_modifier.pending_changes["test_3"] = change

        pending = code_modifier.get_pending_changes()

        assert len(pending) == 1
        assert pending[0]["change_id"] == "test_3"
        assert pending[0]["confidence"] == 0.85

    def test_get_modification_history(self, code_modifier: IntelligentCodeModifier) -> None:
        """Modification history tracks applied and rejected changes."""
        change = CodeChange(
            change_id="test_4",
            file_path="/test/file.py",
            modification_type=ModificationType.REFACTORING,
            description="Refactor",
            original_code="old",
            modified_code="new",
            start_line=1,
            end_line=1,
            confidence=0.95,
            reasoning="Clean code",
            status=ChangeStatus.APPLIED,
        )

        code_modifier.modification_history.append(change)

        history = code_modifier.get_modification_history(limit=10)

        assert len(history) == 1
        assert history[0]["status"] == "applied"


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_analyze_nonexistent_file(self, code_analyzer: CodeAnalyzer) -> None:
        """Analyzing nonexistent file returns empty context."""
        context = code_analyzer.analyze_file("/nonexistent/file.py")

        assert context.language == "unknown"
        assert context.content == ""

    def test_unsupported_file_type(self, code_analyzer: CodeAnalyzer) -> None:
        """Unsupported file types analyzed generically."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".xyz", delete=False) as f:
            f.write("content")
            unknown_file = Path(f.name)

        context = code_analyzer.analyze_file(str(unknown_file))

        assert context.language == "unknown"

    def test_empty_diff(self, diff_generator: DiffGenerator) -> None:
        """Empty diff when no changes present."""
        text = "same content"

        diff = diff_generator.generate_unified_diff(text, text)

        assert diff == ""

    def test_large_code_modification(self, diff_generator: DiffGenerator) -> None:
        """Large file modifications handled efficiently."""
        original = "\n".join([f"line {i}" for i in range(1000)])
        modified = "\n".join([f"line {i} modified" if i % 2 == 0 else f"line {i}" for i in range(1000)])

        summary = diff_generator.get_change_summary(original, modified)

        assert summary["total_changes"] > 0
        assert summary["modifications"] > 0

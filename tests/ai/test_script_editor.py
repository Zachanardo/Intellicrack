"""Comprehensive tests for AI script editor.

Tests validate script parsing, syntax validation, code generation for Frida scripts,
version management, and QEMU-based execution testing.
"""

import json
import tempfile
from pathlib import Path
from typing import Any

import pytest

from intellicrack.ai.script_editor import (
    AIScriptEditor,
    EditRequest,
    EditType,
    ScriptEdit,
    ScriptTester,
    ScriptVersion,
    ScriptVersionManager,
    ValidationResult,
)


class TestScriptTester:
    """Test script validation and testing functionality."""

    def test_validate_script_python_syntax_valid(self) -> None:
        """Test validation of syntactically correct Python script."""
        tester = ScriptTester()

        valid_python = """
def test_function():
    x = 1 + 2
    return x
"""

        result, details = tester.validate_script(valid_python, "python")

        assert isinstance(result, ValidationResult)
        assert "syntax_check" in details

    def test_validate_script_frida_patterns_detected(self) -> None:
        """Test validation detects Frida-specific patterns."""
        tester = ScriptTester()

        frida_script = """
Interceptor.attach(Module.findExportByName(null, 'open'), {
    onEnter: function(args) {
        console.log('Opening file');
    },
    onLeave: function(retval) {
        send({type: 'result', fd: retval});
    }
});
"""

        result, details = tester.validate_script(frida_script, "frida")

        assert isinstance(result, ValidationResult)
        assert details is not None

    def test_validate_frida_syntax_requires_patterns(self) -> None:
        """Test Frida syntax validation requires specific patterns."""
        tester = ScriptTester()

        missing_patterns = "function test() { return 42; }"

        result = tester._validate_frida_syntax(missing_patterns)

        assert result == ValidationResult.LOGIC_ERROR

    def test_validate_frida_syntax_checks_bracket_balance(self) -> None:
        """Test Frida validation checks bracket balance."""
        tester = ScriptTester()

        unbalanced = "Interceptor.attach(ptr(0x1234), { onEnter: function(args) {"

        result = tester._validate_frida_syntax(unbalanced)

        assert result == ValidationResult.SYNTAX_ERROR

    def test_validate_python_syntax_detects_errors(self) -> None:
        """Test Python syntax validation detects syntax errors."""
        tester = ScriptTester()

        invalid_python = "def broken(\n    incomplete"

        result = tester._validate_python_syntax(invalid_python)

        assert result == ValidationResult.SYNTAX_ERROR

    def test_validate_python_syntax_accepts_valid_code(self) -> None:
        """Test Python syntax validation accepts valid code."""
        tester = ScriptTester()

        valid_python = "def valid():\n    return True"

        result = tester._validate_python_syntax(valid_python)

        assert result == ValidationResult.SUCCESS

    def test_scan_security_issues_detects_dangerous_patterns(self) -> None:
        """Test security scanning detects dangerous patterns."""
        tester = ScriptTester()

        dangerous_code = """
import os
user_input = input("Command: ")
os.system(user_input)
exec(user_input)
"""

        issues = tester._scan_security_issues(dangerous_code)

        assert "critical_issues" in issues
        assert len(issues["critical_issues"]) > 0

    def test_analyze_performance_calculates_complexity(self) -> None:
        """Test performance analysis calculates complexity score."""
        tester = ScriptTester()

        complex_code = """
for (var i = 0; i < 100; i++) {
    if (condition) {
        while (true) {
            for (var j = 0; j < 10; j++) {
                process();
            }
        }
    }
}
"""

        metrics = tester._analyze_performance(complex_code)

        assert "complexity_score" in metrics
        assert "optimization_suggestions" in metrics
        assert metrics["complexity_score"] > 0.0

    def test_analyze_performance_suggests_optimizations(self) -> None:
        """Test performance analysis provides optimization suggestions."""
        tester = ScriptTester()

        loop_heavy = "\n".join([f"for i_{n} in range(10): pass" for n in range(15)])

        metrics = tester._analyze_performance(loop_heavy)

        suggestions = metrics["optimization_suggestions"]
        assert isinstance(suggestions, list)

    def test_validate_ghidra_syntax_requires_imports(self) -> None:
        """Test Ghidra validation requires specific imports."""
        tester = ScriptTester()

        missing_imports = "public class Test { public void run() {} }"

        result = tester._validate_ghidra_syntax(missing_imports)

        assert result == ValidationResult.LOGIC_ERROR

    def test_validate_ghidra_syntax_checks_class_structure(self) -> None:
        """Test Ghidra validation checks for proper class structure."""
        tester = ScriptTester()

        valid_ghidra = """
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;

public class AnalyzeScript extends GhidraScript {
    public void run() throws Exception {
        println("Analysis complete");
    }
}
"""

        result = tester._validate_ghidra_syntax(valid_ghidra)

        assert result == ValidationResult.SUCCESS


class TestScriptVersionManager:
    """Test script version management and history tracking."""

    def test_version_manager_initialization(self) -> None:
        """Test version manager initializes with correct directories."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = ScriptVersionManager(tmpdir)

            assert manager.base_path.exists()
            assert manager.versions_dir.exists()

    def test_create_version_saves_to_disk(self) -> None:
        """Test version creation saves version data to disk."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = ScriptVersionManager(tmpdir)

            edit = ScriptEdit(
                edit_id="edit_1",
                timestamp="2025-01-01T00:00:00",
                edit_type=EditType.ENHANCEMENT,
                modification_prompt="Test edit",
                changes_made=["Added feature"],
                confidence_score=0.9
            )

            version = manager.create_version(
                content="def test(): pass",
                edit_history=[edit],
                parent_version=None
            )

            assert version.version_number.startswith("v_")
            assert len(list(manager.versions_dir.glob("*.json"))) > 0

    def test_get_version_history_loads_versions(self) -> None:
        """Test version history loading from disk."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = ScriptVersionManager(tmpdir)

            edit1 = ScriptEdit(
                edit_id="edit_1",
                timestamp="2025-01-01T00:00:00",
                edit_type=EditType.BUGFIX,
                modification_prompt="Fix bug",
                changes_made=["Fixed issue"],
                confidence_score=0.95
            )

            manager.create_version("def v1(): pass", [edit1])
            manager.create_version("def v2(): pass", [edit1])

            history = manager.get_version_history()

            assert len(history) == 2
            assert all(isinstance(v, ScriptVersion) for v in history)

    def test_rollback_to_version_retrieves_content(self) -> None:
        """Test rolling back to a specific version."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = ScriptVersionManager(tmpdir)

            edit = ScriptEdit(
                edit_id="edit_1",
                timestamp="2025-01-01T00:00:00",
                edit_type=EditType.ENHANCEMENT,
                modification_prompt="Test",
                changes_made=[],
                confidence_score=0.8
            )

            original_content = "def original(): return 42"
            version = manager.create_version(original_content, [edit])

            rolled_back = manager.rollback_to_version(version.version_number)

            assert rolled_back == original_content

    def test_rollback_nonexistent_version_returns_none(self) -> None:
        """Test rollback of nonexistent version returns None."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = ScriptVersionManager(tmpdir)

            result = manager.rollback_to_version("nonexistent_version")

            assert result is None

    def test_generate_version_id_is_unique(self) -> None:
        """Test version ID generation creates unique identifiers."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = ScriptVersionManager(tmpdir)

            id1 = manager._generate_version_id("content1")
            id2 = manager._generate_version_id("content2")

            assert id1 != id2

    def test_edit_serialization_round_trip(self) -> None:
        """Test ScriptEdit serialization and deserialization."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = ScriptVersionManager(tmpdir)

            original_edit = ScriptEdit(
                edit_id="test_edit",
                timestamp="2025-01-01T12:00:00",
                edit_type=EditType.REFACTOR,
                modification_prompt="Refactor code",
                changes_made=["Restructured"],
                confidence_score=0.85,
                validation_result=ValidationResult.SUCCESS,
                performance_metrics={"runtime": 0.1},
                rollback_info={"original": "old code"}
            )

            edit_dict = manager._edit_to_dict(original_edit)
            restored_edit = manager._dict_to_edit(edit_dict)

            assert restored_edit.edit_id == original_edit.edit_id
            assert restored_edit.edit_type == original_edit.edit_type
            assert restored_edit.validation_result == original_edit.validation_result


class TestAIScriptEditor:
    """Test AI-powered script editing functionality."""

    def test_script_editor_initialization(self) -> None:
        """Test script editor initializes all components."""
        editor = AIScriptEditor()

        assert editor.ai_generator is not None
        assert editor.tester is not None
        assert editor.version_manager is not None
        assert isinstance(editor.edit_history, dict)

    def test_detect_script_type_from_extension(self) -> None:
        """Test script type detection from file extension."""
        editor = AIScriptEditor()

        assert editor._detect_script_type_from_path("script.js") == "frida"
        assert editor._detect_script_type_from_path("script.py") == "python"
        assert editor._detect_script_type_from_path("script.java") == "ghidra"
        assert editor._detect_script_type_from_path("script.sh") == "shell"

    def test_detect_script_type_from_filename_patterns(self) -> None:
        """Test script type detection from filename patterns."""
        editor = AIScriptEditor()

        assert editor._detect_script_type_from_path("frida_hook.txt") == "frida"
        assert editor._detect_script_type_from_path("ghidra_analysis.txt") == "ghidra"
        assert editor._detect_script_type_from_path("r2_script.txt") == "radare2"

    def test_detect_script_type_from_content_frida(self) -> None:
        """Test script type detection from Frida content patterns."""
        editor = AIScriptEditor()

        frida_content = """
Interceptor.attach(Module.findExportByName(null, 'malloc'), {
    onEnter: function(args) {
        send({size: args[0]});
    }
});
"""

        script_type = editor._detect_script_type("unknown.txt", frida_content)

        assert script_type == "frida"

    def test_detect_script_type_from_content_ghidra(self) -> None:
        """Test script type detection from Ghidra content patterns."""
        editor = AIScriptEditor()

        ghidra_content = """
from ghidra.program.model.listing import Function
from ghidra.app.decompile import DecompInterface

currentProgram = getCurrentProgram()
listing = currentProgram.getListing()
"""

        script_type = editor._detect_script_type("unknown.txt", ghidra_content)

        assert script_type == "ghidra"

    def test_detect_script_type_from_content_python(self) -> None:
        """Test script type detection from Python content patterns."""
        editor = AIScriptEditor()

        python_content = """
import sys
import os

def main():
    print("Hello World")

if __name__ == "__main__":
    main()
"""

        script_type = editor._detect_script_type("unknown.txt", python_content)

        assert script_type == "python"

    def test_calculate_edit_confidence_high_for_success(self) -> None:
        """Test edit confidence calculation for successful edits."""
        editor = AIScriptEditor()

        original = "def old(): pass"
        modified = "def new(): return True"

        confidence = editor._calculate_edit_confidence(
            original,
            modified,
            ValidationResult.SUCCESS
        )

        assert confidence >= 0.5

    def test_calculate_edit_confidence_low_for_errors(self) -> None:
        """Test edit confidence is low for failed validations."""
        editor = AIScriptEditor()

        original = "def test(): pass"
        modified = "def broken("

        confidence = editor._calculate_edit_confidence(
            original,
            modified,
            ValidationResult.SYNTAX_ERROR
        )

        assert confidence < 0.5

    def test_extract_changes_detects_additions(self) -> None:
        """Test change extraction detects line additions."""
        editor = AIScriptEditor()

        original = "def func():\n    pass"
        modified = "def func():\n    x = 1\n    y = 2\n    return x + y"

        changes = editor._extract_changes(original, modified)

        assert any("Added" in change for change in changes)

    def test_extract_changes_detects_removals(self) -> None:
        """Test change extraction detects line removals."""
        editor = AIScriptEditor()

        original = "def func():\n    line1()\n    line2()\n    line3()"
        modified = "def func():\n    line1()"

        changes = editor._extract_changes(original, modified)

        assert any("Removed" in change for change in changes)

    def test_calculate_diff_stats_computes_metrics(self) -> None:
        """Test diff statistics calculation."""
        editor = AIScriptEditor()

        content1 = "line1\nline2\nline3"
        content2 = "line1\nline2\nline3\nline4\nline5"

        stats = editor._calculate_diff_stats(content1, content2)

        assert "lines_added" in stats
        assert "lines_removed" in stats
        assert "similarity_ratio" in stats
        assert stats["lines_added"] == 2

    def test_calculate_similarity_measures_likeness(self) -> None:
        """Test similarity calculation between scripts."""
        editor = AIScriptEditor()

        identical1 = "test content"
        identical2 = "test content"

        different1 = "completely different"
        different2 = "nothing in common"

        assert editor._calculate_similarity(identical1, identical2) == 1.0
        assert editor._calculate_similarity(different1, different2) < 0.5

    def test_generate_version_recommendations_significant_changes(self) -> None:
        """Test version recommendations for significant changes."""
        editor = AIScriptEditor()

        diff_stats = {
            "similarity_ratio": 0.3,
            "lines_added": 100,
            "lines_removed": 50
        }

        recommendations = editor._generate_version_recommendations(diff_stats)

        assert len(recommendations) > 0
        assert any("review" in rec.lower() for rec in recommendations)

    def test_suggest_fixes_for_syntax_errors(self) -> None:
        """Test fix suggestions for syntax errors."""
        editor = AIScriptEditor()

        fixes = editor._suggest_fixes(
            ValidationResult.SYNTAX_ERROR,
            {"syntax_check": False}
        )

        assert len(fixes) > 0
        assert any("bracket" in fix.lower() or "indent" in fix.lower() for fix in fixes)

    def test_suggest_fixes_for_security_issues(self) -> None:
        """Test fix suggestions for security issues."""
        editor = AIScriptEditor()

        fixes = editor._suggest_fixes(
            ValidationResult.SECURITY_ISSUE,
            {"security_scan": {"critical_issues": ["eval usage"]}}
        )

        assert len(fixes) > 0

    def test_generate_edit_id_is_unique(self) -> None:
        """Test edit ID generation creates unique IDs."""
        editor = AIScriptEditor()

        id1 = editor._generate_edit_id()
        id2 = editor._generate_edit_id()

        assert id1 != id2
        assert id1.startswith("edit_")

    def test_analyze_qemu_results_for_goals_success_detection(self) -> None:
        """Test QEMU result analysis detects goal achievement."""
        editor = AIScriptEditor()

        qemu_result = {
            "success": True,
            "output": "Successfully bypassed license check. Found target address.",
            "errors": [],
            "performance": {"runtime_ms": 1500}
        }

        goals = ["bypass license check", "find target address"]

        achieved = editor._analyze_qemu_results_for_goals(qemu_result, goals)

        assert achieved is True

    def test_analyze_qemu_results_for_goals_failure_detection(self) -> None:
        """Test QEMU result analysis detects when goals are not met."""
        editor = AIScriptEditor()

        qemu_result = {
            "success": False,
            "output": "",
            "errors": ["Script failed"],
            "performance": {}
        }

        goals = ["extract password", "decrypt data"]

        achieved = editor._analyze_qemu_results_for_goals(qemu_result, goals)

        assert achieved is False

    def test_is_goal_met_performance_goal(self) -> None:
        """Test performance goal evaluation."""
        editor = AIScriptEditor()

        fast_performance = {"runtime_ms": 1000}
        slow_performance = {"runtime_ms": 10000}

        assert editor._is_goal_met("fast performance", "", [], fast_performance) == 1
        assert editor._is_goal_met("fast performance", "", [], slow_performance) == 0

    def test_is_goal_met_error_free_goal(self) -> None:
        """Test error-free goal evaluation."""
        editor = AIScriptEditor()

        assert editor._is_goal_met("no errors", "", [], {}) == 1
        assert editor._is_goal_met("error-free execution", "", ["error occurred"], {}) == 0


class TestEditRequestAndRecords:
    """Test edit request and record data structures."""

    def test_edit_request_creation(self) -> None:
        """Test creating edit request with all parameters."""
        request = EditRequest(
            original_script_path="/path/to/script.js",
            modification_prompt="Add error handling",
            edit_type=EditType.ENHANCEMENT,
            target_addresses=["0x1234", "0x5678"],
            expected_behavior="Script should handle errors gracefully",
            test_criteria={"should_pass": True},
            preserve_functionality=True
        )

        assert request.edit_type == EditType.ENHANCEMENT
        assert len(request.target_addresses) == 2
        assert request.preserve_functionality is True

    def test_script_edit_creation(self) -> None:
        """Test creating script edit record."""
        edit = ScriptEdit(
            edit_id="edit_123",
            timestamp="2025-01-01T10:00:00",
            edit_type=EditType.BUGFIX,
            modification_prompt="Fix memory leak",
            changes_made=["Added cleanup", "Fixed deallocation"],
            confidence_score=0.92,
            validation_result=ValidationResult.SUCCESS,
            performance_metrics={"memory_saved": 1024},
            rollback_info={"original_content": "old code"}
        )

        assert edit.edit_type == EditType.BUGFIX
        assert len(edit.changes_made) == 2
        assert edit.confidence_score == 0.92

    def test_script_version_tracks_history(self) -> None:
        """Test script version tracks complete edit history."""
        edits = [
            ScriptEdit(
                edit_id=f"edit_{i}",
                timestamp=f"2025-01-01T{i:02d}:00:00",
                edit_type=EditType.ENHANCEMENT,
                modification_prompt=f"Change {i}",
                changes_made=[],
                confidence_score=0.8
            )
            for i in range(3)
        ]

        version = ScriptVersion(
            version_number="v1.0.0",
            content="final code",
            edit_history=edits,
            creation_timestamp="2025-01-01T12:00:00",
            parent_version=None,
            tags=["stable", "tested"],
            metrics={"lines": 100}
        )

        assert len(version.edit_history) == 3
        assert "stable" in version.tags


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_validate_script_empty_content(self) -> None:
        """Test validation of empty script."""
        tester = ScriptTester()

        result, details = tester.validate_script("", "python")

        assert isinstance(result, ValidationResult)

    def test_version_manager_handles_corrupted_json(self) -> None:
        """Test version manager handles corrupted version files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = ScriptVersionManager(tmpdir)

            corrupted_file = manager.versions_dir / "corrupted.json"
            corrupted_file.write_text("invalid json {{{")

            history = manager.get_version_history()

            assert isinstance(history, list)

    def test_detect_script_type_unknown_extension(self) -> None:
        """Test script type detection for unknown extensions."""
        editor = AIScriptEditor()

        result = editor._detect_script_type_from_path("script.xyz")

        assert result == "unknown"

    def test_calculate_diff_stats_identical_content(self) -> None:
        """Test diff calculation for identical content."""
        editor = AIScriptEditor()

        content = "same content"

        stats = editor._calculate_diff_stats(content, content)

        assert stats["lines_added"] == 0
        assert stats["lines_removed"] == 0
        assert stats["similarity_ratio"] == 1.0

    def test_extract_changes_no_changes(self) -> None:
        """Test change extraction when content is identical."""
        editor = AIScriptEditor()

        content = "unchanged"

        changes = editor._extract_changes(content, content)

        assert len(changes) == 0 or all("0" in str(change) for change in changes)

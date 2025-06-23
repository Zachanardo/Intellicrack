"""
Unit tests for Intelligent Code Modifier

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellicrack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack.  If not, see <https://www.gnu.org/licenses/>.
"""

import tempfile
from pathlib import Path
from unittest.mock import Mock


from intellicrack.ai.intelligent_code_modifier import (
    IntelligentCodeModifier, ModificationRequest, CodeChange,
    ModificationType, ChangeStatus, CodeAnalyzer, DiffGenerator
)
from intellicrack.ai.llm_backends import LLMManager


class TestIntelligentCodeModifier:
    """Unit tests for IntelligentCodeModifier class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_llm_manager = Mock(spec=LLMManager)
        self.modifier = IntelligentCodeModifier(self.mock_llm_manager)
        self.temp_dir = Path(tempfile.mkdtemp())

    def teardown_method(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_initialization(self):
        """Test proper initialization of IntelligentCodeModifier."""
        assert self.modifier.llm_manager == self.mock_llm_manager
        assert isinstance(self.modifier.analyzer, CodeAnalyzer)
        assert isinstance(self.modifier.diff_generator, DiffGenerator)
        assert len(self.modifier.pending_changes) == 0
        assert len(self.modifier.modification_history) == 0
        assert self.modifier.confidence_threshold == 0.7
        assert self.modifier.backup_enabled is True

    def test_create_modification_request(self):
        """Test creation of modification requests."""
        description = "Add error handling to functions"
        target_files = ["file1.py", "file2.py"]
        requirements = ["Handle exceptions", "Log errors"]
        constraints = ["Don't break existing code"]
        context_files = ["utils.py"]

        request = self.modifier.create_modification_request(
            description=description,
            target_files=target_files,
            requirements=requirements,
            constraints=constraints,
            context_files=context_files
        )

        assert request.description == description
        assert request.target_files == target_files
        assert request.requirements == requirements
        assert request.constraints == constraints
        assert request.context_files == context_files
        assert request.priority == "medium"
        assert request.request_id.startswith("mod_")

    def test_parse_modification_response(self):
        """Test parsing of AI modification response."""
        # Create a test file
        test_file = self.temp_dir / "test.py"
        test_file.write_text("def test(): pass")

        request = ModificationRequest(
            request_id="test_req",
            description="Test modification",
            target_files=[str(test_file)],
            context_files=[],
            requirements=[],
            constraints=[]
        )

        # Test valid JSON response
        valid_response = '''
Here's the modification:

```json
{
  "modifications": [
    {
      "type": "function_modification",
      "description": "Add error handling",
      "start_line": 1,
      "end_line": 1,
      "original_code": "def test(): pass",
      "modified_code": "def test():\\n    try:\\n        pass\\n    except Exception as e:\\n        print(f\\"Error: {e}\\")",
      "reasoning": "Added try-catch for error handling",
      "confidence": 0.85,
      "impact": "Improves error handling"
    },
    {
      "type": "function_creation",
      "description": "Add helper function",
      "start_line": 2,
      "end_line": 2,
      "original_code": "",
      "modified_code": "def helper():\\n    return \\"helper\\"",
      "reasoning": "Added utility function",
      "confidence": 0.9,
      "impact": "Adds utility functionality"
    }
  ]
}
```
        '''

        changes = self.modifier._parse_modification_response(valid_response, str(test_file), request)

        assert len(changes) == 2

        # Check first change
        change1 = changes[0]
        assert change1.change_id == "test_req_0"
        assert change1.modification_type == ModificationType.FUNCTION_MODIFICATION
        assert change1.description == "Add error handling"
        assert change1.confidence == 0.85
        assert change1.reasoning == "Added try-catch for error handling"
        assert change1.status == ChangeStatus.PENDING

        # Check second change
        change2 = changes[1]
        assert change2.change_id == "test_req_1"
        assert change2.modification_type == ModificationType.FUNCTION_CREATION
        assert change2.confidence == 0.9

    def test_parse_malformed_response(self):
        """Test parsing of malformed AI responses."""
        test_file = self.temp_dir / "test.py"
        test_file.write_text("def test(): pass")

        request = ModificationRequest(
            request_id="test_req",
            description="Test",
            target_files=[str(test_file)],
            context_files=[],
            requirements=[],
            constraints=[]
        )

        # Test malformed JSON
        malformed_responses = [
            "This is not JSON at all",
            "```json\n{invalid json}\n```",
            "```json\n{\"modifications\": [invalid]}\n```",
            "No JSON blocks here",
            ""
        ]

        for response in malformed_responses:
            changes = self.modifier._parse_modification_response(response, str(test_file), request)
            assert len(changes) == 0  # Should handle gracefully

    def test_create_modification_prompt(self):
        """Test creation of modification prompts."""
        from intellicrack.ai.intelligent_code_modifier import CodeContext

        request = ModificationRequest(
            request_id="test_req",
            description="Add logging to functions",
            target_files=["test.py"],
            context_files=[],
            requirements=["Use standard logging", "Log entry and exit"],
            constraints=["Don't change function signatures", "Keep performance impact minimal"]
        )

        context = CodeContext(
            file_path="test.py",
            content="def example():\n    return True",
            language="python",
            imports=["os", "sys"],
            classes=["ExampleClass"],
            functions=["example", "helper"],
            variables=["global_var"],
            dependencies=["requests"],
            ast_info={"complexity": 5}
        )

        prompt = self.modifier._create_modification_prompt(request, context)

        # Check prompt contains expected elements
        assert "Add logging to functions" in prompt
        assert "test.py" in prompt
        assert "python" in prompt
        assert "Use standard logging" in prompt
        assert "Don't change function signatures" in prompt
        assert "def example():" in prompt
        assert "ExampleClass" in prompt
        assert "JSON format" in prompt
        assert "ONLY functional, working code" in prompt

    def test_preview_changes(self):
        """Test preview generation for changes."""
        # Create test changes
        change1 = CodeChange(
            change_id="change_1",
            file_path="file1.py",
            modification_type=ModificationType.FUNCTION_MODIFICATION,
            description="Modify function A",
            original_code="def func_a(): pass",
            modified_code="def func_a(): return True",
            start_line=1,
            end_line=1,
            confidence=0.8,
            reasoning="Improve function"
        )

        change2 = CodeChange(
            change_id="change_2",
            file_path="file2.py",
            modification_type=ModificationType.CLASS_CREATION,
            description="Add new class",
            original_code="",
            modified_code="class NewClass: pass",
            start_line=10,
            end_line=10,
            confidence=0.6,  # Below threshold
            reasoning="Add utility class"
        )

        # Add to pending changes
        self.modifier.pending_changes[change1.change_id] = change1
        self.modifier.pending_changes[change2.change_id] = change2

        # Generate preview
        preview = self.modifier.preview_changes([change1.change_id, change2.change_id])

        assert len(preview["changes"]) == 2
        assert len(preview["files_affected"]) == 2
        assert "file1.py" in preview["files_affected"]
        assert "file2.py" in preview["files_affected"]
        assert preview["total_changes"] == 2
        assert preview["high_risk_changes"] == 1  # change2 has confidence < 0.7

        # Check individual change data
        change1_data = next(c for c in preview["changes"] if c["change_id"] == "change_1")
        assert change1_data["confidence"] == 0.8
        assert change1_data["type"] == "function_modification"
        assert "diff" in change1_data
        assert change1_data["lines_affected"] == "1-1"

    def test_apply_changes_to_file(self):
        """Test applying changes to a file."""
        # Create test file
        test_file = self.temp_dir / "apply_test.py"
        test_file.write_text('''line 1
line 2
line 3
line 4
line 5''')

        # Create changes to apply
        changes = [
            CodeChange(
                change_id="change_1",
                file_path=str(test_file),
                modification_type=ModificationType.FUNCTION_MODIFICATION,
                description="Replace line 2",
                original_code="line 2",
                modified_code="modified line 2",
                start_line=2,
                end_line=2,
                confidence=0.9,
                reasoning="Test change"
            ),
            CodeChange(
                change_id="change_2",
                file_path=str(test_file),
                modification_type=ModificationType.FUNCTION_MODIFICATION,
                description="Replace lines 4-5",
                original_code="line 4\nline 5",
                modified_code="new line 4\nnew line 5\nextra line",
                start_line=4,
                end_line=5,
                confidence=0.8,
                reasoning="Test multi-line change"
            )
        ]

        # Apply changes
        success = self.modifier._apply_changes_to_file(str(test_file), changes)
        assert success is True

        # Check file content
        modified_content = test_file.read_text()
        expected_content = '''line 1
modified line 2
line 3
new line 4
new line 5
extra line'''

        assert modified_content == expected_content

    def test_apply_changes_with_backup(self):
        """Test applying changes with backup creation."""
        # Create test file
        test_file = self.temp_dir / "backup_test.py"
        original_content = "original content"
        test_file.write_text(original_content)

        # Create a change
        change = CodeChange(
            change_id="backup_change",
            file_path=str(test_file),
            modification_type=ModificationType.FUNCTION_MODIFICATION,
            description="Test change",
            original_code="original content",
            modified_code="modified content",
            start_line=1,
            end_line=1,
            confidence=0.9,
            reasoning="Test"
        )

        self.modifier.pending_changes[change.change_id] = change

        # Apply with backup
        results = self.modifier.apply_changes([change.change_id], create_backup=True)

        assert len(results["applied"]) == 1
        assert len(results["backups_created"]) == 1
        assert len(results["failed"]) == 0

        # Check file was modified
        assert test_file.read_text() == "modified content"

        # Check backup was created and contains original content
        backup_path = Path(results["backups_created"][0])
        assert backup_path.exists()
        assert backup_path.read_text() == original_content

        # Check change is in history
        assert len(self.modifier.modification_history) == 1
        assert self.modifier.modification_history[0].status == ChangeStatus.APPLIED

    def test_reject_changes(self):
        """Test rejecting changes."""
        # Create test changes
        change1 = CodeChange(
            change_id="reject_1",
            file_path="file1.py",
            modification_type=ModificationType.FUNCTION_MODIFICATION,
            description="Change to reject",
            original_code="original",
            modified_code="modified",
            start_line=1,
            end_line=1,
            confidence=0.5,
            reasoning="Test rejection"
        )

        change2 = CodeChange(
            change_id="reject_2",
            file_path="file2.py",
            modification_type=ModificationType.CLASS_CREATION,
            description="Another change to reject",
            original_code="",
            modified_code="class Test: pass",
            start_line=1,
            end_line=1,
            confidence=0.3,
            reasoning="Low confidence"
        )

        self.modifier.pending_changes[change1.change_id] = change1
        self.modifier.pending_changes[change2.change_id] = change2

        # Reject changes
        results = self.modifier.reject_changes([change1.change_id, change2.change_id])

        assert len(results["rejected"]) == 2
        assert len(results["not_found"]) == 0

        # Check changes are no longer pending
        assert len(self.modifier.pending_changes) == 0

        # Check changes are in history with rejected status
        assert len(self.modifier.modification_history) == 2
        for hist_change in self.modifier.modification_history:
            assert hist_change.status == ChangeStatus.REJECTED

    def test_get_pending_changes(self):
        """Test getting pending changes."""
        # Add some pending changes
        change1 = CodeChange(
            change_id="pending_1",
            file_path="file1.py",
            modification_type=ModificationType.FUNCTION_MODIFICATION,
            description="Pending change 1",
            original_code="original1",
            modified_code="modified1",
            start_line=1,
            end_line=1,
            confidence=0.8,
            reasoning="Test"
        )

        change2 = CodeChange(
            change_id="pending_2",
            file_path="file2.py",
            modification_type=ModificationType.CLASS_CREATION,
            description="Pending change 2",
            original_code="original2",
            modified_code="modified2",
            start_line=5,
            end_line=10,
            confidence=0.7,
            reasoning="Another test"
        )

        self.modifier.pending_changes[change1.change_id] = change1
        self.modifier.pending_changes[change2.change_id] = change2

        # Get pending changes
        pending = self.modifier.get_pending_changes()

        assert len(pending) == 2

        # Check data format
        for change_data in pending:
            assert "change_id" in change_data
            assert "file_path" in change_data
            assert "description" in change_data
            assert "type" in change_data
            assert "confidence" in change_data
            assert "reasoning" in change_data
            assert "lines" in change_data

        # Check specific values
        change1_data = next(c for c in pending if c["change_id"] == "pending_1")
        assert change1_data["file_path"] == "file1.py"
        assert change1_data["type"] == "function_modification"
        assert change1_data["confidence"] == 0.8
        assert change1_data["lines"] == "1-1"

        change2_data = next(c for c in pending if c["change_id"] == "pending_2")
        assert change2_data["lines"] == "5-10"

    def test_get_modification_history(self):
        """Test getting modification history."""
        # Add some history entries
        history_changes = []
        for i in range(5):
            change = CodeChange(
                change_id=f"history_{i}",
                file_path=f"file{i}.py",
                modification_type=ModificationType.FUNCTION_MODIFICATION,
                description=f"Historical change {i}",
                original_code=f"original{i}",
                modified_code=f"modified{i}",
                start_line=i,
                end_line=i,
                confidence=0.8,
                reasoning=f"Reason {i}",
                status=ChangeStatus.APPLIED if i % 2 == 0 else ChangeStatus.REJECTED
            )
            history_changes.append(change)

        self.modifier.modification_history = history_changes

        # Get full history
        history = self.modifier.get_modification_history(limit=10)
        assert len(history) == 5

        # Check data format
        for record in history:
            assert "change_id" in record
            assert "file_path" in record
            assert "description" in record
            assert "type" in record
            assert "status" in record
            assert "confidence" in record
            assert "created_at" in record

        # Test limit
        limited_history = self.modifier.get_modification_history(limit=3)
        assert len(limited_history) == 3

        # Should be sorted by creation time (most recent first)
        # Since we don't set creation times, just check the structure


class TestDiffGenerator:
    """Unit tests for DiffGenerator class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.diff_generator = DiffGenerator()

    def test_generate_unified_diff(self):
        """Test unified diff generation."""
        original = '''line 1
line 2
line 3
line 4'''

        modified = '''line 1
modified line 2
line 3
new line 4
line 5'''

        diff = self.diff_generator.generate_unified_diff(original, modified, "test.py")

        assert "--- a/test.py" in diff
        assert "+++ b/test.py" in diff
        assert "-line 2" in diff
        assert "+modified line 2" in diff
        assert "-line 4" in diff
        assert "+new line 4" in diff
        assert "+line 5" in diff

    def test_generate_side_by_side_diff(self):
        """Test side-by-side diff generation."""
        original = '''line 1
line 2
line 3'''

        modified = '''line 1
modified line 2
line 3
line 4'''

        diff_data = self.diff_generator.generate_side_by_side_diff(original, modified)

        assert "original_lines" in diff_data
        assert "modified_lines" in diff_data
        assert "changes" in diff_data

        # Check structure of line data
        for line_data in diff_data["original_lines"]:
            assert "line_number" in line_data
            assert "content" in line_data
            assert "type" in line_data

        # Should have detected changes
        assert len(diff_data["changes"]) > 0

        # Check for different types of changes
        line_types = {line["type"] for line in diff_data["original_lines"] + diff_data["modified_lines"]}
        assert "unchanged" in line_types  # line 1 and 3 should be unchanged

    def test_get_change_summary(self):
        """Test change summary generation."""
        original = '''line 1
line 2
line 3
line 4
line 5'''

        modified = '''line 1
modified line 2
line 3
added line
line 5'''

        summary = self.diff_generator.get_change_summary(original, modified)

        assert "additions" in summary
        assert "deletions" in summary
        assert "modifications" in summary
        assert "total_changes" in summary

        # Should detect the changes correctly
        assert summary["additions"] >= 1  # "added line"
        assert summary["deletions"] >= 1  # "line 4" removed
        assert summary["total_changes"] > 0

    def test_empty_diff(self):
        """Test diff generation with identical content."""
        content = "same content"

        diff = self.diff_generator.generate_unified_diff(content, content, "test.py")

        # Should be empty or minimal for identical content
        assert len(diff.strip()) == 0 or "@@" not in diff

        summary = self.diff_generator.get_change_summary(content, content)
        assert summary["additions"] == 0
        assert summary["deletions"] == 0
        assert summary["modifications"] == 0
        assert summary["total_changes"] == 0
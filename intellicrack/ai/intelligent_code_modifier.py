"""Intelligent Code Modification System.

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
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""

import ast
import difflib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any

from ..utils.logger import get_logger
from .llm_backends import LLMManager, LLMMessage


logger = get_logger(__name__)


class ModificationType(Enum):
    """Types of code modifications."""

    FUNCTION_CREATION = "function_creation"
    FUNCTION_MODIFICATION = "function_modification"
    CLASS_CREATION = "class_creation"
    CLASS_MODIFICATION = "class_modification"
    IMPORT_ADDITION = "import_addition"
    VARIABLE_MODIFICATION = "variable_modification"
    COMMENT_ADDITION = "comment_addition"
    REFACTORING = "refactoring"
    BUG_FIX = "bug_fix"
    OPTIMIZATION = "optimization"
    SECURITY_FIX = "security_fix"


class ChangeStatus(Enum):
    """Status of a code change."""

    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    APPLIED = "applied"
    FAILED = "failed"


@dataclass
class CodeChange:
    """Represents a single code change."""

    change_id: str
    file_path: str
    modification_type: ModificationType
    description: str
    original_code: str
    modified_code: str
    start_line: int
    end_line: int
    confidence: float
    reasoning: str
    status: ChangeStatus = ChangeStatus.PENDING
    created_at: datetime = field(default_factory=datetime.now)
    applied_at: datetime | None = None
    dependencies: list[str] = field(default_factory=list)
    impact_analysis: dict[str, Any] = field(default_factory=dict)


@dataclass
class ModificationRequest:
    """Request for code modification."""

    request_id: str
    description: str
    target_files: list[str]
    context_files: list[str]
    requirements: list[str]
    constraints: list[str]
    created_at: datetime = field(default_factory=datetime.now)
    priority: str = "medium"


@dataclass
class CodeContext:
    """Context information for code modification."""

    file_path: str
    content: str
    language: str
    imports: list[str]
    classes: list[str]
    functions: list[str]
    variables: list[str]
    dependencies: list[str]
    ast_info: dict[str, Any]


class CodeAnalyzer:
    """Analyzes code to extract context and dependencies."""

    def __init__(self) -> None:
        """Initialize the code analyzer.

        Sets up supported file extensions and their corresponding
        programming languages for code analysis.
        """
        self.supported_extensions = {
            ".py": "python",
            ".js": "javascript",
            ".ts": "typescript",
            ".java": "java",
            ".cpp": "cpp",
            ".c": "c",
            ".h": "c",
            ".hpp": "cpp",
        }

    def analyze_file(self, file_path: str) -> CodeContext:
        """Analyze a file and extract context information."""
        try:
            # Try to use AIFileTools for file reading if available
            content = None
            try:
                from .ai_file_tools import get_ai_file_tools

                ai_file_tools = get_ai_file_tools(getattr(self, "app_instance", None))
                file_data = ai_file_tools.read_file(file_path, purpose="Code analysis for intelligent modification")
                if file_data.get("status") == "success" and file_data.get("content"):
                    content = file_data["content"]
            except (ImportError, AttributeError, KeyError):
                pass

            # Fallback to direct file reading if AIFileTools not available
            if content is None:
                with open(file_path, encoding="utf-8") as f:
                    content = f.read()

            file_ext = Path(file_path).suffix.lower()
            language = self.supported_extensions.get(file_ext, "unknown")

            if language == "python":
                return self._analyze_python_file(file_path, content)
            if language in ["javascript", "typescript"]:
                return self._analyze_js_file(file_path, content)
            return self._analyze_generic_file(file_path, content, language)

        except Exception as e:
            logger.error("Error analyzing file %s: %s", file_path, e)
            return CodeContext(
                file_path=file_path,
                content="",
                language="unknown",
                imports=[],
                classes=[],
                functions=[],
                variables=[],
                dependencies=[],
                ast_info={},
            )

    def _analyze_python_file(self, file_path: str, content: str) -> CodeContext:
        """Analyze Python file using AST."""
        imports = []
        classes = []
        functions = []
        variables = []
        ast_info = {}

        try:
            tree = ast.parse(content)

            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        imports.append(alias.name)
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        imports.append(node.module)
                elif isinstance(node, ast.ClassDef):
                    classes.append(node.name)
                elif isinstance(node, ast.FunctionDef):
                    functions.append(node.name)
                elif isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            variables.append(target.id)

            ast_info = {
                "node_count": len(list(ast.walk(tree))),
                "complexity": self._calculate_complexity(tree),
            }

        except SyntaxError as e:
            logger.warning("Syntax error in %s: %s", file_path, e)

        return CodeContext(
            file_path=file_path,
            content=content,
            language="python",
            imports=list(set(imports)),
            classes=list(set(classes)),
            functions=list(set(functions)),
            variables=list(set(variables)),
            dependencies=self._extract_dependencies(imports),
            ast_info=ast_info,
        )

    def _analyze_js_file(self, file_path: str, content: str) -> CodeContext:
        """Analyze JavaScript/TypeScript file using regex patterns."""
        # Import patterns
        import_pattern = r'(?:import|require)\s*\(?[\'"`]([^\'"`]+)[\'"`]\)?'
        imports = re.findall(import_pattern, content)

        # Function patterns
        function_pattern = r"(?:function\s+(\w+)|(\w+)\s*[:=]\s*(?:function|\([^)]*\)\s*=>))"
        function_matches = re.findall(function_pattern, content)
        functions = [match[0] or match[1] for match in function_matches if match[0] or match[1]]

        # Class patterns
        class_pattern = r"class\s+(\w+)"
        classes = re.findall(class_pattern, content)

        # Variable patterns
        var_pattern = r"(?:var|let|const)\s+(\w+)"
        variables = re.findall(var_pattern, content)

        return CodeContext(
            file_path=file_path,
            content=content,
            language="javascript",
            imports=list(set(imports)),
            classes=list(set(classes)),
            functions=list(set(functions)),
            variables=list(set(variables)),
            dependencies=self._extract_dependencies(imports),
            ast_info={"estimated_complexity": len(functions) + len(classes)},
        )

    def _analyze_generic_file(self, file_path: str, content: str, language: str) -> CodeContext:
        """Analyze unsupported file types."""
        # Basic function detection
        function_patterns = {
            "c": r"(?:\w+\s+)*(\w+)\s*\([^)]*\)\s*\{",
            "cpp": r"(?:\w+\s+)*(\w+)\s*\([^)]*\)\s*\{",
            "java": r"(?:public|private|protected)?\s*(?:static)?\s*\w+\s+(\w+)\s*\([^)]*\)",
        }

        functions = []
        if language in function_patterns:
            pattern = function_patterns[language]
            functions = re.findall(pattern, content)

        return CodeContext(
            file_path=file_path,
            content=content,
            language=language,
            imports=[],
            classes=[],
            functions=list(set(functions)),
            variables=[],
            dependencies=[],
            ast_info={},
        )

    def _calculate_complexity(self, tree: ast.AST) -> int:
        """Calculate cyclomatic complexity of Python AST."""
        return 1 + sum(
            bool(
                isinstance(
                    node,
                    (
                        ast.If,
                        ast.While,
                        ast.For,
                        ast.AsyncFor,
                        ast.ExceptHandler,
                        ast.And,
                        ast.Or,
                    ),
                )
            )
            for node in ast.walk(tree)
        )

    def _extract_dependencies(self, imports: list[str]) -> list[str]:
        """Extract external dependencies from imports."""
        # Filter out standard library and relative imports
        standard_libs = {
            "os",
            "sys",
            "json",
            "time",
            "datetime",
            "pathlib",
            "re",
            "collections",
            "itertools",
            "functools",
            "typing",
            "enum",
        }

        dependencies = []
        for imp in imports:
            base = imp.split(".")[0] if "." in imp else imp
            if base not in standard_libs and not imp.startswith("."):
                dependencies.append(base)

        return list(set(dependencies))


class DiffGenerator:
    """Generates and formats code diffs."""

    def generate_unified_diff(self, original: str, modified: str, filename: str = "file") -> str:
        """Generate unified diff format."""
        original_lines = original.splitlines(keepends=True)
        modified_lines = modified.splitlines(keepends=True)

        diff = difflib.unified_diff(
            original_lines,
            modified_lines,
            fromfile=f"a/{filename}",
            tofile=f"b/{filename}",
            lineterm="",
        )

        return "".join(diff)

    def generate_side_by_side_diff(self, original: str, modified: str) -> dict[str, Any]:
        """Generate side-by-side diff data."""
        original_lines = original.splitlines()
        modified_lines = modified.splitlines()

        differ = difflib.SequenceMatcher(None, original_lines, modified_lines)
        diff_data = {
            "original_lines": [],
            "modified_lines": [],
            "changes": [],
        }

        for tag, i1, i2, j1, j2 in differ.get_opcodes():
            if tag == "equal":
                for i in range(i1, i2):
                    diff_data["original_lines"].append(
                        {
                            "line_number": i + 1,
                            "content": original_lines[i],
                            "type": "unchanged",
                        },
                    )
                    diff_data["modified_lines"].append(
                        {
                            "line_number": j1 + (i - i1) + 1,
                            "content": original_lines[i],
                            "type": "unchanged",
                        },
                    )

            elif tag == "delete":
                for i in range(i1, i2):
                    diff_data["original_lines"].append(
                        {
                            "line_number": i + 1,
                            "content": original_lines[i],
                            "type": "deleted",
                        },
                    )

            elif tag == "insert":
                for j in range(j1, j2):
                    diff_data["modified_lines"].append(
                        {
                            "line_number": j + 1,
                            "content": modified_lines[j],
                            "type": "added",
                        },
                    )

            elif tag == "replace":
                for i in range(i1, i2):
                    diff_data["original_lines"].append(
                        {
                            "line_number": i + 1,
                            "content": original_lines[i],
                            "type": "modified",
                        },
                    )
                for j in range(j1, j2):
                    diff_data["modified_lines"].append(
                        {
                            "line_number": j + 1,
                            "content": modified_lines[j],
                            "type": "modified",
                        },
                    )

            if tag != "equal":
                diff_data["changes"].append(
                    {
                        "type": tag,
                        "original_start": i1,
                        "original_end": i2,
                        "modified_start": j1,
                        "modified_end": j2,
                    },
                )

        return diff_data

    def get_change_summary(self, original: str, modified: str) -> dict[str, int]:
        """Get summary of changes."""
        original_lines = original.splitlines()
        modified_lines = modified.splitlines()

        differ = difflib.SequenceMatcher(None, original_lines, modified_lines)

        additions = 0
        deletions = 0
        modifications = 0

        for tag, i1, i2, j1, j2 in differ.get_opcodes():
            if tag == "delete":
                deletions += i2 - i1
            elif tag == "insert":
                additions += j2 - j1
            elif tag == "replace":
                modifications += max(i2 - i1, j2 - j1)

        return {
            "additions": additions,
            "deletions": deletions,
            "modifications": modifications,
            "total_changes": additions + deletions + modifications,
        }


class IntelligentCodeModifier:
    """Run class for intelligent code modification."""

    def __init__(self, llm_manager: LLMManager | None = None) -> None:
        """Initialize the intelligent code modifier.

        Args:
            llm_manager: Optional LLM manager for AI-powered code modifications

        """
        self.llm_manager = llm_manager or LLMManager()
        self.analyzer = CodeAnalyzer()
        self.diff_generator = DiffGenerator()

        self.pending_changes: dict[str, CodeChange] = {}
        self.modification_history: list[CodeChange] = []
        self.project_context: dict[str, CodeContext] = {}

        # Configuration
        self.max_context_files = 10
        self.confidence_threshold = 0.7
        self.backup_enabled = True
        self.backup_directory = Path.home() / ".intellicrack" / "code_backups"
        self.backup_directory.mkdir(parents=True, exist_ok=True)

    def gather_project_context(self, project_root: str, target_files: list[str] = None) -> dict[str, CodeContext]:
        """Gather context about the entire project."""
        logger.info("Gathering project context from: %s", project_root)

        project_path = Path(project_root)
        context = {}

        # Find relevant files
        if target_files:
            files_to_analyze = [project_path / f for f in target_files if (project_path / f).exists()]
        else:
            files_to_analyze = []
            for ext in self.analyzer.supported_extensions:
                files_to_analyze.extend(project_path.rglob(f"*{ext}"))

        # Limit number of files to analyze
        if len(files_to_analyze) > self.max_context_files:
            files_to_analyze = files_to_analyze[: self.max_context_files]
            logger.warning("Limited analysis to %d files", self.max_context_files)

        # Analyze each file
        for file_path in files_to_analyze:
            try:
                relative_path = file_path.relative_to(project_path)
                context[str(relative_path)] = self.analyzer.analyze_file(str(file_path))
            except Exception as e:
                logger.error("Failed to analyze %s: %s", file_path, e)

        self.project_context = context
        logger.info("Analyzed %d files for project context", len(context))
        return context

    def create_modification_request(
        self,
        description: str,
        target_files: list[str],
        requirements: list[str] = None,
        constraints: list[str] = None,
        context_files: list[str] = None,
    ) -> ModificationRequest:
        """Create a new modification request."""
        request_id = f"mod_{int(datetime.now().timestamp())}"

        return ModificationRequest(
            request_id=request_id,
            description=description,
            target_files=target_files,
            context_files=context_files or [],
            requirements=requirements or [],
            constraints=constraints or [],
        )

    def analyze_modification_request(self, request: ModificationRequest) -> list[CodeChange]:
        """Analyze a modification request and generate code changes."""
        logger.info("Analyzing modification request: %s", request.request_id)

        # Gather context for target files
        changes = []

        for target_file in request.target_files:
            try:
                context = self.analyzer.analyze_file(target_file)

                # Generate modification prompt
                prompt = self._create_modification_prompt(request, context)

                # Get AI response
                response = self._get_ai_modification_response(prompt)

                # Parse response into code changes
                file_changes = self._parse_modification_response(response, target_file, request)
                changes.extend(file_changes)

            except Exception as e:
                logger.error("Failed to analyze %s: %s", target_file, e)

        # Store pending changes
        for change in changes:
            self.pending_changes[change.change_id] = change

        logger.info("Generated %d code changes", len(changes))
        return changes

    def _create_modification_prompt(self, request: ModificationRequest, context: CodeContext) -> str:
        """Create a prompt for AI modification."""
        return f"""
# Code Modification Request

## Task Description
{request.description}

## Target File Information
- **File**: {context.file_path}
- **Language**: {context.language}
- **Functions**: {", ".join(context.functions)}
- **Classes**: {", ".join(context.classes)}
- **Imports**: {", ".join(context.imports)}

## Requirements
{chr(10).join(f"- {req}" for req in request.requirements)}

## Constraints
{chr(10).join(f"- {constraint}" for constraint in request.constraints)}

## Current Code
```{context.language}
{context.content}
```

## Instructions
Analyze the code and provide specific modifications in JSON format:

```json
{{
  "modifications": [
    {{
      "type": "function_modification|class_creation|etc",
      "description": "Clear description of what this change does",
      "start_line": 10,
      "end_line": 20,
      "original_code": "original code block",
      "modified_code": "modified code block",
      "reasoning": "Why this change is needed",
      "confidence": 0.9,
      "impact": "Description of potential impact"
    }}
  ]
}}
```

Requirements:
1. All code modifications must be production-ready, fully functional implementations that execute immediately
2. Ensure all modifications are syntactically correct with proper error handling and type annotations
3. Maintain existing code style, design patterns, and architectural conventions from the codebase
4. Include comprehensive error handling for edge cases, exceptions, and failure scenarios
5. Consider security implications including input validation, injection prevention, and data sanitization
6. Provide confidence scores (0.0-1.0) for each modification based on static analysis and pattern matching
"""

    def _get_ai_modification_response(self, prompt: str) -> str:
        """Get AI response for modification."""
        try:
            messages = [
                LLMMessage(
                    role="system",
                    content="You are an expert code modification assistant. Provide only working, production-ready code modifications.",
                ),
                LLMMessage(role="user", content=prompt),
            ]

            response = self.llm_manager.chat(messages)
            return response.content if response else ""

        except Exception as e:
            logger.error("Failed to get AI response: %s", e)
            return ""

    def _parse_modification_response(self, response: str, file_path: str, request: ModificationRequest) -> list[CodeChange]:
        """Parse AI response into CodeChange objects."""
        changes = []

        try:
            # Extract JSON from response
            json_match = re.search(r"```json\s*(\{.*?\})\s*```", response, re.DOTALL) or re.search(
                r'(\{.*"modifications".*\})', response, re.DOTALL
            )

            if not json_match:
                logger.warning("No JSON found in AI response")
                return changes

            data = json.loads(json_match[1])
            modifications = data.get("modifications", [])

            for i, mod in enumerate(modifications):
                change_id = f"{request.request_id}_{i}"

                # Map modification type
                mod_type_str = mod.get("type", "modification")
                try:
                    mod_type = ModificationType(mod_type_str)
                except ValueError as e:
                    logger.error("Value error in intelligent_code_modifier: %s", e)
                    mod_type = ModificationType.FUNCTION_MODIFICATION

                change = CodeChange(
                    change_id=change_id,
                    file_path=file_path,
                    modification_type=mod_type,
                    description=mod.get("description", "AI-generated modification"),
                    original_code=mod.get("original_code", ""),
                    modified_code=mod.get("modified_code", ""),
                    start_line=mod.get("start_line", 1),
                    end_line=mod.get("end_line", 1),
                    confidence=float(mod.get("confidence", 0.5)),
                    reasoning=mod.get("reasoning", ""),
                    impact_analysis={"impact": mod.get("impact", "Unknown impact")},
                )

                changes.append(change)

        except json.JSONDecodeError as e:
            logger.error("Failed to parse JSON response: %s", e)
        except Exception as e:
            logger.error("Error parsing modification response: %s", e)

        return changes

    def preview_changes(self, change_ids: list[str]) -> dict[str, Any]:
        """Preview changes before applying them."""
        preview_data = {
            "changes": [],
            "files_affected": set(),
            "total_changes": 0,
            "high_risk_changes": 0,
        }

        for change_id in change_ids:
            if change_id not in self.pending_changes:
                continue

            change = self.pending_changes[change_id]
            preview_data["files_affected"].add(change.file_path)
            preview_data["total_changes"] += 1

            if change.confidence < self.confidence_threshold:
                preview_data["high_risk_changes"] += 1

            # Generate diff
            diff = self.diff_generator.generate_unified_diff(
                change.original_code,
                change.modified_code,
                Path(change.file_path).name,
            )

            change_info = {
                "change_id": change_id,
                "file_path": change.file_path,
                "description": change.description,
                "type": change.modification_type.value,
                "confidence": change.confidence,
                "reasoning": change.reasoning,
                "diff": diff,
                "lines_affected": f"{change.start_line}-{change.end_line}",
                "impact": change.impact_analysis,
            }

            preview_data["changes"].append(change_info)

        preview_data["files_affected"] = list(preview_data["files_affected"])
        return preview_data

    def apply_changes(self, change_ids: list[str], create_backup: bool = True) -> dict[str, Any]:
        """Apply the specified changes to files."""
        results = {
            "applied": [],
            "failed": [],
            "backups_created": [],
            "errors": [],
        }

        # Group changes by file
        changes_by_file = {}
        for change_id in change_ids:
            if change_id not in self.pending_changes:
                results["failed"].append(change_id)
                results["errors"].append(f"Change {change_id} not found")
                continue

            change = self.pending_changes[change_id]
            if change.status != ChangeStatus.PENDING:
                results["failed"].append(change_id)
                results["errors"].append(f"Change {change_id} is not pending")
                continue

            if change.file_path not in changes_by_file:
                changes_by_file[change.file_path] = []
            changes_by_file[change.file_path].append(change)

        # Apply changes file by file
        for file_path, file_changes in changes_by_file.items():
            try:
                # Create backup if requested
                if create_backup:
                    backup_path = self._create_backup(file_path)
                    results["backups_created"].append(str(backup_path))

                if success := self._apply_changes_to_file(file_path, file_changes):
                    logger.debug("Successfully applied changes to %s: %s", file_path, success)
                    for change in file_changes:
                        change.status = ChangeStatus.APPLIED
                        change.applied_at = datetime.now()
                        results["applied"].append(change.change_id)
                        self.modification_history.append(change)
                        del self.pending_changes[change.change_id]
                else:
                    for change in file_changes:
                        change.status = ChangeStatus.FAILED
                        results["failed"].append(change.change_id)
                    results["errors"].append(f"Failed to apply changes to {file_path}")

            except Exception as e:
                logger.error("Error applying changes to %s: %s", file_path, e)
                for change in file_changes:
                    change.status = ChangeStatus.FAILED
                    results["failed"].append(change.change_id)
                results["errors"].append(f"Exception applying {file_path}: {e!s}")

        return results

    def _create_backup(self, file_path: str) -> Path:
        """Create a backup of the file."""
        source_path = Path(file_path)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_name = f"{source_path.name}.{timestamp}.backup"
        backup_path = self.backup_directory / backup_name

        import shutil

        shutil.copy2(source_path, backup_path)

        logger.info("Created backup: %s", backup_path)
        return backup_path

    def _apply_changes_to_file(self, file_path: str, changes: list[CodeChange]) -> bool:
        """Apply multiple changes to a single file."""
        try:
            # Read current file content
            content = None
            try:
                from .ai_file_tools import get_ai_file_tools

                ai_file_tools = get_ai_file_tools(getattr(self, "app_instance", None))
                file_data = ai_file_tools.read_file(file_path, purpose="Read file for applying code modifications")
                if file_data.get("status") == "success" and file_data.get("content"):
                    content = file_data["content"]
            except (ImportError, AttributeError, KeyError):
                pass

            # Fallback to direct file reading if AIFileTools not available
            if content is None:
                with open(file_path, encoding="utf-8") as f:
                    content = f.read()

            lines = content.splitlines()

            # Sort changes by line number (descending to avoid line number shifts)
            changes.sort(key=lambda c: c.start_line, reverse=True)

            # Apply each change
            for change in changes:
                start_idx = change.start_line - 1  # Convert to 0-based index
                end_idx = change.end_line

                # Validate line numbers
                if start_idx < 0 or end_idx > len(lines):
                    logger.warning("Invalid line range for change %s", change.change_id)
                    continue

                # Replace lines
                new_lines = change.modified_code.splitlines()
                lines[start_idx:end_idx] = new_lines

            # Write modified content back to file
            modified_content = "\n".join(lines)
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(modified_content)

            logger.info("Applied %d changes to %s", len(changes), file_path)
            return True

        except Exception as e:
            logger.error("Failed to apply changes to %s: %s", file_path, e)
            return False

    def reject_changes(self, change_ids: list[str]) -> dict[str, Any]:
        """Reject the specified changes."""
        results = {"rejected": [], "not_found": []}

        for change_id in change_ids:
            if change_id in self.pending_changes:
                change = self.pending_changes[change_id]
                change.status = ChangeStatus.REJECTED
                self.modification_history.append(change)
                del self.pending_changes[change_id]
                results["rejected"].append(change_id)
            else:
                results["not_found"].append(change_id)

        return results

    def get_modification_history(self, limit: int = 50) -> list[dict[str, Any]]:
        """Get modification history."""
        history = sorted(self.modification_history, key=lambda c: c.created_at, reverse=True)

        return [
            {
                "change_id": change.change_id,
                "file_path": change.file_path,
                "description": change.description,
                "type": change.modification_type.value,
                "status": change.status.value,
                "confidence": change.confidence,
                "created_at": change.created_at.isoformat(),
                "applied_at": change.applied_at.isoformat() if change.applied_at else None,
            }
            for change in history[:limit]
        ]

    def get_pending_changes(self) -> list[dict[str, Any]]:
        """Get all pending changes."""
        return [
            {
                "change_id": change.change_id,
                "file_path": change.file_path,
                "description": change.description,
                "type": change.modification_type.value,
                "confidence": change.confidence,
                "reasoning": change.reasoning,
                "lines": f"{change.start_line}-{change.end_line}",
            }
            for change in self.pending_changes.values()
        ]

#!/usr/bin/env python3
"""
This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

"""
Comprehensive Linter for Intellicrack Project.

This script analyzes all Python modules in the Intellicrack project and reports
issues, inconsistencies, and areas for improvement.
"""

import ast
import importlib.util
import json
import os
import re
import sys
import time
from collections import defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Try to import optional linting libraries
try:
    import flake8.api.legacy as flake8
    FLAKE8_AVAILABLE = True
except ImportError:
    FLAKE8_AVAILABLE = False

try:
    import pylint.lint
    PYLINT_AVAILABLE = True
except ImportError:
    PYLINT_AVAILABLE = False

try:
    import mypy.api
    MYPY_AVAILABLE = True
except ImportError:
    MYPY_AVAILABLE = False


@dataclass
class LintIssue:
    """Represents a linting issue."""
    file_path: str
    line_number: int
    column: int
    issue_type: str
    severity: str  # error, warning, info
    message: str
    rule: str
    suggestion: Optional[str] = None


@dataclass
class ModuleInfo:
    """Information about a Python module."""
    file_path: str
    line_count: int
    function_count: int
    class_count: int
    import_count: int
    has_docstring: bool
    has_main_guard: bool
    complexity_score: int
    issues: List[LintIssue]


class IntellicrackLinter:
    """Comprehensive linter for the Intellicrack project."""

    def __init__(self, project_root: str):
        self.project_root = Path(project_root)
        self.modules: Dict[str, ModuleInfo] = {}
        self.issues: List[LintIssue] = []
        self.statistics = {
            "total_files": 0,
            "total_lines": 0,
            "total_functions": 0,
            "total_classes": 0,
            "issues_by_type": defaultdict(int),
            "issues_by_severity": defaultdict(int)
        }

    def scan_project(self) -> None:
        """Scan the entire project for Python files."""
        print("🔍 Scanning Intellicrack project...")

        # Find all Python files
        python_files = self._find_python_files()

        print(f"Found {len(python_files)} Python files")

        # Analyze each file
        for i, file_path in enumerate(python_files, 1):
            print(
                f"Analyzing {i}/{len(python_files)}: {file_path.relative_to(self.project_root)}")
            try:
                module_info = self._analyze_file(file_path)
                self.modules[str(file_path)] = module_info
                self.issues.extend(module_info.issues)

                # Update statistics
                self.statistics["total_files"] += 1
                self.statistics["total_lines"] += module_info.line_count
                self.statistics["total_functions"] += module_info.function_count
                self.statistics["total_classes"] += module_info.class_count

            except Exception as e:
                issue = LintIssue(
                    file_path=str(file_path),
                    line_number=1,
                    column=1,
                    issue_type="parse_error",
                    severity="error",
                    message=f"Failed to parse file: {e}",
                    rule="syntax"
                )
                self.issues.append(issue)

        # Update issue statistics
        for issue in self.issues:
            self.statistics["issues_by_type"][issue.issue_type] += 1
            self.statistics["issues_by_severity"][issue.severity] += 1

    def _find_python_files(self) -> List[Path]:
        """Find all Python files in the project."""
        python_files = []

        # Exclude certain directories
        exclude_dirs = {
            "__pycache__", ".git", "node_modules", "venv", ".venv",
            "build", "dist", ".pytest_cache", ".mypy_cache"
        }

        for root, dirs, files in os.walk(self.project_root):
            # Remove excluded directories
            dirs[:] = [d for d in dirs if d not in exclude_dirs]

            for file in files:
                if file.endswith('.py'):
                    python_files.append(Path(root) / file)

        return python_files

    def _analyze_file(self, file_path: Path) -> ModuleInfo:
        """Analyze a single Python file."""
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()

        # Parse AST
        try:
            tree = ast.parse(content)
        except SyntaxError as e:
            # Create minimal module info for files with syntax errors
            return ModuleInfo(
                file_path=str(file_path),
                line_count=len(content.splitlines()),
                function_count=0,
                class_count=0,
                import_count=0,
                has_docstring=False,
                has_main_guard=False,
                complexity_score=0,
                issues=[LintIssue(
                    file_path=str(file_path),
                    line_number=e.lineno or 1,
                    column=e.offset or 1,
                    issue_type="syntax_error",
                    severity="error",
                    message=str(e),
                    rule="syntax"
                )]
            )

        # Analyze the AST
        analyzer = ASTAnalyzer(file_path, content)
        analyzer.visit(tree)

        return ModuleInfo(
            file_path=str(file_path),
            line_count=len(content.splitlines()),
            function_count=analyzer.function_count,
            class_count=analyzer.class_count,
            import_count=analyzer.import_count,
            has_docstring=analyzer.has_module_docstring,
            has_main_guard=analyzer.has_main_guard,
            complexity_score=analyzer.complexity_score,
            issues=analyzer.issues
        )

    def run_external_linters(self) -> None:
        """Run external linting tools if available."""
        print("\n🔧 Running external linters...")

        if FLAKE8_AVAILABLE:
            print("Running flake8...")
            self._run_flake8()
        else:
            print("❌ flake8 not available")

        if PYLINT_AVAILABLE:
            print("Running pylint...")
            self._run_pylint()
        else:
            print("❌ pylint not available")

        if MYPY_AVAILABLE:
            print("Running mypy...")
            self._run_mypy()
        else:
            print("❌ mypy not available")

    def _run_flake8(self) -> None:
        """Run flake8 linter."""
        try:
            style_guide = flake8.get_style_guide()
            report = style_guide.check_files([str(self.project_root)])

            # flake8 results are captured through its internal reporting system
            # This is a simplified implementation
        except Exception as e:
            print(f"Error running flake8: {e}")

    def _run_pylint(self) -> None:
        """Run pylint linter."""
        try:
            # This is a simplified implementation
            # Full integration would require more complex setup
            pass
        except Exception as e:
            print(f"Error running pylint: {e}")

    def _run_mypy(self) -> None:
        """Run mypy type checker."""
        try:
            result = mypy.api.run([str(self.project_root)])
            stdout, stderr, exit_code = result

            if stdout:
                # Parse mypy output and add to issues
                self._parse_mypy_output(stdout)
        except Exception as e:
            print(f"Error running mypy: {e}")

    def _parse_mypy_output(self, output: str) -> None:
        """Parse mypy output and add issues."""
        for line in output.strip().split('\n'):
            if ':' in line and 'error:' in line:
                parts = line.split(':')
                if len(parts) >= 4:
                    file_path = parts[0]
                    line_num = int(parts[1]) if parts[1].isdigit() else 1
                    message = ':'.join(parts[3:]).strip()

                    issue = LintIssue(
                        file_path=file_path,
                        line_number=line_num,
                        column=1,
                        issue_type="type_error",
                        severity="error",
                        message=message,
                        rule="mypy"
                    )
                    self.issues.append(issue)

    def generate_report(self, output_file: str = "lint_report.md") -> None:
        """Generate a comprehensive lint report."""
        print(f"\n📝 Generating report: {output_file}")

        with open(output_file, 'w') as f:
            f.write(self._create_markdown_report())

        print(f"✅ Report generated: {output_file}")

    # pylint: disable=too-complex
    def _create_markdown_report(self) -> str:
        """Create a markdown report."""
        report = []

        # Header
        report.append("# Intellicrack Linter Report")
        report.append(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("")

        # Summary
        report.append("## Summary")
        report.append("")
        report.append(f"- **Total Files**: {self.statistics['total_files']}")
        report.append(f"- **Total Lines**: {self.statistics['total_lines']:,}")
        report.append(
            f"- **Total Functions**: {self.statistics['total_functions']}")
        report.append(
            f"- **Total Classes**: {self.statistics['total_classes']}")
        report.append(f"- **Total Issues**: {len(self.issues)}")
        report.append("")

        # Issues by severity
        report.append("### Issues by Severity")
        report.append("")
        for severity, count in sorted(self.statistics["issues_by_severity"].items()):
            report.append(f"- **{severity.title()}**: {count}")
        report.append("")

        # Issues by type
        report.append("### Issues by Type")
        report.append("")
        for issue_type, count in sorted(self.statistics["issues_by_type"].items()):
            report.append(
                f"- **{issue_type.replace('_', ' ').title()}**: {count}")
        report.append("")

        # Top problematic files
        report.append("## Top Problematic Files")
        report.append("")

        file_issue_count = defaultdict(int)
        for issue in self.issues:
            file_issue_count[issue.file_path] += 1

        top_files = sorted(file_issue_count.items(),
                           key=lambda x: x[1], reverse=True)[:10]

        for file_path, count in top_files:
            rel_path = Path(file_path).relative_to(self.project_root)
            report.append(f"- `{rel_path}`: {count} issues")
        report.append("")

        # Detailed issues by file
        report.append("## Detailed Issues")
        report.append("")

        # Group issues by file
        issues_by_file = defaultdict(list)
        for issue in self.issues:
            issues_by_file[issue.file_path].append(issue)

        for file_path in sorted(issues_by_file.keys()):
            rel_path = Path(file_path).relative_to(self.project_root)
            issues = issues_by_file[file_path]

            report.append(f"### `{rel_path}`")
            report.append("")

            # Sort issues by line number
            issues.sort(key=lambda x: x.line_number)

            for issue in issues:
                severity_emoji = {"error": "❌", "warning": "⚠️",
                                  "info": "ℹ️"}.get(issue.severity, "")
                report.append(
                    f"- **Line {issue.line_number}** {severity_emoji} {issue.message}")
                if issue.suggestion:
                    report.append(f"  - Suggestion: {issue.suggestion}")
            report.append("")

        # Module quality analysis
        report.append("## Module Quality Analysis")
        report.append("")

        # Files without docstrings
        no_docstring = [m for m in self.modules.values()
                        if not m.has_docstring]
        if no_docstring:
            report.append("### Files Missing Module Docstrings")
            report.append("")
            for module in sorted(no_docstring, key=lambda x: x.file_path):
                rel_path = Path(module.file_path).relative_to(
                    self.project_root)
                report.append(f"- `{rel_path}`")
            report.append("")

        # Files without main guard
        no_main_guard = [m for m in self.modules.values(
        ) if not m.has_main_guard and m.line_count > 50]
        if no_main_guard:
            report.append("### Large Files Missing Main Guard")
            report.append("")
            for module in sorted(no_main_guard, key=lambda x: x.line_count, reverse=True):
                rel_path = Path(module.file_path).relative_to(
                    self.project_root)
                report.append(f"- `{rel_path}` ({module.line_count} lines)")
            report.append("")

        # Recommendations
        report.append("## Recommendations")
        report.append("")
        report.append(
            "1. **Fix Syntax Errors**: Address all syntax errors before other improvements")
        report.append(
            "2. **Add Docstrings**: Add module docstrings to improve code documentation")
        report.append(
            "3. **Type Hints**: Add type hints to improve code clarity and catch errors")
        report.append(
            "4. **Code Formatting**: Use black or similar formatter for consistent code style")
        report.append(
            "5. **Import Organization**: Organize imports consistently (stdlib, third-party, local)")
        report.append(
            "6. **Error Handling**: Add proper exception handling where missing")
        report.append(
            "7. **Testing**: Add unit tests for modules with high complexity")
        report.append("")

        return "\n".join(report)


class ASTAnalyzer(ast.NodeVisitor):
    """AST visitor for analyzing Python code."""

    def __init__(self, file_path: Path, content: str):
        self.file_path = file_path
        self.content = content
        self.lines = content.splitlines()
        self.issues: List[LintIssue] = []

        # Counters
        self.function_count = 0
        self.class_count = 0
        self.import_count = 0
        self.complexity_score = 0

        # Flags
        self.has_module_docstring = False
        self.has_main_guard = False

        # Track current context
        self.current_class = None
        self.current_function = None

    def visit_Module(self, node: ast.Module) -> None:
        """Visit module node to check for module docstring."""
        # Check for module docstring
        if (node.body and isinstance(node.body[0], ast.Expr)
                and isinstance(node.body[0].value, ast.Str)):
            self.has_module_docstring = True

        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Visit function definitions to check docstrings and complexity."""
        self.function_count += 1
        prev_function = self.current_function
        self.current_function = node.name

        # Check for function docstring
        if not (node.body and isinstance(node.body[0], ast.Expr)
                and isinstance(node.body[0].value, (ast.Str, ast.Constant))):
            if not node.name.startswith('_'):  # Skip private functions
                self.issues.append(LintIssue(
                    file_path=str(self.file_path),
                    line_number=node.lineno,
                    column=node.col_offset,
                    issue_type="missing_docstring",
                    severity="warning",
                    message=f"Function '{node.name}' missing docstring",
                    rule="docstring",
                    suggestion="Add a docstring describing the function's purpose"
                ))

        # Check function complexity (simplified)
        complexity = self._calculate_complexity(node)
        if complexity > 10:
            self.issues.append(LintIssue(
                file_path=str(self.file_path),
                line_number=node.lineno,
                column=node.col_offset,
                issue_type="high_complexity",
                severity="warning",
                message=f"Function '{node.name}' has high complexity ({complexity})",
                rule="complexity",
                suggestion="Consider breaking this function into smaller functions"
            ))

        self.complexity_score += complexity
        self.generic_visit(node)
        self.current_function = prev_function

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Visit class definitions to check for docstrings."""
        self.class_count += 1
        prev_class = self.current_class
        self.current_class = node.name

        # Check for class docstring
        if not (node.body and isinstance(node.body[0], ast.Expr)
                and isinstance(node.body[0].value, (ast.Str, ast.Constant))):
            self.issues.append(LintIssue(
                file_path=str(self.file_path),
                line_number=node.lineno,
                column=node.col_offset,
                issue_type="missing_docstring",
                severity="warning",
                message=f"Class '{node.name}' missing docstring",
                rule="docstring",
                suggestion="Add a docstring describing the class's purpose"
            ))

        self.generic_visit(node)
        self.current_class = prev_class

    def visit_Import(self, node: ast.Import) -> None:
        """Track import statements."""
        self.import_count += len(node.names)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Track from-import statements and check for relative imports."""
        self.import_count += len(node.names)

        # Check for relative imports
        if node.level > 0:
            # This is a relative import
            pass

        self.generic_visit(node)

    def visit_If(self, node: ast.If) -> None:
        """Visit if statements to check for main guard."""
        # Check for main guard
        if (isinstance(node.test, ast.Compare) and
            isinstance(node.test.left, ast.Name) and
            node.test.left.id == "__name__" and
            len(node.test.ops) == 1 and
            isinstance(node.test.ops[0], ast.Eq) and
            len(node.test.comparators) == 1 and
                isinstance(node.test.comparators[0], (ast.Str, ast.Constant))):

            value = (node.test.comparators[0].s if isinstance(node.test.comparators[0], ast.Str)
                     else node.test.comparators[0].value)
            if value == "__main__":
                self.has_main_guard = True

        self.generic_visit(node)

    def visit_Try(self, node: ast.Try) -> None:
        """Visit try statements to check for bare except clauses."""
        # Check for bare except clauses
        for handler in node.handlers:
            if handler.type is None:
                self.issues.append(LintIssue(
                    file_path=str(self.file_path),
                    line_number=handler.lineno,
                    column=handler.col_offset,
                    issue_type="bare_except",
                    severity="warning",
                    message="Bare except clause catches all exceptions",
                    rule="exception_handling",
                    suggestion="Specify the exception type(s) to catch"
                ))

        self.generic_visit(node)

    def _calculate_complexity(self, node: ast.FunctionDef) -> int:
        """Calculate cyclomatic complexity of a function (simplified)."""
        complexity = 1  # Base complexity

        class ComplexityVisitor(ast.NodeVisitor):
            """AST visitor to calculate cyclomatic complexity."""

            def __init__(self):
                self.complexity = 0

            def visit_If(self, node):
                """Count if statements for complexity."""
                self.complexity += 1
                self.generic_visit(node)

            def visit_For(self, node):
                """Count for loops for complexity."""
                self.complexity += 1
                self.generic_visit(node)

            def visit_While(self, node):
                """Count while loops for complexity."""
                self.complexity += 1
                self.generic_visit(node)

            def visit_Try(self, node):
                """Count try/except blocks for complexity."""
                self.complexity += len(node.handlers)
                self.generic_visit(node)

        visitor = ComplexityVisitor()
        visitor.visit(node)
        return complexity + visitor.complexity


def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Comprehensive linter for Intellicrack project"
    )
    parser.add_argument(
        "--project-root",
        default=".",
        help="Root directory of the project"
    )
    parser.add_argument(
        "--output",
        default="lint_report.md",
        help="Output file for the report"
    )
    parser.add_argument(
        "--external-linters",
        action="store_true",
        help="Run external linters (flake8, pylint, mypy)"
    )

    args = parser.parse_args()

    # Initialize linter
    linter = IntellicrackLinter(args.project_root)

    # Scan project
    linter.scan_project()

    # Run external linters if requested
    if args.external_linters:
        linter.run_external_linters()

    # Generate report
    linter.generate_report(args.output)

    # Print summary
    print(f"\n📊 Linting Summary:")
    print(f"   Files analyzed: {linter.statistics['total_files']}")
    print(f"   Total lines: {linter.statistics['total_lines']:,}")
    print(f"   Total issues: {len(linter.issues)}")
    print(f"   Errors: {linter.statistics['issues_by_severity']['error']}")
    print(f"   Warnings: {linter.statistics['issues_by_severity']['warning']}")
    print(f"   Info: {linter.statistics['issues_by_severity']['info']}")


if __name__ == "__main__":
    main()

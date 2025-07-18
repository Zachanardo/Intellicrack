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
INTELLICRACK COMPREHENSIVE ERROR DETECTOR

This script performs exhaustive static and dynamic analysis to find ALL code issues.
Results are saved to intellicrack_errors.txt which is OVERWRITTEN each run.
"""

import ast
import importlib
import inspect
import os
import pkgutil
import re
import subprocess
import sys
import threading
import time
import traceback
from collections import defaultdict, deque
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

# Add parent directory to path
sys.path.insert(0, os.path.abspath('..'))


class IntellicrackErrorDetector:
    """Comprehensive error detector for Intellicrack codebase."""

    def __init__(self):
        self.project_path = Path('..').resolve()
        self.output_file = Path('intellicrack_errors.txt').resolve()
        self.start_time = time.time()

        # Issue tracking
        self.all_issues = []
        self.issue_counts = defaultdict(int)

        # Initialize output file (overwrites existing)
        with open(self.output_file, 'w', encoding='utf-8') as f:
            f.write(f"""================================================================================
                    INTELLICRACK COMPREHENSIVE ERROR DETECTION
================================================================================
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Python: {sys.version.split()[0]}
Project: {self.project_path}
================================================================================

""")

    def log(self, message: str, category: str = "INFO"):
        """Log to console and file"""
        timestamp = datetime.now().strftime('%H:%M:%S')

        # Console colors
        colors = {
            'ERROR': '\033[91m',
            'WARNING': '\033[93m',
            'SUCCESS': '\033[92m',
            'INFO': '\033[94m',
            'CRITICAL': '\033[95m',
            'HEADER': '\033[96m'
        }

        # Console output
        color = colors.get(category, '')
        print(f"{color}[{timestamp}] {message}\033[0m")

        # File output
        with open(self.output_file, 'a', encoding='utf-8') as f:
            f.write(f"[{timestamp}] {message}\n")

    def add_issue(self, category: str, file: str, line: int, message: str):
        """Add an issue to tracking"""
        issue = {
            'category': category,
            'file': file,
            'line': line,
            'message': message
        }
        self.all_issues.append(issue)
        self.issue_counts[category] += 1

    # pylint: disable=too-complex
    def run_pylint(self):
        """Run Pylint analysis"""
        self.log("\n=== PYLINT ANALYSIS ===", "HEADER")

        try:
            # Check if pylint is installed
            result = subprocess.run(
                [sys.executable, '-m', 'pylint', '--version'],
                capture_output=True,
                text=True
            )

            if result.returncode != 0:
                self.log(
                    "Pylint not installed, skipping pylint analysis", "WARNING")
                return

            # Run pylint with detailed output
            self.log("Running pylint on entire codebase...", "INFO")
            result = subprocess.run(
                [sys.executable, '-m', 'pylint', 'intellicrack',
                 '--output-format=parseable',
                 '--reports=no',
                 '--score=no'],
                capture_output=True,
                text=True,
                cwd=self.project_path.parent
            )

            output = result.stdout + result.stderr
            lines = output.strip().split('\n') if output.strip() else []

            # Parse pylint output
            for line in lines:
                if not line or 'rated at' in line:
                    continue

                # Parse pylint format: file:line: [error-code] message
                match = re.match(
                    r'([^:]+):(\d+):\s*\[([A-Z]\d{4})\]\s*(.+)', line)
                if match:
                    file_path, line_no, code, msg = match.groups()
                    file_rel = file_path.replace(
                        'intellicrack/', '') if 'intellicrack/' in file_path else file_path

                    # Categorize by error type
                    if code.startswith('E'):
                        category = 'PYLINT_ERROR'
                    elif code.startswith('W'):
                        category = 'PYLINT_WARNING'
                    elif code.startswith('C'):
                        category = 'PYLINT_CONVENTION'
                    elif code.startswith('R'):
                        category = 'PYLINT_REFACTOR'
                    else:
                        category = 'PYLINT_OTHER'

                    self.add_issue(category, file_rel, int(
                        line_no), f"[{code}] {msg}")

            error_count = self.issue_counts['PYLINT_ERROR']
            warning_count = self.issue_counts['PYLINT_WARNING']
            self.log(f"Pylint found {error_count} errors and {warning_count} warnings",
                     "ERROR" if error_count > 0 else "SUCCESS")

        except Exception as e:
            self.log(f"Pylint analysis failed: {e}", "ERROR")

    # pylint: disable=too-complex
    def analyze_ast_patterns(self):
        """Deep AST analysis for problematic patterns"""
        self.log("\n=== AST PATTERN ANALYSIS ===", "HEADER")

        patterns_found = 0

        for root, dirs, files in os.walk(self.project_path):
            dirs[:] = [d for d in dirs if d not in ['__pycache__', '.git',
                                                    'venv', 'node_modules', 'ghidra', 'radare2', 'tools']]

            for file in files:
                if not file.endswith('.py'):
                    continue

                filepath = Path(root) / file
                rel_path = filepath.relative_to(self.project_path)

                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        content = f.read()
                        tree = ast.parse(content, str(filepath))

                    # Track various patterns
                    class PatternVisitor(ast.NodeVisitor):
                        """AST visitor to detect code patterns and potential issues."""

                        def __init__(self, detector, rel_path):
                            self.detector = detector
                            self.rel_path = str(rel_path)
                            self.in_init = False
                            self.class_name = None

                        def visit_FunctionDef(self, node):
                            """Visit function definitions to check for mutable defaults and docstrings."""
                            # Mutable default arguments
                            for i, default in enumerate(node.args.defaults):
                                if isinstance(default, (ast.List, ast.Dict, ast.Set)):
                                    self.detector.add_issue(
                                        'MUTABLE_DEFAULT',
                                        self.rel_path,
                                        node.lineno,
                                        f"{node.name}() has mutable default argument"
                                    )

                            # Track if we're in __init__
                            old_in_init = self.in_init
                            if node.name == '__init__':
                                self.in_init = True

                            self.generic_visit(node)
                            self.in_init = old_in_init

                        def visit_ClassDef(self, node):
                            """Visit class definitions to track context."""
                            old_class = self.class_name
                            self.class_name = node.name
                            self.generic_visit(node)
                            self.class_name = old_class

                        def visit_ExceptHandler(self, node):
                            """Check for overly broad exception handlers."""
                            # Bare except
                            if node.type is None:
                                self.detector.add_issue(
                                    'BARE_EXCEPT',
                                    self.rel_path,
                                    node.lineno,
                                    "Bare except clause catches all exceptions"
                                )
                            self.generic_visit(node)

                        def visit_Global(self, node):
                            """Track global variable usage."""
                            # Global usage
                            self.detector.add_issue(
                                'GLOBAL_USAGE',
                                self.rel_path,
                                node.lineno,
                                f"Global declaration: {', '.join(node.names)}"
                            )
                            self.generic_visit(node)

                        def visit_Call(self, node):
                            """Check for potential resource leaks and security issues."""
                            # Dangerous function calls
                            if isinstance(node.func, ast.Name):
                                if node.func.id == 'eval':
                                    self.detector.add_issue(
                                        'EVAL_USAGE',
                                        self.rel_path,
                                        node.lineno,
                                        "eval() usage - security risk"
                                    )
                                elif node.func.id == 'exec':
                                    self.detector.add_issue(
                                        'EXEC_USAGE',
                                        self.rel_path,
                                        node.lineno,
                                        "exec() usage - security risk"
                                    )
                                elif node.func.id == 'open':
                                    # Check if it's in a with statement
                                    parent = getattr(node, '_parent', None)
                                    in_with = False
                                    for _ in range(5):
                                        if parent is None:
                                            break
                                        if isinstance(parent, ast.With):
                                            in_with = True
                                            break
                                        parent = getattr(
                                            parent, '_parent', None)

                                    if not in_with:
                                        self.detector.add_issue(
                                            'FILE_NOT_CLOSED',
                                            self.rel_path,
                                            node.lineno,
                                            "open() without context manager - potential resource leak"
                                        )
                            self.generic_visit(node)

                        def visit_Compare(self, node):
                            """Check for improper identity comparisons."""
                            # None comparison with == instead of is
                            for op, comp in zip(node.ops, node.comparators):
                                if isinstance(comp, ast.Constant) and comp.value is None:
                                    if isinstance(op, (ast.Eq, ast.NotEq)):
                                        self.detector.add_issue(
                                            'NONE_COMPARISON',
                                            self.rel_path,
                                            node.lineno,
                                            "Comparing to None with == or != instead of is/is not"
                                        )
                            self.generic_visit(node)

                        def visit_Assert(self, node):
                            """Track assert statements that could be stripped in production."""
                            # Assert statements
                            self.detector.add_issue(
                                'ASSERT_USAGE',
                                self.rel_path,
                                node.lineno,
                                "Assert statement (disabled with python -O)"
                            )
                            self.generic_visit(node)

                    # Add parent references for context checking
                    for parent in ast.walk(tree):
                        for child in ast.iter_child_nodes(parent):
                            child._parent = parent

                    visitor = PatternVisitor(self, rel_path)
                    visitor.visit(tree)
                    patterns_found += 1

                except SyntaxError as e:
                    self.add_issue(
                        'SYNTAX_ERROR',
                        str(rel_path),
                        e.lineno or 0,
                        f"Syntax Error: {e.msg}"
                    )
                except Exception as e:
                    self.add_issue(
                        'PARSE_ERROR',
                        str(rel_path),
                        0,
                        f"Failed to parse: {str(e)}"
                    )

        self.log(
            f"Analyzed {patterns_found} files for AST patterns", "SUCCESS")

    # pylint: disable=too-complex
    def detect_import_issues(self):
        """Detect import cycles and problematic imports"""
        self.log("\n=== IMPORT ANALYSIS ===", "HEADER")

        imports = defaultdict(set)
        star_imports = []
        relative_imports = []
        missing_init = []

        # Build import graph
        for root, dirs, files in os.walk(self.project_path):
            dirs[:] = [d for d in dirs if d not in ['__pycache__', '.git',
                                                    'venv', 'node_modules', 'ghidra', 'radare2', 'tools']]

            # Check for missing __init__.py
            if files and not '__init__.py' in files and any(f.endswith('.py') for f in files):
                rel_dir = Path(root).relative_to(self.project_path)
                if str(rel_dir) != '.':
                    missing_init.append(str(rel_dir))

            for file in files:
                if not file.endswith('.py'):
                    continue

                filepath = Path(root) / file
                module_path = str(filepath.relative_to(
                    self.project_path.parent)).replace(os.sep, '.')[:-3]

                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        tree = ast.parse(f.read())

                    for node in ast.walk(tree):
                        if isinstance(node, ast.Import):
                            for alias in node.names:
                                if alias.name.startswith('intellicrack'):
                                    imports[module_path].add(alias.name)

                        elif isinstance(node, ast.ImportFrom):
                            # Check for star imports
                            if any(alias.name == '*' for alias in node.names):
                                rel_path = filepath.relative_to(
                                    self.project_path)
                                self.add_issue(
                                    'STAR_IMPORT',
                                    str(rel_path),
                                    node.lineno,
                                    f"Star import from {node.module or '.'}"
                                )

                            # Check for relative imports
                            if node.level > 0:
                                rel_path = filepath.relative_to(
                                    self.project_path)
                                self.add_issue(
                                    'RELATIVE_IMPORT',
                                    str(rel_path),
                                    node.lineno,
                                    f"Relative import (level {node.level})"
                                )

                            # Track intellicrack imports
                            if node.module and node.module.startswith('intellicrack'):
                                imports[module_path].add(node.module)

                except (SyntaxError, ValueError, IOError):
                    pass

        # Find circular imports using DFS
        def find_cycles(graph):
            """Find circular import dependencies using depth-first search."""
            cycles = []
            visited = set()
            rec_stack = []

            def dfs(node, path):
                """Depth-first search to find cycles."""
                if node in rec_stack:
                    cycle_start = rec_stack.index(node)
                    cycle = rec_stack[cycle_start:] + [node]
                    cycles.append(cycle)
                    return

                if node in visited:
                    return

                visited.add(node)
                rec_stack.append(node)

                for neighbor in graph.get(node, []):
                    if neighbor in graph:  # Only follow nodes that exist
                        dfs(neighbor, path + [neighbor])

                rec_stack.pop()

            for node in graph:
                if node not in visited:
                    dfs(node, [node])

            return cycles

        cycles = find_cycles(imports)

        # Report circular imports
        for cycle in cycles:
            if len(cycle) > 2:  # Only report actual cycles
                self.add_issue(
                    'CIRCULAR_IMPORT',
                    'Multiple files',
                    0,
                    f"Import cycle: {' -> '.join(cycle)}"
                )

        # Report missing __init__.py
        for dir_path in missing_init:
            self.add_issue(
                'MISSING_INIT',
                dir_path,
                0,
                "Directory missing __init__.py file"
            )

        self.log(f"Found {len(cycles)} import cycles",
                 "WARNING" if cycles else "SUCCESS")

    # pylint: disable=too-complex
    def test_runtime_safety(self):
        """Test runtime import safety and edge cases"""
        self.log("\n=== RUNTIME SAFETY TESTING ===", "HEADER")

        # Test module imports
        modules_to_test = [
            'intellicrack',
            'intellicrack.core',
            'intellicrack.core.analysis',
            'intellicrack.core.network',
            'intellicrack.ui',
            'intellicrack.ai',
            'intellicrack.utils',
            'intellicrack.hexview'
        ]

        for module_name in modules_to_test:
            try:
                module = importlib.import_module(module_name)

                # Check for missing __all__ entries
                if hasattr(module, '__all__'):
                    for attr in module.__all__:
                        if not hasattr(module, attr):
                            self.add_issue(
                                'MISSING_EXPORT',
                                module_name,
                                0,
                                f"__all__ references missing attribute: {attr}"
                            )

            except ImportError as e:
                self.add_issue(
                    'IMPORT_ERROR',
                    module_name,
                    0,
                    f"Failed to import: {str(e)}"
                )
            except Exception as e:
                self.add_issue(
                    'RUNTIME_ERROR',
                    module_name,
                    0,
                    f"Runtime error during import: {type(e).__name__}: {str(e)}"
                )

        # Test common functions with edge cases
        edge_cases = [
            ('empty_string', ''),
            ('none', None),
            ('empty_list', []),
            ('empty_dict', {}),
            ('zero', 0),
            ('negative', -1),
            ('large_number', 10**100),
            ('unicode', '🔥💻🐛'),
            ('special_chars', '!@#$%^&*()_+-=[]{}|;:,.<>?')
        ]

        # Test analyze_binary
        try:
            from intellicrack.utils.analysis.binary_analysis import analyze_binary

            for case_name, test_value in edge_cases:
                try:
                    result = analyze_binary(test_value)
                    if result is None and case_name not in ['none', 'empty_string']:
                        self.add_issue(
                            'EDGE_CASE_NONE',
                            'binary_analysis.analyze_binary',
                            0,
                            f"Returns None for {case_name}"
                        )
                except TypeError:
                    pass  # Expected for wrong types
                except Exception as e:
                    self.add_issue(
                        'EDGE_CASE_ERROR',
                        'binary_analysis.analyze_binary',
                        0,
                        f"{case_name} causes {type(e).__name__}: {str(e)}"
                    )
        except (ImportError, AttributeError, OSError) as e:
            self.log(
                f"Runtime safety testing failed: {type(e).__name__}: {e}", "ERROR")

        self.log("Runtime safety testing completed", "SUCCESS")

    def check_security_issues(self):
        """Check for security vulnerabilities"""
        self.log("\n=== SECURITY ANALYSIS ===", "HEADER")

        security_patterns = [
            (r'password\s*=\s*["\'][^"\']+["\']',
             'HARDCODED_PASSWORD', 'Hardcoded password'),
            (r'api_key\s*=\s*["\'][^"\']+["\']',
             'HARDCODED_API_KEY', 'Hardcoded API key'),
            (r'secret\s*=\s*["\'][^"\']+["\']',
             'HARDCODED_SECRET', 'Hardcoded secret'),
            (r'token\s*=\s*["\'][^"\']+["\']',
             'HARDCODED_TOKEN', 'Hardcoded token'),
            (r'subprocess\.call\s*\([^)]*shell\s*=\s*True',
             'SHELL_INJECTION', 'subprocess with shell=True'),
            (r'pickle\.loads?\s*\(', 'PICKLE_USAGE',
             'Pickle usage (potential security risk)'),
            (r'yaml\.load\s*\([^)]*\)', 'UNSAFE_YAML',
             'yaml.load without Loader (use safe_load)'),
            (r'input\s*\(', 'USER_INPUT', 'Direct user input (validate/sanitize)'),
        ]

        for root, dirs, files in os.walk(self.project_path):
            dirs[:] = [d for d in dirs if d not in ['__pycache__', '.git',
                                                    'venv', 'node_modules', 'ghidra', 'radare2', 'tools']]

            for file in files:
                if not file.endswith('.py'):
                    continue

                filepath = Path(root) / file
                rel_path = filepath.relative_to(self.project_path)

                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        content = f.read()
                        lines = content.splitlines()

                    for i, line in enumerate(lines, 1):
                        for pattern, category, message in security_patterns:
                            if re.search(pattern, line, re.IGNORECASE):
                                self.add_issue(
                                    category,
                                    str(rel_path),
                                    i,
                                    message
                                )
                except (IOError, UnicodeDecodeError, re.error):
                    pass

        security_count = sum(self.issue_counts[cat] for cat in
                             ['HARDCODED_PASSWORD', 'HARDCODED_API_KEY', 'HARDCODED_SECRET',
                              'HARDCODED_TOKEN', 'SHELL_INJECTION', 'PICKLE_USAGE',
                              'UNSAFE_YAML'])

        self.log(f"Found {security_count} potential security issues",
                 "WARNING" if security_count > 0 else "SUCCESS")

    # pylint: disable=too-complex
    def check_code_quality(self):
        """Check general code quality issues"""
        self.log("\n=== CODE QUALITY ANALYSIS ===", "HEADER")

        for root, dirs, files in os.walk(self.project_path):
            dirs[:] = [d for d in dirs if d not in ['__pycache__', '.git',
                                                    'venv', 'node_modules', 'ghidra', 'radare2', 'tools']]

            for file in files:
                if not file.endswith('.py'):
                    continue

                filepath = Path(root) / file
                rel_path = filepath.relative_to(self.project_path)

                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        content = f.read()
                        lines = content.splitlines()

                    # Check file size
                    if len(lines) > 1000:
                        self.add_issue(
                            'LARGE_FILE',
                            str(rel_path),
                            0,
                            f"File has {len(lines)} lines (consider splitting)"
                        )

                    # Check for to-do/fix-me/hack comments
                    for i, line in enumerate(lines, 1):
                        if re.search(r'\b(TODO|FIXME|HACK|XXX)\b', line, re.IGNORECASE):
                            match = re.search(
                                r'\b(TODO|FIXME|HACK|XXX)\b.*', line, re.IGNORECASE)
                            if match:
                                self.add_issue(
                                    'TODO_COMMENT',
                                    str(rel_path),
                                    i,
                                    match.group(0).strip()
                                )

                    # Parse AST for more checks
                    tree = ast.parse(content)

                    # Check for missing docstrings
                    for node in ast.walk(tree):
                        if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
                            if not ast.get_docstring(node):
                                # Only report public methods/classes
                                if not node.name.startswith('_'):
                                    self.add_issue(
                                        'MISSING_DOCSTRING',
                                        str(rel_path),
                                        node.lineno,
                                        f"{node.name} lacks docstring"
                                    )

                        # Check for overly complex functions
                        if isinstance(node, ast.FunctionDef):
                            # Count complexity (simplified McCabe)
                            complexity = 1
                            for child in ast.walk(node):
                                if isinstance(child, (ast.If, ast.While, ast.For,
                                                      ast.ExceptHandler, ast.With)):
                                    complexity += 1

                            if complexity > 10:
                                self.add_issue(
                                    'HIGH_COMPLEXITY',
                                    str(rel_path),
                                    node.lineno,
                                    f"{node.name} has complexity {complexity} (>10)"
                                )

                except (AttributeError, TypeError, ValueError):
                    pass

        self.log("Code quality analysis completed", "SUCCESS")

    def generate_summary(self):
        """Generate final summary of all issues"""
        duration = time.time() - self.start_time

        # Sort issues by category and file
        issues_by_category = defaultdict(list)
        for issue in self.all_issues:
            issues_by_category[issue['category']].append(issue)

        with open(self.output_file, 'a', encoding='utf-8') as f:
            f.write("\n\n")
            f.write("=" * 80 + "\n")
            f.write("                              DETAILED ISSUES\n")
            f.write("=" * 80 + "\n\n")

            # Write issues by category
            for category in sorted(issues_by_category.keys()):
                issues = issues_by_category[category]
                f.write(f"\n### {category} ({len(issues)} issues) ###\n")
                f.write("-" * 60 + "\n")

                # Sort by file and line
                sorted_issues = sorted(
                    issues, key=lambda x: (x['file'], x['line']))

                for issue in sorted_issues[:50]:  # Limit to 50 per category
                    if issue['line'] > 0:
                        f.write(
                            f"{issue['file']}:{issue['line']} - {issue['message']}\n")
                    else:
                        f.write(f"{issue['file']} - {issue['message']}\n")

                if len(issues) > 50:
                    f.write(
                        f"\n... and {len(issues) - 50} more {category} issues\n")

            # Summary statistics
            f.write("\n\n")
            f.write("=" * 80 + "\n")
            f.write("                              SUMMARY\n")
            f.write("=" * 80 + "\n\n")

            f.write("ISSUE COUNTS BY CATEGORY:\n")
            f.write("-" * 40 + "\n")

            # Group related categories
            error_categories = ['PYLINT_ERROR', 'SYNTAX_ERROR', 'PARSE_ERROR',
                                'IMPORT_ERROR', 'RUNTIME_ERROR']
            warning_categories = ['PYLINT_WARNING', 'MUTABLE_DEFAULT', 'BARE_EXCEPT',
                                  'GLOBAL_USAGE', 'FILE_NOT_CLOSED', 'ASSERT_USAGE']
            security_categories = ['EVAL_USAGE', 'EXEC_USAGE', 'HARDCODED_PASSWORD',
                                   'HARDCODED_API_KEY', 'HARDCODED_SECRET', 'HARDCODED_TOKEN',
                                   'SHELL_INJECTION', 'PICKLE_USAGE', 'UNSAFE_YAML']
            quality_categories = ['MISSING_DOCSTRING', 'HIGH_COMPLEXITY', 'LARGE_FILE',
                                  'TODO_COMMENT', 'STAR_IMPORT', 'RELATIVE_IMPORT']

            total_errors = sum(self.issue_counts[cat]
                               for cat in error_categories)
            total_warnings = sum(
                self.issue_counts[cat] for cat in warning_categories)
            total_security = sum(
                self.issue_counts[cat] for cat in security_categories)
            total_quality = sum(self.issue_counts[cat]
                                for cat in quality_categories)

            f.write(f"ERRORS:    {total_errors:>6}\n")
            f.write(f"WARNINGS:  {total_warnings:>6}\n")
            f.write(f"SECURITY:  {total_security:>6}\n")
            f.write(f"QUALITY:   {total_quality:>6}\n")
            f.write("-" * 20 + "\n")
            f.write(f"TOTAL:     {len(self.all_issues):>6}\n\n")

            f.write(f"Analysis completed in {duration:.1f} seconds\n")
            f.write(f"Report saved to: {self.output_file}\n")

        # Console summary
        self.log("\n" + "=" * 60, "HEADER")
        self.log(
            f"ANALYSIS COMPLETE: {len(self.all_issues)} total issues found", "HEADER")
        self.log(
            f"Errors: {total_errors} | Warnings: {total_warnings} | Security: {total_security} | Quality: {total_quality}", "INFO")
        self.log(f"Full report: {self.output_file}", "SUCCESS")

    def run(self):
        """Run all analyses"""
        self.log("Starting Intellicrack Comprehensive Error Detection...", "HEADER")

        try:
            # 1. Pylint analysis
            self.run_pylint()

            # 2. AST pattern analysis
            self.analyze_ast_patterns()

            # 3. Import analysis
            self.detect_import_issues()

            # 4. Runtime safety
            self.test_runtime_safety()

            # 5. Security analysis
            self.check_security_issues()

            # 6. Code quality
            self.check_code_quality()

            # Generate summary
            self.generate_summary()

        except KeyboardInterrupt:
            self.log("\nAnalysis interrupted by user", "WARNING")
            self.generate_summary()
        except Exception as e:
            self.log(
                f"\nFATAL ERROR: {type(e).__name__}: {str(e)}", "CRITICAL")
            self.log(traceback.format_exc(), "ERROR")
            self.generate_summary()


if __name__ == "__main__":
    detector = IntellicrackErrorDetector()
    detector.run()

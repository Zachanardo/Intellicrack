"""Configuration cleanup utilities.

This module provides utilities for removing unused configuration code
after migration to the central IntellicrackConfig system.

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
along with Intellicrack. If not, see <https://www.gnu.org/licenses/>.
"""

import ast
from pathlib import Path


class UnusedConfigCodeDetector(ast.NodeVisitor):
    """AST visitor to detect unused configuration-related code."""

    def __init__(self) -> None:
        """Initialize the detector."""
        self.unused_imports = set()
        self.unused_methods: set[tuple[str, int]] = set()
        self.qsettings_usage: list[int] = []
        self.legacy_config_patterns: list[tuple[str, int]] = []

    def visit_Import(self, node: ast.Import) -> None:
        """Check for unused configuration imports."""
        for alias in node.names:
            if "QSettings" in alias.name:
                self.unused_imports.add(("QSettings", node.lineno))
            elif "configparser" in alias.name.lower():
                self.unused_imports.add(("configparser", node.lineno))

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Check for unused configuration imports from modules."""
        if node.module and "QtCore" in node.module:
            for alias in node.names:
                if alias.name == "QSettings":
                    self.unused_imports.add(("QSettings", node.lineno))

    def visit_Call(self, node: ast.Call) -> None:
        """Check for legacy configuration method calls."""
        if isinstance(node.func, ast.Name):
            if node.func.id == "QSettings":
                self.qsettings_usage.append(node.lineno)
        elif isinstance(node.func, ast.Attribute):
            # Check for .setValue, .value, .sync calls
            if node.func.attr in ["setValue", "value", "sync"] and (
                hasattr(node.func.value, "id") and "settings" in str(node.func.value.id).lower()
            ):
                self.legacy_config_patterns.append((node.func.attr, node.lineno))

        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Check for unused configuration-related methods."""
        # Check for deprecated file operation methods
        deprecated_patterns = [
            "_save_json_file",
            "_load_json_file",
            "save_to_registry",
            "load_from_registry",
            "write_config_file",
            "read_config_file",
        ]

        for pattern in deprecated_patterns:
            if pattern in node.name and self._is_likely_unused(node):
                self.unused_methods.add((node.name, node.lineno))

        self.generic_visit(node)

    def _is_likely_unused(self, node: ast.FunctionDef) -> bool:
        """Check if a method is likely unused based on docstring or comments."""
        if node.body and isinstance(node.body[0], ast.Expr) and isinstance(node.body[0].value, ast.Constant):
            docstring = node.body[0].value.value
            if isinstance(docstring, str):
                return any(word in docstring.lower() for word in ["deprecated", "unused", "legacy", "old", "migration only"])
        return False


def analyze_file(file_path: Path) -> tuple[set[tuple[str, int]], set[tuple[str, int]], list[int], list[tuple[str, int]]]:
    """Analyze a Python file for unused configuration code.

    Args:
        file_path: Path to the Python file

    Returns:
        Tuple of (unused_imports, unused_methods, qsettings_usage, legacy_patterns)

    """
    try:
        with open(file_path, encoding="utf-8") as f:
            tree = ast.parse(f.read())

        detector = UnusedConfigCodeDetector()
        detector.visit(tree)

        return (
            detector.unused_imports,
            detector.unused_methods,
            detector.qsettings_usage,
            detector.legacy_config_patterns,
        )
    except Exception as e:
        print(f"Error analyzing {file_path}: {e}")
        return set(), set(), [], []


def find_unused_config_code(root_dir: Path) -> dict:
    """Find all unused configuration code in the project.

    Args:
        root_dir: Root directory to search

    Returns:
        Dictionary mapping file paths to unused code information

    """
    results = {}

    for py_file in root_dir.rglob("*.py"):
        # Skip test files and migration scripts
        if "test" in str(py_file).lower() or "migration" in str(py_file).lower():
            continue

        imports, methods, qsettings, legacy = analyze_file(py_file)

        if imports or methods or qsettings or legacy:
            results[str(py_file)] = {
                "unused_imports": list(imports),
                "unused_methods": list(methods),
                "qsettings_usage": qsettings,
                "legacy_patterns": legacy,
            }

    return results


def generate_cleanup_report(results: dict) -> str:
    """Generate a cleanup report from analysis results.

    Args:
        results: Analysis results from find_unused_config_code

    Returns:
        Formatted report string

    """
    report = ["=" * 60, "CONFIGURATION CODE CLEANUP REPORT", "=" * 60, ""]
    total_files = len(results)
    total_issues = sum(
        len(info["unused_imports"]) + len(info["unused_methods"]) + len(info["qsettings_usage"]) + len(info["legacy_patterns"])
        for info in results.values()
    )

    report.extend(
        (
            f"Files with unused config code: {total_files}",
            f"Total issues found: {total_issues}",
        )
    )
    report.append("")

    for file_path, info in sorted(results.items()):
        report.append(f"\n{file_path}:")
        report.append("-" * 40)

        if info["unused_imports"]:
            report.append("  Unused imports:")
            for import_name, line in info["unused_imports"]:
                report.append(f"    Line {line}: {import_name}")

        if info["unused_methods"]:
            report.append("  Unused methods:")
            for method_name, line in info["unused_methods"]:
                report.append(f"    Line {line}: {method_name}")

        if info["qsettings_usage"]:
            report.append("  QSettings usage:")
            for line in info["qsettings_usage"]:
                report.append(f"    Line {line}")

        if info["legacy_patterns"]:
            report.append("  Legacy config patterns:")
            for pattern, line in info["legacy_patterns"]:
                report.append(f"    Line {line}: {pattern}")

    return "\n".join(report)


def remove_unused_imports(file_path: Path, unused_imports: set[tuple[str, int]]) -> bool:
    """Remove unused imports from a file.

    Args:
        file_path: Path to the file
        unused_imports: Set of (import_name, line_number) tuples

    Returns:
        True if successful, False otherwise

    """
    try:
        with open(file_path, encoding="utf-8") as f:
            lines = f.readlines()

        # Create set of line numbers to remove
        lines_to_remove = {line_no - 1 for _, line_no in unused_imports}

        # Filter out the lines
        new_lines = [line for i, line in enumerate(lines) if i not in lines_to_remove]

        with open(file_path, "w", encoding="utf-8") as f:
            f.writelines(new_lines)

        return True
    except Exception as e:
        print(f"Error removing imports from {file_path}: {e}")
        return False


def cleanup_file(file_path: Path, auto_fix: bool = False) -> int:
    """Clean up unused configuration code in a file.

    Args:
        file_path: Path to the file to clean
        auto_fix: Whether to automatically fix issues

    Returns:
        Number of issues fixed

    """
    imports, methods, qsettings, legacy = analyze_file(file_path)

    if not (imports or methods or qsettings or legacy):
        return 0

    fixed_count = 0

    if auto_fix and imports and remove_unused_imports(file_path, imports):
        fixed_count += len(imports)
        print(f"Removed {len(imports)} unused imports from {file_path}")

    # For methods and other patterns, we'll just report them
    # Manual intervention is safer for method removal

    return fixed_count


if __name__ == "__main__":
    # Run cleanup analysis on the project
    project_root = Path(__file__).parent.parent.parent

    print("Analyzing project for unused configuration code...")
    if results := find_unused_config_code(project_root / "intellicrack"):
        report = generate_cleanup_report(results)
        print(report)

        # Save report to file
        report_path = project_root / "config_cleanup_report.txt"
        with open(report_path, "w") as f:
            f.write(report)
        print(f"\nReport saved to: {report_path}")
    else:
        print("No unused configuration code found!")

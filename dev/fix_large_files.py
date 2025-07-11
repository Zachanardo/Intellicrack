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

"""Analyze and report on large files that need splitting."""

import os
from pathlib import Path


def analyze_large_files():
    """Find all Python files with more than 1000 lines."""
    large_files = []

    # Walk through all Python files
    for root, dirs, files in os.walk('/mnt/c/Intellicrack'):
        # Skip directories
        dirs[:] = [d for d in dirs if d not in ['__pycache__', '.git',
                                                'venv', 'node_modules', 'ghidra', 'radare2', 'tools']]

        for file in files:
            if not file.endswith('.py'):
                continue

            filepath = Path(root) / file
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                    line_count = len(lines)

                if line_count > 1000:
                    rel_path = filepath.relative_to('/mnt/c/Intellicrack')
                    large_files.append((str(rel_path), line_count))

            except Exception:
                pass

    return sorted(large_files, key=lambda x: x[1], reverse=True)


def generate_split_recommendations(large_files):
    """Generate recommendations for splitting large files."""
    recommendations = []

    for file_path, line_count in large_files:
        print(f"\nAnalyzing {file_path} ({line_count} lines)...")

        # Read file to analyze structure
        full_path = Path('/mnt/c/Intellicrack') / file_path
        try:
            with open(full_path, 'r', encoding='utf-8') as f:
                content = f.read()

            # Count classes and functions
            import ast
            tree = ast.parse(content)

            classes = []
            functions = []
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef):
                    classes.append(node.name)
                elif isinstance(node, ast.FunctionDef) and not any(isinstance(parent, ast.ClassDef) for parent in ast.walk(tree) if hasattr(parent, 'body') and node in parent.body):
                    functions.append(node.name)

            rec = {
                'file': file_path,
                'lines': line_count,
                'classes': len(classes),
                'functions': len(functions),
                'recommendation': get_recommendation(file_path, line_count, len(classes), len(functions))
            }
            recommendations.append(rec)

            print(f"  - Classes: {len(classes)}")
            print(f"  - Top-level functions: {len(functions)}")
            print(f"  - Recommendation: {rec['recommendation']}")

        except Exception as e:
            print(f"  - Error analyzing: {e}")
            recommendations.append({
                'file': file_path,
                'lines': line_count,
                'classes': 0,
                'functions': 0,
                'recommendation': 'Manual review required'
            })

    return recommendations


def get_recommendation(file_path, line_count, class_count, function_count):
    """Get splitting recommendation based on file characteristics."""

    # Check specific files
    if 'main_app.py' in file_path:
        return "Split into separate dialog/widget modules per feature"
    elif 'runner_functions.py' in file_path:
        return "Split by analysis type (ghidra, frida, memory, network)"
    elif 'utils' in file_path and line_count > 1500:
        return "Split into focused utility modules"
    elif class_count > 5:
        return f"Split into {min(class_count, 3)} modules, grouping related classes"
    elif function_count > 30:
        return "Group related functions into separate modules"
    elif line_count > 2000:
        return "Critical: Split into logical components immediately"
    elif line_count > 1500:
        return "High priority: Consider splitting by functionality"
    else:
        return "Monitor size, split if continues growing"


def write_report(large_files, recommendations):
    """Write detailed report about large files."""
    report_path = Path('/mnt/c/Intellicrack/dev/large_files_report.md')

    with open(report_path, 'w', encoding='utf-8') as f:
        f.write("# Large File Analysis Report\n\n")
        f.write(
            f"Found {len(large_files)} files with more than 1000 lines.\n\n")

        # Summary
        total_lines = sum(lc for _, lc in large_files)
        f.write(f"**Total lines in large files:** {total_lines:,}\n")
        f.write(
            f"**Average lines per large file:** {total_lines // len(large_files):,}\n\n")

        # Critical files (>2000 lines)
        critical_files = [f for f in large_files if f[1] > 2000]
        if critical_files:
            f.write("## Critical Files (>2000 lines)\n\n")
            for file_path, line_count in critical_files:
                rec = next(
                    (r for r in recommendations if r['file'] == file_path), None)
                f.write(f"### {file_path} ({line_count:,} lines)\n")
                if rec:
                    f.write(f"- **Classes:** {rec['classes']}\n")
                    f.write(f"- **Functions:** {rec['functions']}\n")
                    f.write(f"- **Action:** {rec['recommendation']}\n\n")

        # High priority files (1500-2000 lines)
        high_priority = [f for f in large_files if 1500 < f[1] <= 2000]
        if high_priority:
            f.write("## High Priority Files (1500-2000 lines)\n\n")
            for file_path, line_count in high_priority:
                rec = next(
                    (r for r in recommendations if r['file'] == file_path), None)
                f.write(f"### {file_path} ({line_count:,} lines)\n")
                if rec:
                    f.write(
                        f"- **Recommendation:** {rec['recommendation']}\n\n")

        # Moderate files (1000-1500 lines)
        moderate = [f for f in large_files if 1000 < f[1] <= 1500]
        if moderate:
            f.write("## Moderate Files (1000-1500 lines)\n\n")
            f.write("| File | Lines | Recommendation |\n")
            f.write("|------|-------|----------------|\n")
            for file_path, line_count in moderate:
                rec = next(
                    (r for r in recommendations if r['file'] == file_path), None)
                rec_text = rec['recommendation'] if rec else 'Review needed'
                f.write(f"| {file_path} | {line_count:,} | {rec_text} |\n")

        # Refactoring suggestions
        f.write("\n## Refactoring Guidelines\n\n")
        f.write(
            "1. **Single Responsibility:** Each module should have one clear purpose\n")
        f.write("2. **Cohesion:** Keep related functionality together\n")
        f.write("3. **Dependencies:** Minimize circular dependencies\n")
        f.write("4. **Testing:** Ensure tests cover functionality before splitting\n")
        f.write(
            "5. **Documentation:** Update imports and documentation after splitting\n\n")

        f.write("## Next Steps\n\n")
        f.write("1. Address critical files first (>2000 lines)\n")
        f.write("2. Create new module structure before moving code\n")
        f.write("3. Update all imports after refactoring\n")
        f.write("4. Run tests to ensure functionality preserved\n")

    print(f"\nReport written to: {report_path}")


def main():
    """Main entry point for large file analysis."""
    print("Analyzing large files in Intellicrack...")

    # Find large files
    large_files = analyze_large_files()
    print(f"\nFound {len(large_files)} files with more than 1000 lines")

    # Generate recommendations
    recommendations = generate_split_recommendations(large_files)

    # Write report
    write_report(large_files, recommendations)

    # Print summary
    print("\n=== SUMMARY ===")
    critical = len([f for f in large_files if f[1] > 2000])
    high_priority = len([f for f in large_files if 1500 < f[1] <= 2000])
    moderate = len([f for f in large_files if 1000 < f[1] <= 1500])

    print(f"Critical (>2000 lines): {critical} files")
    print(f"High Priority (1500-2000): {high_priority} files")
    print(f"Moderate (1000-1500): {moderate} files")


if __name__ == '__main__':
    main()

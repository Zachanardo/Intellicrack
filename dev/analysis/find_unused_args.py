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
Simple script to find potential unused arguments in Python files.
This mimics pylint's W0613 warning detection.
"""

import ast
import os
import sys
from pathlib import Path


def find_unused_arguments(file_path):
    """Find potential unused arguments in a Python file."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        # Parse the AST
        tree = ast.parse(content, filename=file_path)

        unused_args = []

        class UnusedArgumentFinder(ast.NodeVisitor):
            def __init__(self):
                self.function_stack = []

            def visit_FunctionDef(self, node):
                # Get function arguments
                args = []

                # Regular args
                for arg in node.args.args:
                    args.append(arg.arg)

                # *args
                if node.args.vararg:
                    args.append(node.args.vararg.arg)

                # **kwargs
                if node.args.kwarg:
                    args.append(node.args.kwarg.arg)

                # Filter out 'self' and 'cls' as they're often unused
                filtered_args = [
                    arg for arg in args if arg not in ['self', 'cls']]

                # Find variable references in function body
                used_vars = set()

                class VariableCollector(ast.NodeVisitor):
                    def visit_Name(self, node):
                        if isinstance(node.ctx, ast.Load):
                            used_vars.add(node.id)
                        self.generic_visit(node)

                    def visit_Attribute(self, node):
                        # Handle self.variable references
                        if isinstance(node.value, ast.Name):
                            used_vars.add(node.value.id)
                        self.generic_visit(node)

                collector = VariableCollector()
                for stmt in node.body:
                    collector.visit(stmt)

                # Check for unused arguments
                for arg in filtered_args:
                    if arg not in used_vars:
                        # Skip arguments that start with underscore (conventional unused)
                        if not arg.startswith('_'):
                            unused_args.append({
                                'function': node.name,
                                'argument': arg,
                                'line': node.lineno,
                                'file': file_path
                            })

                self.generic_visit(node)

            def visit_AsyncFunctionDef(self, node):
                # Handle async functions same as regular functions
                self.visit_FunctionDef(node)

        finder = UnusedArgumentFinder()
        finder.visit(tree)

        return unused_args

    except (SyntaxError, UnicodeDecodeError, Exception) as e:
        print(f"Error parsing {file_path}: {e}")
        return []


def scan_directory(directory):
    """Scan directory for Python files and find unused arguments."""
    directory = Path(directory)
    all_unused = []

    for py_file in directory.rglob('*.py'):
        # Skip __pycache__ and other generated directories
        if '__pycache__' in str(py_file) or '.git' in str(py_file):
            continue

        unused = find_unused_arguments(py_file)
        all_unused.extend(unused)

    return all_unused


def main():
    if len(sys.argv) > 1:
        directory = sys.argv[1]
    else:
        directory = 'intellicrack'

    print(f"Scanning {directory} for unused arguments...")
    unused_args = scan_directory(directory)

    if not unused_args:
        print("No unused arguments found!")
        return

    print(f"\nFound {len(unused_args)} potential unused arguments:")
    print("=" * 80)

    # Group by file
    by_file = {}
    for item in unused_args:
        file_path = item['file']
        if file_path not in by_file:
            by_file[file_path] = []
        by_file[file_path].append(item)

    # Print results
    for file_path, items in sorted(by_file.items()):
        print(f"\n{file_path}:")
        for item in sorted(items, key=lambda x: x['line']):
            print(
                f"  Line {item['line']}: Function '{item['function']}' - unused argument '{item['argument']}'")


if __name__ == "__main__":
    main()

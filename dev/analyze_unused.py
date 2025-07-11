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
Script to analyze unused variables and arguments in frida_manager.py
"""

import ast
import sys
from pathlib import Path


class UnusedVariableAnalyzer(ast.NodeVisitor):
    def __init__(self):
        self.unused_variables = []
        self.unused_arguments = []
        self.current_function = None
        self.scopes = [{}]  # Stack of scopes

    def push_scope(self):
        self.scopes.append({})

    def pop_scope(self):
        if len(self.scopes) > 1:
            return self.scopes.pop()
        return {}

    def add_variable(self, name, lineno, type_info="variable"):
        if self.scopes:
            self.scopes[-1][name] = {
                'defined': lineno,
                'used': False,
                'type': type_info
            }

    def use_variable(self, name):
        # Check all scopes from innermost to outermost
        for scope in reversed(self.scopes):
            if name in scope:
                scope[name]['used'] = True
                return

    def visit_FunctionDef(self, node):
        old_function = self.current_function
        self.current_function = node.name

        # Push new scope for function
        self.push_scope()

        # Add function arguments
        for arg in node.args.args:
            self.add_variable(arg.arg, node.lineno, f"argument in {node.name}")

        # Visit function body
        self.generic_visit(node)

        # Check for unused variables in this scope
        scope = self.pop_scope()
        for var_name, var_info in scope.items():
            if not var_info['used']:
                if var_info['type'].startswith('argument'):
                    self.unused_arguments.append({
                        'name': var_name,
                        'line': var_info['defined'],
                        'function': node.name,
                        'type': 'argument'
                    })
                else:
                    self.unused_variables.append({
                        'name': var_name,
                        'line': var_info['defined'],
                        'function': node.name,
                        'type': 'variable'
                    })

        self.current_function = old_function

    def visit_Assign(self, node):
        # Handle variable assignments
        for target in node.targets:
            if isinstance(target, ast.Name):
                self.add_variable(target.id, node.lineno, "variable")

        # Visit the value being assigned
        self.visit(node.value)

    def visit_Name(self, node):
        if isinstance(node.ctx, ast.Load):
            self.use_variable(node.id)
        elif isinstance(node.ctx, ast.Store):
            # This should be handled in visit_Assign
            pass

    def visit_For(self, node):
        # Handle for loop variables
        if isinstance(node.target, ast.Name):
            self.add_variable(node.target.id, node.lineno, "loop_variable")

        self.generic_visit(node)

    def visit_With(self, node):
        # Handle with statement variables
        for item in node.items:
            if item.optional_vars and isinstance(item.optional_vars, ast.Name):
                self.add_variable(item.optional_vars.id,
                                  node.lineno, "with_variable")

        self.generic_visit(node)


def analyze_file(file_path):
    """Analyze a Python file for unused variables and arguments"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        tree = ast.parse(content)
        analyzer = UnusedVariableAnalyzer()
        analyzer.visit(tree)

        return analyzer.unused_variables, analyzer.unused_arguments

    except Exception as e:
        print(f"Error analyzing {file_path}: {e}")
        return [], []


if __name__ == "__main__":
    file_path = "/mnt/c/Intellicrack/intellicrack/core/frida_manager.py"

    unused_vars, unused_args = analyze_file(file_path)

    print("=== UNUSED VARIABLES ===")
    if unused_vars:
        for var in unused_vars:
            print(
                f"Line {var['line']}: '{var['name']}' in function '{var['function']}' ({var['type']})")
    else:
        print("No unused variables found")

    print("\n=== UNUSED ARGUMENTS ===")
    if unused_args:
        for arg in unused_args:
            print(
                f"Line {arg['line']}: '{arg['name']}' in function '{arg['function']}' ({arg['type']})")
    else:
        print("No unused arguments found")

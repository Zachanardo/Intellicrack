#!/usr/bin/env python3
"""
Script to fix missing docstrings in Intellicrack codebase.
"""

import os
import re
import ast
import subprocess
from pathlib import Path
from typing import List, Tuple, Dict

class DocstringFixer:
    """Tool for automatically fixing missing docstrings in Python files."""

    def __init__(self, base_path: str):
        """Initialize the docstring fixer.

        Args:
            base_path: Base path to scan for docstring issues
        """
        self.base_path = Path(base_path)

    def get_docstring_issues(self) -> List[str]:
        """Get all docstring issues from ruff."""
        try:
            result = subprocess.run(
                ["ruff", "check", "--select", "D107", str(self.base_path)],
                capture_output=True,
                text=True,
                cwd=self.base_path
            )
            return result.stdout.strip().split('\n') if result.stdout.strip() else []
        except Exception as e:
            print(f"Error running ruff: {e}")
            return []

    def parse_ruff_output(self, lines: List[str]) -> List[Dict]:
        """Parse ruff output to extract file paths and line numbers."""
        issues = []
        for line in lines:
            if "D107 Missing docstring in `__init__`" in line:
                # Extract file path and line number
                match = re.match(r'^([^:]+):(\d+):\d+:', line)
                if match:
                    file_path = match.group(1)
                    line_num = int(match.group(2))
                    issues.append({
                        'file': file_path,
                        'line': line_num,
                        'type': 'init'
                    })
        return issues

    def fix_init_docstring(self, file_path: str, line_num: int) -> bool:
        """Fix missing __init__ docstring."""
        try:
            full_path = self.base_path / file_path
            with open(full_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()

            # Find the __init__ method definition
            init_line = lines[line_num - 1]

            # Parse the method signature to get parameters
            method_content = []
            indent = len(init_line) - len(init_line.lstrip())

            # Collect the full method signature (might span multiple lines)
            i = line_num - 1
            method_sig = ""
            paren_count = 0
            while i < len(lines):
                line = lines[i].strip()
                method_sig += line + " "
                paren_count += line.count('(') - line.count(')')
                if paren_count == 0 and line.endswith(':'):
                    break
                i += 1

            # Generate docstring based on signature
            docstring = self.generate_init_docstring(method_sig, indent)

            # Insert docstring after the method definition
            insert_line = i + 1
            lines.insert(insert_line, docstring)

            # Write back to file
            with open(full_path, 'w', encoding='utf-8') as f:
                f.writelines(lines)

            print(f"Fixed docstring in {file_path}:{line_num}")
            return True

        except Exception as e:
            print(f"Error fixing {file_path}:{line_num} - {e}")
            return False

    def generate_init_docstring(self, method_sig: str, indent: int) -> str:
        """Generate appropriate docstring for __init__ method."""
        # Extract parameter names (simple regex approach)
        params = re.findall(r'(\w+)(?:\s*:\s*[^,)]+)?(?:\s*=\s*[^,)]+)?', method_sig)

        # Remove 'self' and common parameters
        filtered_params = [p for p in params if p not in ['self', 'def', '__init__']]

        base_indent = ' ' * indent
        doc_indent = ' ' * (indent + 4)

        docstring_lines = [
            f'{base_indent}"""Initialize the object.\n',
        ]

        if filtered_params:
            docstring_lines.append(f'{doc_indent}\n')
            docstring_lines.append(f'{doc_indent}Args:\n')
            for param in filtered_params:
                if param == 'parent':
                    docstring_lines.append(f'{doc_indent}    {param}: Parent object for proper memory management\n')
                elif param in ['file_path', 'filepath', 'path']:
                    docstring_lines.append(f'{doc_indent}    {param}: Path to file\n')
                elif param in ['config', 'configuration']:
                    docstring_lines.append(f'{doc_indent}    {param}: Configuration object\n')
                elif param in ['data', 'content']:
                    docstring_lines.append(f'{doc_indent}    {param}: Data content\n')
                else:
                    docstring_lines.append(f'{doc_indent}    {param}: {param.replace("_", " ").title()}\n')

        docstring_lines.append(f'{base_indent}"""\n')

        return ''.join(docstring_lines)

    def fix_all_docstrings(self):
        """Fix all missing docstring issues."""
        print("Getting docstring issues...")
        ruff_output = self.get_docstring_issues()

        if not ruff_output:
            print("No docstring issues found!")
            return

        print(f"Found {len(ruff_output)} docstring issues")

        issues = self.parse_ruff_output(ruff_output)
        print(f"Parsed {len(issues)} __init__ docstring issues")

        fixed_count = 0
        for issue in issues:
            if self.fix_init_docstring(issue['file'], issue['line']):
                fixed_count += 1

        print(f"Fixed {fixed_count} out of {len(issues)} docstring issues")

if __name__ == "__main__":
    fixer = DocstringFixer("C:\\Intellicrack")
    fixer.fix_all_docstrings()

#!/usr/bin/env python3
"""
Fix all indentation errors in the Intellicrack codebase.
This script finds and fixes syntax errors caused by incorrect indentation,
particularly after docstring additions.
"""

import os
import re
import sys
import ast
import subprocess
from pathlib import Path
from typing import List, Tuple, Optional

class IndentationFixer:
    def __init__(self, root_dir: str):
        self.root_dir = Path(root_dir)
        self.fixed_files = []
        self.failed_files = []
        self.errors_found = []
    
    def find_python_files(self) -> List[Path]:
        """Find all Python files in the project."""
        python_files = []
        for root, dirs, files in os.walk(self.root_dir):
            # Skip virtual environments and cache directories
            dirs[:] = [d for d in dirs if d not in {'.venv', '__pycache__', '.git', 'venv', '.venv_wsl', '.venv_windows'}]
            
            for file in files:
                if file.endswith('.py'):
                    python_files.append(Path(root) / file)
        
        return python_files
    
    def check_syntax(self, filepath: Path) -> Optional[str]:
        """Check if a file has syntax errors."""
        try:
            result = subprocess.run(
                [sys.executable, '-m', 'py_compile', str(filepath)],
                capture_output=True,
                text=True
            )
            if result.returncode != 0:
                return result.stderr
            return None
        except Exception as e:
            return str(e)
    
    def fix_file_indentation(self, filepath: Path) -> bool:
        """Fix indentation issues in a single file."""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
            
            original_content = content
            lines = content.splitlines(keepends=True)
            fixed_lines = []
            in_class = False
            in_method = False
            class_indent = 0
            method_indent = 0
            in_docstring = False
            docstring_quote = None
            
            i = 0
            while i < len(lines):
                line = lines[i]
                stripped = line.lstrip()
                current_indent = len(line) - len(stripped)
                
                # Track class and method context
                if stripped.startswith('class '):
                    in_class = True
                    class_indent = current_indent
                    in_method = False
                    fixed_lines.append(line)
                    i += 1
                    continue
                
                if in_class and (stripped.startswith('def ') or stripped.startswith('async def ')):
                    in_method = True
                    method_indent = current_indent
                    fixed_lines.append(line)
                    i += 1
                    continue
                
                # Handle docstrings
                if not in_docstring:
                    # Check for docstring start
                    if '"""' in stripped or "'''" in stripped:
                        quote_match = re.match(r'^(\s*)("""|\'\'\')(.*)', line)
                        if quote_match:
                            indent_str = quote_match.group(1)
                            quote = quote_match.group(2)
                            rest = quote_match.group(3)
                            
                            # Check if it's a single-line docstring
                            if rest.count(quote) > 0:
                                # Single line docstring
                                if in_method:
                                    # Method docstring should be indented 8 spaces
                                    fixed_line = ' ' * 8 + quote + rest
                                    fixed_lines.append(fixed_line)
                                else:
                                    fixed_lines.append(line)
                            else:
                                # Multi-line docstring start
                                in_docstring = True
                                docstring_quote = quote
                                if in_method:
                                    # Method docstring should be indented 8 spaces
                                    fixed_line = ' ' * 8 + quote + rest + '\n'
                                    fixed_lines.append(fixed_line)
                                else:
                                    fixed_lines.append(line)
                        else:
                            fixed_lines.append(line)
                    else:
                        # Regular code line
                        if in_method and current_indent < 8 and stripped and not stripped.startswith('#'):
                            # Fix method body indentation
                            fixed_line = ' ' * 8 + stripped
                            fixed_lines.append(fixed_line)
                        else:
                            fixed_lines.append(line)
                else:
                    # Inside docstring
                    if docstring_quote in stripped:
                        # End of docstring
                        in_docstring = False
                        if in_method:
                            # Ensure closing quotes are properly indented
                            fixed_line = ' ' * 8 + stripped
                            fixed_lines.append(fixed_line)
                        else:
                            fixed_lines.append(line)
                    else:
                        # Docstring content
                        if in_method:
                            # Ensure docstring content is properly indented
                            fixed_line = ' ' * 8 + stripped
                            fixed_lines.append(fixed_line)
                        else:
                            fixed_lines.append(line)
                
                # Reset method context when dedenting
                if in_method and current_indent <= class_indent and stripped:
                    in_method = False
                
                # Reset class context when at module level
                if in_class and current_indent == 0 and stripped and not line.startswith(' '):
                    in_class = False
                    in_method = False
                
                i += 1
            
            # Join the fixed lines
            fixed_content = ''.join(fixed_lines)
            
            # Additional fixes for common patterns
            fixed_content = self.apply_pattern_fixes(fixed_content)
            
            # Only write if content changed
            if fixed_content != original_content:
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(fixed_content)
                return True
            
            return False
            
        except Exception as e:
            self.failed_files.append((filepath, str(e)))
            return False
    
    def apply_pattern_fixes(self, content: str) -> str:
        """Apply pattern-based fixes for common indentation issues."""
        lines = content.splitlines(keepends=True)
        fixed_lines = []
        
        for i, line in enumerate(lines):
            stripped = line.lstrip()
            
            # Fix imports that got indented
            if stripped.startswith(('import ', 'from ')) and line.startswith(' '):
                fixed_lines.append(stripped)
                continue
            
            # Fix try/except blocks
            if i > 0 and stripped.startswith('except') and lines[i-1].strip().endswith(':'):
                prev_indent = len(lines[i-1]) - len(lines[i-1].lstrip())
                if len(line) - len(stripped) != prev_indent:
                    fixed_lines.append(' ' * prev_indent + stripped)
                    continue
            
            fixed_lines.append(line)
        
        return ''.join(fixed_lines)
    
    def run(self) -> None:
        """Run the indentation fixer on all Python files."""
        print("Finding Python files...")
        python_files = self.find_python_files()
        print(f"Found {len(python_files)} Python files")
        
        # First pass: identify files with syntax errors
        print("\nChecking for syntax errors...")
        files_to_fix = []
        
        for filepath in python_files:
            error = self.check_syntax(filepath)
            if error:
                if 'IndentationError' in error or 'unexpected indent' in error:
                    files_to_fix.append(filepath)
                    self.errors_found.append((filepath, error))
        
        print(f"Found {len(files_to_fix)} files with indentation errors")
        
        # Second pass: fix the files
        print("\nFixing indentation errors...")
        for filepath in files_to_fix:
            print(f"Fixing {filepath.relative_to(self.root_dir)}...")
            if self.fix_file_indentation(filepath):
                # Verify the fix
                error = self.check_syntax(filepath)
                if error:
                    print(f"  Still has errors after fix: {error}")
                    self.failed_files.append((filepath, error))
                else:
                    print(f"  Fixed successfully!")
                    self.fixed_files.append(filepath)
        
        # Summary
        print("\n" + "="*60)
        print("SUMMARY")
        print("="*60)
        print(f"Total files checked: {len(python_files)}")
        print(f"Files with errors: {len(files_to_fix)}")
        print(f"Files fixed: {len(self.fixed_files)}")
        print(f"Files still failing: {len(self.failed_files)}")
        
        if self.failed_files:
            print("\nFiles that still have errors:")
            for filepath, error in self.failed_files:
                print(f"  {filepath.relative_to(self.root_dir)}")
        
        # Test import
        print("\nTesting import intellicrack...")
        try:
            subprocess.run([sys.executable, '-c', 'import intellicrack'], check=True)
            print("SUCCESS: intellicrack imports without errors!")
        except subprocess.CalledProcessError as e:
            print("FAILED: intellicrack still has import errors")
            print("Running targeted fix on remaining files...")
            self.targeted_fix()
    
    def targeted_fix(self) -> None:
        """Apply more aggressive fixes to remaining problem files."""
        print("\nApplying targeted fixes...")
        
        # Get the specific error from importing intellicrack
        result = subprocess.run(
            [sys.executable, '-c', 'import intellicrack'],
            capture_output=True,
            text=True
        )
        
        if result.returncode != 0:
            error_output = result.stderr
            print(f"Import error: {error_output}")
            
            # Extract the problematic file from the error
            import_error_match = re.search(r'File "([^"]+)"', error_output)
            if import_error_match:
                problem_file = Path(import_error_match.group(1))
                print(f"Targeting fix on: {problem_file}")
                
                # Apply more aggressive fix
                self.aggressive_fix(problem_file)
    
    def aggressive_fix(self, filepath: Path) -> None:
        """Apply aggressive indentation fix to a file."""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Use AST to parse and reformat if possible
            try:
                tree = ast.parse(content)
                # If AST parsing succeeds, the file is syntactically correct
                print(f"  {filepath} parses correctly with AST")
                return
            except SyntaxError as e:
                print(f"  Syntax error at line {e.lineno}: {e.msg}")
                
                # Apply line-by-line fixes around the error
                lines = content.splitlines(keepends=True)
                if e.lineno and e.lineno <= len(lines):
                    # Fix the specific line and surrounding context
                    self.fix_error_context(filepath, lines, e.lineno - 1)
        
        except Exception as e:
            print(f"  Failed to apply aggressive fix: {e}")
    
    def fix_error_context(self, filepath: Path, lines: List[str], error_line: int) -> None:
        """Fix the context around a syntax error."""
        # Look at the error line and surrounding lines
        start = max(0, error_line - 10)
        end = min(len(lines), error_line + 10)
        
        print(f"  Examining lines {start+1} to {end}")
        
        # Apply specific fixes based on patterns
        for i in range(start, end):
            line = lines[i]
            stripped = line.lstrip()
            
            # Fix common patterns
            if i == error_line:
                print(f"  Error line {i+1}: {line.rstrip()}")
                
                # If it's an improperly indented line after a colon
                if i > 0 and lines[i-1].rstrip().endswith(':'):
                    prev_indent = len(lines[i-1]) - len(lines[i-1].lstrip())
                    expected_indent = prev_indent + 4
                    if len(line) - len(stripped) != expected_indent:
                        lines[i] = ' ' * expected_indent + stripped
                        print(f"  Fixed indentation to {expected_indent} spaces")
        
        # Write the fixed content
        with open(filepath, 'w', encoding='utf-8') as f:
            f.writelines(lines)


if __name__ == '__main__':
    # Get the Intellicrack root directory
    script_dir = Path(__file__).parent
    root_dir = script_dir.parent.parent  # Go up from dev/scripts to root
    
    print(f"Intellicrack root directory: {root_dir}")
    
    fixer = IndentationFixer(root_dir)
    fixer.run()
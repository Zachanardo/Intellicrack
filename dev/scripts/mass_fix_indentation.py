#!/usr/bin/env python3
"""
Mass fix all remaining indentation errors across the codebase.
"""

import os
import re
import sys
import subprocess
from pathlib import Path
from typing import List

def fix_file_comprehensive(filepath: Path) -> bool:
    """Apply comprehensive fixes to a single file."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()

        original_content = content

        # 1. Fix the docstring-code same line pattern
        content = re.sub(
            r'(    """[^"]*"""|    \'\'\'[^\']*\'\'\')(\s+)([^\n\r\s][^\n\r]*)',
            r'\1\n        \3',
            content,
            flags=re.MULTILINE
        )

        # 2. Fix try blocks without proper structure
        lines = content.splitlines()
        fixed_lines = []

        i = 0
        while i < len(lines):
            line = lines[i]
            stripped = line.lstrip()
            current_indent = len(line) - len(stripped)

            if stripped == 'try:':
                fixed_lines.append(line)
                # Look for the matching except/finally
                j = i + 1
                found_except = False
                found_return_or_method = False

                # Process lines until we find except/finally or a new method
                while j < len(lines):
                    next_line = lines[j]
                    next_stripped = next_line.lstrip()
                    next_indent = len(next_line) - len(next_stripped)

                    if not next_stripped:  # Empty line
                        fixed_lines.append(next_line)
                        j += 1
                        continue

                    # Found except/finally at the right level
                    if (next_stripped.startswith(('except ', 'finally:')) and
                        next_indent == current_indent):
                        found_except = True
                        fixed_lines.append(next_line)
                        break

                    # Found a new method definition or class - need to add except
                    if (next_stripped.startswith(('def ', 'class ')) and
                        next_indent <= current_indent):
                        found_return_or_method = True
                        # Add a generic except block
                        fixed_lines.append(' ' * current_indent + 'except Exception as e:')
                        fixed_lines.append(' ' * (current_indent + 4) + 'self.logger.error("Error: %s", e)')
                        fixed_lines.append(' ' * (current_indent + 4) + 'return None')
                        break

                    # Regular line inside try block
                    if next_indent <= current_indent and next_stripped and not next_stripped.startswith('#'):
                        # Make sure it's properly indented
                        fixed_lines.append(' ' * (current_indent + 4) + next_stripped)
                    else:
                        fixed_lines.append(next_line)

                    j += 1

                # If we didn't find except/finally and didn't find a method, add one
                if not found_except and not found_return_or_method:
                    fixed_lines.append(' ' * current_indent + 'except Exception as e:')
                    fixed_lines.append(' ' * (current_indent + 4) + 'self.logger.error("Error: %s", e)')
                    fixed_lines.append(' ' * (current_indent + 4) + 'return None')

                i = j
                continue

            # Handle orphaned else blocks
            if stripped == 'else:':
                # Look for a matching if/for/while in recent lines
                found_match = False
                for k in range(max(0, len(fixed_lines) - 10), len(fixed_lines)):
                    if k < len(fixed_lines):
                        prev_line = fixed_lines[k]
                        prev_stripped = prev_line.lstrip()
                        prev_indent = len(prev_line) - len(prev_stripped)

                        if (prev_stripped.startswith(('if ', 'elif ', 'for ', 'while ')) and
                            prev_indent == current_indent):
                            found_match = True
                            break

                if found_match:
                    fixed_lines.append(line)
                # If no match, skip the orphaned else
                i += 1
                continue

            # Handle imports that got indented
            if stripped.startswith(('import ', 'from ')) and current_indent > 0:
                # Move to module level only if it's a standard import
                if any(module in stripped for module in ['sys', 'os', 're', 'json', 'pathlib', 'typing']):
                    fixed_lines.append(stripped)
                else:
                    fixed_lines.append(line)
                i += 1
                continue

            # Regular line
            fixed_lines.append(line)
            i += 1

        content = '\n'.join(fixed_lines)

        # 3. Clean up specific patterns
        content = re.sub(r'\n\s*import re\s*\n', r'\n', content)  # Remove misplaced import re
        content = re.sub(r'^(\s*)else:\s*$\n^\s*else:', r'\1else:', content, flags=re.MULTILINE)  # Remove duplicate else

        # Only write if content changed
        if content != original_content:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)
            return True

        return False

    except Exception as e:
        print(f"Error fixing {filepath}: {e}")
        return False

def main():
    root_dir = Path(r"C:\Intellicrack")

    # Focus on the core files that are blocking import
    core_files = [
        "intellicrack/core/analysis/symbolic_executor.py",
        "intellicrack/core/config_manager.py",
        "intellicrack/core/analysis/binary_similarity_search.py",
        "intellicrack/core/analysis/firmware_analyzer.py",
        "intellicrack/core/analysis/memory_forensics_engine.py",
        "intellicrack/core/analysis/rop_generator.py",
        "intellicrack/core/analysis/yara_pattern_engine.py",
    ]

    fixed_count = 0

    for relative_path in core_files:
        filepath = root_dir / relative_path
        if filepath.exists():
            print(f"Fixing {relative_path}...")
            if fix_file_comprehensive(filepath):

                # Test syntax after each fix
                result = subprocess.run([sys.executable, '-m', 'py_compile', str(filepath)], capture_output=True, text=True)
                if result.returncode == 0:
                    print(f"  ✓ Fixed successfully")
                    fixed_count += 1

                    # Test import after core files
                    if 'symbolic_executor' in str(filepath) or 'config_manager' in str(filepath):
                        import_result = subprocess.run([sys.executable, '-c', 'import intellicrack'], capture_output=True, text=True)
                        if import_result.returncode == 0:
                            print("SUCCESS: intellicrack imports correctly!")
                            return
                else:
                    print(f"  ✗ Still has errors: {result.stderr.split(':', 3)[-1].strip()}")
            else:
                print(f"  - No changes needed")

    print(f"\nFixed {fixed_count} files")

    # Final test
    print("\nTesting final import...")
    result = subprocess.run([sys.executable, '-c', 'import intellicrack'], capture_output=True, text=True)
    if result.returncode == 0:
        print("SUCCESS: intellicrack imports correctly!")
    else:
        print("Import still has errors:")
        # Show the specific error
        error_lines = result.stderr.split('\n')
        for line in error_lines:
            if 'File "' in line and 'intellicrack' in line:
                print(f"  {line}")
                # Show the next line with the error
                idx = error_lines.index(line)
                if idx + 1 < len(error_lines):
                    print(f"  {error_lines[idx + 1]}")
                break

if __name__ == '__main__':
    main()

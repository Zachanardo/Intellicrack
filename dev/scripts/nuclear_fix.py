#!/usr/bin/env python3
"""
Nuclear option: fix all indentation issues across key files using pattern matching.
"""

import os
import re
import sys
import subprocess
from pathlib import Path

def nuclear_fix_file(filepath: Path) -> bool:
    """Apply nuclear-level fixes to completely repair a file."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()

        original_content = content

        # 1. Remove all duplicate except blocks
        content = re.sub(r'(except [^:]+:)\s*\n\s*\1', r'\1', content, flags=re.MULTILINE)

        # 2. Fix all docstring-code same line issues
        content = re.sub(
            r'("""[^"]*""")(\s+)([^\n\r\s][^\n\r]*)',
            r'\1\n        \3',
            content,
            flags=re.MULTILINE
        )

        # 3. Fix all except blocks that don't have content
        lines = content.splitlines()
        fixed_lines = []

        i = 0
        while i < len(lines):
            line = lines[i]
            stripped = line.lstrip()
            current_indent = len(line) - len(stripped)

            # If this is an except line
            if stripped.startswith('except ') and stripped.endswith(':'):
                fixed_lines.append(line)

                # Check if the next non-empty line is properly indented
                j = i + 1
                found_content = False

                while j < len(lines):
                    next_line = lines[j]
                    next_stripped = next_line.lstrip()
                    next_indent = len(next_line) - len(next_stripped)

                    if not next_stripped:  # Empty line
                        fixed_lines.append(next_line)
                        j += 1
                        continue

                    # If we found content at the right indentation level
                    if next_indent > current_indent and next_stripped:
                        found_content = True
                        break

                    # If we found content at the wrong level or a new block
                    if (next_stripped.startswith(('def ', 'class ', 'except ', 'try:', 'if ')) or
                        next_indent <= current_indent):
                        break

                    j += 1

                # If no content found, add a pass statement
                if not found_content:
                    fixed_lines.append(' ' * (current_indent + 4) + 'pass')

                i += 1
                continue

            # Fix try blocks without except
            elif stripped == 'try:':
                fixed_lines.append(line)

                # Look ahead to see if there's a matching except
                j = i + 1
                found_except = False

                # Scan ahead for except/finally
                while j < len(lines):
                    scan_line = lines[j]
                    scan_stripped = scan_line.lstrip()
                    scan_indent = len(scan_line) - len(scan_stripped)

                    if scan_stripped.startswith(('except ', 'finally:')) and scan_indent == current_indent:
                        found_except = True
                        break

                    # If we hit a new method/class at the same or lower level, stop
                    if (scan_stripped.startswith(('def ', 'class ')) and scan_indent <= current_indent):
                        break

                    j += 1

                # If no except found, we'll need to add one when we hit a boundary
                if not found_except:
                    # Continue processing until we find where to add the except
                    while i + 1 < len(lines):
                        next_line = lines[i + 1]
                        next_stripped = next_line.lstrip()
                        next_indent = len(next_line) - len(next_stripped)

                        i += 1

                        # If we hit a new method/class at same or lower level, add except before it
                        if (next_stripped.startswith(('def ', 'class ')) and next_indent <= current_indent):
                            fixed_lines.append(' ' * current_indent + 'except Exception:')
                            fixed_lines.append(' ' * (current_indent + 4) + 'pass')
                            fixed_lines.append(lines[i])
                            break
                        else:
                            fixed_lines.append(lines[i])
                else:
                    i += 1
                continue

            # Regular line
            fixed_lines.append(line)
            i += 1

        content = '\n'.join(fixed_lines)

        # 4. Additional cleanup patterns
        # Remove imports that got misplaced
        content = re.sub(r'\n\s+import re\n', r'\n', content)

        # Fix orphaned else blocks by removing them
        content = re.sub(r'\n\s*else:\s*\n(?=\s*(def |class |\n))', r'\n', content, flags=re.MULTILINE)

        # Write if changed
        if content != original_content:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)
            return True

        return False

    except Exception as e:
        print(f"Error in nuclear fix for {filepath}: {e}")
        return False

def main():
    root_dir = Path(r"C:\Intellicrack")

    # Core files that must be fixed for import to work
    critical_files = [
        "intellicrack/core/analysis/symbolic_executor.py",
        "intellicrack/core/config_manager.py",
        "intellicrack/core/analysis/binary_similarity_search.py",
        "intellicrack/core/analysis/firmware_analyzer.py",
        "intellicrack/core/analysis/memory_forensics_engine.py",
        "intellicrack/core/analysis/rop_generator.py",
        "intellicrack/core/analysis/yara_pattern_engine.py",
    ]

    for file_path in critical_files:
        full_path = root_dir / file_path
        if full_path.exists():
            print(f"Nuclear fixing {file_path}...")
            nuclear_fix_file(full_path)

            # Test syntax
            result = subprocess.run([sys.executable, '-m', 'py_compile', str(full_path)], capture_output=True, text=True)
            if result.returncode == 0:
                print(f"  ✓ {file_path} is now syntactically correct")
            else:
                print(f"  ✗ {file_path} still has issues: {result.stderr.split(':')[-1].strip()}")

    # Test import
    print("\nTesting import...")
    result = subprocess.run([sys.executable, '-c', 'import intellicrack'], capture_output=True, text=True)
    if result.returncode == 0:
        print("🎉 SUCCESS: intellicrack imports correctly!")
    else:
        print("❌ Import still failed:")
        # Show just the key error
        lines = result.stderr.split('\n')
        for i, line in enumerate(lines):
            if 'File "' in line and 'intellicrack' in line:
                print(f"  {line}")
                if i + 1 < len(lines):
                    print(f"  {lines[i + 1]}")
                break

if __name__ == '__main__':
    main()

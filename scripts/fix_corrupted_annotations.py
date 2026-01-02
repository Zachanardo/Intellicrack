#!/usr/bin/env python3
"""
Fix corrupted type annotations in test files.

The fix_test_types.py script incorrectly produced patterns like:
- `param: dict[str, Any]: Any`
- `param: tuple[X, Y]: Any`

These need to be fixed by removing the trailing `: Any`.
"""
import re
import sys
from pathlib import Path


def fix_corrupted_annotations(file_path: Path) -> int:
    """Fix corrupted type annotations in a file.

    Args:
        file_path: Path to the Python file to process.

    Returns:
        Number of fixes applied.
    """
    content = file_path.read_text(encoding='utf-8')
    original_content = content
    fixes = 0

    # Pattern to match corrupted annotations like:
    # param: SomeType[...]: Any -> param: SomeType[...]
    # This happens when `: Any` was added after an already-typed annotation
    corrupted_pattern = re.compile(
        r'(\w+: (?:dict|tuple|list|set|Dict|Tuple|List|Set|Optional|Union)'
        r'\[[^\]]+\]): Any(?=\s*[,)])'
    )

    def fix_corruption(match: re.Match[str]) -> str:
        nonlocal fixes
        fixes += 1
        return match.group(1)

    content = corrupted_pattern.sub(fix_corruption, content)

    # Also fix malformed dict types like dict[str: Any, Any]
    # Should be dict[str, Any]
    malformed_dict = re.compile(r'dict\[str: Any, Any\]')
    new_content = malformed_dict.sub('dict[str, Any]', content)
    if new_content != content:
        fixes += content.count('dict[str: Any, Any]')
        content = new_content

    # Fix list[tuple[EventType, str: Any, str]] -> list[tuple[EventType, str, str]]
    malformed_list = re.compile(r'list\[tuple\[EventType, str: Any, str\]\]')
    new_content = malformed_list.sub('list[tuple[EventType, str, str]]', content)
    if new_content != content:
        fixes += content.count('list[tuple[EventType, str: Any, str]]')
        content = new_content

    if content != original_content:
        file_path.write_text(content, encoding='utf-8')
        print(f"  Fixed {fixes} corrupted annotations in {file_path.name}")

    return fixes


def process_directory(dir_path: Path) -> int:
    """Process all Python files in directory recursively.

    Args:
        dir_path: Directory to process.

    Returns:
        Total fixes applied.
    """
    total_fixes = 0

    for py_file in dir_path.rglob('*.py'):
        if '__pycache__' in str(py_file):
            continue
        try:
            fixes = fix_corrupted_annotations(py_file)
            total_fixes += fixes
        except Exception as e:
            print(f"  Error processing {py_file}: {e}")

    return total_fixes


def main() -> None:
    """Main entry point."""
    if len(sys.argv) < 2:
        print("Usage: python fix_corrupted_annotations.py <path>")
        sys.exit(1)

    path = Path(sys.argv[1])

    if path.is_file():
        fixes = fix_corrupted_annotations(path)
    elif path.is_dir():
        fixes = process_directory(path)
    else:
        print(f"Path not found: {path}")
        sys.exit(1)

    print(f"\nTotal fixes applied: {fixes}")


if __name__ == '__main__':
    main()

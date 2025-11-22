"""Fix __all__ sorting using AST parsing."""

import ast
from pathlib import Path
from typing import Any


def fix_all_in_file(file_path: Path) -> bool:
    """Fix __all__ sorting in a Python file using AST.

    Args:
        file_path: Path to Python file

    Returns:
        True if file was modified

    """
    content = file_path.read_text(encoding="utf-8")
    original_content = content
    lines = content.splitlines(keepends=True)

    try:
        tree = ast.parse(content)
    except SyntaxError:
        print(f"Syntax error in {file_path}, skipping")
        return False

    modifications = []

    for node in ast.walk(tree):
        #  Find __all__ assignments
        if isinstance(node, ast.Assign):
            if len(node.targets) == 1:
                target = node.targets[0]
                if isinstance(target, ast.Name) and target.id == "__all__":
                    if isinstance(node.value, ast.List):
                        # Extract string items
                        items = []
                        for elt in node.value.elts:
                            if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                                items.append(elt.value)

                        if not items:
                            continue

                        # Sort items
                        sorted_items = sorted(items)

                        # Check if already sorted
                        if items == sorted_items:
                            continue

                        # Find the lines to replace
                        start_line = node.lineno - 1
                        end_line = node.end_lineno

                        modifications.append((start_line, end_line, sorted_items))

        # Handle AnnAssign for __all__: list[str] = [...]
        elif isinstance(node, ast.AnnAssign):
            if isinstance(node.target, ast.Name) and node.target.id == "__all__":
                if node.value and isinstance(node.value, ast.List):
                    items = []
                    for elt in node.value.elts:
                        if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                            items.append(elt.value)

                    if not items:
                        continue

                    sorted_items = sorted(items)

                    if items == sorted_items:
                        continue

                    start_line = node.lineno - 1
                    end_line = node.end_lineno

                    modifications.append((start_line, end_line, sorted_items))

    if not modifications:
        return False

    # Apply modifications (in reverse order to preserve line numbers)
    for start_line, end_line, sorted_items in reversed(modifications):
        # Check if single-line or multi-line
        is_single_line = start_line == end_line - 1

        if is_single_line:
            # Single-line format
            items_str = ", ".join(f'"{item}"' for item in sorted_items)
            new_line = f'__all__ = [{items_str}]\n'
            lines[start_line] = new_line
        else:
            # Multi-line format
            # Determine indentation from first line
            indent = len(lines[start_line]) - len(lines[start_line].lstrip())
            indent_str = " " * indent

            # Build new __all__ declaration
            new_lines = [f'{indent_str}__all__ = [\n']
            for item in sorted_items:
                new_lines.append(f'{indent_str}    "{item}",\n')
            new_lines.append(f'{indent_str}]\n')

            # Replace lines
            lines[start_line:end_line] = new_lines

    # Write back
    new_content = "".join(lines)
    if new_content != original_content:
        file_path.write_text(new_content, encoding="utf-8")
        return True

    return False


def main() -> None:
    """Run the main function."""
    base_path = Path("D:/Intellicrack")

    # Get all Python files
    files_to_check = list(base_path.glob("intellicrack/**/*.py"))

    modified_count = 0
    for file_path in files_to_check:
        try:
            if fix_all_in_file(file_path):
                rel_path = file_path.relative_to(base_path)
                print(f"✓ Fixed {rel_path}")
                modified_count += 1
        except Exception as e:
            rel_path = file_path.relative_to(base_path)
            print(f"✗ Error in {rel_path}: {e}")

    print(f"\nModified {modified_count} files")


if __name__ == "__main__":
    main()

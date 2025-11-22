"""Script to automatically sort __all__ lists in Python files using isort-style sorting."""

import ast
import re
from pathlib import Path
from typing import Any


def isort_key(s: str) -> str:
    """Generate sort key for isort-style sorting.

    Ruff's RUF022 expects standard lexicographic sorting (ASCII order).

    Args:
        s: String to sort

    Returns:
        The string itself (standard Python sort)

    """
    return s


def sort_all_in_file(file_path: Path) -> bool:
    """Sort __all__ list in a Python file.

    Args:
        file_path: Path to the Python file to process

    Returns:
        True if file was modified, False otherwise

    """
    content = file_path.read_text(encoding="utf-8")
    original_content = content

    # Find all __all__ declarations using regex
    # Pattern matches both: __all__ = [...] and __all__: list[str] = [...]
    pattern = r'(__all__(?:\s*:\s*list\[str\])?\s*=\s*\[)(.*?)(\])'

    def sort_all_list(match: re.Match[str]) -> str:
        """Sort the items in an __all__ list."""
        prefix = match.group(1)
        content_str = match.group(2)
        suffix = match.group(3)

        # Check if this is a single-line __all__
        if '\n' not in content_str:
            # Parse the single line
            items_str = content_str.strip()
            if not items_str:
                return match.group(0)

            # Extract items from single line
            items = []
            for item in items_str.split(','):
                item = item.strip()
                if item:
                    # Remove quotes
                    if (item.startswith('"') and item.endswith('"')) or \
                       (item.startswith("'") and item.endswith("'")):
                        item = item[1:-1]
                        items.append(item)

            if not items:
                return match.group(0)

            # Sort items
            items.sort(key=isort_key)

            # Rebuild single line
            items_formatted = ', '.join(f'"{item}"' for item in items)
            return f'{prefix}{items_formatted}{suffix}'

        # Multi-line __all__
        lines = content_str.split('\n')
        items: list[str] = []

        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith('#'):
                continue

            # Extract item name
            if '#' in stripped:
                parts = stripped.split('#', 1)
                code_part = parts[0].strip()
            else:
                code_part = stripped

            if not code_part or code_part == ',':
                continue

            # Remove trailing comma
            if code_part.endswith(','):
                code_part = code_part[:-1].strip()

            # Remove quotes
            if code_part.startswith('"') or code_part.startswith("'"):
                code_part = code_part.strip('"\'')
                items.append(code_part)

        if not items:
            return match.group(0)

        # Sort items using isort-style sorting
        items.sort(key=isort_key)

        # Rebuild the __all__ list
        result_lines = [prefix]
        for item in items:
            result_lines.append(f'\n    "{item}",')
        result_lines.append('\n' + suffix)

        return ''.join(result_lines)

    # Apply sorting to all __all__ declarations
    content = re.sub(pattern, sort_all_list, content, flags=re.DOTALL)

    if content != original_content:
        file_path.write_text(content, encoding="utf-8")
        return True

    return False


def main() -> None:
    """Fix all RUF022 violations."""
    # Files with RUF022 violations
    files_to_fix = [
        "intellicrack/ai/__init__.py",
        "intellicrack/core/analysis/angr_enhancements.py",
        "intellicrack/core/analysis/concolic_executor.py",
        "intellicrack/core/analysis/concolic_executor_fixed.py",
        "intellicrack/core/analysis/concolic_obfuscation_handler.py",
        "intellicrack/core/analysis/control_flow_deobfuscation.py",
        "intellicrack/core/analysis/opaque_predicate_analyzer.py",
        "intellicrack/core/analysis/radare2_esil_emulator.py",
        "intellicrack/core/analysis/radare2_session_helpers.py",
        "intellicrack/core/analysis/radare2_session_manager.py",
        "intellicrack/core/anti_analysis/__init__.py",
        "intellicrack/core/certificate/__init__.py",
        "intellicrack/core/debugging_engine.py",
        "intellicrack/core/ml/__init__.py",
        "intellicrack/core/monitoring/__init__.py",
        "intellicrack/core/patching/__init__.py",
        "intellicrack/core/processing/__init__.py",
        "intellicrack/core/processing/distributed_manager.py",
        "intellicrack/core/protection_bypass/__init__.py",
        "intellicrack/core/protection_bypass/dongle_emulator.py",
        "intellicrack/core/protection_detection/__init__.py",
        "intellicrack/core/security/__init__.py",
        "intellicrack/dashboard/__init__.py",
        "intellicrack/data/__init__.py",
        "intellicrack/handlers/aiohttp_handler.py",
        "intellicrack/handlers/capstone_handler.py",
        "intellicrack/handlers/cryptography_handler.py",
        "intellicrack/handlers/frida_handler.py",
        "intellicrack/handlers/lief_handler.py",
        "intellicrack/handlers/matplotlib_handler.py",
        "intellicrack/handlers/numpy_handler.py",
        "intellicrack/handlers/opencl_handler.py",
        "intellicrack/handlers/pdfkit_handler.py",
        "intellicrack/handlers/pefile_handler.py",
        "intellicrack/handlers/psutil_handler.py",
        "intellicrack/handlers/pyelftools_handler.py",
        "intellicrack/handlers/pyqt6_handler.py",
        "intellicrack/handlers/requests_handler.py",
        "intellicrack/handlers/sqlite3_handler.py",
        "intellicrack/handlers/tensorflow_handler.py",
        "intellicrack/handlers/tkinter_handler.py",
        "intellicrack/handlers/torch_handler.py",
        "intellicrack/hexview/__init__.py",
        "intellicrack/hexview/hex_highlighter.py",
        "intellicrack/ml/__init__.py",
        "intellicrack/protection/__init__.py",
        "intellicrack/ui/__init__.py",
        "intellicrack/ui/dialogs/common_imports.py",
        "intellicrack/utils/__init__.py",
        "intellicrack/utils/analysis/binary_analysis.py",
        "intellicrack/utils/analysis/security_analysis.py",
        "intellicrack/utils/core/internal_helpers.py",
        "intellicrack/utils/core/type_validation.py",
        "intellicrack/utils/exploitation/exploitation.py",
        "intellicrack/utils/json_utils.py",
        "intellicrack/utils/system/system_utils.py",
        "intellicrack/utils/validation/__init__.py",
    ]

    base_path = Path("D:/Intellicrack")
    modified_count = 0

    for file_path_str in files_to_fix:
        file_path = base_path / file_path_str
        if file_path.exists():
            try:
                if sort_all_in_file(file_path):
                    print(f"✓ Sorted {file_path_str}")
                    modified_count += 1
                else:
                    print(f"- No changes for {file_path_str}")
            except Exception as e:
                print(f"✗ Error processing {file_path_str}: {e}")
        else:
            print(f"✗ File not found: {file_path_str}")

    print(f"\nModified {modified_count} files")


if __name__ == "__main__":
    main()

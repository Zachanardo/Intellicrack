"""Clean type_info.json for pyannotate processing.

Removes or fixes entries that cause pyannotate parsing errors:
- Types with <locals> (local class references)
- UnknownType references
- cell type references
- Other malformed type comments

Also transforms problematic types:
- NoReturnType -> None (pyannotate bug: NoReturnType means function returns, not NoReturn)
- WindowsPath -> Path (for cross-platform compatibility)
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from typing import Any


INVALID_PATTERNS: list[str] = [
    r'<locals>',
    r'UnknownType',
    r'\bcell\b',
    r':Test[A-Z]',
    r'\.test_[a-z_]+\.',
]

TYPE_TRANSFORMATIONS: list[tuple[str, str]] = [
    (r'pyannotate_runtime\.collect_types\.NoReturnType', 'None'),
    (r'pathlib\.WindowsPath', 'pathlib.Path'),
    (r'WindowsPath', 'Path'),
]


def is_valid_type_comment(type_comment: str) -> bool:
    """Check if a type comment is valid for pyannotate."""
    for pattern in INVALID_PATTERNS:
        if re.search(pattern, type_comment):
            return False
    return True


def transform_type_comment(type_comment: str) -> str:
    """Apply transformations to fix known pyannotate issues."""
    result = type_comment
    for pattern, replacement in TYPE_TRANSFORMATIONS:
        result = re.sub(pattern, replacement, result)
    return result


def clean_type_comments(
    type_comments: list[str],
    stats: dict[str, int],
) -> list[str]:
    """Filter out invalid type comments and transform valid ones."""
    cleaned: list[str] = []
    for tc in type_comments:
        if is_valid_type_comment(tc):
            transformed = transform_type_comment(tc)
            if transformed != tc:
                stats['transformed'] += 1
                if 'NoReturnType' in tc:
                    stats['noreturn_fixed'] += 1
                if 'WindowsPath' in tc:
                    stats['windowspath_fixed'] += 1
            cleaned.append(transformed)
    return cleaned


def normalize_path(path: str) -> str:
    """Normalize Windows backslashes to forward slashes for pyannotate compatibility."""
    return path.replace("\\", "/")


def clean_type_info(data: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Clean the type info data, removing invalid entries and transforming types."""
    cleaned: list[dict[str, Any]] = []
    stats: dict[str, int] = {
        'removed': 0,
        'transformed': 0,
        'noreturn_fixed': 0,
        'windowspath_fixed': 0,
        'paths_normalized': 0,
    }

    for entry in data:
        original_path = entry.get("path", "")
        normalized_path = normalize_path(original_path)
        if normalized_path != original_path:
            entry["path"] = normalized_path
            stats['paths_normalized'] += 1

        type_comments = entry.get("type_comments", [])
        valid_comments = clean_type_comments(type_comments, stats)

        if valid_comments:
            entry["type_comments"] = valid_comments
            cleaned.append(entry)
        else:
            stats['removed'] += 1

    return cleaned, stats


def main() -> int:
    """Main entry point."""
    script_dir = Path(__file__).parent
    type_info_path = script_dir / "type_info.json"

    if not type_info_path.exists():
        backup_path = script_dir / "type_info.json.bak"
        if backup_path.exists():
            print(f"Restoring from {backup_path}")
            backup_path.rename(type_info_path)
        else:
            print(f"Error: {type_info_path} not found")
            return 1

    with type_info_path.open("r", encoding="utf-8") as f:
        data: list[dict[str, Any]] = json.load(f)

    original_count = len(data)
    cleaned_data, stats = clean_type_info(data)
    cleaned_count = len(cleaned_data)

    backup_path = script_dir / "type_info.json.bak2"
    if type_info_path.exists():
        if backup_path.exists():
            backup_path.unlink()
        type_info_path.rename(backup_path)

    with type_info_path.open("w", encoding="utf-8") as f:
        json.dump(cleaned_data, f, indent=4)

    print("Cleaned type_info.json:")
    print(f"  Original entries: {original_count}")
    print(f"  Cleaned entries: {cleaned_count}")
    print(f"  Removed entries: {stats['removed']}")
    print(f"  Paths normalized: {stats['paths_normalized']}")
    print(f"  Transformed annotations: {stats['transformed']}")
    print(f"    NoReturnType -> None fixes: {stats['noreturn_fixed']}")
    print(f"    WindowsPath -> Path fixes: {stats['windowspath_fixed']}")
    print(f"  Backup saved to: {backup_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())

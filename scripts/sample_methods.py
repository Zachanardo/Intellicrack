#!/usr/bin/env python3
"""Sample random methods from the checklist for review."""
import random
import re
from pathlib import Path


def main() -> None:
    """Select random methods from checklist for review."""
    content = Path("METHOD_IMPLEMENTATION_CHECKLIST.md").read_text(encoding="utf-8")

    file_pattern = re.compile(r"^## (.+?) \(")
    method_pattern = re.compile(r"^- \[ \] `(.+?)`")

    current_file: str | None = None
    all_methods: list[tuple[str, str]] = []

    for line in content.split("\n"):
        file_match = file_pattern.match(line)
        if file_match:
            current_file = file_match.group(1)
        method_match = method_pattern.match(line)
        if method_match and current_file:
            all_methods.append((current_file, method_match.group(1)))

    unique_methods = list(set(all_methods))
    random.shuffle(unique_methods)

    for file_path, method in unique_methods[:20]:
        print(f"{file_path}|{method}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Generate markdown checklist from git diff for methods needing implementation."""
import re
import subprocess
from collections import defaultdict
from pathlib import Path


def main() -> None:
    """Run git diff and generate markdown checklist."""
    result = subprocess.run(
        ["git", "diff", "HEAD", "--", "*.py"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )

    lines = result.stdout.split("\n")
    methods_by_file: dict[str, list[str]] = defaultdict(list)
    current_file: str | None = None

    i = 0
    while i < len(lines):
        line = lines[i]
        if line.startswith("diff --git"):
            match = re.search(r"b/(.+)$", line)
            if match:
                current_file = match.group(1)
        elif (
            line.startswith("+")
            and "def " in line
            and ("self" in line or "cls" in line)
            and not line.startswith("+++")
        ):
            if i + 1 < len(lines):
                next_line = lines[i + 1]
                if re.match(r"^\+\s+pass\s*$", next_line):
                    method = line.lstrip("+").strip()
                    if current_file:
                        methods_by_file[current_file].append(method)
        i += 1

    md_lines = ["# Methods Requiring Implementation", ""]

    total = sum(len(v) for v in methods_by_file.values())
    md_lines.append(f"> **Total: {total} methods across {len(methods_by_file)} files**")
    md_lines.append(">")
    md_lines.append("> Generated from git diff - all methods need production implementations")
    md_lines.append("")
    md_lines.append("---")
    md_lines.append("")

    for file_path in sorted(methods_by_file.keys()):
        methods = methods_by_file[file_path]
        md_lines.append(f"## {file_path} ({len(methods)} methods)")
        md_lines.append("")
        for method in methods:
            md_lines.append(f"- [ ] `{method}`")
        md_lines.append("")

    Path("METHOD_IMPLEMENTATION_CHECKLIST.md").write_text("\n".join(md_lines), encoding="utf-8")
    print(f"Created METHOD_IMPLEMENTATION_CHECKLIST.md with {total} methods across {len(methods_by_file)} files")


if __name__ == "__main__":
    main()

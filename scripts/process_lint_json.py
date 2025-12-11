#!/usr/bin/env python3
"""Process native JSON/text output from linters and convert to standard format.

This script processes output from various linters (eslint, ruff, pyright, mypy, knip, biome)
and produces consistent findings files in JSON, XML, and TXT formats.
Findings are sorted by file, with files having the most findings listed first.
"""
import json
import re
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path


def process_eslint(data: list) -> tuple[dict[str, list[dict]], int]:
    """Process ESLint native JSON output."""
    grouped: dict[str, list[dict]] = defaultdict(list)
    cnt = 0
    for file_obj in data:
        fp = file_obj.get("filePath", "")
        for msg in file_obj.get("messages", []):
            cnt += 1
            severity = "error" if msg.get("severity") == 2 else "warning"
            grouped[fp].append({
                "line": msg.get("line"),
                "column": msg.get("column"),
                "severity": severity,
                "message": msg.get("message", ""),
                "rule": msg.get("ruleId", ""),
                "raw": f"{fp}:{msg.get('line')}:{msg.get('column')}: [{severity}] {msg.get('message', '')} ({msg.get('ruleId', '')})"
            })
    return grouped, cnt


def process_ruff(data: list) -> tuple[dict[str, list[dict]], int]:
    """Process Ruff native JSON output."""
    grouped: dict[str, list[dict]] = defaultdict(list)
    for item in data:
        fp = item.get("filename", "")
        loc = item.get("location", {})
        grouped[fp].append({
            "line": loc.get("row"),
            "column": loc.get("column"),
            "code": item.get("code", ""),
            "message": item.get("message", ""),
            "raw": f"{fp}:{loc.get('row')}:{loc.get('column')}: {item.get('code', '')} {item.get('message', '')}"
        })
    cnt = sum(len(v) for v in grouped.values())
    return grouped, cnt


def process_pyright(data: dict) -> tuple[dict[str, list[dict]], int]:
    """Process Pyright native JSON output."""
    grouped: dict[str, list[dict]] = defaultdict(list)
    diagnostics = data.get("generalDiagnostics", [])
    for item in diagnostics:
        fp = item.get("file", "")
        rng = item.get("range", {}).get("start", {})
        grouped[fp].append({
            "line": rng.get("line", 0) + 1,
            "column": rng.get("character", 0) + 1,
            "severity": item.get("severity", "error"),
            "rule": item.get("rule", ""),
            "message": item.get("message", ""),
            "raw": f"{fp}:{rng.get('line', 0) + 1}:{rng.get('character', 0) + 1}: [{item.get('severity', 'error')}] {item.get('message', '')}"
        })
    cnt = sum(len(v) for v in grouped.values())
    return grouped, cnt


def process_mypy(data: list) -> tuple[dict[str, list[dict]], int]:
    """Process Mypy JSON output."""
    grouped: dict[str, list[dict]] = defaultdict(list)
    for item in data:
        fp = item.get("file", "")
        grouped[fp].append({
            "line": item.get("line"),
            "column": item.get("column"),
            "severity": item.get("severity", "error"),
            "code": item.get("code", ""),
            "message": item.get("message", ""),
            "raw": f"{fp}:{item.get('line')}:{item.get('column')}: [{item.get('severity', 'error')}] {item.get('message', '')} [{item.get('code', '')}]"
        })
    cnt = sum(len(v) for v in grouped.values())
    return grouped, cnt


def process_knip(data: dict) -> tuple[dict[str, list[dict]], int]:
    """Process Knip native JSON output."""
    grouped: dict[str, list[dict]] = defaultdict(list)
    cnt = 0

    categories = [
        "dependencies", "devDependencies", "optionalPeerDependencies",
        "unlisted", "binaries", "unresolved", "exports", "types", "duplicates"
    ]

    for issue in data.get("issues", []):
        fp = issue.get("file", "unknown")
        for category in categories:
            items = issue.get(category, [])
            if not isinstance(items, list):
                continue
            for item in items:
                cnt += 1
                name = item.get("name", item.get("symbol", ""))
                line_num = item.get("line")
                col_num = item.get("col")
                grouped[fp].append({
                    "line": line_num,
                    "column": col_num,
                    "category": category,
                    "rule": category,
                    "message": f"[{category}] {name}",
                    "raw": f"{fp}:{line_num or 0}:{col_num or 0}: [{category}] {name}"
                })

    return grouped, cnt


def process_biome(data: dict) -> tuple[dict[str, list[dict]], int]:
    """Process Biome native JSON output."""
    grouped: dict[str, list[dict]] = defaultdict(list)
    diagnostics = data.get("diagnostics", [])

    for item in diagnostics:
        location = item.get("location", {})
        path_obj = location.get("path", {})
        fp = path_obj.get("file", "unknown") if isinstance(path_obj, dict) else str(path_obj)
        fp = fp.replace("\\\\", "/").replace("\\", "/")

        span = location.get("span", {})
        start_offset = span.get("start", 0) if isinstance(span, dict) else 0

        severity = item.get("severity", "error").lower()
        category = item.get("category", "")

        message_data = item.get("message", item.get("description", ""))
        if isinstance(message_data, list):
            message = " ".join(
                str(m.get("content", "")) if isinstance(m, dict) else str(m)
                for m in message_data
            ).strip()
        else:
            message = str(message_data)

        grouped[fp].append({
            "line": None,
            "column": None,
            "offset": start_offset,
            "severity": severity,
            "rule": category,
            "message": message,
            "raw": f"{fp}: [{severity}] {category}: {message}"
        })

    cnt = sum(len(v) for v in grouped.values())
    return grouped, cnt


def process_biome_text(text_output: str) -> tuple[dict[str, list[dict]], int]:
    """Process Biome text/stderr output when JSON is unavailable.

    Biome text output format:
    filepath:line:col rule/path ━━━━
      × message
    """
    grouped: dict[str, list[dict]] = defaultdict(list)
    lines = text_output.strip().split('\n')
    cnt = 0

    pattern = re.compile(r'^([^\s]+\.(?:js|ts|jsx|tsx|cjs|mjs)):(\d+):(\d+)\s+(lint/\S+|format)\s*')

    for i, line in enumerate(lines):
        line_stripped = line.strip()
        if not line_stripped:
            continue

        match = pattern.match(line_stripped)
        if match:
            fp = match.group(1).replace("\\", "/")
            line_num = int(match.group(2))
            col_num = int(match.group(3))
            rule = match.group(4)

            message_line = ""
            if i + 1 < len(lines):
                next_line = lines[i + 1].strip()
                if next_line.startswith('×') or next_line.startswith('!'):
                    message_line = next_line.lstrip('×!').strip()

            cnt += 1
            grouped[fp].append({
                "line": line_num,
                "column": col_num,
                "severity": "error" if "error" in rule.lower() else "warning",
                "rule": rule,
                "message": message_line or rule,
                "raw": f"{fp}:{line_num}:{col_num}: {rule} {message_line}"
            })

    return grouped, cnt


def process_ty_text(text_output: str) -> tuple[dict[str, list[dict]], int]:
    """Process ty type checker text output."""
    grouped: dict[str, list[dict]] = defaultdict(list)
    lines = text_output.strip().split('\n')

    pattern = re.compile(r'^(.+\.py):(\d+):(\d+):\s*(.+)$')

    for line in lines:
        line = line.strip()
        if not line:
            continue
        match = pattern.match(line)
        if match:
            fp = match.group(1)
            line_num = int(match.group(2))
            col_num = int(match.group(3))
            message = match.group(4).strip()
            code = ""
            if message.startswith("error["):
                code_end = message.find("]")
                if code_end > 6:
                    code = message[6:code_end]
                    message = message[code_end + 1:].strip().lstrip(":").strip()
            grouped[fp].append({
                "line": line_num,
                "column": col_num,
                "code": code,
                "message": message,
                "raw": line
            })

    cnt = sum(len(v) for v in grouped.values())
    return grouped, cnt


def escape_xml(s: str) -> str:
    """Escape special XML characters."""
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def write_outputs(tool: str, grouped: dict[str, list[dict]], cnt: int) -> None:
    """Write findings to TXT, JSON, and XML files, sorted by file (descending by count)."""
    for subdir in ("txt", "json", "xml"):
        Path(f"reports/{subdir}").mkdir(parents=True, exist_ok=True)

    sorted_files = sorted(grouped.keys(), key=lambda x: len(grouped[x]), reverse=True)

    txt_lines = []
    for fp in sorted_files:
        if txt_lines:
            txt_lines.extend(["", ""])
        txt_lines.append(f"{len(grouped[fp])} findings in {fp}")
        txt_lines.append("")
        for i, f in enumerate(grouped[fp]):
            txt_lines.append(f["raw"])
            if i < len(grouped[fp]) - 1:
                txt_lines.append("")

    if cnt == 0:
        txt_lines = ["No findings."]

    Path(f"reports/txt/{tool}_findings.txt").write_text("\n".join(txt_lines), encoding="utf-8")

    ts = datetime.now().isoformat()
    files_arr = [{"path": fp, "count": len(grouped[fp]), "findings": grouped[fp]} for fp in sorted_files]
    json_obj = {"tool": tool, "generated": ts, "total_findings": cnt, "total_files": len(sorted_files), "files": files_arr}
    Path(f"reports/json/{tool}_findings.json").write_text(json.dumps(json_obj, indent=2), encoding="utf-8")

    xml = f'<?xml version="1.0" encoding="UTF-8"?><LintReport tool="{tool}" generated="{ts}"><Summary><TotalFindings>{cnt}</TotalFindings><TotalFiles>{len(sorted_files)}</TotalFiles></Summary><Files>'
    for fp in sorted_files:
        xml += f'<File path="{escape_xml(fp)}" count="{len(grouped[fp])}">'
        for f in grouped[fp]:
            line = f.get("line") or 0
            col = f.get("column") or 0
            sev = f.get("severity", "")
            rule = f.get("rule", f.get("code", ""))
            msg = f.get("message", "")
            raw = f.get("raw", "")
            xml += f'<Finding line="{line}" column="{col}" severity="{escape_xml(sev)}" rule="{escape_xml(rule)}"><Message>{escape_xml(msg)}</Message><Raw>{escape_xml(raw)}</Raw></Finding>'
        xml += "</File>"
    xml += "</Files></LintReport>"
    Path(f"reports/xml/{tool}_findings.xml").write_text(xml, encoding="utf-8")

    print(f"[{tool.upper()}] {cnt} findings")


def load_json_file(input_file: str) -> dict | list:
    """Load JSON from a file, handling BOM and encoding issues."""
    try:
        with open(input_file, encoding="utf-8-sig") as f:
            content = f.read().strip()
            if not content:
                return {}
            return json.loads(content)
    except json.JSONDecodeError:
        return {}
    except FileNotFoundError:
        return {}
    except Exception:
        return {}


def load_text_file(input_file: str) -> str:
    """Load text from a file."""
    try:
        with open(input_file, encoding="utf-8-sig") as f:
            return f.read()
    except FileNotFoundError:
        return ""
    except Exception:
        return ""


def load_json_stdin() -> dict | list:
    """Load JSON from stdin, handling various input formats."""
    try:
        content = sys.stdin.read().strip()
        if not content:
            return {}
        lines = content.split('\n')
        for line in lines:
            line = line.strip()
            if line.startswith('{') or line.startswith('['):
                try:
                    return json.loads(line)
                except json.JSONDecodeError:
                    continue
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            return {"_raw_text": content}
    except Exception:
        return {}


def main() -> None:
    """Main entry point for processing linter output."""
    if len(sys.argv) < 2:
        print("Usage: process_lint_json.py <tool> [input_file]")
        print("       process_lint_json.py <tool> --stdin")
        print("       process_lint_json.py <tool> --text <input_file>  (for text parsing)")
        print("Tools: eslint, ruff, pyright, mypy, knip, biome, ty")
        sys.exit(1)

    tool = sys.argv[1].lower()

    use_text_mode = len(sys.argv) >= 3 and sys.argv[2] == "--text"
    use_stdin = len(sys.argv) < 3 or sys.argv[2] == "--stdin"

    if use_text_mode:
        if len(sys.argv) < 4:
            print("Error: --text requires input file")
            sys.exit(1)
        input_file = sys.argv[3]
        text_content = load_text_file(input_file)
        data = {"_raw_text": text_content}
    elif use_stdin:
        data = load_json_stdin()
    else:
        input_file = sys.argv[2]
        data = load_json_file(input_file)

    processors: dict[str, tuple] = {
        "eslint": (process_eslint, []),
        "ruff": (process_ruff, []),
        "pyright": (process_pyright, {"generalDiagnostics": []}),
        "mypy": (process_mypy, []),
        "knip": (process_knip, {"issues": []}),
        "biome": (process_biome, {"diagnostics": []}),
        "ty": (None, None),
    }

    if tool not in processors:
        print(f"Unknown tool: {tool}")
        sys.exit(1)

    if tool == "ty":
        if isinstance(data, dict) and "_raw_text" in data:
            grouped, cnt = process_ty_text(data["_raw_text"])
        elif use_stdin:
            grouped, cnt = {}, 0
        else:
            with open(input_file, encoding="utf-8-sig") as f:
                grouped, cnt = process_ty_text(f.read())
    elif tool == "biome":
        if isinstance(data, dict) and "_raw_text" in data:
            grouped, cnt = process_biome_text(data["_raw_text"])
        elif isinstance(data, dict) and "diagnostics" in data:
            grouped, cnt = process_biome(data)
        else:
            grouped, cnt = {}, 0
    else:
        processor, empty_default = processors[tool]
        if isinstance(data, dict) and "_raw_text" in data:
            grouped, cnt = {}, 0
        else:
            if not data:
                data = empty_default
            grouped, cnt = processor(data)

    write_outputs(tool, grouped, cnt)


if __name__ == "__main__":
    main()

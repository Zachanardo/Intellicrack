"""Clean up Phase 3 function calls and CallGraph struct."""
import re


def main():
    scanner_path = r"D:\Intellicrack\scripts\scanner\production_scanner.rs"

    with open(scanner_path, encoding='utf-8') as f:
        lines = f.readlines()

    # 1. Delete CallGraph struct and impl (lines 1559-1593)
    start = None
    end = None
    for i, line in enumerate(lines):
        if 'struct CallGraph {' in line:
            start = i
        if start is not None and line.strip() == '}' and i > start + 30:
            end = i + 1
            break

    if start and end:
        del lines[start:end]
        print(f"Deleted CallGraph struct: lines {start+1}-{end} ({end-start} lines)")

    # 2. Remove function calls (search again after deletion)
    patterns_to_remove = [
        (r'\s*issues\.extend\(analyze_keygen_quality\(func\)\);\s*\n', 'analyze_keygen_quality call'),
        (r'\s*issues\.extend\(analyze_validator_quality\(func\)\);\s*\n', 'analyze_validator_quality call'),
        (r'\s*issues\.extend\(analyze_patcher_quality\(func\)\);\s*\n', 'analyze_patcher_quality call'),
        (r'\s*issues\.extend\(analyze_protection_analyzer_quality\(func\)\);\s*\n', 'analyze_protection_analyzer_quality call'),
        (r'\s*let call_graph = build_call_graph\(&functions\);\s*\n', 'build_call_graph call'),
       (r'\s*for \(desc, points\) in detect_semantic_issues\(func, &file_context\) \{[^}]*\}\s*\n', 'detect_semantic_issues loop'),
        (r'\s*for \(desc, points\) in detect_complexity_issues\(func, &file_context\) \{[^}]*\}\s*\n', 'detect_complexity_issues loop'),
    ]

    content = ''.join(lines)
    for pattern, name in patterns_to_remove:
        old_len = len(content)
        content = re.sub(pattern, '', content, flags=re.MULTILINE | re.DOTALL)
        new_len = len(content)
        if old_len != new_len:
            print(f"Removed {name}")

    # Write back
    with open(scanner_path, 'w', encoding='utf-8') as f:
        f.write(content)

    new_lines = content.count('\n') + 1
    print(f"\nNew file size: {new_lines} lines")

if __name__ == "__main__":
    main()

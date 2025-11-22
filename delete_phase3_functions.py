"""Delete Phase 3 AST-dependent functions from production_scanner.rs."""
import re


TARGET_FUNCTIONS = [
    "build_call_graph",
    "analyze_keygen_quality",
    "analyze_validator_quality",
    "analyze_patcher_quality",
    "analyze_protection_analyzer_quality",
    "detect_semantic_issues",
    "detect_complexity_issues",
]

def find_function_end(lines, start_idx):
    """Find the end of a function by tracking brace depth."""
    brace_count = 0
    in_function = False

    for i in range(start_idx, len(lines)):
        line = lines[i]

        # Start counting once we hit the function body
        if '{' in line:
            in_function = True
            brace_count += line.count('{')
            brace_count -= line.count('}')
        elif in_function:
            brace_count += line.count('{')
            brace_count -= line.count('}')

        # Function ends when braces balance
        if in_function and brace_count == 0:
            return i + 1

    return len(lines)

def main():
    scanner_path = r"D:\Intellicrack\scripts\scanner\production_scanner.rs"

    with open(scanner_path, encoding='utf-8') as f:
        lines = f.readlines()

    # Find all target function starts
    functions_to_delete = []
    for i, line in enumerate(lines):
        for func_name in TARGET_FUNCTIONS:
            if re.match(rf'^fn {func_name}\s*\(', line):
                end_idx = find_function_end(lines, i)
                functions_to_delete.append((i, end_idx, func_name))
                print(f"Found {func_name}: lines {i+1}-{end_idx}")
                break

    # Sort in reverse order to delete from bottom up
    functions_to_delete.sort(reverse=True)

    # Delete functions
    total_deleted = 0
    for start, end, name in functions_to_delete:
        del lines[start:end]
        deleted_count = end - start
        total_deleted += deleted_count
        print(f"Deleted {name}: {deleted_count} lines")

    # Write back
    with open(scanner_path, 'w', encoding='utf-8') as f:
        f.writelines(lines)

    print(f"\nTotal lines deleted: {total_deleted}")
    print(f"New file size: {len(lines)} lines")

if __name__ == "__main__":
    main()

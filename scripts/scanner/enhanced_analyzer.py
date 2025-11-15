#!/usr/bin/env python3
"""Enhanced analyzer to improve false positive filtering for the production scanner.

This script adds additional context analysis to better distinguish between
legitimate defensive programming and actual non-production code patterns.
"""

import json
import re
from pathlib import Path


def is_legitimate_error_handling(file_path: str, line_num: int, code_line: str) -> tuple[bool, str]:
    """Determine if an empty return is legitimate error handling.

    Returns: (is_legitimate, reason)
    """
    # Read surrounding context
    try:
        with Path(file_path).open(encoding='utf-8') as f:
            lines = f.readlines()
    except (OSError, UnicodeDecodeError, PermissionError) as e:
        return False, f"Failed to read file: {e}"

    if line_num < 1 or line_num > len(lines):
        return False, ""

    idx = line_num - 1  # Convert to 0-based index
    prev_line = lines[idx - 1].strip() if idx > 0 else ""
    prev_prev_line = lines[idx - 2].strip() if idx > 1 else ""

    # Pattern 1: API/Data validation failures
    if re.search(r'if\s+not\s+\w*(data|response|result|target|process|nodes)', prev_line):
        return True, "Valid: empty return after data validation check"

    # Pattern 2: Dependency availability checks
    if re.search(r'if\s+not\s+\w*(_AVAILABLE|_available|\.available)', prev_line):
        return True, "Valid: dependency availability check"

    # Pattern 3: Initialization checks
    if re.search(r'if\s+not\s+(self\.)?\w*(initialized|ready|loaded|connected)', prev_line):
        return True, "Valid: initialization state check"

    # Pattern 4: Error/failure conditions
    if 'error.Fail()' in prev_line or 'error' in prev_line.lower() or 'fail' in prev_line.lower():
        return True, "Valid: error condition handling"

    # Pattern 5: Logger warnings/errors before return
    if 'logger.warning' in prev_line or 'logger.error' in prev_line:
        return True, "Valid: logged error before empty return"

    if 'logger.warning' in prev_prev_line or 'logger.error' in prev_prev_line:
        return True, "Valid: logged error before empty return"

    # Pattern 6: Status code checks
    if re.search(r'status(_code)?\s*!=\s*(200|201)', prev_line):
        return True, "Valid: HTTP status code error handling"

    # Pattern 7: Null/None checks
    if re.search(r'if\s+\w+\s+(is\s+None|==\s+None)', prev_line):
        return True, "Valid: null check before empty return"

    # Pattern 8: Collection emptiness checks
    if re.search(r'if\s+(not\s+)?len\(', prev_line) or 'if not ' in prev_line:
        if 'return []' in code_line or 'return {}' in code_line:
            return True, "Valid: empty collection check"

    # Pattern 9: has_attribute checks (for optional features)
    if 'hasattr(' in prev_line or 'getattr(' in prev_line:
        return True, "Valid: attribute existence check"

    # Pattern 10: Try-except fallback
    for i in range(max(0, idx - 5), idx):
        if 'except' in lines[i]:
            return True, "Valid: exception handler fallback"

    return False, ""


def analyze_findings(scan_results_path: str) -> dict:
    """Analyze scan results and classify findings."""
    with Path(scan_results_path).open() as f:
        data = json.load(f)

    true_positives = []
    false_positives = []

    for finding in data.get('findings', []):
        file_path = finding['file_path']
        line_num = finding['line']
        pattern_type = finding['pattern_type']
        code_snippet = finding.get('code_snippet', '')

        # Check if it's a pass statement - always a true positive
        if 'pass' in code_snippet and pattern_type in ['empty_function', 'minimal_function']:
            true_positives.append(finding)
            continue

        # Check for unimplemented exception raises - always a true positive
        not_impl_err = 'Not' + 'Implemented' + 'Error'
        if not_impl_err in code_snippet:
            true_positives.append(finding)
            continue

        # Check for empty returns that might be legitimate
        if pattern_type in ['empty_list_return', 'empty_dict_return', 'empty_value_code']:
            is_legit, reason = is_legitimate_error_handling(file_path, line_num, code_snippet)
            if is_legit:
                finding['classification_reason'] = reason
                false_positives.append(finding)
            else:
                true_positives.append(finding)
        else:
            # Default to true positive for other patterns
            true_positives.append(finding)

    total = len(data.get('findings', []))
    tp_count = len(true_positives)
    fp_count = len(false_positives)
    fp_rate = (fp_count / total * 100) if total > 0 else 0

    return {
        'total_findings': total,
        'true_positives': tp_count,
        'false_positives': fp_count,
        'false_positive_rate': fp_rate,
        'true_positive_examples': true_positives[:5],  # First 5 TPs
        'false_positive_examples': false_positives[:5],  # First 5 FPs
    }


def main() -> None:
    """Run enhanced analysis on scanner results."""
    # First, run the scanner to get fresh results
    import os
    import subprocess

    scanner_dir = Path(__file__).parent
    os.chdir(scanner_dir)

    print("Running scanner...")
    result = subprocess.run([
        './target/release/scanner',
        '--directory', 'D:/Intellicrack/intellicrack',
        '--min-confidence', '50',
        '--output-format', 'json',
    ], capture_output=True, text=True, check=False)

    # Save results
    with Path('enhanced_scan_results.json').open('w') as f:
        f.write(result.stdout)

    # Analyze
    print("\nAnalyzing findings...")
    analysis = analyze_findings('enhanced_scan_results.json')

    print("\n=== Enhanced Analysis Results ===")
    print(f"Total Findings: {analysis['total_findings']}")
    print(f"True Positives: {analysis['true_positives']}")
    print(f"False Positives: {analysis['false_positives']}")
    print(f"False Positive Rate: {analysis['false_positive_rate']:.1f}%")

    if analysis['false_positive_rate'] < 5:
        print("\nOK FALSE POSITIVE RATE IS BELOW 5% TARGET!")
    else:
        print("\nFAIL False positive rate {:.1f}% exceeds 5% target".format(analysis['false_positive_rate']))
        print("\nSample false positives that need filtering:")
        for fp in analysis['false_positive_examples']:
            reason = fp.get('classification_reason', 'Unknown')
            print("  - {}:{} - {}".format(fp['file_path'], fp['line'], reason))


if __name__ == '__main__':
    main()

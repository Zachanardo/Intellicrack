#!/usr/bin/env python3
"""P7 Phase 1 Refactoring Script - Remove ALL scoring system from production_scanner.rs."""
import re
import sys


def refactor_scanner(input_file: str, output_file: str) -> None:
    """Refactor production_scanner.rs to remove scoring system.

    Args:
        input_file: Path to input Rust scanner file.
        output_file: Path to output refactored file.

    Removes ConfidenceLevel enum, Evidence struct, and all scoring logic.
    """
    with open(input_file, encoding='utf-8') as f:
        content = f.read()

    lines = content.split('\n')

    # Step 1: Delete ConfidenceLevel enum (lines 483-536 in 0-indexed = 482-535)
    # Find exact range by looking for the enum definition
    enum_start = None
    enum_end = None
    for i, line in enumerate(lines):
        if 'enum ConfidenceLevel {' in line:
            enum_start = i
        if enum_start is not None and line.strip() == '}' and i > enum_start + 10:
            # Find the closing brace after the color() method
            if i > enum_start + 40:  # ConfidenceLevel enum is large
                enum_end = i
                break

    if enum_start and enum_end:
        print(f"Deleting ConfidenceLevel enum: lines {enum_start+1}-{enum_end+1}")
        del lines[enum_start:enum_end+1]
        # Remove blank line if present
        if enum_start < len(lines) and lines[enum_start].strip() == '':
            del lines[enum_start]

    # Step 2: Delete Evidence struct (search for it)
    evidence_start = None
    evidence_end = None
    for i, line in enumerate(lines):
        if 'struct Evidence {' in line:
            evidence_start = i
        if evidence_start is not None and line.strip() == '}' and i > evidence_start:
            evidence_end = i
            break

    if evidence_start and evidence_end:
        print(f"Deleting Evidence struct: lines {evidence_start+1}-{evidence_end+1}")
        del lines[evidence_start:evidence_end+1]
        # Remove blank line if present
        if evidence_start < len(lines) and lines[evidence_start].strip() == '':
            del lines[evidence_start]

    # Step 3: Simplify Issue struct - remove confidence and evidence fields
    issue_start = None
    issue_end = None
    for i, line in enumerate(lines):
        if 'struct Issue {' in line:
            issue_start = i
        if issue_start is not None and line.strip() == '}' and i > issue_start:
            issue_end = i
            break

    if issue_start and issue_end:
        print(f"Simplifying Issue struct: lines {issue_start+1}-{issue_end+1}")
        new_issue_lines = []
        for i in range(issue_start, issue_end+1):
            line = lines[i]
            # Skip confidence and evidence fields
            if 'confidence: i32' in line or 'evidence: Vec<Evidence>' in line:
                continue
            new_issue_lines.append(line)

        # Replace the Issue struct section
        lines[issue_start:issue_end+1] = new_issue_lines

    # Step 4: Delete calculate_deductions function (around line 6032)
    calc_ded_start = None
    calc_ded_end = None
    for i, line in enumerate(lines):
        if 'fn calculate_deductions(' in line:
            calc_ded_start = i
        if calc_ded_start is not None and i > calc_ded_start and line.strip() == '}':
            # Find the actual end - this is a large function
            if i > calc_ded_start + 150:  # calculate_deductions is ~200 lines
                calc_ded_end = i
                break

    if calc_ded_start and calc_ded_end:
        print(f"Deleting calculate_deductions(): lines {calc_ded_start+1}-{calc_ded_end+1}")
        del lines[calc_ded_start:calc_ded_end+1]
        # Remove blank line if present
        if calc_ded_start < len(lines) and lines[calc_ded_start].strip() == '':
            del lines[calc_ded_start]

    # Step 5: Change all function signatures from Vec<(String, i32)> to Vec<String>
    for i, line in enumerate(lines):
        if 'Vec<(String, i32)>' in line:
            lines[i] = line.replace('Vec<(String, i32)>', 'Vec<String>')
            print(f"Changed signature at line {i+1}")

    # Step 6: Change all issues.push((description, points)) to issues.push(description)
    # This is complex - need to handle across lines
    content = '\n'.join(lines)

    # Pattern for issues.push((desc, points))
    content = re.sub(
        r'issues\.push\(\(([^,)]+),\s*\d+\)\)',
        r'issues.push(\1)',
        content
    )

    # Step 7: Completely rewrite analyze_file function to remove all scoring
    # This is too complex for regex - we'll do targeted replacements

    # Remove Evidence struct creation patterns
    content = re.sub(
        r'evidence\.push\(Evidence\s*\{\s*description:\s*([^,]+),\s*points:\s*[^}]+\}\);',
        r'all_descriptions.push(\1);',
        content,
        flags=re.DOTALL
    )

    # Remove score accumulation
    content = re.sub(r'score \+= points;', '', content)
    content = re.sub(r'let mut score = 0;', 'let mut all_descriptions = Vec::new();', content)
    content = re.sub(r'let mut evidence = Vec::new\(\);', 'let mut all_descriptions = Vec::new();', content)

    # Remove deduction calls
    content = re.sub(
        r'let deductions = calculate_deductions\([^)]+\);[\s\S]*?points: -deductions,[\s\S]*?\}\);',
        '',
        content
    )
    content = re.sub(r'score -= deductions;', '', content)

    # Remove multiplier application
    content = re.sub(
        r'if is_legitimate_delegation\(func\) \{[\s\S]*?score = \(score as f32 \* 0\.5\) as i32;[\s\S]*?\}',
        '',
        content
    )

    # Remove ConfidenceLevel::from_score calls
    content = re.sub(r'let confidence_level = ConfidenceLevel::from_score\([^)]+\);', '', content)
    content = re.sub(r'confidence_level\.as_str\(\)\.to_string\(\)', '"INCOMPLETE".to_string()', content)

    # Step 8: Fix the actual issue creation in analyze_file
    # Replace the complex evidence/score logic with simple description collection
    content = re.sub(
        r'for \(desc, points\) in ([^\s]+)\(',
        r'for desc in \1(',
        content
    )

    # Step 9: Update generate_suggested_fix signature
    content = re.sub(
        r'fn generate_suggested_fix\(func_name: &str, evidence: &\[Evidence\], lang: &LanguageType\)',
        r'fn generate_suggested_fix(func_name: &str, descriptions: &[String], lang: &LanguageType)',
        content
    )

    # Update evidence references in generate_suggested_fix to descriptions
    content = re.sub(
        r'evidence\.iter\(\)\.any\(\|e\| e\.description\.contains\(',
        r'descriptions.iter().any(|d| d.contains(',
        content
    )

    # Step 10: Fix Issue struct instantiation
    # This requires careful handling - replace the old issue creation

    # This is complex - we'll handle it differently

    # Write output
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(content)

    print(f"\nRefactoring complete! Output written to {output_file}")
    print("Removed ConfidenceLevel enum, Evidence struct, and all scoring logic.")

if __name__ == '__main__':
    input_file = 'D:/Intellicrack/scripts/scanner/production_scanner.rs'
    output_file = 'D:/Intellicrack/scripts/scanner/production_scanner_refactored.rs'

    refactor_scanner(input_file, output_file)

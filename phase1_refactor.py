#!/usr/bin/env python3
"""P7 Phase 1: Remove ALL Scoring System from production_scanner.rs.

This script performs surgical refactoring to remove:
1. ConfidenceLevel enum
2. Evidence struct
3. Issue.confidence and Issue.evidence fields
4. calculate_deductions() function
5. All Vec<(String, i32)> -> Vec<String>
6. All scoring logic in analyze_file()
"""


def _delete_block(lines: list[str], start_pattern: str, end_marker: str, min_size: int = 1) -> tuple[list[str], str | None]:
    """Delete a code block from start pattern to end marker."""
    del_start = None
    del_end = None
    for i in range(len(lines)):
        if start_pattern in lines[i]:
            del_start = i
        if del_start is not None and lines[i].strip() == end_marker and i > del_start + min_size:
            del_end = i
            break

    if del_start is not None and del_end is not None:
        for _ in range(del_end - del_start + 1):
            lines.pop(del_start)
        if del_start < len(lines) and lines[del_start].strip() == '':
            lines.pop(del_start)
        return lines, f"Deleted block: lines {del_start+1}-{del_end+1}"
    return lines, None


def _delete_confidence_level_enum(lines: list[str]) -> tuple[list[str], list[str]]:
    """Delete ConfidenceLevel enum from lines."""
    changes = []
    for i in range(len(lines)):
        if '#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]' in lines[i]:
            if i + 1 < len(lines) and 'enum ConfidenceLevel {' in lines[i+1]:
                del_start = i
                del_end = None
                for j in range(i, len(lines)):
                    if lines[j].strip() == '}' and j > del_start + 45:
                        del_end = j
                        break
                if del_end:
                    changes.append(f"Deleted ConfidenceLevel enum: lines {del_start+1}-{del_end+1}")
                    for _ in range(del_end - del_start + 1):
                        lines.pop(del_start)
                    if del_start < len(lines) and lines[del_start].strip() == '':
                        lines.pop(del_start)
                    break
    return lines, changes


def _delete_evidence_struct(lines: list[str]) -> tuple[list[str], list[str]]:
    """Delete Evidence struct from lines."""
    changes = []
    for i in range(len(lines)):
        if '#[derive(Debug, Clone, Serialize, Deserialize)]' in lines[i]:
            if i + 1 < len(lines) and 'struct Evidence {' in lines[i+1]:
                del_start = i
                del_end = None
                for j in range(i, len(lines)):
                    if lines[j].strip() == '}' and j > del_start + 1:
                        del_end = j
                        break
                if del_end:
                    changes.append(f"Deleted Evidence struct: lines {del_start+1}-{del_end+1}")
                    for _ in range(del_end - del_start + 1):
                        lines.pop(del_start)
                    if del_start < len(lines) and lines[del_start].strip() == '':
                        lines.pop(del_start)
                    break
    return lines, changes


def _modify_issue_struct(lines: list[str]) -> tuple[list[str], list[str]]:
    """Remove confidence and evidence fields from Issue struct."""
    changes = []
    issue_start = None
    for i in range(len(lines)):
        if '#[derive(Debug, Clone, Serialize, Deserialize)]' in lines[i]:
            if i + 1 < len(lines) and 'struct Issue {' in lines[i+1]:
                issue_start = i + 1
                break

    if issue_start:
        i = issue_start
        while i < len(lines) and lines[i].strip() != '}':
            if 'confidence: i32' in lines[i] or 'evidence: Vec<Evidence>' in lines[i]:
                changes.append(f"Removed field from Issue struct at line {i+1}")
                lines.pop(i)
            else:
                i += 1
    return lines, changes


def _delete_calculate_deductions(lines: list[str]) -> tuple[list[str], list[str]]:
    """Delete calculate_deductions function."""
    changes = []
    del_start = None
    brace_count = 0

    for i in range(len(lines)):
        if 'fn calculate_deductions(func: &FunctionInfo, file_context: &FileContext) -> i32 {' in lines[i]:
            del_start = i
            brace_count = 1
            for j in range(i + 1, len(lines)):
                brace_count += lines[j].count('{') - lines[j].count('}')
                if brace_count == 0:
                    changes.append(f"Deleted calculate_deductions(): lines {del_start+1}-{j+1}")
                    for _ in range(j - del_start + 1):
                        lines.pop(del_start)
                    if del_start < len(lines) and lines[del_start].strip() == '':
                        lines.pop(del_start)
                    break
            break
    return lines, changes


def _process_simple_replacements(lines: list[str]) -> tuple[list[str], list[str]]:
    """Process simple string replacements across all lines."""
    changes = []
    vec_changes = 0
    push_changes = 0

    for i in range(len(lines)):
        if 'Vec<(String, i32)>' in lines[i]:
            lines[i] = lines[i].replace('Vec<(String, i32)>', 'Vec<String>')
            vec_changes += 1

        if 'issues.push((' in lines[i] and ', ' in lines[i]:
            before = lines[i].split('issues.push((')[0]
            rest = lines[i].split('issues.push((')[1]
            desc_part = rest.split(', ')[0]
            lines[i] = before + 'issues.push(' + desc_part + ');\n'
            push_changes += 1

    if vec_changes:
        changes.append(f"Changed {vec_changes} Vec signatures")
    if push_changes:
        changes.append(f"Changed {push_changes} issues.push() calls")
    return lines, changes


def _fix_analyze_file(lines: list[str]) -> tuple[list[str], list[str]]:  # noqa: C901
    """Fix analyze_file function to remove scoring logic."""
    changes = []
    analyze_start = None

    for i in range(len(lines)):
        if 'fn analyze_file(path: &Path, content: &str, lang: LanguageType) -> Vec<Issue> {' in lines[i]:
            analyze_start = i
            break

    if not analyze_start:
        return lines, changes

    i = analyze_start
    while i < len(lines):
        if i > analyze_start and lines[i].startswith('fn ') and not lines[i].strip().startswith('//'):
            break

        # Step 1: Delete ConfidenceLevel enum (lines 483-536)
    del_start = None
    del_end = None
    for i in range(len(lines)):
        if '#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]' in lines[i]:
            if i + 1 < len(lines) and 'enum ConfidenceLevel {' in lines[i+1]:
                del_start = i
        if del_start is not None and lines[i].strip() == '}' and i > del_start + 45:
            del_end = i
            break

    if del_start is not None and del_end is not None:
        changes.append(f"Deleted ConfidenceLevel enum: lines {del_start+1}-{del_end+1}")
        for _ in range(del_end - del_start + 1):
            lines.pop(del_start)
        # Remove blank line after
        if del_start < len(lines) and lines[del_start].strip() == '':
            lines.pop(del_start)

    # Step 2: Delete Evidence struct
    del_start = None
    del_end = None
    for i in range(len(lines)):
        if '#[derive(Debug, Clone, Serialize, Deserialize)]' in lines[i]:
            if i + 1 < len(lines) and 'struct Evidence {' in lines[i+1]:
                del_start = i
        if del_start is not None and lines[i].strip() == '}' and i > del_start + 1:
            del_end = i
            break

    if del_start is not None and del_end is not None:
        changes.append(f"Deleted Evidence struct: lines {del_start+1}-{del_end+1}")
        for _ in range(del_end - del_start + 1):
            lines.pop(del_start)
        # Remove blank line after
        if del_start < len(lines) and lines[del_start].strip() == '':
            lines.pop(del_start)

    # Step 3: Modify Issue struct - remove confidence and evidence fields
    issue_start = None
    for i in range(len(lines)):
        if '#[derive(Debug, Clone, Serialize, Deserialize)]' in lines[i]:
            if i + 1 < len(lines) and 'struct Issue {' in lines[i+1]:
                issue_start = i + 1
                break

    if issue_start:
        # Find and remove the two lines
        i = issue_start
        while i < len(lines) and lines[i].strip() != '}':
            if 'confidence: i32' in lines[i]:
                changes.append(f"Removed confidence field from Issue struct at line {i+1}")
                lines.pop(i)
                continue  # Don't increment i
            elif 'evidence: Vec<Evidence>' in lines[i]:
                changes.append(f"Removed evidence field from Issue struct at line {i+1}")
                lines.pop(i)
                continue  # Don't increment i
            i += 1

    # Step 4: Delete calculate_deductions function
    del_start = None
    del_end = None
    brace_count = 0
    in_function = False

    for i in range(len(lines)):
        if 'fn calculate_deductions(func: &FunctionInfo, file_context: &FileContext) -> i32 {' in lines[i]:
            del_start = i
            brace_count = 1
            in_function = True
            continue

        if in_function:
            brace_count += lines[i].count('{')
            brace_count -= lines[i].count('}')
            if brace_count == 0:
                del_end = i
                break

    if del_start is not None and del_end is not None:
        changes.append(f"Deleted calculate_deductions() function: lines {del_start+1}-{del_end+1} ({del_end - del_start + 1} lines)")
        for _ in range(del_end - del_start + 1):
            lines.pop(del_start)
        # Remove blank line after
        if del_start < len(lines) and lines[del_start].strip() == '':
            lines.pop(del_start)

    # Step 5: Change all Vec<(String, i32)> to Vec<String>
    vec_changes = 0
    for i in range(len(lines)):
        if 'Vec<(String, i32)>' in lines[i]:
            lines[i] = lines[i].replace('Vec<(String, i32)>', 'Vec<String>')
            vec_changes += 1
    changes.append(f"Changed {vec_changes} function signatures from Vec<(String, i32)> to Vec<String>")

    # Step 6: Change issues.push((desc, points)) to issues.push(desc)
    push_changes = 0
    for i in range(len(lines)):
        # Pattern: issues.push((something, number));
        if 'issues.push((' in lines[i] and ', ' in lines[i]:
            # Extract the description part before the comma
            before = lines[i].split('issues.push((')[0]
            rest = lines[i].split('issues.push((')[1]
            desc_part = rest.split(', ')[0]  # Get everything before first comma after (
            # Reconstruct without the points
            lines[i] = before + 'issues.push(' + desc_part + ');\n'
            push_changes += 1
    changes.append(f"Changed {push_changes} issues.push() calls to remove scoring")

    # Step 7: Fix analyze_file - remove evidence/score variables and logic
    # Find analyze_file function
    analyze_start = None
    for i in range(len(lines)):
        if 'fn analyze_file(path: &Path, content: &str, lang: LanguageType) -> Vec<Issue> {' in lines[i]:
            analyze_start = i
            break

    if analyze_start:
        # Within analyze_file, make targeted replacements
        i = analyze_start
        while i < len(lines):
            # Stop at next function definition
            if i > analyze_start and lines[i].startswith('fn ') and not lines[i].strip().startswith('//'):
                break

            # Replace evidence/score initialization
            if 'let mut evidence = Vec::new();' in lines[i]:
                lines[i] = lines[i].replace('let mut evidence = Vec::new();', 'let mut all_descriptions = Vec::new();')
                changes.append(f"Replaced evidence vec with all_descriptions at line {i+1}")

            if 'let mut score = 0;' in lines[i]:
                lines.pop(i)
                changes.append(f"Removed score initialization at line {i+1}")
                continue

            # Replace evidence.push(Evidence { ... }) with all_descriptions.push(desc)
            if 'evidence.push(Evidence {' in lines[i]:
                # This is multiline - need to handle specially
                # For now, replace the whole pattern in one line if possible
                if 'description: desc,' in lines[i] and 'points,' in lines[i]:
                    lines[i] = lines[i].split('evidence.push')[0] + 'all_descriptions.push(desc);\n'
                    changes.append(f"Replaced evidence.push with all_descriptions.push at line {i+1}")

            # Remove score += points lines
            if 'score += points;' in lines[i]:
                lines.pop(i)
                changes.append(f"Removed score accumulation at line {i+1}")
                continue

            # Remove deduction lines
            if 'let deductions = calculate_deductions' in lines[i]:
                lines.pop(i)
                changes.append(f"Removed deductions call at line {i+1}")
                continue

            if 'score -= deductions;' in lines[i]:
                lines.pop(i)
                changes.append(f"Removed deductions subtraction at line {i+1}")
                continue

            # Remove confidence level calculation
            if 'let confidence_level = ConfidenceLevel::from_score' in lines[i]:
                lines.pop(i)
                changes.append(f"Removed confidence_level calculation at line {i+1}")
                continue

            # Replace confidence_level.as_str() with "INCOMPLETE"
            if 'confidence_level.as_str().to_string()' in lines[i]:
                lines[i] = lines[i].replace('confidence_level.as_str().to_string()', '"INCOMPLETE".to_string()')
                changes.append(f"Replaced confidence_level with INCOMPLETE at line {i+1}")

            # Change for (desc, points) in to for desc in
            if 'for (desc, points) in ' in lines[i]:
                lines[i] = lines[i].replace('for (desc, points) in ', 'for desc in ')
                changes.append(f"Changed for loop to unpack single value at line {i+1}")

            i += 1

    # Step 8: Update generate_suggested_fix signature and body
    for i in range(len(lines)):
        if 'fn generate_suggested_fix(func_name: &str, evidence: &[Evidence], lang: &LanguageType)' in lines[i]:
            lines[i] = lines[i].replace('evidence: &[Evidence]', 'descriptions: &[String]')
            changes.append(f"Updated generate_suggested_fix signature at line {i+1}")

        # Update evidence.iter() calls to descriptions.iter()
        if 'evidence.iter().any(|e| e.description.contains(' in lines[i]:
            lines[i] = lines[i].replace('evidence.iter().any(|e| e.description.contains(', 'descriptions.iter().any(|d| d.contains(')
            changes.append(f"Updated evidence iteration to descriptions at line {i+1}")

    # Write output
    with open(output_path, 'w', encoding='utf-8') as f:
        f.writelines(lines)

    print("=" * 80)
    print("P7 PHASE 1 REFACTORING COMPLETE")
    print("=" * 80)
    for change in changes:
        print(f"✓ {change}")
    print("=" * 80)
    print(f"Total changes: {len(changes)}")
    print(f"Output written to: {output_path}")

if __name__ == '__main__':
    main()

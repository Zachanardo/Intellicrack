#!/usr/bin/env python3
"""Fix the analyze_file function in production_scanner.rs after Phase 1 refactoring."""

def main() -> None:
    """Fix analyze_file function by replacing Evidence struct with Vec<String>.

    Performs surgical string replacement in production_scanner.rs to convert
    Evidence-based code to simple string vector operations after Phase 1 refactoring.
    """
    filepath = r'D:\Intellicrack\scripts\scanner\production_scanner.rs'

    with open(filepath, encoding='utf-8') as f:
        content = f.read()

    # Replace Evidence struct pushes with simple Vec<String> pushes
    # Pattern: evidence.push(Evidence { description: desc, points, });
    # Replace with: all_descriptions.push(desc);
    content = content.replace(
        '''evidence.push(Evidence {
                description: desc,
                points,
            });
            score += points;''',
        'all_descriptions.push(desc);'
    )

    # Replace the variable declarations
    content = content.replace(
        '        let mut evidence = Vec::new();\n        let mut score = 0;',
        '        let mut all_descriptions = Vec::new();'
    )

    # Remove score-related lines that remain
    lines = content.split('\n')
    new_lines = []
    i = 0
    while i < len(lines):
        line = lines[i]

        # Skip lines with deductions/multipliers
        if 'let deductions = calculate_deductions' in line:
            i += 1
            continue
        if 'score -= deductions;' in line:
            i += 1
            continue
        if 'if deductions > 0 {' in line:
            # Skip the entire deductions block
            brace_count = 1
            i += 1
            while i < len(lines) and brace_count > 0:
                if '{' in lines[i]:
                    brace_count += lines[i].count('{')
                if '}' in lines[i]:
                    brace_count -= lines[i].count('}')
                i += 1
            continue

        # Skip multiplier blocks
        if 'Apply pattern-based confidence multipliers' in line:
            i += 1
            continue
        if 'if is_legitimate_delegation(func) {' in line and i + 1 < len(lines) and 'score = (score as f32' in lines[i + 1]:
            # Skip the multiplier if-else chain
            while i < len(lines) and not (lines[i].strip() == '}' and 'if is_' not in lines[i+1] if i+1 < len(lines) else True):
                i += 1
            i += 1  # Skip the final closing brace
            continue

        # Replace confidence_level references
        if 'let confidence_level = ConfidenceLevel::from_score(score);' in line:
            i += 1
            continue
        if 'confidence_level.as_str().to_string()' in line:
            new_lines.append(line.replace('confidence_level.as_str().to_string()', '"INCOMPLETE".to_string()'))
            i += 1
            continue

        # Fix the threshold check
        if 'if score >= 0 && !evidence.is_empty() {' in line:
            new_lines.append(line.replace('score >= 0 && !evidence.is_empty()', '!all_descriptions.is_empty()'))
            i += 1
            continue

        # Fix evidence references in issue_type determination
        if 'let issue_type = if evidence' in line:
            # Start of issue_type block - rewrite it
            new_lines.append('            let issue_type = if all_descriptions')
            i += 1
            # Continue until we hit the actual closing of this if-else
            while i < len(lines):
                if '.any(|e| e.description.contains(' in lines[i]:
                    new_lines.append(lines[i].replace('|e| e.description.contains(', '|d| d.contains('))
                elif '} else if evidence.iter()' in lines[i]:
                    new_lines.append(lines[i].replace('evidence.iter()', 'all_descriptions.iter()'))
                elif lines[i].strip() == '};' and 'issue_type' not in lines[i-1]:
                    new_lines.append(lines[i])
                    i += 1
                    break
                else:
                    new_lines.append(lines[i])
                i += 1
            continue

        # Fix description creation
        if 'let description = if evidence.len() == 1 {' in line:
            new_lines.append('            let description = if all_descriptions.len() == 1 {')
            i += 1
            continue
        if 'evidence[0].description.clone()' in line:
            new_lines.append(line.replace('evidence[0].description.clone()', 'all_descriptions[0].clone()'))
            i += 1
            continue
        if 'format!("{} production issues detected", evidence.len())' in line:
            new_lines.append(line.replace('evidence.len()', 'all_descriptions.len()'))
            i += 1
            continue

        # Fix generate_suggested_fix call
        if 'let suggested_fix = generate_suggested_fix(&func.name, &evidence, &lang);' in line:
            new_lines.append(line.replace('&evidence', '&all_descriptions'))
            i += 1
            continue

        # Fix Issue struct creation - remove confidence and evidence fields
        if 'severity: confidence_level.as_str().to_string(),' in line:
            new_lines.append(line.replace('confidence_level.as_str().to_string()', '"INCOMPLETE".to_string()'))
            i += 1
            continue
        if 'confidence: score,' in line:
            # Skip this line entirely
            i += 1
            continue
        if 'evidence,' in line and 'all_issues.push(Issue {' in '\n'.join(lines[max(0, i-10):i]):
            # Skip the evidence field in Issue creation
            i += 1
            continue

        # Default: keep the line
        new_lines.append(line)
        i += 1

    content = '\n'.join(new_lines)

    # Write back
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)

    print("Fixed analyze_file function")

if __name__ == '__main__':
    main()

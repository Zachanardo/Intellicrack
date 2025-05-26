#!/usr/bin/env python3
"""Analyze the largest functions to see if they contain nested functions or missing implementations."""

import re
import os

def analyze_large_function(content, func_name, start_line, end_line):
    """Analyze a large function for nested functions and code patterns."""
    lines = content.splitlines()
    func_lines = lines[start_line-1:end_line]
    func_content = '\n'.join(func_lines)
    
    analysis = {
        'name': func_name,
        'start_line': start_line,
        'end_line': end_line,
        'size': len(func_lines),
        'nested_functions': [],
        'nested_classes': [],
        'if_elif_blocks': 0,
        'try_except_blocks': 0,
        'while_loops': 0,
        'for_loops': 0,
        'large_string_blocks': 0,
        'code_sections': []
    }
    
    # Find nested functions
    for i, line in enumerate(func_lines):
        stripped = line.strip()
        
        # Nested function definitions
        nested_func_match = re.match(r'\s+def\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(', line)
        if nested_func_match:
            nested_name = nested_func_match.group(1)
            analysis['nested_functions'].append({
                'name': nested_name,
                'line': start_line + i,
                'indent': len(line) - len(line.lstrip())
            })
        
        # Nested classes
        nested_class_match = re.match(r'\s+class\s+([a-zA-Z_][a-zA-Z0-9_]*)', line)
        if nested_class_match:
            nested_name = nested_class_match.group(1)
            analysis['nested_classes'].append({
                'name': nested_name,
                'line': start_line + i
            })
        
        # Count control structures
        if re.match(r'\s*if\s+.*:', stripped) or re.match(r'\s*elif\s+.*:', stripped):
            analysis['if_elif_blocks'] += 1
        elif re.match(r'\s*try\s*:', stripped):
            analysis['try_except_blocks'] += 1
        elif re.match(r'\s*while\s+.*:', stripped):
            analysis['while_loops'] += 1
        elif re.match(r'\s*for\s+.*:', stripped):
            analysis['for_loops'] += 1
    
    # Look for large string blocks (could be embedded code)
    string_blocks = re.findall(r'["\'][\s\S]{200,}["\']', func_content)
    analysis['large_string_blocks'] = len(string_blocks)
    
    # Look for code sections that could be separate functions
    if_blocks = list(re.finditer(r'if\s+.*?=="([^"]+)".*?:', func_content))
    for match in if_blocks[:10]:  # First 10
        condition = match.group(1)
        analysis['code_sections'].append(f"Condition: {condition}")
    
    return analysis

def main():
    monolith_path = "Intellicrack.py"
    
    with open(monolith_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
    
    lines = content.splitlines()
    
    # Find the largest functions
    large_functions = [
        ('run_plugin_remotely', 38221, 38221 + 6103),
        ('register', 44325, 44325 + 6052),
        ('calculate_entropy', 2489, 2489 + 5782),
        ('process_distributed_results', 24973, 24973 + 2826),
        ('generate_complete_api_hooking_script', 11583, 11583 + 1956),
        ('run_network_license_server', 13540, 13540 + 1671),
        ('run_report_generation', 23205, 23205 + 1560),
        ('run_enhanced_protection_scan', 17883, 17883 + 1355),
        ('run_analysis_manager', 35439, 35439 + 1116),
        ('run_multi_format_analysis', 22215, 22215 + 989)
    ]
    
    print("=== ANALYSIS OF LARGEST FUNCTIONS ===\n")
    
    total_nested_functions = 0
    all_nested_functions = []
    
    for func_name, start_line, end_line in large_functions:
        print(f"Analyzing {func_name} ({end_line - start_line} lines)...")
        
        analysis = analyze_large_function(content, func_name, start_line, end_line)
        
        print(f"  Nested functions: {len(analysis['nested_functions'])}")
        print(f"  Nested classes: {len(analysis['nested_classes'])}")
        print(f"  If/elif blocks: {analysis['if_elif_blocks']}")
        print(f"  Try/except blocks: {analysis['try_except_blocks']}")
        print(f"  While loops: {analysis['while_loops']}")
        print(f"  For loops: {analysis['for_loops']}")
        print(f"  Large string blocks: {analysis['large_string_blocks']}")
        
        if analysis['nested_functions']:
            print("  Nested function names:")
            for nested in analysis['nested_functions']:
                print(f"    - {nested['name']} (line {nested['line']})")
                all_nested_functions.append(nested['name'])
        
        if analysis['nested_classes']:
            print("  Nested class names:")
            for nested in analysis['nested_classes']:
                print(f"    - {nested['name']} (line {nested['line']})")
        
        if analysis['code_sections']:
            print("  Code sections:")
            for section in analysis['code_sections'][:5]:
                print(f"    - {section}")
        
        total_nested_functions += len(analysis['nested_functions'])
        print()
    
    print(f"=== SUMMARY ===")
    print(f"Total nested functions found: {total_nested_functions}")
    print(f"All nested function names: {all_nested_functions}")
    
    # Check if these nested functions are implemented in our modular structure
    print(f"\n=== CHECKING NESTED FUNCTIONS IN MODULAR STRUCTURE ===")
    
    modular_functions = set()
    for root, dirs, files in os.walk('intellicrack'):
        dirs[:] = [d for d in dirs if d != '__pycache__']
        for file in files:
            if file.endswith('.py'):
                filepath = os.path.join(root, file)
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        content = f.read()
                    
                    for match in re.finditer(r'^\s*def\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(', content, re.MULTILINE):
                        func_name = match.group(1)
                        modular_functions.add(func_name)
                except:
                    pass
    
    missing_nested = []
    for nested_name in all_nested_functions:
        if nested_name not in modular_functions:
            missing_nested.append(nested_name)
    
    print(f"Missing nested functions: {len(missing_nested)}")
    if missing_nested:
        print("Missing nested functions:")
        for name in missing_nested:
            print(f"  - {name}")
    else:
        print("✅ All nested functions are implemented!")
    
    # Look for patterns in the largest function
    print(f"\n=== DETAILED ANALYSIS OF run_plugin_remotely ===")
    start_line = 38221
    end_line = 38221 + 6103
    func_lines = lines[start_line-1:end_line]
    
    # Look for major code sections
    major_sections = []
    current_section = None
    section_start = None
    
    for i, line in enumerate(func_lines):
        stripped = line.strip()
        
        # Look for major conditional blocks or sections
        if re.match(r'if\s+.*=="[^"]+"\s*:', stripped):
            if current_section:
                major_sections.append((current_section, section_start, i))
            
            condition = re.search(r'"([^"]+)"', stripped)
            current_section = condition.group(1) if condition else f"condition_{i}"
            section_start = i
        elif re.match(r'^\s*def\s+', line):
            if current_section:
                major_sections.append((current_section, section_start, i))
                current_section = None
    
    if current_section:
        major_sections.append((current_section, section_start, len(func_lines)))
    
    print(f"Major sections in run_plugin_remotely:")
    for section_name, start, end in major_sections[:15]:  # First 15
        print(f"  {section_name}: lines {start_line + start} - {start_line + end} ({end - start} lines)")

if __name__ == '__main__':
    main()
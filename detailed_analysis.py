#!/usr/bin/env python3
"""More detailed analysis to find any missing patterns or large function blocks."""

import re
import os
from collections import defaultdict

def analyze_monolith_in_detail():
    """Detailed analysis of the monolithic file."""
    monolith_path = "Intellicrack.py"
    
    with open(monolith_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
    
    lines = content.splitlines()
    print(f"Analyzing {len(lines)} lines...")
    
    # Find all function definitions with more context
    functions = []
    classes = []
    current_class = None
    
    for line_num, line in enumerate(lines, 1):
        stripped = line.strip()
        
        # Track classes
        class_match = re.match(r'class\s+([a-zA-Z_][a-zA-Z0-9_]*)', stripped)
        if class_match:
            class_name = class_match.group(1)
            classes.append({
                'name': class_name,
                'line': line_num,
                'methods': []
            })
            current_class = class_name
            continue
        
        # Track functions/methods
        func_match = re.match(r'def\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(', stripped)
        if func_match:
            func_name = func_match.group(1)
            
            # Determine the indentation level to know if it's a method
            indent = len(line) - len(line.lstrip())
            is_method = indent > 0
            
            func_info = {
                'name': func_name,
                'line': line_num,
                'is_method': is_method,
                'class': current_class if is_method else None,
                'indent': indent,
                'full_line': line
            }
            functions.append(func_info)
            
            # Add to current class if it's a method
            if is_method and classes:
                classes[-1]['methods'].append(func_name)
    
    print(f"Found {len(classes)} classes and {len(functions)} functions")
    
    # Analyze function distribution
    methods = [f for f in functions if f['is_method']]
    standalone = [f for f in functions if not f['is_method']]
    
    print(f"  - Standalone functions: {len(standalone)}")
    print(f"  - Class methods: {len(methods)}")
    
    # Show class breakdown
    print(f"\nClass breakdown:")
    for cls in classes:
        print(f"  {cls['name']}: {len(cls['methods'])} methods (line {cls['line']})")
    
    # Look for large function blocks (potential missing implementations)
    print(f"\nAnalyzing function sizes...")
    large_functions = []
    
    for i, func in enumerate(functions):
        start_line = func['line']
        # Find end of function (next function or class, or end of file)
        end_line = len(lines)
        
        for j in range(i + 1, len(functions)):
            next_func = functions[j]
            if next_func['indent'] <= func['indent']:
                end_line = next_func['line'] - 1
                break
        
        func_size = end_line - start_line
        func['size'] = func_size
        
        if func_size > 100:  # Functions larger than 100 lines
            large_functions.append(func)
    
    print(f"Found {len(large_functions)} functions > 100 lines:")
    for func in sorted(large_functions, key=lambda x: x['size'], reverse=True)[:10]:
        class_part = f" (in {func['class']})" if func['class'] else ""
        print(f"  {func['name']}{class_part}: {func['size']} lines (line {func['line']})")
    
    return functions, classes

def check_specific_patterns():
    """Check for specific patterns that might indicate missing functionality."""
    monolith_path = "Intellicrack.py"
    
    with open(monolith_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
    
    # Look for patterns that might not be captured as functions
    patterns = {
        'lambdas': r'lambda\s+[^:]+:',
        'signal_connections': r'\.connect\(',
        'thread_targets': r'target\s*=\s*([a-zA-Z_][a-zA-Z0-9_]*)',
        'callbacks': r'callback\s*=\s*([a-zA-Z_][a-zA-Z0-9_]*)',
        'getattr_calls': r'getattr\([^,]+,\s*[\'"]([a-zA-Z_][a-zA-Z0-9_]*)[\'"]',
        'exec_calls': r'exec\(',
        'eval_calls': r'eval\(',
        'setattr_calls': r'setattr\(',
    }
    
    print(f"\nPattern analysis:")
    for pattern_name, pattern in patterns.items():
        matches = re.findall(pattern, content)
        print(f"  {pattern_name}: {len(matches)} occurrences")
        if matches and pattern_name in ['thread_targets', 'callbacks', 'getattr_calls']:
            unique_matches = set(matches)
            print(f"    Unique references: {len(unique_matches)}")
            if len(unique_matches) < 20:
                print(f"    {list(unique_matches)}")

def main():
    print("=== DETAILED MONOLITH ANALYSIS ===\n")
    
    functions, classes = analyze_monolith_in_detail()
    check_specific_patterns()
    
    # Compare with our implemented functions
    print(f"\n=== COMPARISON WITH MODULAR STRUCTURE ===")
    
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
    
    monolith_function_names = {f['name'] for f in functions}
    
    missing_from_modular = monolith_function_names - modular_functions
    extra_in_modular = modular_functions - monolith_function_names
    
    print(f"Monolith functions: {len(monolith_function_names)}")
    print(f"Modular functions: {len(modular_functions)}")
    print(f"Missing from modular: {len(missing_from_modular)}")
    print(f"Extra in modular: {len(extra_in_modular)}")
    
    if missing_from_modular:
        print(f"\nMissing functions:")
        for func_name in sorted(missing_from_modular):
            # Find the function info
            func_info = next((f for f in functions if f['name'] == func_name), None)
            if func_info:
                class_info = f" (in {func_info['class']})" if func_info['class'] else ""
                print(f"  {func_name}{class_info} - line {func_info['line']}")
    
    if extra_in_modular:
        print(f"\nExtra functions in modular (first 20):")
        for func_name in sorted(extra_in_modular)[:20]:
            print(f"  {func_name}")
        if len(extra_in_modular) > 20:
            print(f"  ... and {len(extra_in_modular) - 20} more")

if __name__ == '__main__':
    main()
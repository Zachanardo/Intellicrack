#!/usr/bin/env python3
"""Final comprehensive check to find what's actually missing."""

import re
import os
from collections import defaultdict

def extract_all_monolith_functions():
    """Extract ALL functions from monolith including nested ones."""
    monolith_path = "Intellicrack.py"
    
    with open(monolith_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
    
    lines = content.splitlines()
    
    all_functions = []
    
    # Find all function definitions regardless of indentation
    for line_num, line in enumerate(lines, 1):
        # Match any function definition with any indentation
        match = re.match(r'(\s*)def\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(', line)
        if match:
            indent = len(match.group(1))
            func_name = match.group(2)
            
            all_functions.append({
                'name': func_name,
                'line': line_num,
                'indent': indent,
                'is_nested': indent > 0
            })
    
    return all_functions

def extract_all_modular_functions():
    """Extract ALL functions from modular structure."""
    all_functions = set()
    
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
                        all_functions.add(func_name)
                except:
                    pass
    
    return all_functions

def main():
    print("=== FINAL COMPREHENSIVE MISSING FUNCTION CHECK ===\n")
    
    # Extract from monolith
    monolith_functions = extract_all_monolith_functions()
    monolith_names = [f['name'] for f in monolith_functions]
    
    print(f"Monolith analysis:")
    print(f"  Total function definitions: {len(monolith_functions)}")
    
    # Count top-level vs nested
    top_level = [f for f in monolith_functions if not f['is_nested']]
    nested = [f for f in monolith_functions if f['is_nested']]
    
    print(f"  Top-level functions: {len(top_level)}")
    print(f"  Nested functions: {len(nested)}")
    
    # Unique names
    unique_monolith_names = set(monolith_names)
    print(f"  Unique function names: {len(unique_monolith_names)}")
    
    # Extract from modular
    modular_functions = extract_all_modular_functions()
    
    print(f"\nModular structure:")
    print(f"  Unique function names: {len(modular_functions)}")
    
    # Find missing
    missing_functions = unique_monolith_names - modular_functions
    extra_functions = modular_functions - unique_monolith_names
    
    print(f"\nComparison:")
    print(f"  Missing from modular: {len(missing_functions)}")
    print(f"  Extra in modular: {len(extra_functions)}")
    
    if missing_functions:
        print(f"\n=== MISSING FUNCTIONS ({len(missing_functions)}) ===")
        
        # Group missing functions by where they appear in monolith
        missing_with_context = []
        for func_info in monolith_functions:
            if func_info['name'] in missing_functions:
                missing_with_context.append(func_info)
        
        # Sort by line number
        missing_with_context.sort(key=lambda x: x['line'])
        
        # Categorize
        ui_functions = []
        analysis_functions = []
        private_functions = []
        event_handlers = []
        other_functions = []
        
        for func_info in missing_with_context:
            name = func_info['name']
            
            if name.startswith('_'):
                private_functions.append(func_info)
            elif any(x in name for x in ['ui', 'setup_', 'create_', 'show_', 'update_', 'on_', 'handle_']):
                if name.startswith('on_') or 'event' in name or 'click' in name:
                    event_handlers.append(func_info)
                else:
                    ui_functions.append(func_info)
            elif any(x in name for x in ['analyze', 'scan', 'detect', 'run_', 'process_']):
                analysis_functions.append(func_info)
            else:
                other_functions.append(func_info)
        
        categories = [
            ("UI Functions", ui_functions),
            ("Event Handlers", event_handlers),
            ("Analysis Functions", analysis_functions),
            ("Private Functions", private_functions),
            ("Other Functions", other_functions)
        ]
        
        for cat_name, funcs in categories:
            if funcs:
                print(f"\n{cat_name} ({len(funcs)}):")
                for func_info in funcs[:15]:  # Show first 15
                    nested_info = " (nested)" if func_info['is_nested'] else ""
                    print(f"  Line {func_info['line']:5d}: {func_info['name']}{nested_info}")
                if len(funcs) > 15:
                    print(f"  ... and {len(funcs) - 15} more")
        
        # Write to file for analysis
        with open('truly_missing_functions.txt', 'w') as f:
            f.write(f"=== TRULY MISSING FUNCTIONS ===\n\n")
            f.write(f"Total missing: {len(missing_functions)}\n\n")
            
            for cat_name, funcs in categories:
                if funcs:
                    f.write(f"{cat_name} ({len(funcs)}):\n")
                    for func_info in funcs:
                        nested_info = " (nested)" if func_info['is_nested'] else ""
                        f.write(f"  Line {func_info['line']:5d}: {func_info['name']}{nested_info}\n")
                    f.write("\n")
        
        print(f"\nDetailed missing functions written to truly_missing_functions.txt")
    
    else:
        print(f"\n🎉 ALL FUNCTIONS FROM MONOLITH ARE IMPLEMENTED! 🎉")
    
    # Show some statistics about extra functions
    if extra_functions:
        print(f"\nExtra functions in modular (improvements):")
        extra_list = sorted(extra_functions)
        for func in extra_list[:20]:
            print(f"  {func}")
        if len(extra_functions) > 20:
            print(f"  ... and {len(extra_functions) - 20} more")

if __name__ == '__main__':
    main()
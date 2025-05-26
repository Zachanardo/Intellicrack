#!/usr/bin/env python3
"""Comprehensive function analysis to find ALL functions in the monolithic file."""

import re
import os
from pathlib import Path

def extract_all_functions_from_monolith():
    """Extract ALL function definitions from the monolithic Intellicrack.py file."""
    monolith_path = "Intellicrack.py"
    
    if not os.path.exists(monolith_path):
        print(f"Error: {monolith_path} not found!")
        return []
    
    print(f"Analyzing {monolith_path}...")
    
    with open(monolith_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
    
    print(f"File size: {len(content)} characters, {len(content.splitlines())} lines")
    
    # Find all function definitions
    functions = []
    
    # Pattern for function definitions (including methods)
    function_pattern = r'^\s*def\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\('
    
    for line_num, line in enumerate(content.splitlines(), 1):
        match = re.match(function_pattern, line)
        if match:
            func_name = match.group(1)
            functions.append({
                'name': func_name,
                'line': line_num,
                'definition': line.strip()
            })
    
    print(f"Found {len(functions)} function definitions in monolith")
    return functions

def extract_all_functions_from_modular():
    """Extract ALL function definitions from the modular structure."""
    functions = set()
    
    # Find all Python files in the intellicrack directory
    python_files = []
    for root, dirs, files in os.walk('intellicrack'):
        # Skip __pycache__ directories
        dirs[:] = [d for d in dirs if d != '__pycache__']
        for file in files:
            if file.endswith('.py'):
                python_files.append(os.path.join(root, file))
    
    print(f"Scanning {len(python_files)} Python files in modular structure...")
    
    for py_file in python_files:
        try:
            with open(py_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Find function definitions
            function_pattern = r'^\s*def\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\('
            for match in re.finditer(function_pattern, content, re.MULTILINE):
                func_name = match.group(1)
                functions.add(func_name)
                
        except Exception as e:
            print(f"Error reading {py_file}: {e}")
    
    print(f"Found {len(functions)} unique functions in modular structure")
    return functions

def main():
    print("=== COMPREHENSIVE FUNCTION ANALYSIS ===\n")
    
    # Extract from monolith
    monolith_functions = extract_all_functions_from_monolith()
    monolith_names = [f['name'] for f in monolith_functions]
    
    # Extract from modular
    modular_functions = extract_all_functions_from_modular()
    
    # Find missing functions
    missing_functions = []
    for func_info in monolith_functions:
        func_name = func_info['name']
        if func_name not in modular_functions:
            missing_functions.append(func_info)
    
    print(f"\n=== RESULTS ===")
    print(f"Monolith functions: {len(monolith_functions)}")
    print(f"Modular functions: {len(modular_functions)}")
    print(f"Missing functions: {len(missing_functions)}")
    print(f"Coverage: {(len(monolith_functions) - len(missing_functions)) / len(monolith_functions) * 100:.1f}%")
    
    if missing_functions:
        print(f"\n=== MISSING FUNCTIONS ({len(missing_functions)}) ===")
        
        # Categorize missing functions
        ui_methods = []
        init_methods = []
        event_handlers = []
        private_methods = []
        setup_methods = []
        callback_methods = []
        other_methods = []
        
        for func_info in missing_functions:
            name = func_info['name']
            line = func_info['line']
            
            if name == '__init__':
                init_methods.append((name, line))
            elif name.startswith('on_') or name.endswith('_callback') or name.endswith('_finished'):
                callback_methods.append((name, line))
            elif name.startswith('setup_') or name.startswith('init_'):
                setup_methods.append((name, line))
            elif any(x in name for x in ['event', 'click', 'changed', 'pressed', 'selected']):
                event_handlers.append((name, line))
            elif name.startswith('_'):
                private_methods.append((name, line))
            elif any(x in name for x in ['ui', 'widget', 'dialog', 'window', 'tab', 'menu']):
                ui_methods.append((name, line))
            else:
                other_methods.append((name, line))
        
        categories = [
            ("Initialization Methods", init_methods),
            ("UI Methods", ui_methods),
            ("Event Handlers", event_handlers),
            ("Setup Methods", setup_methods),
            ("Callback Methods", callback_methods),
            ("Private Methods", private_methods),
            ("Other Methods", other_methods)
        ]
        
        for category_name, methods in categories:
            if methods:
                print(f"\n{category_name} ({len(methods)}):")
                for name, line in sorted(methods)[:20]:  # Show first 20
                    print(f"  Line {line:5d}: {name}")
                if len(methods) > 20:
                    print(f"  ... and {len(methods) - 20} more")
        
        # Write detailed missing functions to file
        with open('detailed_missing_functions.txt', 'w') as f:
            f.write(f"=== DETAILED MISSING FUNCTIONS ANALYSIS ===\n\n")
            f.write(f"Total missing: {len(missing_functions)}\n\n")
            
            for category_name, methods in categories:
                if methods:
                    f.write(f"{category_name} ({len(methods)}):\n")
                    for name, line in sorted(methods):
                        f.write(f"  Line {line:5d}: {name}\n")
                    f.write("\n")
            
            f.write("=== ALL MISSING FUNCTIONS (by line number) ===\n")
            for func_info in sorted(missing_functions, key=lambda x: x['line']):
                f.write(f"Line {func_info['line']:5d}: {func_info['name']}\n")
                f.write(f"    {func_info['definition']}\n\n")
        
        print(f"\nDetailed analysis written to detailed_missing_functions.txt")
    
    else:
        print("\n🎉 ALL FUNCTIONS IMPLEMENTED! 🎉")
    
    # Also show some statistics about monolith functions
    print(f"\n=== MONOLITH FUNCTION STATISTICS ===")
    
    # Count by prefix
    prefixes = {}
    for func_info in monolith_functions:
        name = func_info['name']
        if name.startswith('_'):
            prefix = 'private'
        elif name.startswith('on_'):
            prefix = 'event_handler'
        elif name.startswith('setup_'):
            prefix = 'setup'
        elif name.startswith('run_'):
            prefix = 'runner'
        elif name == '__init__':
            prefix = 'constructor'
        else:
            prefix = 'public'
        
        prefixes[prefix] = prefixes.get(prefix, 0) + 1
    
    for prefix, count in sorted(prefixes.items()):
        print(f"  {prefix}: {count}")

if __name__ == '__main__':
    main()
#!/usr/bin/env python3
"""Check which functions from truly_missing_functions.txt are actually missing."""

import os
import re
from pathlib import Path

# Read the list of functions
with open('truly_missing_functions.txt', 'r') as f:
    all_functions = [line.strip() for line in f if line.strip()]

# Remove line numbers from the function list
functions = []
for line in all_functions:
    parts = line.split('\t')
    if len(parts) > 1:
        functions.append(parts[1])
    else:
        functions.append(line)

print(f"Total functions to check: {len(functions)}")

# Find all Python files in the project
python_files = []
for root, dirs, files in os.walk('intellicrack'):
    # Skip __pycache__ directories
    dirs[:] = [d for d in dirs if d != '__pycache__']
    for file in files:
        if file.endswith('.py'):
            python_files.append(os.path.join(root, file))

print(f"Found {len(python_files)} Python files")

# Check which functions exist
found_functions = set()
function_locations = {}

for py_file in python_files:
    try:
        with open(py_file, 'r', encoding='utf-8') as f:
            content = f.read()
            
        # Find function definitions
        for match in re.finditer(r'^\s*def\s+(\w+)\s*\(', content, re.MULTILINE):
            func_name = match.group(1)
            if func_name in functions:
                found_functions.add(func_name)
                if func_name not in function_locations:
                    function_locations[func_name] = []
                function_locations[func_name].append(py_file)
                
        # Also check for class methods that might be missing
        for match in re.finditer(r'^\s*def\s+(\w+)\s*\(self', content, re.MULTILINE):
            func_name = match.group(1)
            if func_name in functions:
                found_functions.add(func_name)
                if func_name not in function_locations:
                    function_locations[func_name] = []
                function_locations[func_name].append(py_file)
    except Exception as e:
        print(f"Error reading {py_file}: {e}")

# Find truly missing functions
missing_functions = [f for f in functions if f not in found_functions]

print(f"\nFound {len(found_functions)} functions")
print(f"Missing {len(missing_functions)} functions")

# Categorize missing functions
ui_functions = []
internal_helpers = []
thread_functions = []
handler_functions = []
analysis_functions = []
patch_functions = []
report_functions = []
other_functions = []

for func in sorted(missing_functions):
    if func.startswith('_'):
        internal_helpers.append(func)
    elif 'thread' in func.lower() or '_thread' in func:
        thread_functions.append(func)
    elif 'handle_' in func or 'handler' in func or 'do_GET' in func or 'do_POST' in func:
        handler_functions.append(func)
    elif any(x in func for x in ['ui', 'dialog', 'widget', 'menu', 'tab', 'browse_', 'show_', 'open_', 'setup_', 'update_', 'refresh_', 'clear_', 'toggle_']):
        ui_functions.append(func)
    elif any(x in func for x in ['analyze', 'scan', 'detect', 'check', 'monitor']):
        analysis_functions.append(func)
    elif any(x in func for x in ['patch', 'apply', 'revert', 'rewrite']):
        patch_functions.append(func)
    elif any(x in func for x in ['report', 'format', 'export']):
        report_functions.append(func)
    else:
        other_functions.append(func)

print("\n=== MISSING FUNCTIONS BY CATEGORY ===")
print(f"\nUI Functions ({len(ui_functions)}):")
for f in ui_functions[:10]:  # Show first 10
    print(f"  - {f}")
if len(ui_functions) > 10:
    print(f"  ... and {len(ui_functions) - 10} more")

print(f"\nInternal Helpers ({len(internal_helpers)}):")
for f in internal_helpers[:10]:
    print(f"  - {f}")
if len(internal_helpers) > 10:
    print(f"  ... and {len(internal_helpers) - 10} more")

print(f"\nThread Functions ({len(thread_functions)}):")
for f in thread_functions:
    print(f"  - {f}")

print(f"\nHandler Functions ({len(handler_functions)}):")
for f in handler_functions[:10]:
    print(f"  - {f}")
if len(handler_functions) > 10:
    print(f"  ... and {len(handler_functions) - 10} more")

print(f"\nAnalysis Functions ({len(analysis_functions)}):")
for f in analysis_functions:
    print(f"  - {f}")

print(f"\nPatch Functions ({len(patch_functions)}):")
for f in patch_functions:
    print(f"  - {f}")

print(f"\nReport Functions ({len(report_functions)}):")
for f in report_functions:
    print(f"  - {f}")

print(f"\nOther Functions ({len(other_functions)}):")
for f in other_functions[:20]:
    print(f"  - {f}")
if len(other_functions) > 20:
    print(f"  ... and {len(other_functions) - 20} more")

# Write truly missing functions to a file
with open('actually_missing_functions.txt', 'w') as f:
    f.write("=== ACTUALLY MISSING FUNCTIONS ===\n\n")
    f.write(f"Total missing: {len(missing_functions)}\n\n")
    
    f.write(f"UI Functions ({len(ui_functions)}):\n")
    for func in ui_functions:
        f.write(f"  {func}\n")
    
    f.write(f"\nInternal Helpers ({len(internal_helpers)}):\n")
    for func in internal_helpers:
        f.write(f"  {func}\n")
    
    f.write(f"\nThread Functions ({len(thread_functions)}):\n")
    for func in thread_functions:
        f.write(f"  {func}\n")
    
    f.write(f"\nHandler Functions ({len(handler_functions)}):\n")
    for func in handler_functions:
        f.write(f"  {func}\n")
    
    f.write(f"\nAnalysis Functions ({len(analysis_functions)}):\n")
    for func in analysis_functions:
        f.write(f"  {func}\n")
    
    f.write(f"\nPatch Functions ({len(patch_functions)}):\n")
    for func in patch_functions:
        f.write(f"  {func}\n")
    
    f.write(f"\nReport Functions ({len(report_functions)}):\n")
    for func in report_functions:
        f.write(f"  {func}\n")
    
    f.write(f"\nOther Functions ({len(other_functions)}):\n")
    for func in other_functions:
        f.write(f"  {func}\n")

print(f"\nResults written to actually_missing_functions.txt")
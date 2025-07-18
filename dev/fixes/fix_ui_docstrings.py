#!/usr/bin/env python3
"""Fix missing docstrings in UI directory."""

import os
import re
import ast
from pathlib import Path

# Base directory
UI_DIR = Path("C:/Intellicrack/intellicrack/ui")

def add_init_docstring(file_path: Path, class_name: str, init_method_info: dict):
    """Add docstring to __init__ method."""
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Find the __init__ method pattern
    pattern = rf'(class {re.escape(class_name)}.*?\n.*?)(\n    def __init__\([^)]*\):\n)'
    match = re.search(pattern, content, re.DOTALL)
    
    if not match:
        print(f"Could not find __init__ method for {class_name} in {file_path}")
        return False
    
    # Extract the init method signature to determine parameters
    init_signature = match.group(2).strip()
    params_match = re.search(r'__init__\(([^)]*)\)', init_signature)
    
    if params_match:
        params = [p.strip() for p in params_match.group(1).split(',') if p.strip()]
        # Remove 'self'
        params = [p for p in params if not p.startswith('self')]
    else:
        params = []
    
    # Generate appropriate docstring
    if class_name.endswith('Thread') or 'Worker' in class_name:
        docstring = f'        """Initialize the {class_name.lower().replace("_", " ")} worker.\n        \n'
        if params:
            docstring += '        Args:\n'
            for param in params:
                param_name = param.split('=')[0].split(':')[0].strip()
                docstring += f'            {param_name}: Configuration parameter for the worker\n'
        docstring += '        """\n'
    elif class_name.endswith('Dialog'):
        docstring = f'        """Initialize the {class_name.replace("Dialog", "").lower().replace("_", " ")} dialog.\n        \n'
        if params:
            docstring += '        Args:\n'
            for param in params:
                param_name = param.split('=')[0].split(':')[0].strip()
                if param_name == 'parent':
                    docstring += f'            {param_name}: Parent widget for the dialog\n'
                else:
                    docstring += f'            {param_name}: Configuration parameter for the dialog\n'
        docstring += '        """\n'
    elif class_name.endswith('Widget'):
        docstring = f'        """Initialize the {class_name.replace("Widget", "").lower().replace("_", " ")} widget.\n        \n'
        if params:
            docstring += '        Args:\n'
            for param in params:
                param_name = param.split('=')[0].split(':')[0].strip()
                if param_name == 'parent':
                    docstring += f'            {param_name}: Parent widget\n'
                else:
                    docstring += f'            {param_name}: Configuration parameter for the widget\n'
        docstring += '        """\n'
    else:
        docstring = f'        """Initialize the {class_name.lower().replace("_", " ")}.\n        \n'
        if params:
            docstring += '        Args:\n'
            for param in params:
                param_name = param.split('=')[0].split(':')[0].strip()
                docstring += f'            {param_name}: Initialization parameter\n'
        docstring += '        """\n'
    
    # Replace the content
    new_content = content.replace(
        match.group(2),
        match.group(2) + docstring
    )
    
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(new_content)
    
    return True

def add_module_docstring(file_path: Path):
    """Add module docstring if missing."""
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Check if module already has docstring
    if content.strip().startswith('"""') or content.strip().startswith("'''"):
        return
    
    # Find the first non-comment, non-import line
    lines = content.split('\n')
    insert_line = 0
    
    for i, line in enumerate(lines):
        stripped = line.strip()
        if (stripped and 
            not stripped.startswith('#') and 
            not stripped.startswith('from ') and 
            not stripped.startswith('import ') and
            not stripped.startswith('"""') and
            not stripped.startswith("'''")):
            insert_line = i
            break
    
    # Generate module docstring based on file name
    module_name = file_path.stem.replace('_', ' ').title()
    module_docstring = f'"""UI module for {module_name}.\n\nThis module provides UI components and dialogs for {module_name.lower()} functionality.\n"""\n\n'
    
    # Insert the docstring
    lines.insert(insert_line, module_docstring)
    
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))

def find_classes_with_missing_init_docstrings(file_path: Path):
    """Find classes with missing __init__ docstrings."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Parse the AST
        tree = ast.parse(content)
        
        classes_to_fix = []
        
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                class_name = node.name
                
                # Find __init__ method
                for item in node.body:
                    if (isinstance(item, ast.FunctionDef) and 
                        item.name == '__init__'):
                        
                        # Check if it has a docstring
                        has_docstring = (len(item.body) > 0 and 
                                       isinstance(item.body[0], ast.Expr) and
                                       isinstance(item.body[0].value, ast.Constant) and
                                       isinstance(item.body[0].value.value, str))
                        
                        if not has_docstring:
                            classes_to_fix.append({
                                'class_name': class_name,
                                'line': item.lineno
                            })
        
        return classes_to_fix
    
    except Exception as e:
        print(f"Error parsing {file_path}: {e}")
        return []

def main():
    """Main function to fix all docstrings."""
    python_files = list(UI_DIR.rglob("*.py"))
    
    for file_path in python_files:
        print(f"Processing: {file_path}")
        
        # Add module docstring if missing
        try:
            add_module_docstring(file_path)
        except Exception as e:
            print(f"Error adding module docstring to {file_path}: {e}")
        
        # Find and fix missing __init__ docstrings
        try:
            classes_to_fix = find_classes_with_missing_init_docstrings(file_path)
            
            for class_info in classes_to_fix:
                print(f"  Fixing {class_info['class_name']}.__init__ docstring")
                add_init_docstring(file_path, class_info['class_name'], class_info)
        
        except Exception as e:
            print(f"Error processing {file_path}: {e}")

if __name__ == "__main__":
    main()
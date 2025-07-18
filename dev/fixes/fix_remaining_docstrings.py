#!/usr/bin/env python3
"""Fix remaining D100, D101, and D105 docstring issues."""

from pathlib import Path

def add_module_docstring(file_path):
    """Add module docstring to files missing them."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # If file already starts with docstring, skip
        if content.strip().startswith('"""') or content.strip().startswith("'''"):
            return False
        
        # Extract module name from path for generic docstring
        module_name = file_path.stem.replace('_', ' ').title()
        
        # Add appropriate module docstring based on file type
        if 'tab' in file_path.name:
            docstring = f'"""{module_name} implementation for Intellicrack UI."""\n\n'
        elif 'widget' in file_path.name:
            docstring = f'"""{module_name} implementation for Intellicrack UI."""\n\n'
        elif 'dialog' in file_path.name:
            docstring = f'"""{module_name} implementation for Intellicrack UI."""\n\n'
        else:
            docstring = f'"""{module_name} module for Intellicrack."""\n\n'
        
        new_content = docstring + content
        
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(new_content)
        
        print(f"Added module docstring to {file_path.relative_to(Path('C:/Intellicrack'))}")
        return True
        
    except Exception as e:
        print(f"Error processing {file_path}: {e}")
        return False

def add_magic_method_docstrings(file_path):
    """Add docstrings to magic methods missing them."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        original_content = content
        
        # Common magic method patterns
        replacements = [
            (r'(\s+)def __str__\(self\):\s*\n(\s+)(?!""")(.*?return.*?)\n',
             r'\1def __str__(self):\n\2"""Return string representation."""\n\2\3\n'),
            (r'(\s+)def __repr__\(self\):\s*\n(\s+)(?!""")(.*?return.*?)\n',
             r'\1def __repr__(self):\n\2"""Return detailed string representation."""\n\2\3\n'),
            (r'(\s+)def __len__\(self\):\s*\n(\s+)(?!""")(.*?return.*?)\n',
             r'\1def __len__(self):\n\2"""Return length."""\n\2\3\n'),
            (r'(\s+)def __bool__\(self\):\s*\n(\s+)(?!""")(.*?return.*?)\n',
             r'\1def __bool__(self):\n\2"""Return boolean value."""\n\2\3\n'),
            (r'(\s+)def __enter__\(self\):\s*\n(\s+)(?!""")(.*?return.*?)\n',
             r'\1def __enter__(self):\n\2"""Enter context manager."""\n\2\3\n'),
            (r'(\s+)def __exit__\(self[^)]*\):\s*\n(\s+)(?!""")',
             r'\1def __exit__(self, exc_type, exc_val, exc_tb):\n\2"""Exit context manager."""\n\2'),
        ]
        
        import re
        for pattern, replacement in replacements:
            content = re.sub(pattern, replacement, content, flags=re.MULTILINE)
        
        if content != original_content:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            print(f"Added magic method docstrings to {file_path.relative_to(Path('C:/Intellicrack'))}")
            return True
            
    except Exception as e:
        print(f"Error processing {file_path}: {e}")
        return False
    
    return False

# Files missing module docstrings
module_docstring_files = [
    "intellicrack/ui/tabs/ai_assistant_tab.py",
    "intellicrack/ui/tabs/analysis_tab_original.py",
    "intellicrack/ui/tabs/dashboard_tab_original.py", 
    "intellicrack/ui/tabs/exploitation_tab.py",
    "intellicrack/ui/tabs/project_workspace_tab.py",
    "intellicrack/ui/tabs/settings_tab.py",
    "intellicrack/ui/tabs/tools_tab.py",
    "intellicrack/ui/widgets/cpu_status_widget.py",
    "intellicrack/ui/widgets/gpu_status_widget.py"
]

# Files with missing magic method docstrings
magic_method_files = [
    "intellicrack/plugins/custom_modules/hardware_dongle_emulator.py",
    "intellicrack/plugins/custom_modules/success_rate_analyzer.py",
    "intellicrack/plugins/custom_modules/vm_protection_unwrapper.py",
    "intellicrack/scripts/cli/progress_manager.py"
]

base_path = Path("C:/Intellicrack")

print("Adding module docstrings...")
for file_path in module_docstring_files:
    full_path = base_path / file_path
    if full_path.exists():
        add_module_docstring(full_path)

print("\nAdding magic method docstrings...")  
for file_path in magic_method_files:
    full_path = base_path / file_path
    if full_path.exists():
        add_magic_method_docstrings(full_path)

print("\nDone fixing remaining docstring issues!")
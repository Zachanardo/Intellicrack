#!/usr/bin/env python3
"""
Fix undefined variable errors in Intellicrack codebase
"""

import re

# List of files and their undefined variable fixes
fixes = [
    {
        'file': '/mnt/c/Intellicrack/intellicrack/core/processing/distributed_analysis_manager.py',
        'replacements': [
            # Fix vm variable references
            ('for _vm in self.vms:', 'vm[', '_vm['),
            ('for _vm in self.vms:', 'vm["', '_vm["'),
            ('for _vm in self.vms:', "vm['", "_vm['"),
            # Fix container variable references  
            ('for _container in self.containers:', 'container[', '_container['),
            ('for _container in self.containers:', 'container["', '_container["'),
            ('for _container in self.containers:', "container['", "_container['"),
        ]
    },
    {
        'file': '/mnt/c/Intellicrack/intellicrack/core/analysis/cfg_explorer.py',
        'replacements': [
            # Fix insn variable
            ('insn = None', 'return insn', 'return None'),
        ]
    },
    {
        'file': '/mnt/c/Intellicrack/intellicrack/core/analysis/rop_generator.py',
        'replacements': [
            # Fix gadget_type variable
            ('gadget_type = None', '"type": gadget_type', '"type": None'),
        ]
    }
]

def fix_file(file_path, replacements):
    """Fix undefined variables in a file."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        original_content = content
        
        # Apply replacements based on context
        for context, old_pattern, new_pattern in replacements:
            # Find all occurrences within the context
            lines = content.split('\n')
            in_context = False
            new_lines = []
            
            for line in lines:
                if context in line:
                    in_context = True
                elif line.strip() == '' or (line.strip() and not line.startswith(' ') and not line.startswith('\t')):
                    # Exit context on empty line or new unindented line
                    in_context = False
                
                if in_context and old_pattern in line:
                    line = line.replace(old_pattern, new_pattern)
                
                new_lines.append(line)
            
            content = '\n'.join(new_lines)
        
        if content != original_content:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            print(f"Fixed {file_path}")
            return True
        else:
            print(f"No changes needed in {file_path}")
            return False
            
    except Exception as e:
        print(f"Error fixing {file_path}: {e}")
        return False

# Apply fixes
for fix_info in fixes:
    fix_file(fix_info['file'], fix_info['replacements'])

print("\nDone!")
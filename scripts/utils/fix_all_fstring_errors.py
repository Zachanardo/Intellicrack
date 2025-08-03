#!/usr/bin/env python3
"""Fix all remaining f-string double brace errors in plugin_manager_dialog.py"""

import re

def fix_all_fstring_errors(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # List of specific fixes needed based on the search results
    fixes = [
        (r'\{\{file_size:,\}\}', r'{file_size:,}'),
        (r'\{\{len\(network_imports\)\}\}', r'{len(network_imports)}'),
        (r'\{\{1,3\}\}', r'{1,3}'),
        (r'\{\{3\}\}', r'{3}'),
        (r'\{\{2,\}\}', r'{2,}'),
        (r'\{\{len\(valid_ips\)\}\}', r'{len(valid_ips)}'),
        (r'\{\{len\(domains\)\}\}', r'{len(domains)}'),
        (r"\{\{', '.join\(map\(str, port_refs\)\)\}\}", r"{', '.join(map(str, port_refs))}"),
        (r'\{\{str\(e\)\}\}', r'{str(e)}'),
        (r'\{\{data\.get\(\'execution_time\', 0\):.2f\}\}', r"{data.get('execution_time', 0):.2f}"),
        (r'\{\{\}\}', r'{}'),
        # Fix return dictionaries
        (r'return \{\{', r'return {'),
        (r'\}\}$', r'}'),
        (r"'data': \{\{\}\}", r"'data': {}"),
        (r"'message': f'[^']*',\s*'data': \{\{\}\}", r"'message': f'{error_msg}',\n                        'data': {}"),
    ]
    
    for pattern, replacement in fixes:
        content = re.sub(pattern, replacement, content, flags=re.MULTILINE)
    
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(content)
    
    print(f"Fixed all f-string errors in {file_path}")

if __name__ == "__main__":
    fix_all_fstring_errors("C:/Intellicrack/intellicrack/ui/dialogs/plugin_manager_dialog.py")
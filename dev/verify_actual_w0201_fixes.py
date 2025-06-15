#!/usr/bin/env python3
"""
Verify the actual W0201 fixes applied by the script.
"""

import os
import re
from typing import Dict, List, Set

# Files that were actually modified (from git diff --name-only)
MODIFIED_FILES = [
    'intellicrack/ai/enhanced_training_interface.py',
    'intellicrack/core/network/cloud_license_hooker.py',
    'intellicrack/core/network/license_protocol_handler.py',
    'intellicrack/core/network/license_server_emulator.py',
    'intellicrack/core/network/ssl_interceptor.py',
    'intellicrack/core/network/traffic_analyzer.py',
    'intellicrack/core/network/traffic_interception_engine.py',
    'intellicrack/core/patching/adobe_injector.py',
    'intellicrack/core/processing/memory_optimizer.py',
    'intellicrack/hexview/advanced_search.py',
    'intellicrack/hexview/ai_bridge.py',
    'intellicrack/hexview/api.py',
    'intellicrack/hexview/data_inspector.py',
    'intellicrack/hexview/performance_monitor.py',
    'intellicrack/ui/dialogs/help_documentation_widget.py',
    'intellicrack/ui/dialogs/keygen_dialog.py',
    'intellicrack/ui/dialogs/llm_config_dialog.py',
    'intellicrack/ui/dialogs/model_finetuning_dialog.py',
    'intellicrack/ui/dialogs/plugin_manager_dialog.py',
    'intellicrack/ui/dialogs/report_manager_dialog.py',
    'intellicrack/ui/dialogs/script_generator_dialog.py',
    'intellicrack/ui/dialogs/similarity_search_dialog.py',
    'intellicrack/ui/dialogs/system_utilities_dialog.py',
    'intellicrack/ui/main_app.py',
    'intellicrack/ui/main_window.py',
    'intellicrack/ui/widgets/hex_viewer.py'
]

def extract_added_attributes(file_path):
    """Extract attributes that were added by the W0201 fix script."""
    full_path = f'/mnt/c/Intellicrack/{file_path}'
    
    if not os.path.exists(full_path):
        return [], []
    
    try:
        with open(full_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Find all "self.attribute = None" lines after "Initialize UI attributes" comment
        added_attributes = []
        
        # Look for the section after "Initialize UI attributes"
        ui_attrs_pos = content.find('# Initialize UI attributes')
        if ui_attrs_pos != -1:
            # Extract lines after the comment until we hit something that's not an attribute assignment
            lines_after = content[ui_attrs_pos:].split('\n')
            
            for line in lines_after[1:]:  # Skip the comment line itself
                line = line.strip()
                # Stop if we hit super() call, class definition, or method definition
                if (line.startswith('super(') or 
                    line.startswith('class ') or 
                    line.startswith('def ') or
                    (line and not line.startswith('self.') and not line.startswith('#'))):
                    break
                
                # Extract attribute assignments
                attr_match = re.match(r'self\.(\w+)\s*=\s*None', line)
                if attr_match:
                    added_attributes.append(attr_match.group(1))
        
        # Check for hasattr uses of these attributes
        hasattr_issues = []
        for attr in added_attributes:
            hasattr_pattern = rf'hasattr\s*\(\s*self\s*,\s*[\'\"]{attr}[\'\"]\s*\)'
            if re.search(hasattr_pattern, content):
                hasattr_issues.append(attr)
        
        return added_attributes, hasattr_issues
        
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return [], []

def main():
    """Check all modified files for W0201 fix verification."""
    print("🔍 Verifying actual W0201 fixes applied by the script...\n")
    
    total_files = 0
    total_attributes = 0
    total_hasattr_issues = 0
    
    for file_path in MODIFIED_FILES:
        added_attrs, hasattr_issues = extract_added_attributes(file_path)
        
        if added_attrs:  # Only show files that had attributes added
            total_files += 1
            total_attributes += len(added_attrs)
            
            print(f"📁 {os.path.basename(file_path)}")
            print(f"   ✅ {len(added_attrs)} attributes added: {', '.join(added_attrs[:5])}" + 
                  (f" (and {len(added_attrs)-5} more)" if len(added_attrs) > 5 else ""))
            
            if hasattr_issues:
                total_hasattr_issues += len(hasattr_issues)
                print(f"   ⚠️  {len(hasattr_issues)} hasattr issues: {', '.join(hasattr_issues)}")
            
            print()
    
    print(f"📊 Summary:")
    print(f"   Files with W0201 fixes: {total_files}")
    print(f"   Total attributes added: {total_attributes}")
    print(f"   Files with hasattr issues: {len([f for f in MODIFIED_FILES if extract_added_attributes(f)[1]])}")
    print(f"   Total hasattr issues: {total_hasattr_issues}")
    
    if total_hasattr_issues > 0:
        print(f"\n⚠️  Manual fix needed: Convert hasattr() checks to 'is None' checks for {total_hasattr_issues} attributes")

if __name__ == '__main__':
    main()
#!/usr/bin/env python3
"""
Verify all main_app.py W0201 fixes are working correctly.
"""

import re

# All attributes that were added to main_app.py
MAIN_APP_ATTRIBUTES = [
    'traffic_analyzer', 'capture_thread', 'packet_update_timer', 'chat_display',
    'user_input', 'assistant_status', 'binary_tool_file_label', 'binary_tool_file_info',
    'binary_tool_stack', 'view_current_btn', 'edit_current_btn', 'disasm_text',
    'plugin_name_label', 'log_filter', 'info_check', 'warning_check', 'error_check',
    'debug_check', 'log_output', 'recent_files_list', 'binary_info_group',
    'notifications_list', 'activity_log', '_hex_viewer_dialogs', 'last_log_accessed',
    'log_access_history', 'assistant_tab', 'ai_conversation_history', 'report_viewer',
    'reports'
]

def check_main_app_attributes():
    """Check all attributes in main_app.py"""
    file_path = '/mnt/c/Intellicrack/intellicrack/ui/main_app.py'
    
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    print("Checking main_app.py attributes...\n")
    
    # Check if all attributes are initialized in __init__
    init_section = re.search(r'def __init__\(self\):.*?super\(\).__init__\(\)', content, re.DOTALL)
    if not init_section:
        print("❌ Could not find __init__ method")
        return
    
    init_content = init_section.group(0)
    
    for attr in MAIN_APP_ATTRIBUTES:
        # Check if attribute is initialized
        if f'self.{attr} = ' in init_content:
            print(f"✅ {attr}: Initialized in __init__")
        else:
            print(f"❌ {attr}: NOT initialized in __init__")
        
        # Check usage patterns
        assignments = re.findall(rf'self\.{attr}\s*=\s*[^=]', content)
        if len(assignments) > 1:  # More than just the init assignment
            print(f"  📝 {attr}: {len(assignments)} assignments found")
        
        # Check for problematic hasattr usage
        hasattr_uses = re.findall(rf'hasattr\s*\(\s*self\s*,\s*[\'\"]{attr}[\'\"]\s*\)', content)
        if hasattr_uses:
            print(f"  ⚠️  {attr}: {len(hasattr_uses)} hasattr uses found (might need fixing)")
        
        # Check for None checks (good)
        none_checks = re.findall(rf'self\.{attr}\s+is\s+(None|not\s+None)', content)
        if none_checks:
            print(f"  ✅ {attr}: {len(none_checks)} proper None checks found")

if __name__ == '__main__':
    check_main_app_attributes()
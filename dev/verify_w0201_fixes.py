#!/usr/bin/env python3
"""
Verify that W0201 fixes didn't break functionality.
"""

import ast
import os
import re
from typing import List, Set, Tuple

def check_hasattr_usage(file_path: str, modified_attrs: Set[str]) -> List[str]:
    """Check if any modified attributes are used with hasattr checks."""
    issues = []
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        for attr in modified_attrs:
            # Check for hasattr usage
            pattern = rf'hasattr\s*\(\s*self\s*,\s*[\'"]?{attr}[\'"]?\s*\)'
            matches = re.findall(pattern, content)
            if matches:
                issues.append(f"Attribute '{attr}' is checked with hasattr - initialization to None might change behavior")
            
            # Check for try/except AttributeError
            if f'self.{attr}' in content:
                # Simple check for AttributeError handling
                lines = content.split('\n')
                for i, line in enumerate(lines):
                    if f'self.{attr}' in line:
                        # Check surrounding lines for try/except
                        context_start = max(0, i - 5)
                        context_end = min(len(lines), i + 5)
                        context = '\n'.join(lines[context_start:context_end])
                        if 'except AttributeError' in context or 'except:' in context:
                            issues.append(f"Attribute '{attr}' might be used in try/except block - needs manual review")
    
    except Exception as e:
        issues.append(f"Error analyzing {file_path}: {e}")
    
    return issues


def check_conditional_creation(file_path: str, modified_attrs: Set[str]) -> List[str]:
    """Check if attributes are created conditionally."""
    issues = []
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Parse the AST
        tree = ast.parse(content)
        
        # Find all assignments to self attributes within if statements
        class ConditionalAssignmentVisitor(ast.NodeVisitor):
            def __init__(self):
                self.conditional_attrs = set()
                self.in_if = False
            
            def visit_If(self, node):
                old_in_if = self.in_if
                self.in_if = True
                self.generic_visit(node)
                self.in_if = old_in_if
            
            def visit_Assign(self, node):
                if self.in_if:
                    for target in node.targets:
                        if isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name) and target.value.id == 'self':
                            self.conditional_attrs.add(target.attr)
                self.generic_visit(node)
        
        visitor = ConditionalAssignmentVisitor()
        visitor.visit(tree)
        
        # Check if any modified attributes are conditionally created
        for attr in modified_attrs:
            if attr in visitor.conditional_attrs:
                issues.append(f"Attribute '{attr}' is created conditionally - initialization might affect logic")
    
    except Exception as e:
        issues.append(f"Error parsing {file_path}: {e}")
    
    return issues


def verify_file(file_path: str, attributes: List[Tuple[str, int]]) -> List[str]:
    """Verify a single file for potential issues."""
    all_issues = []
    attr_names = {attr[0] for attr in attributes}
    
    # Check hasattr usage
    hasattr_issues = check_hasattr_usage(file_path, attr_names)
    all_issues.extend(hasattr_issues)
    
    # Check conditional creation
    conditional_issues = check_conditional_creation(file_path, attr_names)
    all_issues.extend(conditional_issues)
    
    return all_issues


# Files modified by the script
MODIFIED_FILES = {
    'intellicrack/ui/main_app.py': ['traffic_analyzer', 'capture_thread', 'packet_update_timer', 'chat_display', 'user_input', 'assistant_status', 'binary_tool_file_label', 'binary_tool_file_info', 'binary_tool_stack', 'view_current_btn', 'edit_current_btn', 'disasm_text', 'plugin_name_label', 'log_filter', 'info_check', 'warning_check', 'error_check', 'debug_check', 'log_output', 'recent_files_list', 'binary_info_group', 'notifications_list', 'activity_log', '_hex_viewer_dialogs', 'last_log_accessed', 'log_access_history', 'assistant_tab', 'ai_conversation_history', 'report_viewer', 'reports'],
    'intellicrack/ui/main_window.py': ['file_path_label', 'browse_button', 'analyze_button', 'scan_vulnerabilities_button', 'generate_report_button', 'info_display', 'vulnerability_scan_cb', 'entropy_analysis_cb', 'import_analysis_cb', 'export_analysis_cb', 'analysis_output', 'results_display', 'clear_results_button', 'export_results_button', 'verbose_logging_cb', 'auto_save_results_cb'],
    'intellicrack/ui/dialogs/help_documentation_widget.py': ['features_tree', 'feature_details', 'tutorial_tabs', 'tutorial_viewer', 'issues_tree', 'solution_viewer'],
    'intellicrack/ui/dialogs/keygen_dialog.py': ['tabs', 'algorithm_combo', 'format_combo', 'length_spin', 'validation_check', 'generate_btn', 'key_display', 'copy_btn', 'save_single_btn', 'results_display', 'batch_count_spin', 'batch_algorithm_combo', 'batch_format_combo', 'batch_generate_btn', 'batch_stop_btn', 'batch_clear_btn', 'batch_export_btn', 'batch_progress', 'batch_table', 'analysis_display', 'existing_keys_input', 'analyze_keys_btn', 'key_analysis_display'],
    'intellicrack/ui/widgets/hex_viewer.py': ['open_btn', 'save_btn', 'search_btn', 'perf_btn', 'file_info_label'],
}


def main():
    """Main verification function."""
    total_issues = 0
    
    print("Verifying W0201 fixes for potential functionality issues...\n")
    
    for file_path, attrs in MODIFIED_FILES.items():
        full_path = os.path.join('/mnt/c/Intellicrack', file_path)
        
        if os.path.exists(full_path):
            print(f"Checking {file_path}...")
            
            # Convert attribute list to expected format
            attr_tuples = [(attr, 0) for attr in attrs]
            issues = verify_file(full_path, attr_tuples)
            
            if issues:
                print(f"  Found {len(issues)} potential issues:")
                for issue in issues:
                    print(f"    - {issue}")
                total_issues += len(issues)
            else:
                print("  No issues found")
            print()
    
    print(f"\nTotal potential issues found: {total_issues}")
    
    if total_issues == 0:
        print("\nAll W0201 fixes appear to be safe. The initialization to None should not break functionality.")
    else:
        print("\nSome attributes may need manual review to ensure functionality is preserved.")
        print("However, in most cases, initializing to None is the correct fix and improves code quality.")


if __name__ == '__main__':
    main()
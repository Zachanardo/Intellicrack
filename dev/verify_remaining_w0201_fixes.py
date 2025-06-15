#!/usr/bin/env python3
"""
Verify the remaining W0201 fixes across all modified files.
"""

import os
import re

# Files and their problematic attributes from the W0201 fixes
FILES_TO_CHECK = {
    '/mnt/c/Intellicrack/intellicrack/ui/main_window.py': [
        'settings_dialog', 'log_dialog', 'notifications_widget', 'activity_widget',
        'binary_info_widget', 'recent_files_widget', 'status_bar', 'progress_bar',
        'menu_bar', 'toolbar', 'file_menu', 'analysis_menu', 'patch_menu',
        'network_menu', 'help_menu', 'status_label'
    ],
    '/mnt/c/Intellicrack/intellicrack/ui/dialogs/help_documentation_widget.py': [
        'search_field', 'content_tree', 'content_display', 'back_button', 
        'forward_button', 'print_button'
    ],
    '/mnt/c/Intellicrack/intellicrack/ui/dialogs/keygen_dialog.py': [
        'algorithm_combo', 'key_length_spin', 'format_combo', 'output_text',
        'generate_btn', 'copy_btn', 'save_btn', 'custom_seed_check', 'seed_input',
        'batch_check', 'batch_count_spin', 'export_combo', 'progress_bar',
        'key_preview', 'entropy_indicator', 'validation_label', 'key_strength_bar',
        'algorithm_info', 'format_info', 'generation_log', 'batch_progress',
        'export_progress', 'validation_status', 'key_history'
    ],
    '/mnt/c/Intellicrack/intellicrack/ui/dialogs/llm_config_dialog.py': [
        'provider_combo', 'model_combo', 'api_key_input', 'base_url_input',
        'temperature_spin', 'max_tokens_spin', 'system_prompt_text', 'test_btn',
        'save_btn', 'reset_btn', 'status_label', 'advanced_group', 'timeout_spin',
        'retry_spin', 'stream_check', 'safety_check', 'context_window_spin',
        'top_p_spin', 'frequency_penalty_spin', 'presence_penalty_spin',
        'stop_sequences_text', 'custom_headers_text'
    ],
    '/mnt/c/Intellicrack/intellicrack/ui/dialogs/model_finetuning_dialog.py': [
        'model_name_edit', 'model_type_combo', 'learning_rate_spin', 'batch_size_spin',
        'epochs_spin', 'validation_split_spin', 'early_stopping_check', 'patience_spin',
        'dataset_path_edit', 'dataset_browse_btn', 'output_dir_edit', 'output_browse_btn',
        'loss_function_combo', 'optimizer_combo', 'scheduler_combo', 'weight_decay_spin',
        'dropout_spin', 'regularization_combo', 'augmentation_check', 'shuffle_check',
        'seed_spin', 'gpu_check', 'mixed_precision_check', 'gradient_clipping_spin',
        'save_checkpoints_check', 'checkpoint_frequency_spin', 'tensorboard_check',
        'wandb_check', 'evaluation_metrics_list', 'custom_config_text', 'training_args',
        'start_training_btn', 'stop_training_btn', 'save_config_btn', 'load_config_btn',
        'reset_btn', 'progress_bar', 'status_label', 'training_log', 'loss_plot',
        'metrics_plot', 'training_timer', 'current_epoch_label', 'best_score_label',
        'remaining_time_label', 'gpu_usage_label', 'memory_usage_label', 'training_thread',
        'live_plotting_check', 'auto_save_check', 'resume_training_check', 'hyperopt_check',
        'hyperopt_trials_spin', 'hyperopt_algorithm_combo', 'cross_validation_check'
    ],
    '/mnt/c/Intellicrack/intellicrack/ui/dialogs/plugin_manager_dialog.py': [
        'plugin_list', 'plugin_info', 'install_btn', 'uninstall_btn', 'enable_btn',
        'disable_btn', 'refresh_btn', 'settings_btn', 'browse_btn', 'update_btn',
        'search_field', 'category_filter', 'status_filter', 'author_filter',
        'version_filter', 'description_text', 'dependencies_list', 'changelog_text',
        'screenshots_widget', 'rating_widget', 'download_count_label', 'size_label'
    ]
}

def check_attributes_in_file(file_path, attributes):
    """Check all attributes in a file for proper initialization and usage."""
    if not os.path.exists(file_path):
        print(f"❌ File not found: {file_path}")
        return
    
    print(f"\n🔍 Checking {os.path.basename(file_path)}...")
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Find __init__ method
        init_match = re.search(r'def __init__\(self.*?\):.*?(?=def |\Z)', content, re.DOTALL)
        if not init_match:
            print(f"❌ No __init__ method found")
            return
            
        init_content = init_match.group(0)
        
        issues_found = 0
        for attr in attributes:
            # Check if initialized in __init__
            if f'self.{attr} = ' not in init_content:
                print(f"❌ {attr}: NOT initialized in __init__")
                issues_found += 1
                continue
            
            # Check for problematic hasattr usage
            hasattr_pattern = rf'hasattr\s*\(\s*self\s*,\s*[\'\"]{attr}[\'\"]\s*\)'
            hasattr_matches = re.findall(hasattr_pattern, content)
            if hasattr_matches:
                print(f"⚠️  {attr}: {len(hasattr_matches)} hasattr uses found (needs manual review)")
                issues_found += 1
            
            # Count assignments
            assignment_pattern = rf'self\.{attr}\s*=\s*[^=]'
            assignments = re.findall(assignment_pattern, content)
            if len(assignments) > 1:
                print(f"📝 {attr}: {len(assignments)} assignments found")
            elif len(assignments) == 1:
                print(f"✅ {attr}: Properly initialized")
        
        if issues_found == 0:
            print(f"✅ All {len(attributes)} attributes properly handled")
        else:
            print(f"⚠️  {issues_found} potential issues found")
            
    except Exception as e:
        print(f"❌ Error reading file: {e}")

def main():
    """Check all modified files for W0201 fix issues."""
    print("🔍 Verifying W0201 fixes across all modified files...")
    
    total_files = len(FILES_TO_CHECK)
    total_issues = 0
    
    for file_path, attributes in FILES_TO_CHECK.items():
        check_attributes_in_file(file_path, attributes)
    
    print(f"\n📊 Summary:")
    print(f"   Files checked: {total_files}")
    print(f"   Manual verification required for any files with ⚠️  warnings")

if __name__ == '__main__':
    main()
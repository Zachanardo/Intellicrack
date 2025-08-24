#!/usr/bin/env python3
"""Batch fix for B904 raise-without-from-inside-except issues."""

import os

# Define files and their simple fixes
fixes = [
    # Files with simple exception chaining needed
    ("intellicrack\\cli\\hex_viewer_cli.py", "raise OSError(f\"Cannot open file: {e}\")", "raise OSError(f\"Cannot open file: {e}\") from e"),
    ("intellicrack\\cli\\pipeline.py", "raise ValueError(f\"Invalid output path: {e}\")", "raise ValueError(f\"Invalid output path: {e}\") from e"),
    ("intellicrack\\core\\ai_model_manager.py", "raise RuntimeError(\"No local model backend available (install transformers or llama-cpp-python)\")", "raise RuntimeError(\"No local model backend available (install transformers or llama-cpp-python)\") from None"),
    ("intellicrack\\core\\config_migration_handler.py", "raise MigrationError(f\"Backup creation failed: {e}\")", "raise MigrationError(f\"Backup creation failed: {e}\") from e"),
    ("intellicrack\\plugins\\plugin_system.py", "raise ValueError(\"Remote plugin contains binary data\")", "raise ValueError(\"Remote plugin contains binary data\") from e"),
    ("intellicrack\\plugins\\remote_executor.py", "raise ValueError(\"Invalid JSON data\")", "raise ValueError(\"Invalid JSON data\") from e"),
    ("intellicrack\\utils\\runtime\\runner_functions.py", "raise ValueError(f\"Invalid JSON file: {e}\")", "raise ValueError(f\"Invalid JSON file: {e}\") from e"),
]

def fix_simple_b904_issues():
    """Fix simple B904 issues by adding proper exception chaining."""
    for file_path, old_text, new_text in fixes:
        full_path = os.path.join("C:", file_path)  # Add C: prefix
        if os.path.exists(full_path):
            try:
                with open(full_path, 'r', encoding='utf-8') as f:
                    content = f.read()

                if old_text in content:
                    new_content = content.replace(old_text, new_text)
                    with open(full_path, 'w', encoding='utf-8') as f:
                        f.write(new_content)
                    print(f"Fixed: {file_path}")
                else:
                    print(f"Not found in {file_path}: {old_text[:50]}...")
            except Exception as e:
                print(f"Error processing {file_path}: {e}")

if __name__ == "__main__":
    print("Fixing B904 raise-without-from-inside-except issues...")
    fix_simple_b904_issues()
    print("Batch fix completed!")

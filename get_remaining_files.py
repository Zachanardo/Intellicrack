#!/usr/bin/env python3
"""Calculate remaining files for final batch."""
import json

# Read violations
with open('ruff_ann_d_violations.json', 'r', encoding='utf-8') as f:
    content = f.read()
    start_idx = content.find('[')
    violations = json.loads(content[start_idx:])

file_counts = {}
for v in violations:
    file_path = v['filename']
    file_counts[file_path] = file_counts.get(file_path, 0) + 1

# Files completed from Batch 19 (just completed)
batch_19_completed = {
    'D:\\Intellicrack\\intellicrack\\core\\process_manipulation.py',
    'D:\\Intellicrack\\intellicrack\\core\\protection_analyzer.py',
    'D:\\Intellicrack\\intellicrack\\core\\protection_detection\\securom_detector.py',
    'D:\\Intellicrack\\intellicrack\\core\\shared\\result_types.py',
    'D:\\Intellicrack\\intellicrack\\dashboard\\dashboard_manager.py',
    'D:\\Intellicrack\\intellicrack\\dashboard\\visualization_renderer.py',
    'D:\\Intellicrack\\intellicrack\\handlers\\aiohttp_handler.py',
    'D:\\Intellicrack\\intellicrack\\handlers\\ipex_handler.py',
    'D:\\Intellicrack\\intellicrack\\handlers\\pyelftools_handler.py',
    'D:\\Intellicrack\\intellicrack\\hexview\\checksums.py',
    'D:\\Intellicrack\\intellicrack\\hexview\\data_inspector.py',
    'D:\\Intellicrack\\intellicrack\\hexview\\hex_highlighter.py',
    'D:\\Intellicrack\\intellicrack\\hexview\\statistics.py',
    'D:\\Intellicrack\\intellicrack\\ml\\__init__.py',
    'D:\\Intellicrack\\intellicrack\\plugins\\custom_modules\\vm_protection_unwrapper.py',
    'D:\\Intellicrack\\intellicrack\\protection\\__init__.py',
    'D:\\Intellicrack\\intellicrack\\protection\\icp_report_generator.py',
    'D:\\Intellicrack\\intellicrack\\ui\\dashboard_manager.py',
    'D:\\Intellicrack\\intellicrack\\ui\\dialogs\\event_handler_utils.py',
    'D:\\Intellicrack\\intellicrack\\ui\\dialogs\\first_run_setup.py',
}

print(f"Total unique files with violations: {len(file_counts)}")
print(f"Files in Batch 19: {len(batch_19_completed)}")
print(f"Calculated: {143} - {105} (batches 1-17) - {20} (batch 19) = {143-105-20} remaining")
print()

# Show files from batch 19 in violations to confirm they exist
found_in_batch19 = sum(1 for f in batch_19_completed if f in file_counts)
print(f"Batch 19 files found in violations: {found_in_batch19}/20")

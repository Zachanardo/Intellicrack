import re
import os

def fix_s110_in_file(filepath):
    """Fix S110 violations in a single file."""
    
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    modified = False
    
    # Pattern to find try-except-pass blocks
    # This matches except Exception: followed by just pass
    pattern = r'(\s*)(except\s+(?:Exception|[A-Za-z]+Error)[^:]*:\s*\n\s*)pass(\s*\n)'
    
    def replace_with_logging(match):
        indent = match.group(1)
        except_line = match.group(2)
        after = match.group(3)
        
        # Determine appropriate logging based on context
        # Use debug level for fallback scenarios
        return f"{indent}{except_line}{indent}    logger.debug('Exception caught in fallback path', exc_info=False){after}"
    
    # Check if logger is available
    has_logger = 'from intellicrack.logger import logger' in content or 'logger = logging.getLogger' in content
    
    if not has_logger and 'import logging' in content:
        # Add logger setup after logging import
        content = content.replace('import logging\n', 'import logging\n\nlogger = logging.getLogger(__name__)\n', 1)
        modified = True
    
    # Replace try-except-pass patterns
    new_content, count = re.subn(pattern, replace_with_logging, content)
    
    if count > 0:
        modified = True
        content = new_content
    
    if modified:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        return count
    
    return 0

# Files with S110 violations based on ruff output
files_to_fix = [
    'intellicrack/plugins/custom_modules/license_server_emulator.py',
]

total_fixed = 0
for file in files_to_fix:
    if os.path.exists(file):
        count = fix_s110_in_file(file)
        if count > 0:
            print(f"Fixed {count} S110 violations in {file}")
            total_fixed += count

print(f"\nTotal S110 violations fixed: {total_fixed}")
#!/usr/bin/env python3
"""Add success logging to the launch function"""
import re

# Read the main_app.py file
with open('/mnt/c/Intellicrack/intellicrack/ui/main_app.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Add success logging after window.show()
old_pattern = r'(window\.show\(\))'
new_pattern = r'''\1
        
        # Log successful launch
        logger.info("🎉 INTELLICRACK LAUNCHED SUCCESSFULLY! Window is now visible.")
        
        # Also write to a file for verification
        import datetime
        with open('LAUNCH_SUCCESS.log', 'w') as f:
            f.write(f"Intellicrack launched successfully at {datetime.datetime.now()}\\n")
            f.write("Window is visible and application is running!\\n")'''

content = re.sub(old_pattern, new_pattern, content, flags=re.MULTILINE)

# Write back
with open('/mnt/c/Intellicrack/intellicrack/ui/main_app.py', 'w', encoding='utf-8') as f:
    f.write(content)

print("Added launch success logging")
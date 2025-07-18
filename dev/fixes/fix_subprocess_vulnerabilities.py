#!/usr/bin/env python3
"""
Fix subprocess vulnerabilities in Intellicrack
Replaces shell=True with safer alternatives
"""

import os
import re

def fix_c2_client():
    """Fix subprocess calls in c2_client.py"""

    file_path = 'intellicrack/core/c2/c2_client.py'

    if not os.path.exists(file_path):
        print(f"File not found: {file_path}")
        return

    print(f"Fixing subprocess vulnerabilities in {file_path}")

    with open(file_path, 'r') as f:
        content = f.read()

    original = content

    # Fix 1: Line ~437 - _execute_shell_command method
    # Change shell=True to use shlex.split for safer command parsing
    content = re.sub(
        r'(async def _execute_shell_command.*?)(result = subprocess\.run\(\s*command,\s*shell=True,)',
        r'\1import shlex\n        try:\n            # Parse command safely\n            if isinstance(command, str):\n                cmd_args = shlex.split(command)\n            else:\n                cmd_args = command\n            \n            result = subprocess.run(\n                cmd_args,\n                shell=False,',
        content,
        flags=re.DOTALL
    )

    # Fix 2: Line ~1314 - fodhelper.exe privilege escalation
    # This is a UAC bypass technique - should be removed or secured
    content = re.sub(
        r"subprocess\.Popen\(\['fodhelper\.exe'\], shell=True\)",
        r"# SECURITY: UAC bypass removed - requires manual review\n            # subprocess.Popen(['fodhelper.exe'], shell=False)",
        content
    )

    # Fix 3: Line ~1520 - Generic command execution
    content = re.sub(
        r"result = subprocess\.run\(cmd, capture_output=True, text=True, shell=True\)",
        r"# Use shlex to parse command safely\n            import shlex\n            cmd_args = shlex.split(cmd) if isinstance(cmd, str) else cmd\n            result = subprocess.run(cmd_args, capture_output=True, text=True, shell=False)",
        content
    )

    if content != original:
        with open(file_path, 'w') as f:
            f.write(content)
        print(f"  ✓ Fixed subprocess vulnerabilities in {file_path}")
    else:
        print(f"  ! No changes made to {file_path}")

def fix_base_exploitation():
    """Fix subprocess calls in base_exploitation.py"""

    file_path = 'intellicrack/core/exploitation/base_exploitation.py'

    if not os.path.exists(file_path):
        print(f"File not found: {file_path}")
        return

    print(f"Reviewing subprocess calls in {file_path}")

    with open(file_path, 'r') as f:
        content = f.read()

    # Find lines with subprocess and shell=True
    if 'shell=True' in content:
        print(f"  ⚠ Found subprocess with shell=True in {file_path}")

        # Generic fix for subprocess calls
        original = content
        content = re.sub(
            r'subprocess\.(run|call|check_output|Popen)\((.*?),\s*shell=True',
            r'subprocess.\1(\2, shell=False',
            content
        )

        if content != original:
            with open(file_path, 'w') as f:
                f.write(content)
            print(f"  ✓ Fixed subprocess calls in {file_path}")

def fix_tools_tab():
    """Fix subprocess calls in tools_tab.py"""

    file_path = 'intellicrack/ui/tabs/tools_tab.py'

    if not os.path.exists(file_path):
        print(f"File not found: {file_path}")
        return

    print(f"Reviewing subprocess calls in {file_path}")

    with open(file_path, 'r') as f:
        content = f.read()

    # Check for subprocess calls
    if 'subprocess' in content and 'shell=True' in content:
        print(f"  ⚠ Found subprocess with shell=True in {file_path}")

        # Apply generic fixes
        original = content
        content = re.sub(
            r'subprocess\.(run|call|check_output|Popen)\((.*?),\s*shell=True',
            r'subprocess.\1(\2, shell=False',
            content
        )

        if content != original:
            with open(file_path, 'w') as f:
                f.write(content)
            print(f"  ✓ Fixed subprocess calls in {file_path}")

def main():
    """Main function to fix subprocess vulnerabilities"""

    print("Fixing Subprocess Vulnerabilities")
    print("=================================\n")

    # Fix known vulnerable files
    fix_c2_client()
    fix_base_exploitation()
    fix_tools_tab()

    print("\n✓ Subprocess vulnerability fixes completed!")
    print("\nManual review required for:")
    print("1. UAC bypass code in c2_client.py (fodhelper.exe)")
    print("2. Any complex command constructions that need shell features")
    print("3. Commands that use shell redirects, pipes, or wildcards")

if __name__ == "__main__":
    main()

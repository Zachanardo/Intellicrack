#!/usr/bin/env python3
"""
This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

"""
Fix hasattr issues after W0201 fixes.
"""

import re

# Attributes that use hasattr checks and need special handling
HASATTR_FIXES = {
    'intellicrack/ui/main_app.py': [
        # Change hasattr checks to None checks for these attributes
        ('traffic_analyzer', 'if not hasattr(self, \'traffic_analyzer\'):',
         'if self.traffic_analyzer is None:'),
        ('traffic_analyzer', 'if hasattr(self, \'traffic_analyzer\'):',
         'if self.traffic_analyzer is not None:'),
        ('capture_thread', 'if hasattr(self, \'capture_thread\'):',
         'if self.capture_thread is not None:'),
        ('_hex_viewer_dialogs', 'if not hasattr(self, \'_hex_viewer_dialogs\'):',
         'if self._hex_viewer_dialogs is None:'),
        ('_hex_viewer_dialogs', 'if hasattr(self, \'_hex_viewer_dialogs\'):',
         'if self._hex_viewer_dialogs is not None:'),
        ('reports', 'if not hasattr(self, \'reports\'):', 'if self.reports is None:'),
        ('reports', 'if hasattr(self, \'reports\'):', 'if self.reports is not None:'),
        ('assistant_status', 'if hasattr(self, \'assistant_status\'):',
         'if self.assistant_status is not None:'),
        ('assistant_tab', 'if hasattr(self, \'assistant_tab\'):',
         'if self.assistant_tab is not None:'),
        ('chat_display', 'if hasattr(self, \'chat_display\'):',
         'if self.chat_display is not None:'),
        ('packet_update_timer', 'if hasattr(self, \'packet_update_timer\'):',
         'if self.packet_update_timer is not None:'),
        ('log_access_history', 'if not hasattr(self, \'log_access_history\'):',
         'if self.log_access_history is None:'),
        ('disasm_text', 'if hasattr(self, \'disasm_text\'):',
         'if self.disasm_text is not None:'),
    ]
}


def fix_hasattr_checks(file_path: str, fixes: list):
    """Fix hasattr checks by converting them to None checks."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        original_content = content

        for attr_name, old_pattern, new_pattern in fixes:
            # First try exact match
            if old_pattern in content:
                content = content.replace(old_pattern, new_pattern)
                print(f"  Fixed: {old_pattern} -> {new_pattern}")
            else:
                # Try regex for variations
                # Handle different quote styles and spacing
                patterns = [
                    rf'if\s+not\s+hasattr\s*\(\s*self\s*,\s*[\'"]?{attr_name}[\'"]?\s*\)\s*:',
                    rf'if\s+hasattr\s*\(\s*self\s*,\s*[\'"]?{attr_name}[\'"]?\s*\)\s*:'
                ]

                for pattern in patterns:
                    matches = list(re.finditer(pattern, content))
                    # Process in reverse to maintain positions
                    for match in reversed(matches):
                        old_text = match.group(0)
                        if 'not hasattr' in old_text:
                            new_text = f'if self.{attr_name} is None:'
                        else:
                            new_text = f'if self.{attr_name} is not None:'

                        content = content[:match.start()] + \
                            new_text + content[match.end():]
                        print(f"  Fixed: {old_text} -> {new_text}")

        if content != original_content:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            print(f"  Saved changes to {file_path}")
        else:
            print(f"  No changes needed for {file_path}")

    except Exception as e:
        print(f"  Error processing {file_path}: {e}")


def main():
    """Main function to fix hasattr issues."""
    import os

    print("Fixing hasattr checks that were affected by W0201 fixes...\n")

    for file_path, fixes in HASATTR_FIXES.items():
        full_path = os.path.join('/mnt/c/Intellicrack', file_path)

        if os.path.exists(full_path):
            print(f"Processing {file_path}...")
            fix_hasattr_checks(full_path, fixes)
        else:
            print(f"File not found: {full_path}")

    print("\nDone! The hasattr checks have been converted to None checks.")
    print("This ensures the functionality is preserved while keeping the W0201 fixes.")


if __name__ == '__main__':
    main()

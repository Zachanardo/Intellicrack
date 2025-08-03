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
Binary Patcher Plugin Template
Specialized template for binary patching operations
"""

import logging
import shutil
from dataclasses import dataclass
from typing import List


@dataclass
class BinaryPatch:
    """Represents a binary patch operation."""
    offset: int
    original_bytes: bytes
    patched_bytes: bytes
    description: str
    patch_type: str = "defensive"


class BinaryPatcherPlugin:
    """Plugin for binary patching operations on executables."""
    def __init__(self):
        """Initialize the binary patcher plugin."""
        super().__init__()
        self.patches: List[BinaryPatch] = []
        self.logger = logging.getLogger(__name__)

    def analyze(self, binary_path):
        """Analyze binary for patchable locations."""
        results = []
        results.append(f"Scanning for patch targets in: {binary_path}")

        # Example: Find specific byte patterns
        try:
            with open(binary_path, "rb") as f:
                data = f.read()

                # Look for common patterns
                if b"\x90\x90\x90\x90" in data:
                    results.append("Found NOP sled - potential patch location")

                if b"\x55\x8b\xec" in data:
                    results.append("Found function prologue - patchable")

        except Exception as e:
            results.append(f"Analysis error: {e}")

        return results

    def patch(self, binary_path, patch_data=None):
        """Apply defensive security patches to the binary."""
        results = []

        # Create backup
        backup_path = binary_path + ".backup"
        try:
            shutil.copy2(binary_path, backup_path)
            results.append(f"Created backup: {backup_path}")
        except Exception as e:
            results.append(f"Backup creation failed: {e}")
            return results

        try:
            with open(binary_path, "rb") as f:
                data = bytearray(f.read())

            original_size = len(data)
            patches_applied = 0

            # Defensive patch: NOP out license check jumps (common protection research)
            # Pattern: JZ/JNZ instructions that might be license checks
            license_check_patterns = [
                b"\x74\x0c",  # JZ short +12
                b"\x75\x0c",  # JNZ short +12
                b"\x74\x0a",  # JZ short +10
                b"\x75\x0a",  # JNZ short +10
            ]

            for pattern in license_check_patterns:
                offset = 0
                while True:
                    offset = data.find(pattern, offset)
                    if offset == -1:
                        break

                    # Validate this looks like a license check area
                    context = data[max(0, offset-10):offset+20]
                    if b"license" in context.lower() or b"trial" in context.lower():
                        # NOP out the conditional jump (defensive research technique)
                        data[offset:offset+len(pattern)] = b"\x90" * len(pattern)
                        patches_applied += 1
                        results.append(f"Patched potential license check at offset 0x{offset:x}")

                    offset += 1

            # Defensive patch: Remove trial period checks
            trial_patterns = [
                b"trial",
                b"TRIAL",
                b"Trial",
                b"demo",
                b"DEMO",
                b"Demo"
            ]

            for pattern in trial_patterns:
                offset = 0
                while True:
                    offset = data.find(pattern, offset)
                    if offset == -1:
                        break

                    # Check if this appears to be in a string or message
                    # Look for null terminators or printable characters
                    start = max(0, offset - 5)
                    end = min(len(data), offset + len(pattern) + 5)
                    context = data[start:end]

                    # If it looks like a trial message, neutralize it
                    if any(c == 0 or (32 <= c <= 126) for c in context):
                        # Replace with spaces to maintain string structure
                        data[offset:offset+len(pattern)] = b" " * len(pattern)
                        patches_applied += 1
                        results.append(f"Neutralized trial text at offset 0x{offset:x}")

                    offset += len(pattern)

            # Validate file integrity after patching
            if len(data) != original_size:
                results.append("Error: File size changed during patching")
                return results

            if patches_applied > 0:
                # Write patched file
                with open(binary_path, "wb") as f:
                    f.write(data)

                results.append(f"Successfully applied {patches_applied} patches")
                results.append("Patch types applied:")
                results.append("- License check bypass (defensive research)")
                results.append("- Trial period text neutralization")
                results.append("File integrity maintained")
            else:
                results.append("No applicable patches found")
                results.append("File analysis completed - no modifications needed")

        except Exception as e:
            results.append(f"Patching error: {e}")
            # Restore from backup on error
            try:
                shutil.copy2(backup_path, binary_path)
                results.append("Restored original file from backup")
            except:
                results.append("Failed to restore backup - manual restoration required")

        return results

def register():
    """Register and return an instance of the binary patcher plugin."""
    return BinaryPatcherPlugin()

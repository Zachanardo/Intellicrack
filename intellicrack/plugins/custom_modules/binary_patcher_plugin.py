"""Binary patcher plugin for Intellicrack.

This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see https://www.gnu.org/licenses/.
"""

import logging
import shutil
from dataclasses import dataclass

from intellicrack.utils.logger import log_all_methods


"""
Binary Patcher Plugin Template
Specialized template for binary patching operations
"""


@dataclass
class BinaryPatch:
    """Represents a binary patch operation.

    This dataclass encapsulates the metadata and byte sequences for a single
    binary patch operation, including the location, original content, patched
    content, and type of patch applied.

    Attributes:
        offset: The byte offset in the binary where the patch is applied.
        original_bytes: The original bytes at the patch location before patching.
        patched_bytes: The replacement bytes to write at the patch location.
        description: Human-readable description of the patch operation.
        patch_type: Classification of the patch type (default: "defensive").

    """

    offset: int
    original_bytes: bytes
    patched_bytes: bytes
    description: str
    patch_type: str = "defensive"


@log_all_methods
class BinaryPatcherPlugin:
    """Plugin for binary patching operations on executables."""

    def __init__(self) -> None:
        """Initialize the binary patcher plugin."""
        super().__init__()
        self.patches: list[BinaryPatch] = []
        self.logger = logging.getLogger(__name__)

    def analyze(self, binary_path: str) -> list[str]:
        """Analyze binary for patchable locations.

        Scans a binary executable for common patterns that indicate patchable
        locations related to licensing checks and protection mechanisms. This
        analysis identifies potential targets for defensive research patching
        including NOP sleds and function prologues.

        Args:
            binary_path: Absolute or relative path to the binary file to analyze.

        Returns:
            A list of strings containing analysis results and findings, including
            identified patch targets and any errors encountered during analysis.

        Raises:
            No exceptions are explicitly raised; errors are caught and reported
            in the returned results list.

        """
        results = [f"Scanning for patch targets in: {binary_path}"]
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
            self.logger.exception("Analysis error: %s", e)
            results.append(f"Analysis error: {e}")

        return results

    def patch(self, binary_path: str, patch_data: dict[str, object] | None = None) -> list[str]:
        """Apply defensive security patches to the binary.

        Applies defensive research patches to remove or neutralize licensing
        checks and trial period enforcement mechanisms in a binary executable.
        This method creates a backup before patching and implements rollback
        functionality if patching fails. Patches target common licensing
        protection patterns including conditional jumps around license checks
        and trial-related string markers.

        Args:
            binary_path: Absolute or relative path to the binary executable to patch.
            patch_data: Optional dictionary containing patch configuration parameters
                (currently unused but reserved for future extension).

        Returns:
            A list of strings containing detailed results of the patching operation,
            including backup creation status, number of patches applied, patch types,
            and any errors encountered.

        Raises:
            No exceptions are explicitly raised; all errors are caught and reported
            in the returned results list. File restoration is attempted on failure.

        Notes:
            - Creates a .backup file before any modifications
            - Implements file size validation to detect corruption
            - Uses NOP (0x90) byte sequences to neutralize conditional jumps
            - Replaces trial-related text with spaces to preserve string structure
            - Restores from backup if patching encounters errors

        """
        results = []

        # Create backup
        backup_path = f"{binary_path}.backup"
        try:
            shutil.copy2(binary_path, backup_path)
            results.append(f"Created backup: {backup_path}")
        except Exception as e:
            self.logger.exception("Backup creation failed: %s", e)
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
                    context = data[max(0, offset - 10) : offset + 20]
                    if b"license" in context.lower() or b"trial" in context.lower():
                        # NOP out the conditional jump (defensive research technique)
                        data[offset : offset + len(pattern)] = b"\x90" * len(pattern)
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
                b"Demo",
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
                        data[offset : offset + len(pattern)] = b" " * len(pattern)
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

                results.extend((
                    f"Successfully applied {patches_applied} patches",
                    "Patch types applied:",
                    "- License check bypass (defensive research)",
                    "- Trial period text neutralization",
                    "File integrity maintained",
                ))
            else:
                results.extend((
                    "No applicable patches found",
                    "File analysis completed - no modifications needed",
                ))
        except Exception as e:
            self.logger.exception("Patching error: %s", e)
            results.append(f"Patching error: {e}")
            # Restore from backup on error
            try:
                shutil.copy2(backup_path, binary_path)
                results.append("Restored original file from backup")
            except Exception:
                self.logger.exception("Failed to restore backup - manual restoration required")
                results.append("Failed to restore backup - manual restoration required")

        return results


def register() -> BinaryPatcherPlugin:
    """Register and return an instance of the binary patcher plugin.

    Factory function that instantiates and returns a new BinaryPatcherPlugin
    instance. This function is called by the plugin system to create the plugin
    for use in the Intellicrack framework.

    Returns:
        A fully initialized BinaryPatcherPlugin instance ready for use.

    Notes:
        This function follows the standard plugin registration interface and
        should be called by the plugin loader system.

    """
    return BinaryPatcherPlugin()

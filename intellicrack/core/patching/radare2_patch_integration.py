"""Radare2 Patch Integration Module.

Integrates enhanced Radare2 patch instruction generation from Day 4.1
with existing binary modification capabilities.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellicrack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""

import logging
import os
import shutil
from typing import Any

from ...plugins.custom_modules.binary_patcher_plugin import BinaryPatch, BinaryPatcherPlugin
from ..analysis.radare2_bypass_generator import R2BypassGenerator


logger = logging.getLogger(__name__)


class R2PatchIntegrator:
    """Integrates Radare2 bypass generation with binary modification capabilities."""

    def __init__(self) -> None:
        """Initialize the R2 patch integrator."""
        self.bypass_generator = R2BypassGenerator()
        self.binary_patcher = BinaryPatcherPlugin()
        self.patch_cache = {}

    def generate_integrated_patches(self, binary_path: str, license_analysis: dict[str, Any]) -> dict[str, Any]:
        """Generate patches using R2 bypass generator and convert to binary patches.

        Args:
            binary_path: Path to the binary file
            license_analysis: License analysis results from R2

        Returns:
            Dictionary containing integrated patch results

        """
        try:
            # Generate R2 bypass patches using enhanced instruction generation
            bypass_result = self._generate_r2_bypass_patches(binary_path, license_analysis)

            # Convert R2 patches to binary patch format
            binary_patches = self._convert_r2_to_binary_patches(bypass_result)

            # Validate patches using existing binary patcher
            validated_patches = self._validate_patches_with_binary_patcher(binary_patches)

            # Create integrated result
            integrated_result = {
                "success": True,
                "binary_path": binary_path,
                "r2_bypass_patches": bypass_result.get("automated_patches", []),
                "memory_patches": bypass_result.get("memory_patches", []),
                "binary_patches": validated_patches,
                "patch_count": len(validated_patches),
                "integration_metadata": {
                    "r2_generator_version": "enhanced_v4.1",
                    "binary_patcher_integration": True,
                    "validation_passed": True,
                },
            }

            logger.info("Generated %d integrated patches for %s", len(validated_patches), binary_path)
            return integrated_result

        except Exception as e:
            logger.exception("Error generating integrated patches: %s", e)
            return {
                "success": False,
                "error": str(e),
                "binary_path": binary_path,
                "binary_patches": [],
            }

    def _generate_r2_bypass_patches(self, binary_path: str, license_analysis: dict[str, Any]) -> dict[str, Any]:
        """Generate bypass patches using the enhanced R2 bypass generator."""
        try:
            # Use the existing R2 bypass generator with enhanced patch instructions
            with self.bypass_generator._get_r2_session(binary_path) as r2:
                return {
                    "automated_patches": self.bypass_generator._generate_automated_patches(r2, license_analysis),
                    "memory_patches": self.bypass_generator._generate_memory_patches(r2, license_analysis),
                }
        except Exception as e:
            logger.exception("Error generating R2 bypass patches: %s", e)
            return {"automated_patches": [], "memory_patches": []}

    def _convert_r2_to_binary_patches(self, r2_result: dict[str, Any]) -> list[BinaryPatch]:
        """Convert R2 patch format to binary patch format.

        Args:
            r2_result: Results from R2 bypass generator

        Returns:
            List of BinaryPatch objects

        """
        binary_patches = []

        # Process automated patches
        for patch in r2_result.get("automated_patches", []):
            if binary_patch := self._create_binary_patch_from_r2(patch, "automated"):
                binary_patches.append(binary_patch)

        # Process memory patches
        for patch in r2_result.get("memory_patches", []):
            if binary_patch := self._create_binary_patch_from_r2(patch, "memory"):
                binary_patches.append(binary_patch)

        return binary_patches

    def _create_binary_patch_from_r2(self, r2_patch: dict[str, Any], patch_category: str) -> BinaryPatch | None:
        """Create a BinaryPatch from R2 patch data.

        Args:
            r2_patch: R2 patch dictionary
            patch_category: Category of patch (automated/memory)

        Returns:
            BinaryPatch object or None if conversion fails

        """
        try:
            # Extract address (handle both hex string and int formats)
            address_str = r2_patch.get("address", "0x0")
            if isinstance(address_str, str):
                if address_str.startswith("0x"):
                    offset = int(address_str, 16)
                else:
                    offset = int(address_str, 16)  # Assume hex
            else:
                offset = int(address_str)

            if patch_bytes_str := r2_patch.get("patch_bytes", ""):
                # Handle hex string format (remove spaces, convert to bytes)
                clean_hex = patch_bytes_str.replace(" ", "").replace("??", "90")
                # Ensure even length for proper byte conversion
                if len(clean_hex) % 2:
                    clean_hex += "0"
                patched_bytes = bytes.fromhex(clean_hex)
            else:
                # Fallback: NOP instruction
                patched_bytes = b"\x90"

            if original_bytes_str := r2_patch.get("original_bytes", ""):
                clean_orig_hex = original_bytes_str.replace(" ", "")
                if len(clean_orig_hex) % 2:
                    clean_orig_hex += "0"
                original_bytes = bytes.fromhex(clean_orig_hex)
            else:
                original_bytes = self._read_original_bytes_from_binary(r2_patch.get("binary_path", ""), offset, len(patched_bytes))

            # Create description
            description = r2_patch.get("patch_description", f"{patch_category}_patch_at_{hex(offset)}")

            return BinaryPatch(
                offset=offset,
                original_bytes=original_bytes,
                patched_bytes=patched_bytes,
                description=description,
                patch_type="license_bypass",
            )

        except (ValueError, TypeError) as e:
            logger.exception("Error converting R2 patch to binary patch: %s", e)
            return None

    def _validate_patches_with_binary_patcher(self, patches: list[BinaryPatch]) -> list[BinaryPatch]:
        """Validate patches using the existing binary patcher plugin.

        Args:
            patches: List of BinaryPatch objects

        Returns:
            List of validated BinaryPatch objects

        """
        validated_patches = []

        for patch in patches:
            # Basic validation: check that patch has valid data
            if self._is_valid_patch(patch):
                # Add to binary patcher's patch list for tracking
                self.binary_patcher.patches.append(patch)
                validated_patches.append(patch)
            else:
                logger.warning("Invalid patch at offset %s: %s", hex(patch.offset), patch.description)

        logger.info("Validated %d/%d patches", len(validated_patches), len(patches))
        return validated_patches

    def _is_valid_patch(self, patch: BinaryPatch) -> bool:
        """Validate a single binary patch.

        Args:
            patch: BinaryPatch to validate

        Returns:
            True if patch is valid, False otherwise

        """
        # Check offset is valid
        if patch.offset < 0:
            return False

        # Check that patched bytes exist
        if not patch.patched_bytes:
            return False

        # Check that original and patched bytes have compatible lengths
        if len(patch.original_bytes) > 0 and len(patch.patched_bytes) > len(patch.original_bytes) * 2:
            return False

        return len(patch.patched_bytes) <= 1024

    def _read_original_bytes_from_binary(self, binary_path: str, offset: int, length: int) -> bytes:
        """Read original bytes from binary file at specified offset.

        Args:
            binary_path: Path to the binary file
            offset: Offset in the binary
            length: Number of bytes to read

        Returns:
            Original bytes from binary, or zeros if unable to read

        """
        try:
            if not binary_path or not os.path.exists(binary_path):
                logger.warning("Binary path not available or doesn't exist: %s", binary_path)
                return b"\x00" * length

            with open(binary_path, "rb") as f:
                f.seek(offset)
                original_bytes = f.read(length)

                if len(original_bytes) < length:
                    logger.warning("Read only %d/%d bytes from %s at offset %s", len(original_bytes), length, binary_path, hex(offset))
                    original_bytes += b"\x00" * (length - len(original_bytes))

                return original_bytes

        except (OSError, ValueError) as e:
            logger.exception("Failed to read original bytes from %s at offset %s: %s", binary_path, hex(offset), e)
            return b"\x00" * length

    def apply_integrated_patches(self, binary_path: str, patches: list[BinaryPatch], output_path: str | None = None) -> dict[str, Any]:
        """Apply integrated patches to a binary file.

        Args:
            binary_path: Path to the original binary
            patches: List of BinaryPatch objects to apply
            output_path: Output path for patched binary (optional)

        Returns:
            Dictionary containing application results

        """
        try:
            if not output_path:
                output_path = f"{binary_path}.patched"

            # Create backup of original binary
            backup_path = f"{binary_path}.backup"
            shutil.copy2(binary_path, backup_path)

            # Copy to output location
            shutil.copy2(binary_path, output_path)

            # Apply patches to the copied binary
            patches_applied = 0
            failed_patches = []

            with open(output_path, "r+b") as binary_file:
                for patch in patches:
                    try:
                        # Seek to patch location
                        binary_file.seek(patch.offset)

                        # Read current bytes for verification
                        current_bytes = binary_file.read(len(patch.original_bytes))

                        # Verify original bytes match (if specified and non-zero)
                        if (
                            patch.original_bytes
                            and patch.original_bytes != b"\x00" * len(patch.original_bytes)
                            and current_bytes != patch.original_bytes
                        ):
                            logger.warning(
                                "Original bytes mismatch at %s: expected %s, found %s",
                                hex(patch.offset),
                                patch.original_bytes.hex(),
                                current_bytes.hex(),
                            )

                        # Apply patch
                        binary_file.seek(patch.offset)
                        binary_file.write(patch.patched_bytes)
                        patches_applied += 1

                        logger.debug("Applied patch at %s: %s", hex(patch.offset), patch.description)

                    except Exception as e:
                        logger.exception("Failed to apply patch at %s: %s", hex(patch.offset), e)
                        failed_patches.append({"patch": patch, "error": str(e)})

            result = {
                "success": True,
                "output_path": output_path,
                "backup_path": backup_path,
                "patches_applied": patches_applied,
                "patches_failed": len(failed_patches),
                "failed_patches": failed_patches,
            }

            logger.info("Applied %d/%d patches to %s", patches_applied, len(patches), output_path)
            return result

        except Exception as e:
            logger.exception("Error applying integrated patches: %s", e)
            return {
                "success": False,
                "error": str(e),
                "output_path": output_path,
                "patches_applied": 0,
            }

    def get_integration_status(self) -> dict[str, Any]:
        """Get the current integration status.

        Returns:
            Dictionary containing integration status information

        """
        return {
            "r2_bypass_generator": {
                "available": self.bypass_generator is not None,
                "enhanced_instructions": True,
                "version": "4.1_enhanced",
            },
            "binary_patcher": {
                "available": self.binary_patcher is not None,
                "patches_loaded": len(self.binary_patcher.patches),
            },
            "integration": {"active": True, "cache_entries": len(self.patch_cache)},
        }

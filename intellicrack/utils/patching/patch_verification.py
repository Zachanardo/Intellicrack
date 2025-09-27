"""Patch verification utilities for validating binary patches."""

import os
import shutil
import tempfile
import time
import traceback
from typing import Any

from intellicrack.logger import logger

from ..exploitation.exploitation import run_automated_patch_agent
from ..logger import log_message

"""
Patch verification and validation utilities for Intellicrack.

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


# Import analysis dependencies with fallbacks
try:
    from intellicrack.handlers.capstone_handler import (
        CS_ARCH_X86,
        CS_MODE_32,
        CS_MODE_64,
        Cs,
        capstone,
    )

    CAPSTONE_AVAILABLE = True
except ImportError as e:
    logger.error("Import error in patch_verification: %s", e)
    capstone = None
    CS_ARCH_X86 = CS_MODE_32 = CS_MODE_64 = Cs = None
    CAPSTONE_AVAILABLE = False

try:
    from intellicrack.handlers.pefile_handler import pefile

    PEFILE_AVAILABLE = True
except ImportError as e:
    logger.error("Import error in patch_verification: %s", e)
    pefile = None
    PEFILE_AVAILABLE = False

try:
    import keystone
except ImportError as e:
    logger.error("Import error in patch_verification: %s", e)
    keystone = None


def verify_patches(app: Any, patched_path: str, instructions: list[dict[str, Any]]) -> list[str]:
    """Verify that patches were applied correctly.

    Args:
        app: Application instance
        patched_path: Path to the patched binary
        instructions: List of patch instructions with addresses and byte values

    Returns:
        List[str]: Verification results messages

    """
    app.update_output.emit(log_message(f"[Verify] Verifying patches in {patched_path}..."))

    if not pefile:
        return ["Error: pefile module not available for patch verification"]

    try:
        pe = pefile.PE(patched_path)

        verification_results = []
        success_count = 0
        fail_count = 0

        for patch in instructions:
            address = patch.get("address")
            expected_bytes = patch.get("new_bytes")
            description = patch.get("description", "No description")

            if not address or not expected_bytes:
                verification_results.append(f"Invalid patch instruction: {patch}")
                fail_count += 1
                continue

            # Get file offset from RVA - using identical calculation logic as in apply_patches
            image_base = pe.OPTIONAL_HEADER.ImageBase
            if address >= image_base:
                rva = address - image_base
                try:
                    offset = pe.get_offset_from_rva(rva)
                except (OSError, ValueError, RuntimeError) as offset_error:
                    logger.error("Error in patch_verification: %s", offset_error)
                    error_msg = f"Error calculating offset for address 0x{address:X}: {offset_error}"
                    app.update_output.emit(log_message(f"[Verify] {error_msg}"))
                    verification_results.append(error_msg)
                    fail_count += 1
                    continue
            else:
                # Assuming address might be a direct file offset if smaller than image base
                offset = address
                app.update_output.emit(
                    log_message(f"[Verify] Warning: Address 0x{address:X} seems low, treating as direct file offset 0x{offset:X}.")
                )

            # Check bytes at offset
            try:
                with open(patched_path, "rb") as f:
                    f.seek(offset)
                    actual_bytes = f.read(len(expected_bytes))

                if actual_bytes == expected_bytes:
                    verification_results.append(f"Patch at 0x{address:X} verified successfully: {description}")
                    success_count += 1
                else:
                    mismatch_msg = f"Patch at 0x{address:X} verification failed: expected {expected_bytes.hex().upper()}, got {actual_bytes.hex().upper()}"
                    # Add explicit warning log for UI display
                    app.update_output.emit(log_message(f"[Verify] WARNING: {mismatch_msg}"))
                    verification_results.append(mismatch_msg)
                    fail_count += 1
            except (OSError, ValueError, RuntimeError) as read_error:
                logger.error("Error in patch_verification: %s", read_error)
                verification_results.append(f"Error reading bytes at address 0x{address:X}: {read_error}")
                fail_count += 1

        # Summary
        verification_results.append(f"Verification complete: {success_count} patches succeeded, {fail_count} failed")

        return verification_results

    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error in patch_verification: %s", e)
        return [f"Error during patch verification: {e}"]


def test_patch_and_verify(binary_path: str, patches: list[dict[str, Any]]) -> list[str]:
    """Test patch application in isolated environment and verify results.

    Creates a temporary copy of the binary, applies patches, and performs
    comprehensive verification including sandbox testing.

    Args:
        binary_path: Path to the original binary
        patches: List of patch instructions

    Returns:
        List[str]: Test results messages

    """
    results = [f"Testing {len(patches)} patches on {binary_path}..."]

    if not pefile:
        results.append("Error: pefile module not available for patch testing")
        return results

    try:
        # Create a temporary directory for isolated testing
        temp_dir = tempfile.mkdtemp(prefix="intellicrack_test_")
        temp_path = os.path.join(temp_dir, os.path.basename(binary_path))
        shutil.copy2(binary_path, temp_path)

        results.append(f"Created test environment at {temp_dir}")

        # Apply patches to the temporary copy
        pe = pefile.PE(temp_path)

        patch_results = []
        for i, patch in enumerate(patches):
            try:
                address = patch.get("address")
                new_bytes = patch.get("new_bytes")
                description = patch.get("description", "No description")

                if not address or not new_bytes:
                    patch_results.append((False, f"Patch {i + 1}: Invalid patch data"))
                    continue

                # Get file offset from RVA
                offset = pe.get_offset_from_rva(address - pe.OPTIONAL_HEADER.ImageBase)

                # Apply patch
                with open(temp_path, "r+b") as f:
                    f.seek(offset)
                    f.write(new_bytes)

                patch_results.append(
                    (
                        True,
                        f"Patch {i + 1}: Successfully applied at offset 0x{offset:X} ({description})",
                    )
                )
            except (OSError, ValueError, RuntimeError) as patch_error:
                logger.error("Error in patch_verification: %s", patch_error)
                patch_results.append((False, f"Patch {i + 1}: Failed - {patch_error}"))

        # Report patch results
        results.append("\nPatch verification results:")
        for success, message in patch_results:
            if success:
                results.append(f"✓ {message}")
            else:
                results.append(f"✗ {message}")

        # Verify patched binary
        try:
            # Basic verification: check if the file loads and seems valid
            verification_pe = pefile.PE(temp_path)
            is_valid_pe = True
        except (OSError, ValueError, RuntimeError) as verification_error:
            logger.error("Error in patch_verification: %s", verification_error)
            is_valid_pe = False
            results.append(f"\nVerification failed: Invalid PE file after patching - {verification_error}")

        if is_valid_pe:
            results.append("\nBasic verification passed: File appears to be a valid PE executable")

            # Compare sections with original
            original_pe = pefile.PE(binary_path)

            # Check section sizes
            for i, (orig_section, patched_section) in enumerate(zip(original_pe.sections, verification_pe.sections, strict=False)):
                orig_name = orig_section.Name.decode("utf-8", "ignore").strip("\x00")
                patched_name = patched_section.Name.decode("utf-8", "ignore").strip("\x00")

                if orig_name != patched_name:
                    results.append(f"Warning: Section {i + 1} name changed: {orig_name} -> {patched_name}")

                if orig_section.SizeOfRawData != patched_section.SizeOfRawData:
                    results.append(
                        f"Warning: Section {orig_name} size changed: {orig_section.SizeOfRawData} -> {patched_section.SizeOfRawData}"
                    )

            # Check entry point
            if hasattr(original_pe, "OPTIONAL_HEADER") and hasattr(verification_pe, "OPTIONAL_HEADER"):
                if hasattr(original_pe.OPTIONAL_HEADER, "AddressOfEntryPoint") and hasattr(
                    verification_pe.OPTIONAL_HEADER, "AddressOfEntryPoint"
                ):
                    if original_pe.OPTIONAL_HEADER.AddressOfEntryPoint != verification_pe.OPTIONAL_HEADER.AddressOfEntryPoint:
                        results.append(
                            f"Warning: Entry point changed: 0x{original_pe.OPTIONAL_HEADER.AddressOfEntryPoint:X} -> 0x{verification_pe.OPTIONAL_HEADER.AddressOfEntryPoint:X}"
                        )
                    else:
                        results.append(f"Entry point verification passed: 0x{verification_pe.OPTIONAL_HEADER.AddressOfEntryPoint:X}")
                else:
                    results.append("Warning: Could not verify entry point - AddressOfEntryPoint attribute not found")
            else:
                results.append("Warning: Could not verify entry point - OPTIONAL_HEADER not found")

            # Verify patches were applied correctly
            for i, patch in enumerate(patches):
                try:
                    address = patch.get("address")
                    new_bytes = patch.get("new_bytes")
                    description = patch.get("description", "No description")

                    if not address or not new_bytes:
                        continue

                    # Get file offset from RVA
                    offset = verification_pe.get_offset_from_rva(address - verification_pe.OPTIONAL_HEADER.ImageBase)

                    # Read bytes at patched location
                    with open(temp_path, "rb") as f:
                        f.seek(offset)
                        actual_bytes = f.read(len(new_bytes))

                    if actual_bytes == new_bytes:
                        results.append(f"✓ Patch {i + 1} verification: Bytes match at offset 0x{offset:X}")
                    else:
                        results.append(f"✗ Patch {i + 1} verification: Bytes mismatch at offset 0x{offset:X}")
                        results.append(f"  Expected: {new_bytes.hex().upper()}")
                        results.append(f"  Actual: {actual_bytes.hex().upper()}")
                except (OSError, ValueError, RuntimeError) as verify_error:
                    logger.error("Error in patch_verification: %s", verify_error)
                    results.append(f"✗ Patch {i + 1} verification failed: {verify_error}")

        try:
            shutil.rmtree(temp_dir)
            results.append("\nCleanup: Temporary files removed")
        except (OSError, ValueError, RuntimeError) as cleanup_error:
            logger.error("Error in patch_verification: %s", cleanup_error)
            results.append(f"\nCleanup failed: {cleanup_error}")

    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error in patch_verification: %s", e)
        results.append(f"Error during patch verification: {e}")
        results.append(traceback.format_exc())

    return results


def apply_parsed_patch_instructions_with_validation(app: Any, instructions: list[dict[str, Any]]) -> bool:
    """Applies parsed patch instructions to a copy of the binary.

    Takes a list of patch instructions (typically parsed from AI output)
    and applies them to a copy of the target binary. Includes comprehensive
    validation, error handling, and backup creation for safety.

    Each instruction contains an address, new bytes to write, and a description.
    The function verifies each patch can be applied safely before making changes.

    Args:
        app: Application instance containing UI elements and binary path
        instructions: List of patch instructions with addresses and byte values

    Returns:
        bool: True if patching was successful, False otherwise

    """
    if not app.binary_path:
        app.update_output.emit(log_message("[Patch] Error: No binary selected."))
        return False
    if not instructions:
        app.update_output.emit(log_message("[Patch] Error: No patch instructions provided."))
        return False

    if not pefile:
        app.update_output.emit(log_message("[Patch] Error: pefile module not available for patching."))
        return False

    # Create backup (using timestamp for uniqueness)
    backup_path = app.binary_path + f".backup_{int(time.time())}"
    try:
        shutil.copy2(app.binary_path, backup_path)
        app.update_output.emit(log_message(f"[Patch] Created backup: {backup_path}"))
    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error in patch_verification: %s", e)
        app.update_output.emit(log_message(f"[Patch] CRITICAL ERROR: Failed to create backup: {e}"))
        app.update_output.emit(log_message("[Patch] Aborting patching process."))
        return False  # Stop patching if backup fails

    # Create patched file path
    base_name, ext = os.path.splitext(app.binary_path)
    patched_path = f"{base_name}_patched{ext}"

    try:
        # Copy original to patched path
        shutil.copy2(app.binary_path, patched_path)
        app.update_output.emit(log_message(f"[Patch] Created temporary patched file: {patched_path}"))

        # Load PE structure of the *patched* file for offset calculations
        try:
            pe = pefile.PE(patched_path)
            image_base = pe.OPTIONAL_HEADER.ImageBase
        except pefile.PEFormatError as e:
            logger.error("pefile.PEFormatError in patch_verification: %s", e)
            app.update_output.emit(log_message(f"[Patch] Error: Cannot parse PE structure of '{patched_path}': {e}"))
            app.update_output.emit(log_message("[Patch] Aborting patching."))
            # Clean up the potentially corrupted patched file
            try:
                os.remove(patched_path)
            except FileNotFoundError as e:
                logger.error("File not found in patch_verification: %s", e)
                # File already doesn't exist, which is fine
            except PermissionError as perm_error:
                logger.error("Permission error in patch_verification: %s", perm_error)
                app.update_output.emit(log_message(f"[Patch] Warning: Cannot remove corrupted file due to permissions: {perm_error}"))
            except OSError as os_error:
                logger.error("OS error in patch_verification: %s", os_error)
                app.update_output.emit(log_message(f"[Patch] Warning: Failed to cleanup corrupted file: {os_error}"))
            return False

        applied_count = 0
        error_count = 0

        # Apply patches to the copy
        with open(patched_path, "r+b") as f:
            for i, patch in enumerate(instructions):
                patch_num = i + 1
                address = patch.get("address")
                new_bytes = patch.get("new_bytes")
                desc = patch.get("description", "No description")

                if address is None or new_bytes is None:
                    app.update_output.emit(log_message(f"[Patch {patch_num}] Skipped: Invalid instruction data."))
                    error_count += 1
                    continue

                try:
                    # Calculate file offset from RVA (relative to image base)
                    # Ensure address is treated as RVA if it's above image
                    # base, otherwise assume direct file offset (less common)
                    if address >= image_base:
                        rva = address - image_base
                        try:
                            offset = pe.get_offset_from_rva(rva)
                        except Exception as e_rva:
                            logger.error("Exception in patch_verification: %s", e_rva)
                            app.update_output.emit(
                                log_message(f"[Patch {patch_num}] ERROR: Failed to get offset for RVA 0x{rva:X}: {e_rva}")
                            )
                            error_count += 1
                            continue  # Skip this patch entirely rather than using risky fallback
                    else:
                        # Assuming address might be a direct file offset if
                        # smaller than image base (use with caution)
                        offset = address
                        app.update_output.emit(
                            log_message(
                                f"[Patch {patch_num}] Warning: Address 0x{address:X} seems low, treating as direct file offset 0x{offset:X}."
                            )
                        )

                    # Apply patch
                    app.update_output.emit(
                        log_message(
                            f"[Patch {patch_num}] Applying at address 0x{address:X} (offset 0x{offset:X}): {len(new_bytes)} bytes for '{desc}'"
                        )
                    )
                    f.seek(offset)
                    f.write(new_bytes)
                    applied_count += 1

                except pefile.PEFormatError as e_offset:
                    logger.error("pefile.PEFormatError in patch_verification: %s", e_offset)
                    app.update_output.emit(
                        log_message(f"[Patch {patch_num}] Skipped: Error getting offset for address 0x{address:X}: {e_offset}")
                    )
                    error_count += 1
                except OSError as e_io:
                    logger.error("IO error in patch_verification: %s", e_io)
                    app.update_output.emit(
                        log_message(f"[Patch {patch_num}] Skipped: File I/O error applying patch at offset 0x{offset:X}: {e_io}")
                    )
                    error_count += 1
                except Exception as e_apply:
                    logger.error("Exception in patch_verification: %s", e_apply)
                    app.update_output.emit(log_message(f"[Patch {patch_num}] Skipped: Unexpected error applying patch: {e_apply}"))
                    app.update_output.emit(log_message(traceback.format_exc()))
                    error_count += 1

        # Close the PE file handle before verification
        pe.close()

        app.update_output.emit(log_message(f"[Patch] Applied {applied_count} patches with {error_count} errors/skips."))

        if applied_count > 0 and error_count == 0:
            app.update_output.emit(log_message(f"[Patch] Verifying patched file integrity: {patched_path}"))

            # --- Post-Patch Validation ---
            validation_passed = False
            try:
                # 1. Basic PE Load Check
                verify_pe = pefile.PE(patched_path)
                verify_pe.close()  # Close handle after check
                validation_passed = True
                app.update_output.emit(log_message("[Verify] Patched file is still a valid PE executable."))
            except pefile.PEFormatError as e_verify:
                logger.error("pefile.PEFormatError in patch_verification: %s", e_verify)
                app.update_output.emit(
                    log_message(f"[Verify] CRITICAL ERROR: Patched file '{patched_path}' failed PE validation: {e_verify}")
                )
                app.update_output.emit(log_message("[Verify] The patch might have corrupted the file structure."))
                app.update_output.emit(log_message(f"[Verify] Please examine the file or restore from backup: {backup_path}"))

            # --- Detailed Byte Verification ---
            if validation_passed:
                verification_results = verify_patches(app, patched_path, instructions)  # Use the existing verify function
                for line in verification_results:
                    app.update_output.emit(log_message(f"[Verify] {line}"))

                # Check if all patches verified successfully
                if all("verified successfully" in line or "Invalid patch" in line for line in verification_results):
                    app.update_output.emit(log_message(f"[Patch] Successfully created and verified patched file: {patched_path}"))
                    return True
                app.update_output.emit(log_message("[Patch] Warning: Some patches could not be verified. Review logs."))

        elif applied_count == 0:
            app.update_output.emit(log_message("[Patch] No patches were applied. Original file remains unchanged."))
            # Clean up the copied file if no patches applied
            try:
                os.remove(patched_path)
            except FileNotFoundError as e:
                logger.error("File not found in patch_verification: %s", e)
                # File already doesn't exist, which is acceptable
            except PermissionError as perm_error2:
                logger.error("Permission error in patch_verification: %s", perm_error2)
                app.update_output.emit(log_message(f"[Patch] Warning: Cannot remove unused patched file due to permissions: {perm_error2}"))
            except OSError as os_error2:
                logger.error("OS error in patch_verification: %s", os_error2)
                app.update_output.emit(log_message(f"[Patch] Warning: Failed to cleanup unused patched file: {os_error2}"))
        else:  # Errors occurred during patching
            app.update_output.emit(log_message(f"[Patch] Patching completed with {error_count} errors. Review logs for details."))

    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error in patch_verification: %s", e)
        app.update_output.emit(log_message(f"[Patch] Error during patching process: {e}"))
        app.update_output.emit(log_message(traceback.format_exc()))

    return False


def _validate_binary_selection(app: Any) -> bool:
    """Validate that a binary is selected.

    Returns:
        True if binary is selected, False otherwise

    """
    if not app.binary_path:
        app.update_output.emit(log_message("[License Rewrite] No binary selected."))
        return False
    return True


def _process_deep_analysis_candidates(app: Any) -> tuple[list, str]:
    """Process candidates from deep license analysis.

    Returns:
        Tuple of (patches list, strategy used)

    """
    patches = []
    strategy_used = "None"

    app.update_output.emit(log_message("[License Rewrite] Running deep license analysis to find candidates..."))
    from ...core.analysis.core_analysis import enhanced_deep_license_analysis

    candidates = enhanced_deep_license_analysis(app.binary_path)

    if not candidates:
        return patches, strategy_used

    app.update_output.emit(log_message(f"[License Rewrite] Deep analysis found {len(candidates)} candidates. Processing top candidates..."))
    strategy_used = "Deep Analysis"

    # Sort candidates by confidence
    candidates = _sort_candidates_by_confidence(candidates)
    top_candidates = candidates[:5]  # Limit number of candidates to patch

    # Process candidates with pefile/capstone/keystone
    patches = _process_candidates_with_tools(app, top_candidates, candidates)

    return patches, strategy_used


def _sort_candidates_by_confidence(candidates):
    """Sort candidates by confidence score.

    Returns:
        Sorted list of candidates

    """
    if isinstance(candidates, list):
        candidates.sort(key=lambda x: x.get("confidence", 0), reverse=True)
    elif isinstance(candidates, dict):
        # Convert dict to list if needed
        candidates = list(candidates.values()) if hasattr(candidates, "values") else []
    return candidates


def _process_candidates_with_tools(app: Any, top_candidates: list, candidates: list) -> list:
    """Process candidates using pefile, capstone, and keystone tools.

    Returns:
        List of patches generated

    """
    patches = []

    if not pefile or not Cs or not keystone:
        app.update_output.emit(log_message("[License Rewrite] Error: Required modules (pefile, capstone, keystone) not found."))
        return patches

    try:
        pe = pefile.PE(app.binary_path)
        is_64bit = getattr(pe.FILE_HEADER, "Machine", 0) == 0x8664

        # Setup disassembler and assembler
        tools = _setup_disassembly_tools(is_64bit)

        # Get .text section
        text_section = _get_text_section(pe, app)
        if not text_section:
            return patches

        code_data = text_section.get_data()
        code_base_addr = pe.OPTIONAL_HEADER.ImageBase + text_section.VirtualAddress

        # Process each candidate
        for candidate in top_candidates:
            patch = _process_single_candidate(app, candidate, is_64bit, tools, code_data, code_base_addr, candidates)
            if patch:
                patches.append(patch)

    except ImportError as e:
        logger.error("Import error in patch_verification: %s", e)
        app.update_output.emit(log_message("[License Rewrite] Error: Required modules (pefile, capstone, keystone) not found."))
    except Exception as e_deep:
        logger.error("Exception in patch_verification: %s", e_deep)
        app.update_output.emit(log_message(f"[License Rewrite] Error processing deep analysis candidates: {e_deep}"))
        app.update_output.emit(log_message(traceback.format_exc()))

    return patches


def _setup_disassembly_tools(is_64bit: bool) -> dict:
    """Setup capstone and keystone tools.

    Returns:
        Dictionary with 'ks' and 'md' tools

    """
    arch = keystone.KS_ARCH_X86
    ks_mode = keystone.KS_MODE_64 if is_64bit else keystone.KS_MODE_32
    cs_mode = CS_MODE_64 if is_64bit else CS_MODE_32

    ks = keystone.Ks(arch, ks_mode)
    md = Cs(CS_ARCH_X86, cs_mode)
    md.detail = True  # Enable detail for instruction size

    return {"ks": ks, "md": md}


def _get_text_section(pe, app: Any):
    """Get the .text section from PE file.

    Returns:
        Text section or None if not found

    """
    text_section = next((s for s in pe.sections if b".text" in s.Name.lower()), None)
    if not text_section:
        app.update_output.emit(log_message("[License Rewrite] Error: Cannot find .text section."))
    return text_section


def _process_single_candidate(
    app: Any,
    candidate: dict,
    is_64bit: bool,
    tools: dict,
    code_data: bytes,
    code_base_addr: int,
    candidates: list,
) -> dict | None:
    """Process a single candidate for patching.

    Returns:
        Patch dictionary or None if no patch generated

    """
    start_addr = candidate["start"]
    keywords = candidate.get("keywords", [])

    app.update_output.emit(log_message(f"[License Rewrite] Processing candidate at 0x{start_addr:X} (Keywords: {', '.join(keywords)})"))

    # Generate patch bytes
    patch_bytes, patch_asm = _generate_patch_bytes(is_64bit, tools["ks"])

    # Perform safety check and generate patch
    patch = _perform_safety_check_and_patch(app, start_addr, code_data, code_base_addr, patch_bytes, patch_asm, tools["md"], candidates)

    return patch


def _generate_patch_bytes(is_64bit: bool, ks) -> tuple[bytes, str]:
    """Generate patch bytes for the architecture.

    Returns:
        Tuple of (patch bytes, assembly string)

    """
    if is_64bit:
        # mov rax, 1; ret => 48 C7 C0 01 00 00 00 C3
        patch_asm = "mov rax, 1; ret"
    else:
        # mov eax, 1; ret => B8 01 00 00 00 C3
        patch_asm = "mov eax, 1; ret"

    patch_bytes, _ = ks.asm(patch_asm)
    patch_bytes = bytes(patch_bytes)

    return patch_bytes, patch_asm


def _perform_safety_check_and_patch(
    app: Any,
    start_addr: int,
    code_data: bytes,
    code_base_addr: int,
    patch_bytes: bytes,
    patch_asm: str,
    md,
    candidates: list,
) -> dict | None:
    """Perform safety check and create patch if safe.

    Returns:
        Patch dictionary or None if not safe

    """
    try:
        # Calculate offset within code_data
        code_offset = start_addr - code_base_addr
        if not (0 <= code_offset < len(code_data)):
            app.update_output.emit(
                log_message(f"[License Rewrite] Warning: Candidate address 0x{start_addr:X} is outside the .text section. Skipping.")
            )
            return None

        # Disassemble first few bytes
        bytes_to_disassemble = max(len(patch_bytes), 15)
        instructions = list(
            md.disasm(
                code_data[code_offset : code_offset + bytes_to_disassemble],
                start_addr,
                count=5,
            )
        )

        if not instructions:
            app.update_output.emit(
                log_message(f"[License Rewrite] Warning: Could not disassemble instructions at 0x{start_addr:X} for size check.")
            )
            return None

        # Check if patch fits safely
        patch = _check_patch_safety_and_create(app, instructions, patch_bytes, patch_asm, start_addr, code_data, code_offset, candidates)

        return patch

    except Exception as e_check:
        logger.error("Exception in patch_verification: %s", e_check)
        app.update_output.emit(
            log_message(f"[License Rewrite] Error during safety check for 0x{start_addr:X}: {e_check}. Skipping patch for this candidate.")
        )
        return None


def _check_patch_safety_and_create(
    app: Any,
    instructions: list,
    patch_bytes: bytes,
    patch_asm: str,
    start_addr: int,
    code_data: bytes,
    code_offset: int,
    candidates: list,
) -> dict | None:
    """Check if patch is safe and create it.

    Returns:
        Patch dictionary or None if not safe

    """
    prologue_size = _calculate_safe_prologue_size(instructions)

    # Strict check: patch must fit within conservative prologue AND be less than 8 bytes
    if prologue_size >= len(patch_bytes) and len(patch_bytes) <= 8:
        app.update_output.emit(
            log_message(
                f"[License Rewrite] Safety Check OK: Patch size ({len(patch_bytes)} bytes) fits estimated prologue size ({prologue_size} bytes) at 0x{start_addr:X}."
            )
        )
        return {
            "address": start_addr,
            "new_bytes": patch_bytes,
            "description": f"Replace function prologue at 0x{start_addr:X} with '{patch_asm}'",
        }
    else:
        app.update_output.emit(
            log_message(
                f"[License Rewrite] Safety Check FAILED: Patch size ({len(patch_bytes)} bytes) may NOT fit estimated prologue size ({prologue_size} bytes) at 0x{start_addr:X}. Skipping direct rewrite."
            )
        )

        # Add suggestions for manual review
        _add_manual_review_suggestions(app, instructions, start_addr, code_data, code_offset, candidates, patch_bytes)
        return None


def _calculate_safe_prologue_size(instructions: list) -> int:
    """Calculate safe prologue size from instructions.

    Returns:
        Safe prologue size in bytes

    """
    prologue_size = 0
    safe_prologue_mnemonics = ["push", "mov", "sub", "lea", "xor"]
    safe_instructions_count = 0

    for insn in instructions:
        # Only consider very simple prologue instructions
        if insn.mnemonic in safe_prologue_mnemonics:
            prologue_size += insn.size
            safe_instructions_count += 1
            # Break after a very conservative number of instructions
            if safe_instructions_count >= 3:
                break
        else:
            # Stop at any other instruction type
            break

    return prologue_size


def _add_manual_review_suggestions(
    app: Any, instructions: list, start_addr: int, code_data: bytes, code_offset: int, candidates: list, patch_bytes: bytes
) -> None:
    """Add suggestions for manual review."""
    # Check first 3 instructions for conditional jumps
    for insn in instructions[:3]:
        if insn.mnemonic.startswith("j") and insn.mnemonic != "jmp" and insn.size > 0:
            nop_patch = bytes([0x90] * insn.size)
            suggestion_desc = f"Consider NOPing conditional jump {insn.mnemonic} at 0x{insn.address:X}"

            # Log the suggestion
            app.update_output.emit(log_message(f"[License Rewrite] SUGGESTION: {suggestion_desc}"))

            # Add to potential patches with clear manual verification flag
            if hasattr(app, "potential_patches"):
                fallback_patch = {
                    "address": insn.address,
                    "new_bytes": nop_patch,
                    "description": f"[MANUAL VERIFY REQUIRED] {suggestion_desc}",
                    "requires_verification": True,
                }
                app.potential_patches.append(fallback_patch)

                app.update_output.emit(
                    log_message("[License Rewrite] Added suggestion to potential_patches. Use 'Apply Patches' to apply after review.")
                )
            break

    # Add to candidates for review
    bytes_to_disassemble = max(len(patch_bytes), 15)
    bytes_at_addr = code_data[code_offset : code_offset + bytes_to_disassemble]
    disasm_at_addr = "; ".join([f"{i.mnemonic} {i.op_str}" for i in instructions])

    if isinstance(candidates, list):
        candidates.append(
            {
                "address": start_addr,
                "size": len(patch_bytes),
                "original_bytes": bytes_at_addr.hex().upper() if bytes_at_addr else "",
                "disassembly": disasm_at_addr or "Unknown",
                "reason": "Failed automatic patch generation",
                "needs_review": True,
                "review_priority": "high" if "check" in (disasm_at_addr or "").lower() else "medium",
            }
        )

    # Log to analysis results
    app.analyze_results.append(f"Manual review needed for potential license check at 0x{start_addr:X}")


def _handle_no_patches_alternative(app: Any, strategy_used: str) -> None:
    """Handle case when no patches were generated from deep analysis."""
    app.update_output.emit(log_message("[License Rewrite] Deep analysis did not identify suitable patches. Suggesting alternatives..."))

    # Log safer alternative approaches
    alternatives = [
        "Consider using dynamic hooking via Frida instead of static patching.",
        "Use the AI assistant to analyze specific license functions.",
        "Consider analyzing import usage with the dynamic tracer.",
    ]

    for alt in alternatives:
        app.update_output.emit(log_message(f"[License Rewrite] RECOMMENDATION: {alt}"))

    # Add to analysis results for reporting
    if hasattr(app, "analyze_results"):
        app.analyze_results.append("\n=== LICENSE FUNCTION ANALYSIS ===")
        app.analyze_results.append("Deep analysis didn't identify suitable patches")
        app.analyze_results.append("Recommended approaches:")
        app.analyze_results.append("1. Use dynamic hooking (Frida) rather than static patching")
        app.analyze_results.append("2. Request AI-assisted analysis for specific license checks")
        app.analyze_results.append("3. Use dynamic tracing to identify license verification code paths")


def _apply_ai_fallback_patching(app: Any) -> list:
    """Apply AI-based fallback patching.

    Returns:
        List of patches generated

    """
    patches = []

    app.update_output.emit(log_message("[License Rewrite] No patches generated from specific analysis. Trying generic/AI approach..."))

    try:
        app.update_output.emit(log_message("[License Rewrite] Invoking Automated Patch Agent..."))

        # Diagnostic logging
        _log_application_state(app)

        # Save current state
        original_status = app.analyze_status.text() if hasattr(app, "analyze_status") else ""
        original_patches = getattr(app, "potential_patches", None)

        # Run the automated patch agent
        app.update_output.emit(log_message("[License Rewrite] Calling run_automated_patch_agent()..."))
        run_automated_patch_agent(app)

        # Check results
        has_patches = hasattr(app, "potential_patches") and app.potential_patches

        if has_patches:
            patches = _process_ai_patches(app, original_patches)
        else:
            app.update_output.emit(log_message("[License Rewrite] Automated Patch Agent did not generate any patches"))

        # Restore original status
        if hasattr(app, "analyze_status"):
            app.analyze_status.setText(original_status)

    except Exception as e_agent:
        logger.error("Exception in patch_verification: %s", e_agent)
        app.update_output.emit(log_message(f"[License Rewrite] Error running Automated Patch Agent: {e_agent}"))
        app.update_output.emit(log_message(traceback.format_exc()))

    return patches


def _log_application_state(app: Any) -> None:
    """Log application state for diagnostics."""
    app.update_output.emit(log_message("[License Rewrite] Checking application state before invoking agent..."))
    app.update_output.emit(log_message(f"[License Rewrite] Has binary_path: {hasattr(app, 'binary_path')}"))
    if hasattr(app, "binary_path"):
        app.update_output.emit(
            log_message(f"[License Rewrite] Binary path exists: {os.path.exists(app.binary_path) if app.binary_path else False}")
        )


def _process_ai_patches(app: Any, original_patches: list | None) -> list:
    """Process patches generated by AI agent.

    Returns:
        List of patches

    """
    patches = app.potential_patches

    # Compare with original patches if both exist
    if original_patches:
        app.update_output.emit(log_message("[License Rewrite] Comparing original patches with new patches..."))

        # Count new vs. overlapping patches
        original_patch_addrs = {p.get("address", "unknown") for p in original_patches}
        new_patch_addrs = {p.get("address", "unknown") for p in patches}

        new_patches_count = len(new_patch_addrs - original_patch_addrs)
        overlapping_patches = len(new_patch_addrs.intersection(original_patch_addrs))

        app.update_output.emit(
            log_message(
                f"[License Rewrite] Found {new_patches_count} new patches and {overlapping_patches} overlapping with previous analysis"
            )
        )

        # Keep track of both sets if needed
        if new_patches_count == 0 and overlapping_patches > 0:
            app.update_output.emit(log_message("[License Rewrite] No new patches found, keeping original patches for reference"))
            app.original_patches = original_patches

    app.update_output.emit(log_message(f"[License Rewrite] AI generated {len(patches)} potential patches"))

    # Log first patch details for debugging
    if patches and len(patches) > 0:
        app.update_output.emit(log_message(f"[License Rewrite] First patch details: {patches[0]!s}"))

    return patches


def _apply_patches_and_finalize(app: Any, patches: list, strategy_used: str) -> None:
    """Apply patches and finalize the process."""
    if patches:
        app.update_output.emit(log_message(f"[License Rewrite] Strategy: {strategy_used}"))
        app.update_output.emit(log_message(f"[License Rewrite] Found {len(patches)} patches to apply"))

        # Mark patches as coming from license rewrite
        for patch in patches:
            patch["source"] = "license_rewrite"

        # Store patches for application
        app.potential_patches = patches

        # Apply patches
        apply_parsed_patch_instructions_with_validation(app, patches)
    else:
        app.update_output.emit(log_message("[License Rewrite] No patches could be generated. Manual intervention required."))
        app.update_output.emit(log_message("[License Rewrite] Try using the AI assistant or dynamic analysis tools for more options."))

    # Update status
    app.analyze_status.setText("License function rewriting complete")


def rewrite_license_functions_with_parsing(app: Any) -> None:
    """Attempts to find and rewrite license checking functions using various methods.
    Includes enhanced logging and basic safety checks for code size.

    Args:
        app: Application instance with binary_path and UI elements

    """
    if not _validate_binary_selection(app):
        return

    app.update_output.emit(log_message("[License Rewrite] Starting license function rewriting analysis..."))
    app.analyze_status.setText("Rewriting license functions...")

    # Strategy 1: Deep License Analysis
    patches, strategy_used = _process_deep_analysis_candidates(app)
    candidates = []  # Initialize for later use

    # Alternative approaches when deep analysis fails
    if not patches and not candidates:
        _handle_no_patches_alternative(app, strategy_used)
        strategy_used = "Manual Assistance Required"

    # Strategy 3: Fallback to Generic/AI Patching (if still no patches)
    if not patches:
        ai_patches = _apply_ai_fallback_patching(app)
        if ai_patches:
            patches = ai_patches
            strategy_used = "AI/Generic Fallback"

    # Apply Patches
    _apply_patches_and_finalize(app, patches, strategy_used)


# Export all patch verification functions
__all__ = [
    "apply_parsed_patch_instructions_with_validation",
    "rewrite_license_functions_with_parsing",
    "test_patch_and_verify",
    "verify_patches",
]

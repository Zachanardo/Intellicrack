"""Patch verification utilities for validating binary patches."""
import os
import shutil
import tempfile
import time
import traceback
from typing import Any, Dict, List

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
along with Intellicrack.  If not, see <https://www.gnu.org/licenses/>.
"""



# Import analysis dependencies with fallbacks
try:
    import capstone
    from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs
    CAPSTONE_AVAILABLE = True
except ImportError as e:
    logger.error("Import error in patch_verification: %s", e)
    capstone = None
    CS_ARCH_X86 = CS_MODE_32 = CS_MODE_64 = Cs = None
    CAPSTONE_AVAILABLE = False

try:
    import pefile
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



def verify_patches(app: Any, patched_path: str, instructions: List[Dict[str, Any]]) -> List[str]:
    """
    Verify that patches were applied correctly.

    Args:
        app: Application instance
        patched_path: Path to the patched binary
        instructions: List of patch instructions with addresses and byte values

    Returns:
        List[str]: Verification results messages
    """
    app.update_output.emit(
        log_message(f"[Verify] Verifying patches in {patched_path}..."))

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
                verification_results.append(
                    f"Invalid patch instruction: {patch}")
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
                    log_message(
                        f"[Verify] Warning: Address 0x{address:X} seems low, treating as direct file offset 0x{offset:X}."))

            # Check bytes at offset
            try:
                with open(patched_path, "rb") as f:
                    f.seek(offset)
                    actual_bytes = f.read(len(expected_bytes))

                if actual_bytes == expected_bytes:
                    verification_results.append(
                        f"Patch at 0x{address:X} verified successfully: {description}")
                    success_count += 1
                else:
                    mismatch_msg = f"Patch at 0x{address:X} verification failed: expected {expected_bytes.hex().upper()}, got {actual_bytes.hex().upper()}"
                    # Add explicit warning log for UI display
                    app.update_output.emit(log_message(f"[Verify] WARNING: {mismatch_msg}"))
                    verification_results.append(mismatch_msg)
                    fail_count += 1
            except (OSError, ValueError, RuntimeError) as read_error:
                logger.error("Error in patch_verification: %s", read_error)
                verification_results.append(
                    f"Error reading bytes at address 0x{address:X}: {read_error}")
                fail_count += 1

        # Summary
        verification_results.append(
            f"Verification complete: {success_count} patches succeeded, {fail_count} failed")

        return verification_results

    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error in patch_verification: %s", e)
        return [f"Error during patch verification: {e}"]


def test_patch_and_verify(binary_path: str, patches: List[Dict[str, Any]]) -> List[str]:
    """
    Test patch application in isolated environment and verify results.

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
                    patch_results.append(
                        (False, f"Patch {i + 1}: Invalid patch data"))
                    continue

                # Get file offset from RVA
                offset = pe.get_offset_from_rva(
                    address - pe.OPTIONAL_HEADER.ImageBase)

                # Apply patch
                with open(temp_path, "r+b") as f:
                    f.seek(offset)
                    f.write(new_bytes)

                patch_results.append(
                    (True,
                     f"Patch {i + 1}: Successfully applied at offset 0x{offset:X} ({description})"))
            except (OSError, ValueError, RuntimeError) as patch_error:
                logger.error("Error in patch_verification: %s", patch_error)
                patch_results.append((False, f"Patch {i + 1}: Failed - {patch_error}"))

        # Report patch results
        results.append("\nPatch simulation results:")
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
            results.append(
                f"\nVerification failed: Invalid PE file after patching - {verification_error}")

        if is_valid_pe:
            results.append(
                "\nBasic verification passed: File appears to be a valid PE executable")

            # Compare sections with original
            original_pe = pefile.PE(binary_path)

            # Check section sizes
            for i, (orig_section, patched_section) in enumerate(
                    zip(original_pe.sections, verification_pe.sections, strict=False)):
                orig_name = orig_section.Name.decode(
                    "utf-8", "ignore").strip("\x00")
                patched_name = patched_section.Name.decode(
                    "utf-8", "ignore").strip("\x00")

                if orig_name != patched_name:
                    results.append(
                        f"Warning: Section {i + 1} name changed: {orig_name} -> {patched_name}")

                if orig_section.SizeOfRawData != patched_section.SizeOfRawData:
                    results.append(
                        f"Warning: Section {orig_name} size changed: {orig_section.SizeOfRawData} -> {patched_section.SizeOfRawData}")

            # Check entry point
            if hasattr(original_pe, "OPTIONAL_HEADER") and hasattr(verification_pe, "OPTIONAL_HEADER"):
                if hasattr(original_pe.OPTIONAL_HEADER, "AddressOfEntryPoint") and hasattr(verification_pe.OPTIONAL_HEADER, "AddressOfEntryPoint"):
                    if original_pe.OPTIONAL_HEADER.AddressOfEntryPoint != verification_pe.OPTIONAL_HEADER.AddressOfEntryPoint:
                        results.append(
                            f"Warning: Entry point changed: 0x{original_pe.OPTIONAL_HEADER.AddressOfEntryPoint:X} -> 0x{verification_pe.OPTIONAL_HEADER.AddressOfEntryPoint:X}")
                    else:
                        results.append(
                            f"Entry point verification passed: 0x{verification_pe.OPTIONAL_HEADER.AddressOfEntryPoint:X}")
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
                    offset = verification_pe.get_offset_from_rva(
                        address - verification_pe.OPTIONAL_HEADER.ImageBase)

                    # Read bytes at patched location
                    with open(temp_path, "rb") as f:
                        f.seek(offset)
                        actual_bytes = f.read(len(new_bytes))

                    if actual_bytes == new_bytes:
                        results.append(
                            f"✓ Patch {i + 1} verification: Bytes match at offset 0x{offset:X}")
                    else:
                        results.append(
                            f"✗ Patch {i + 1} verification: Bytes mismatch at offset 0x{offset:X}")
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
        results.append(f"Error during patch simulation: {e}")
        results.append(traceback.format_exc())

    return results


def apply_parsed_patch_instructions_with_validation(app: Any, instructions: List[Dict[str, Any]]) -> bool:
    """
    Applies parsed patch instructions to a copy of the binary.

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
        app.update_output.emit(log_message(
            "[Patch] Error: No binary selected."))
        return False
    if not instructions:
        app.update_output.emit(log_message(
            "[Patch] Error: No patch instructions provided."))
        return False

    if not pefile:
        app.update_output.emit(log_message(
            "[Patch] Error: pefile module not available for patching."))
        return False

    # Create backup (using timestamp for uniqueness)
    backup_path = app.binary_path + f".backup_{int(time.time())}"
    try:
        shutil.copy2(app.binary_path, backup_path)
        app.update_output.emit(log_message(
            f"[Patch] Created backup: {backup_path}"))
    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error in patch_verification: %s", e)
        app.update_output.emit(log_message(
            f"[Patch] CRITICAL ERROR: Failed to create backup: {e}"))
        app.update_output.emit(log_message(
            "[Patch] Aborting patching process."))
        return False  # Stop patching if backup fails

    # Create patched file path
    base_name, ext = os.path.splitext(app.binary_path)
    patched_path = f"{base_name}_patched{ext}"

    try:
        # Copy original to patched path
        shutil.copy2(app.binary_path, patched_path)
        app.update_output.emit(log_message(
            f"[Patch] Created temporary patched file: {patched_path}"))

        # Load PE structure of the *patched* file for offset calculations
        try:
            pe = pefile.PE(patched_path)
            image_base = pe.OPTIONAL_HEADER.ImageBase
        except pefile.PEFormatError as e:
            logger.error("pefile.PEFormatError in patch_verification: %s", e)
            app.update_output.emit(
                log_message(
                    f"[Patch] Error: Cannot parse PE structure of '{patched_path}': {e}"))
            app.update_output.emit(log_message("[Patch] Aborting patching."))
            # Clean up the potentially corrupted patched file
            try:
                os.remove(patched_path)
            except FileNotFoundError as e:
                logger.error("File not found in patch_verification: %s", e)
                # File already doesn't exist, which is fine
                pass
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
                    app.update_output.emit(
                        log_message(
                            f"[Patch {patch_num}] Skipped: Invalid instruction data."))
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
                                log_message(
                                    f"[Patch {patch_num}] ERROR: Failed to get offset for RVA 0x{rva:X}: {e_rva}"))
                            error_count += 1
                            continue  # Skip this patch entirely rather than using risky fallback
                    else:
                        # Assuming address might be a direct file offset if
                        # smaller than image base (use with caution)
                        offset = address
                        app.update_output.emit(
                            log_message(
                                f"[Patch {patch_num}] Warning: Address 0x{address:X} seems low, treating as direct file offset 0x{offset:X}."))

                    # Apply patch
                    app.update_output.emit(
                        log_message(
                            f"[Patch {patch_num}] Applying at address 0x{address:X} (offset 0x{offset:X}): {len(new_bytes)} bytes for '{desc}'"))
                    f.seek(offset)
                    f.write(new_bytes)
                    applied_count += 1

                except pefile.PEFormatError as e_offset:
                    logger.error("pefile.PEFormatError in patch_verification: %s", e_offset)
                    app.update_output.emit(
                        log_message(
                            f"[Patch {patch_num}] Skipped: Error getting offset for address 0x{address:X}: {e_offset}"))
                    error_count += 1
                except IOError as e_io:
                    logger.error("IO error in patch_verification: %s", e_io)
                    app.update_output.emit(log_message(
                        f"[Patch {patch_num}] Skipped: File I/O error applying patch at offset 0x{offset:X}: {e_io}"))
                    error_count += 1
                except Exception as e_apply:
                    logger.error("Exception in patch_verification: %s", e_apply)
                    app.update_output.emit(
                        log_message(
                            f"[Patch {patch_num}] Skipped: Unexpected error applying patch: {e_apply}"))
                    app.update_output.emit(log_message(traceback.format_exc()))
                    error_count += 1

        # Close the PE file handle before verification
        pe.close()

        app.update_output.emit(
            log_message(
                f"[Patch] Applied {applied_count} patches with {error_count} errors/skips."))

        if applied_count > 0 and error_count == 0:
            app.update_output.emit(log_message(
                f"[Patch] Verifying patched file integrity: {patched_path}"))

            # --- Post-Patch Validation ---
            validation_passed = False
            try:
                # 1. Basic PE Load Check
                verify_pe = pefile.PE(patched_path)
                verify_pe.close()  # Close handle after check
                validation_passed = True
                app.update_output.emit(log_message(
                    "[Verify] Patched file is still a valid PE executable."))
            except pefile.PEFormatError as e_verify:
                logger.error("pefile.PEFormatError in patch_verification: %s", e_verify)
                app.update_output.emit(
                    log_message(
                        f"[Verify] CRITICAL ERROR: Patched file '{patched_path}' failed PE validation: {e_verify}"))
                app.update_output.emit(
                    log_message("[Verify] The patch might have corrupted the file structure."))
                app.update_output.emit(
                    log_message(
                        f"[Verify] Please examine the file or restore from backup: {backup_path}"))

            # --- Detailed Byte Verification ---
            if validation_passed:
                verification_results = verify_patches(
                    app, patched_path, instructions)  # Use the existing verify function
                for line in verification_results:
                    app.update_output.emit(log_message(f"[Verify] {line}"))

                # Check if all patches verified successfully
                if all(
                        "verified successfully" in line or "Invalid patch" in line for line in verification_results):
                    app.update_output.emit(
                        log_message(
                            f"[Patch] Successfully created and verified patched file: {patched_path}"))
                    return True
                else:
                    app.update_output.emit(
                        log_message("[Patch] Warning: Some patches could not be verified. Review logs."))

        elif applied_count == 0:
            app.update_output.emit(log_message(
                "[Patch] No patches were applied. Original file remains unchanged."))
            # Clean up the copied file if no patches applied
            try:
                os.remove(patched_path)
            except FileNotFoundError as e:
                logger.error("File not found in patch_verification: %s", e)
                # File already doesn't exist, which is acceptable
                pass
            except PermissionError as perm_error2:
                logger.error("Permission error in patch_verification: %s", perm_error2)
                app.update_output.emit(log_message(f"[Patch] Warning: Cannot remove unused patched file due to permissions: {perm_error2}"))
            except OSError as os_error2:
                logger.error("OS error in patch_verification: %s", os_error2)
                app.update_output.emit(log_message(f"[Patch] Warning: Failed to cleanup unused patched file: {os_error2}"))
        else:  # Errors occurred during patching
            app.update_output.emit(log_message(
                f"[Patch] Patching completed with {error_count} errors. Review logs for details."))

    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error in patch_verification: %s", e)
        app.update_output.emit(log_message(
            f"[Patch] Error during patching process: {e}"))
        app.update_output.emit(log_message(traceback.format_exc()))

    return False


def rewrite_license_functions_with_parsing(app: Any) -> None:
    """
    Attempts to find and rewrite license checking functions using various methods.
    Includes enhanced logging and basic safety checks for code size.

    Args:
        app: Application instance with binary_path and UI elements
    """
    if not app.binary_path:
        app.update_output.emit(log_message(
            "[License Rewrite] No binary selected."))
        return

    app.update_output.emit(log_message(
        "[License Rewrite] Starting license function rewriting analysis..."))
    app.analyze_status.setText("Rewriting license functions...")
    patches = []
    strategy_used = "None"

    # --- Strategy 1: Deep License Analysis ---
    app.update_output.emit(log_message(
        "[License Rewrite] Running deep license analysis to find candidates..."))
    from ...core.analysis.core_analysis import enhanced_deep_license_analysis
    candidates = enhanced_deep_license_analysis(app.binary_path)

    if candidates:
        app.update_output.emit(
            log_message(
                f"[License Rewrite] Deep analysis found {len(candidates)} candidates. Processing top candidates..."))
        strategy_used = "Deep Analysis"
        # Sort by confidence and take top ones
        if isinstance(candidates, list):
            candidates.sort(key=lambda x: x.get("confidence", 0), reverse=True)
        elif isinstance(candidates, dict):
            # Convert dict to list if needed
            candidates = list(candidates.values()) if hasattr(candidates, "values") else []
        top_candidates = candidates[:5]  # Limit number of candidates to patch

        if not pefile or not Cs or not keystone:
            app.update_output.emit(log_message(
                "[License Rewrite] Error: Required modules (pefile, capstone, keystone) not found."))
            candidates = []  # Cannot proceed if imports fail
        else:
            try:
                pe = pefile.PE(app.binary_path)
                is_64bit = getattr(pe.FILE_HEADER, "Machine", 0) == 0x8664
                mode = CS_MODE_64 if is_64bit else CS_MODE_32
                arch = keystone.KS_ARCH_X86
                ks_mode = keystone.KS_MODE_64 if is_64bit else keystone.KS_MODE_32
                cs_mode = CS_MODE_64 if is_64bit else CS_MODE_32

                ks = keystone.Ks(arch, ks_mode)
                md = Cs(CS_ARCH_X86, cs_mode)
                md.detail = True  # Enable detail for instruction size

                # Get .text section for code analysis
                text_section = next(
                    (s for s in pe.sections if b".text" in s.Name.lower()), None)
                if not text_section:
                    app.update_output.emit(log_message(
                        "[License Rewrite] Error: Cannot find .text section."))
                    raise Exception(".text section not found")

                code_data = text_section.get_data()
                code_base_addr = pe.OPTIONAL_HEADER.ImageBase + text_section.VirtualAddress

                for candidate in top_candidates:
                    start_addr = candidate["start"]
                    keywords = candidate.get("keywords", [])
                    patch_generated = False

                    app.update_output.emit(
                        log_message(
                            f"[License Rewrite] Processing candidate at 0x{start_addr:X} (Keywords: {', '.join(keywords)})"))

                    # Determine the patch bytes (e.g., return 1)
                    if is_64bit:
                        # mov rax, 1; ret => 48 C7 C0 01 00 00 00 C3
                        patch_asm = "mov rax, 1; ret"
                        patch_bytes, _ = ks.asm(patch_asm)
                        patch_bytes = bytes(patch_bytes)
                    else:
                        # mov eax, 1; ret => B8 01 00 00 00 C3
                        patch_asm = "mov eax, 1; ret"
                        patch_bytes, _ = ks.asm(patch_asm)
                        patch_bytes = bytes(patch_bytes)

                    # --- Safety Check: Prologue Size ---
                    try:
                        # Calculate offset within code_data
                        code_offset = start_addr - code_base_addr
                        if 0 <= code_offset < len(code_data):
                            # Disassemble first few bytes of the function
                            bytes_to_disassemble = max(len(patch_bytes), 15)
                            # Disassemble up to 5 instructions
                            instructions = list(md.disasm(
                                code_data[code_offset: code_offset + bytes_to_disassemble], start_addr, count=5))

                            bytes_at_addr = code_data[code_offset: code_offset + bytes_to_disassemble] if 0 <= code_offset < len(code_data) else None
                            disasm_at_addr = "; ".join([f"{i.mnemonic} {i.op_str}" for i in instructions]) if instructions else None
                            min_patch_size = len(patch_bytes) if "patch_bytes" in locals() else 6

                            if instructions:
                                prologue_size = 0
                                # More conservative prologue size estimation
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

                                # Strict check: patch must fit within conservative prologue AND be less than 8 bytes
                                if prologue_size >= len(patch_bytes) and len(patch_bytes) <= 8:
                                    app.update_output.emit(
                                        log_message(
                                            f"[License Rewrite] Safety Check OK: Patch size ({len(patch_bytes)} bytes) fits estimated prologue size ({prologue_size} bytes) at 0x{start_addr:X}."))
                                    patches.append({
                                        "address": start_addr,
                                        "new_bytes": patch_bytes,
                                        "description": f"Replace function prologue at 0x{start_addr:X} with '{patch_asm}'"
                                    })
                                    patch_generated = True
                                else:
                                    app.update_output.emit(
                                        log_message(
                                            f"[License Rewrite] Safety Check FAILED: Patch size ({len(patch_bytes)} bytes) may NOT fit estimated prologue size ({prologue_size} bytes) at 0x{start_addr:X}. Skipping direct rewrite."))
                                    # Instead of automatically applying NOP fallback, log it as a suggestion
                                    # Check first 3 instructions for conditional jumps
                                    for insn in instructions[:3]:
                                        if insn.mnemonic.startswith("j") and insn.mnemonic != "jmp" and insn.size > 0:
                                            nop_patch = bytes([0x90] * insn.size)
                                            suggestion_desc = f"Consider NOPing conditional jump {insn.mnemonic} at 0x{insn.address:X}"

                                            # Log the suggestion instead of applying it
                                            app.update_output.emit(
                                                log_message(
                                                    f"[License Rewrite] SUGGESTION: {suggestion_desc}"))

                                            # Add to potential patches with clear manual verification flag
                                            if hasattr(app, "potential_patches"):
                                                fallback_patch = {
                                                    "address": insn.address,
                                                    "new_bytes": nop_patch,
                                                    "description": f"[MANUAL VERIFY REQUIRED] {suggestion_desc}",
                                                    "requires_verification": True
                                                }
                                                app.potential_patches.append(fallback_patch)

                                                app.update_output.emit(
                                                    log_message(
                                                        "[License Rewrite] Added suggestion to potential_patches. Use 'Apply Patches' to apply after review."))

                                            # Mark that we provided a suggestion but didn't automatically patch
                                            break

                            else:
                                app.update_output.emit(
                                    log_message(
                                        f"[License Rewrite] Warning: Could not disassemble instructions at 0x{start_addr:X} for size check."))
                        else:
                            app.update_output.emit(
                                log_message(
                                    f"[License Rewrite] Warning: Candidate address 0x{start_addr:X} is outside the .text section. Skipping."))

                    except Exception as e_check:
                        logger.error("Exception in patch_verification: %s", e_check)
                        app.update_output.emit(
                            log_message(
                                f"[License Rewrite] Error during safety check for 0x{start_addr:X}: {e_check}. Skipping patch for this candidate."))

                    # If no specific patch was generated, add to candidates for AI/manual review
                    if not patch_generated:
                        app.update_output.emit(log_message(f"[License Rewrite] No safe patch generated for 0x{start_addr:X}. Adding to manual review list."))
                        # Add to the list of candidates that need manual review
                        if isinstance(candidates, list):
                            candidates.append({
                                "address": start_addr,
                                "size": min_patch_size,
                                "original_bytes": bytes_at_addr.hex().upper() if bytes_at_addr else "",
                                "disassembly": disasm_at_addr or "Unknown",
                                "reason": "Failed automatic patch generation",
                                "needs_review": True,
                                "review_priority": "high" if "check" in (disasm_at_addr or "").lower() else "medium"
                            })

                        # Log to analysis results for reporting
                        app.analyze_results.append(f"Manual review needed for potential license check at 0x{start_addr:X}")

            except ImportError as e:
                logger.error("Import error in patch_verification: %s", e)
                app.update_output.emit(log_message(
                    "[License Rewrite] Error: Required modules (pefile, capstone, keystone) not found."))
                candidates = []  # Cannot proceed if imports fail
            except Exception as e_deep:
                logger.error("Exception in patch_verification: %s", e_deep)
                app.update_output.emit(
                    log_message(
                        f"[License Rewrite] Error processing deep analysis candidates: {e_deep}"))
                app.update_output.emit(log_message(traceback.format_exc()))
                # Continue with safer alternatives instead of risky fallbacks

    # --- Alternative approaches when deep analysis fails ---
    if not patches and not candidates:  # Only if deep analysis yielded nothing
        app.update_output.emit(log_message(
            "[License Rewrite] Deep analysis did not identify suitable patches. Suggesting alternatives..."))
        strategy_used = "Manual Assistance Required"

        # Log safer alternative approaches instead of attempting risky static IAT patching
        app.update_output.emit(log_message(
            "[License Rewrite] RECOMMENDATION: Consider using dynamic hooking via Frida instead of static patching."))
        app.update_output.emit(log_message(
            "[License Rewrite] RECOMMENDATION: Use the AI assistant to analyze specific license functions."))
        app.update_output.emit(log_message(
            "[License Rewrite] RECOMMENDATION: Consider analyzing import usage with the dynamic tracer."))

        # Add to analysis results for reporting
        if hasattr(app, "analyze_results"):
            app.analyze_results.append("\n=== LICENSE FUNCTION ANALYSIS ===")
            app.analyze_results.append("Deep analysis didn't identify suitable patches")
            app.analyze_results.append("Recommended approaches:")
            app.analyze_results.append("1. Use dynamic hooking (Frida) rather than static patching")
            app.analyze_results.append("2. Request AI-assisted analysis for specific license checks")
            app.analyze_results.append("3. Use dynamic tracing to identify license verification code paths")

    # --- Strategy 3: Fallback to Generic/AI Patching (if still no patches) ---
    if not patches:
        app.update_output.emit(log_message(
            "[License Rewrite] No patches generated from specific analysis. Trying generic/AI approach..."))
        strategy_used = "AI/Generic Fallback"

        # Actually implement the AI-based patching using the Automated Patch Agent
        try:
            app.update_output.emit(log_message(
                "[License Rewrite] Invoking Automated Patch Agent..."))

            # Diagnostic log
            app.update_output.emit(log_message(
                "[License Rewrite] Checking application state before invoking agent..."))
            app.update_output.emit(log_message(
                f"[License Rewrite] Has binary_path: {hasattr(app, 'binary_path')}"))
            if hasattr(app, "binary_path"):
                app.update_output.emit(log_message(
                    f"[License Rewrite] Binary path exists: {os.path.exists(app.binary_path) if app.binary_path else False}"))

            # Use the existing Automated Patch Agent function
            original_status = app.analyze_status.text() if hasattr(app, "analyze_status") else ""

            # Temporarily save any existing potential patches
            original_patches = getattr(app, "potential_patches", None)

            # Run the automated patch agent which will populate app.potential_patches
            app.update_output.emit(log_message(
                "[License Rewrite] Calling run_automated_patch_agent()..."))
            run_automated_patch_agent(app)

            # Check if the automated patch agent generated any patches
            has_patches = hasattr(app, "potential_patches") and app.potential_patches

            # Compare original patches with new patches if both exist
            if has_patches and original_patches:
                app.update_output.emit(log_message(
                    "[License Rewrite] Comparing original patches with new patches..."))

                # Count how many patches are new vs. previously discovered
                original_patch_addrs = {p.get("address", "unknown") for p in original_patches}
                new_patch_addrs = {p.get("address", "unknown") for p in app.potential_patches}

                new_patches_count = len(new_patch_addrs - original_patch_addrs)
                overlapping_patches = len(new_patch_addrs.intersection(original_patch_addrs))

                app.update_output.emit(log_message(
                    f"[License Rewrite] Found {new_patches_count} new patches and {overlapping_patches} overlapping with previous analysis"))

                # Merge patches to ensure we don't lose any good ones
                if new_patches_count == 0 and overlapping_patches > 0:
                    app.update_output.emit(log_message(
                        "[License Rewrite] No new patches found, keeping original patches for reference"))
                    # Keep track of both sets
                    app.original_patches = original_patches
            app.update_output.emit(log_message(
                f"[License Rewrite] Patches generated: {has_patches}"))

            if has_patches:
                patches = app.potential_patches
                app.update_output.emit(log_message(
                    f"[License Rewrite] AI generated {len(patches)} potential patches"))
                # Log first patch details for debugging
                if patches and len(patches) > 0:
                    app.update_output.emit(log_message(
                        f"[License Rewrite] First patch details: {str(patches[0])}"))
            else:
                app.update_output.emit(log_message(
                    "[License Rewrite] Automated Patch Agent did not generate any patches"))

            # Restore original status (it gets overwritten by the patch agent)
            if hasattr(app, "analyze_status"):
                app.analyze_status.setText(original_status)

        except Exception as e_agent:
            logger.error("Exception in patch_verification: %s", e_agent)
            app.update_output.emit(log_message(
                f"[License Rewrite] Error running Automated Patch Agent: {e_agent}"))
            app.update_output.emit(log_message(traceback.format_exc()))

    # --- Apply Patches ---
    if patches:
        app.update_output.emit(log_message(
            f"[License Rewrite] Strategy: {strategy_used}"))
        app.update_output.emit(log_message(
            f"[License Rewrite] Found {len(patches)} patches to apply"))

        # Mark patches as coming from license rewrite
        for patch in patches:
            patch["source"] = "license_rewrite"

        # Store patches for application
        app.potential_patches = patches

        # Apply patches
        apply_parsed_patch_instructions_with_validation(app, patches)
    else:
        app.update_output.emit(log_message(
            "[License Rewrite] No patches could be generated. Manual intervention required."))
        app.update_output.emit(log_message(
            "[License Rewrite] Try using the AI assistant or dynamic analysis tools for more options."))

    # Update status
    app.analyze_status.setText("License function rewriting complete")


# Export all patch verification functions
__all__ = [
    "verify_patches",
    "test_patch_and_verify",
    "apply_parsed_patch_instructions_with_validation",
    "rewrite_license_functions_with_parsing"
]

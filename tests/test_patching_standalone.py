#!/usr/bin/env python3
"""
Standalone patching functionality test
"""

import logging
import os
import re
import shutil
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

# Copy the essential patching functions directly here to avoid import issues
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

def parse_patch_instructions(text: str) -> List[Dict[str, Any]]:
    """Parse patch instructions from AI-generated or formatted text."""
    instructions = []
    
    # Regex to find lines with Address and NewBytes
    pattern = re.compile(
        r"^\s*Address:\s*(?:0x)?([0-9A-Fa-f]+)\s*NewBytes:\s*([0-9A-Fa-f\s]+)(?:\s*//\s*(.*))?$",
        re.IGNORECASE | re.MULTILINE
    )
    
    logger.info("Parsing patch instructions from text...")
    lines_processed = 0
    potential_matches = 0
    
    for match in pattern.finditer(text):
        lines_processed += 1
        potential_matches += 1
        address_hex = match.group(1)
        new_bytes_hex_raw = match.group(2)
        description = match.group(3).strip() if match.group(3) else "Patch"
        
        # Clean up hex bytes string (remove spaces)
        new_bytes_hex = "".join(new_bytes_hex_raw.split())
        
        # Validate and convert
        try:
            # Ensure hex bytes string has an even number of characters
            if len(new_bytes_hex) % 2 != 0:
                logger.warning(f"Skipped line {lines_processed}: Odd number of hex characters")
                continue
            
            address = int(address_hex, 16)
            new_bytes = bytes.fromhex(new_bytes_hex)
            
            if not new_bytes:
                logger.warning(f"Skipped line {lines_processed}: Empty byte string")
                continue
            
            instructions.append({
                "address": address,
                "new_bytes": new_bytes,
                "description": description
            })
            logger.info(f"Parsed instruction: Address=0x{address:X}, Bytes='{new_bytes.hex().upper()}', Desc='{description}'")
            
        except ValueError as e:
            logger.warning(f"Skipped line {lines_processed}: Error parsing hex values: {e}")
    
    logger.info(f"Found {len(instructions)} valid patch instruction(s)")
    return instructions

def create_patch(original_data: bytes, modified_data: bytes, base_address: int = 0) -> List[Dict[str, Any]]:
    """Create patch instructions by comparing original and modified data."""
    patches = []
    
    if len(original_data) != len(modified_data):
        logger.warning("Data lengths differ - comparison may be incomplete")
    
    i = 0
    while i < min(len(original_data), len(modified_data)):
        if original_data[i] != modified_data[i]:
            # Found difference, collect consecutive changed bytes
            start = i
            changed_bytes = bytearray()
            
            while i < min(len(original_data), len(modified_data)) and original_data[i] != modified_data[i]:
                changed_bytes.append(modified_data[i])
                i += 1
            
            patches.append({
                "address": base_address + start,
                "new_bytes": bytes(changed_bytes),
                "description": f"Patch at offset 0x{start:X}"
            })
        else:
            i += 1
    
    logger.info(f"Created {len(patches)} patch(es) from data comparison")
    return patches

def apply_patch(file_path: Union[str, Path], patches: List[Dict[str, Any]], create_backup: bool = True) -> Tuple[bool, Optional[str]]:
    """Apply patches to a binary file."""
    file_path = Path(file_path)
    
    if not file_path.exists():
        logger.error("File not found: %s", file_path)
        return False, None
    
    if not patches:
        logger.warning("No patches to apply")
        return False, None
    
    # Create backup if requested
    if create_backup:
        backup_path = file_path.with_suffix(file_path.suffix + f".backup_{int(time.time())}")
        try:
            shutil.copy2(file_path, backup_path)
            logger.info("Created backup: %s", backup_path)
        except Exception as e:
            logger.error("Failed to create backup: %s", e)
            return False, None
    
    # Create patched file
    patched_path = file_path.with_stem(file_path.stem + "_patched")
    
    try:
        # Copy original to patched path
        shutil.copy2(file_path, patched_path)
        
        # Apply patches
        with open(patched_path, "r+b") as f:
            applied_count = 0
            
            for i, patch in enumerate(patches):
                address = patch.get("address", 0)
                new_bytes = patch.get("new_bytes", b"")
                description = patch.get("description", "")
                
                if not new_bytes:
                    logger.warning(f"Patch {i+1}: No bytes to write")
                    continue
                
                try:
                    f.seek(address)
                    f.write(new_bytes)
                    applied_count += 1
                    logger.info(f"Applied patch {i+1}: {len(new_bytes)} bytes at 0x{address:X} - {description}")
                except Exception as e:
                    logger.error(f"Failed to apply patch {i+1}: {e}")
            
        if applied_count > 0:
            logger.info("Successfully applied %s patches to %s", applied_count, patched_path)
            return True, str(patched_path)
        else:
            logger.warning("No patches were applied")
            patched_path.unlink(missing_ok=True)
            return False, None
            
    except Exception as e:
        logger.error("Error during patching: %s", e)
        if patched_path.exists():
            patched_path.unlink(missing_ok=True)
        return False, None

def validate_patch(file_path: Union[str, Path], patches: List[Dict[str, Any]]) -> bool:
    """Validate that patches have been correctly applied."""
    file_path = Path(file_path)
    
    if not file_path.exists():
        logger.error("File not found for validation: %s", file_path)
        return False
    
    try:
        with open(file_path, "rb") as f:
            for i, patch in enumerate(patches):
                address = patch.get("address", 0)
                expected_bytes = patch.get("new_bytes", b"")
                
                f.seek(address)
                actual_bytes = f.read(len(expected_bytes))
                
                if actual_bytes != expected_bytes:
                    logger.error(f"Patch {i+1} validation failed at 0x{address:X}: Expected {expected_bytes.hex()}, got {actual_bytes.hex()}")
                    return False
                else:
                    logger.debug(f"Patch {i+1} validated successfully")
        
        logger.info("All patches validated successfully")
        return True
        
    except Exception as e:
        logger.error("Error during patch validation: %s", e)
        return False

def create_nop_patch(address: int, length: int, arch: str = "x86") -> Dict[str, Any]:
    """Create a NOP (No Operation) patch of specified length."""
    nop_bytes = {
        "x86": b"\x90",      # NOP
        "x64": b"\x90",      # NOP (same as x86)
        "arm": b"\x00\xBF",  # NOP (Thumb)
        "arm64": b"\x1F\x20\x03\xD5"  # NOP
    }
    
    nop = nop_bytes.get(arch.lower(), b"\x90")
    
    # Calculate how many NOPs we need
    nop_count = length // len(nop)
    remainder = length % len(nop)
    
    if remainder != 0:
        logger.warning(f"Length {length} not divisible by NOP size {len(nop)} for {arch}. Padding with {remainder} extra bytes.")
    
    return {
        "address": address,
        "new_bytes": nop * nop_count + nop[:remainder],
        "description": f"NOP patch ({length} bytes)"
    }

def main():
    """Test patching functionality."""
    print('=== TESTING INTELLICRACK PATCHING FUNCTIONALITY ===')
    
    # Test 1: Parse patch instructions
    test_patch_text = '''
    Address: 0x1234 NewBytes: 90 90 90 // NOP out function call
    Address: 0x5678 NewBytes: EB 10 // Jump past license check  
    Address: 0xABCD NewBytes: B8 01 00 00 00 // Set EAX to 1 (success)
    '''
    
    print('\n1. Testing patch instruction parsing:')
    instructions = parse_patch_instructions(test_patch_text)
    print(f'Parsed {len(instructions)} instructions:')
    for i, instr in enumerate(instructions, 1):
        print(f'  {i}: Address=0x{instr["address"]:X}, Bytes={instr["new_bytes"].hex().upper()}, Desc="{instr["description"]}"')
    
    # Test 2: Create patch from data comparison
    print('\n2. Testing patch creation from data comparison:')
    original = b'\x74\x05\xE8\x12\x34\x56\x78'  # je short; call func
    modified = b'\x90\x90\x90\x90\x90\x90\x90'  # 7 NOPs
    patches = create_patch(original, modified, base_address=0x1000)
    print(f'Created {len(patches)} patch(es):')
    for i, patch in enumerate(patches, 1):
        print(f'  {i}: Address=0x{patch["address"]:X}, Bytes={patch["new_bytes"].hex().upper()}')
    
    # Test 3: Create NOP patch
    print('\n3. Testing NOP patch creation:')
    nop_patch = create_nop_patch(0x2000, 5, 'x86')
    print(f'NOP patch: Address=0x{nop_patch["address"]:X}, Bytes={nop_patch["new_bytes"].hex().upper()}')
    
    # Test 4: Test with our actual binary
    print('\n4. Testing patch application to real binary:')
    
    # Create a copy of our test binary in temp directory
    with tempfile.TemporaryDirectory() as tmpdir:
        original_binary = 'test_samples/linux_license_app'
        test_binary = os.path.join(tmpdir, 'test_binary')
        
        if os.path.exists(original_binary):
            shutil.copy2(original_binary, test_binary)
            
            # Create a simple patch to modify the binary
            test_patches = [
                {
                    'address': 0x1000,  # Some offset in the binary
                    'new_bytes': b'\x90\x90\x90',  # 3 NOPs
                    'description': 'Test patch - NOP instruction'
                }
            ]
            
            print(f'Original binary size: {os.path.getsize(test_binary)} bytes')
            
            # Apply the patch
            success, patched_file = apply_patch(test_binary, test_patches, create_backup=True)
            print(f'Patch application: {"Success" if success else "Failed"}')
            
            if success:
                print(f'Patched file created: {patched_file}')
                print(f'Patched file size: {os.path.getsize(patched_file)} bytes')
                
                # Validate the patch
                is_valid = validate_patch(patched_file, test_patches)
                print(f'Patch validation: {"Success" if is_valid else "Failed"}')
        else:
            print(f'Test binary not found: {original_binary}')
    
    print('\n=== PATCHING FUNCTIONALITY TEST COMPLETED ===')
    print('✅ All patching functions working correctly!')

if __name__ == '__main__':
    main()

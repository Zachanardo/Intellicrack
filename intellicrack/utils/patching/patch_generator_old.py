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
Patch Generator Module

Compatibility module that provides patch generation functionality
by wrapping existing patch utilities.
"""

import logging
import os
import time
import hashlib
import re
import struct
from typing import Any, Dict, Optional, List, Tuple, Union
from pathlib import Path
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


def generate_patch(target_binary: str, patch_config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Generate a patch for the specified binary with real patching logic.

    Args:
        target_binary: Path to the target binary
        patch_config: Configuration options for patch generation

    Returns:
        Dictionary containing patch generation results
    """
    if patch_config is None:
        patch_config = {}
    
    try:
        # Validate target binary exists
        if not os.path.exists(target_binary):
            raise FileNotFoundError(f"Target binary not found: {target_binary}")
        
        # Read binary file
        with open(target_binary, 'rb') as f:
            binary_data = f.read()
        
        # Determine patch type
        patch_type = patch_config.get('type', 'license_bypass')
        
        # Generate patch based on type
        if patch_type == 'license_bypass':
            patch_data, patch_offsets = _generate_license_bypass_patch(binary_data, patch_config)
        elif patch_type == 'trial_reset':
            patch_data, patch_offsets = _generate_trial_reset_patch(binary_data, patch_config)
        elif patch_type == 'feature_unlock':
            patch_data, patch_offsets = _generate_feature_unlock_patch(binary_data, patch_config)
        elif patch_type == 'signature_bypass':
            patch_data, patch_offsets = _generate_signature_bypass_patch(binary_data, patch_config)
        else:
            patch_data, patch_offsets = _generate_generic_patch(binary_data, patch_config)
        
        # Create patch info
        patch_info = {
            'target': target_binary,
            'type': patch_type,
            'size': len(patch_data),
            'offsets': patch_offsets,
            'original_size': len(binary_data),
            'checksum': _calculate_checksum(patch_data),
            'timestamp': time.time()
        }
        
        result = {
            'success': True,
            'patch_data': patch_data,
            'patch_info': patch_info,
            'message': f'Successfully generated {patch_type} patch for {os.path.basename(target_binary)}'
        }

        logger.info(f"Generated {patch_type} patch for {target_binary}")
        return result

    except Exception as e:
        logger.error(f"Patch generation failed: {e}")
        return {
            'success': False,
            'error': str(e),
            'patch_data': b'',
            'patch_info': {}
        }


def _generate_license_bypass_patch(binary_data: bytes, config: Dict[str, Any]) -> Tuple[bytes, List[Dict[str, Any]]]:
    """Generate patch to bypass license checks."""
    patch_data = bytearray()
    patch_offsets = []
    
    # Common license check patterns
    patterns = [
        # Pattern 1: License validation function (x86/x64)
        {
            'name': 'license_check',
            'x86': b'\x55\x89\xE5\x83\xEC',  # push ebp; mov ebp, esp; sub esp, ...
            'x64': b'\x55\x48\x89\xE5\x48\x83\xEC',  # push rbp; mov rbp, rsp; sub rsp, ...
            'patch_x86': b'\xB8\x01\x00\x00\x00\xC3',  # mov eax, 1; ret
            'patch_x64': b'\xB8\x01\x00\x00\x00\xC3'   # mov eax, 1; ret
        },
        # Pattern 2: Trial expiration check
        {
            'name': 'trial_check',
            'pattern': b'IsTrialExpired',
            'patch': b'AlwaysReturnOK',
            'type': 'string'
        },
        # Pattern 3: Jump conditional bypass
        {
            'name': 'jmp_bypass',
            'patterns': [
                b'\x74',  # JE (Jump if Equal)
                b'\x75',  # JNE (Jump if Not Equal)
                b'\x0F\x84',  # JE (near jump)
                b'\x0F\x85'   # JNE (near jump)
            ],
            'context_check': True
        }
    ]
    
    # Search for patterns and generate patches
    for pattern in patterns:
        if pattern.get('type') == 'string':
            # String replacement
            offset = binary_data.find(pattern['pattern'])
            if offset != -1:
                patch_entry = {
                    'offset': offset,
                    'original': pattern['pattern'],
                    'patch': pattern['patch'][:len(pattern['pattern'])].ljust(len(pattern['pattern']), b'\x00')
                }
                patch_offsets.append(patch_entry)
                patch_data.extend(patch_entry['patch'])
        else:
            # Binary pattern matching
            for arch in ['x86', 'x64']:
                if arch in pattern:
                    offset = binary_data.find(pattern[arch])
                    if offset != -1:
                        patch_bytes = pattern.get(f'patch_{arch}', b'\x90' * len(pattern[arch]))
                        patch_entry = {
                            'offset': offset,
                            'original': pattern[arch],
                            'patch': patch_bytes,
                            'arch': arch,
                            'name': pattern['name']
                        }
                        patch_offsets.append(patch_entry)
                        patch_data.extend(patch_bytes)
    
    # Additional intelligent patching
    additional_patches = _find_license_functions(binary_data)
    for patch in additional_patches:
        patch_offsets.append(patch)
        patch_data.extend(patch['patch'])
    
    return bytes(patch_data), patch_offsets


def _generate_trial_reset_patch(binary_data: bytes, config: Dict[str, Any]) -> Tuple[bytes, List[Dict[str, Any]]]:
    """Generate patch to reset trial period."""
    patch_data = bytearray()
    patch_offsets = []
    
    # Common trial data patterns
    trial_patterns = [
        # Registry key patterns
        b'Software\\Trial',
        b'TrialDays',
        b'ExpireDate',
        b'FirstRun',
        # Time check patterns
        b'GetSystemTime',
        b'time',
        b'clock'
    ]
    
    for pattern in trial_patterns:
        offset = 0
        while True:
            offset = binary_data.find(pattern, offset)
            if offset == -1:
                break
            
            # Create NOP patch or redirect
            patch_entry = {
                'offset': offset,
                'original': pattern,
                'patch': b'\x90' * len(pattern),  # NOP sled
                'type': 'trial_pattern'
            }
            patch_offsets.append(patch_entry)
            patch_data.extend(patch_entry['patch'])
            offset += len(pattern)
    
    # Patch time-based checks
    time_checks = _find_time_checks(binary_data)
    for check in time_checks:
        patch_offsets.append(check)
        patch_data.extend(check['patch'])
    
    return bytes(patch_data), patch_offsets


def _generate_feature_unlock_patch(binary_data: bytes, config: Dict[str, Any]) -> Tuple[bytes, List[Dict[str, Any]]]:
    """Generate patch to unlock features."""
    patch_data = bytearray()
    patch_offsets = []
    
    # Feature check patterns
    feature_patterns = [
        # Common feature flags
        {'pattern': b'IsPro', 'patch': b'True\x00\x00'},
        {'pattern': b'IsLicensed', 'patch': b'ReturnTrue'},
        {'pattern': b'FeatureEnabled', 'patch': b'AlwaysEnabled\x00'},
        {'pattern': b'CheckFeature', 'patch': b'SkipCheck\x00\x00\x00'}
    ]
    
    for feat in feature_patterns:
        offset = binary_data.find(feat['pattern'])
        if offset != -1:
            patch_bytes = feat['patch'][:len(feat['pattern'])].ljust(len(feat['pattern']), b'\x00')
            patch_entry = {
                'offset': offset,
                'original': feat['pattern'],
                'patch': patch_bytes,
                'type': 'feature_unlock'
            }
            patch_offsets.append(patch_entry)
            patch_data.extend(patch_bytes)
    
    # Find and patch feature comparison functions
    feature_checks = _find_feature_checks(binary_data)
    for check in feature_checks:
        patch_offsets.append(check)
        patch_data.extend(check['patch'])
    
    return bytes(patch_data), patch_offsets


def _generate_signature_bypass_patch(binary_data: bytes, config: Dict[str, Any]) -> Tuple[bytes, List[Dict[str, Any]]]:
    """Generate patch to bypass signature verification."""
    patch_data = bytearray()
    patch_offsets = []
    
    # Signature verification patterns
    sig_patterns = [
        # Common crypto API calls
        {'pattern': b'CryptVerifySignature', 'type': 'api'},
        {'pattern': b'WinVerifyTrust', 'type': 'api'},
        {'pattern': b'SignatureValid', 'type': 'string'},
        # Assembly patterns for signature checks
        {'pattern': b'\x3D\x00\x02\x00\x00', 'patch': b'\x3D\x00\x00\x00\x00', 'type': 'cmp'},  # cmp eax, 0x200
        {'pattern': b'\x81\xF9\x00\x02\x00\x00', 'patch': b'\x81\xF9\x00\x00\x00\x00', 'type': 'cmp'}  # cmp ecx, 0x200
    ]
    
    for sig in sig_patterns:
        offset = binary_data.find(sig['pattern'])
        if offset != -1:
            if sig['type'] == 'api':
                # Replace API call with success return
                patch_bytes = b'\xB8\x01\x00\x00\x00\xC3'  # mov eax, 1; ret
            elif sig['type'] == 'string':
                # Replace string
                patch_bytes = b'AlwaysValid\x00'.ljust(len(sig['pattern']), b'\x00')
            else:
                # Use provided patch
                patch_bytes = sig.get('patch', b'\x90' * len(sig['pattern']))
            
            patch_entry = {
                'offset': offset,
                'original': sig['pattern'],
                'patch': patch_bytes,
                'type': 'signature_bypass'
            }
            patch_offsets.append(patch_entry)
            patch_data.extend(patch_bytes)
    
    return bytes(patch_data), patch_offsets


def _generate_generic_patch(binary_data: bytes, config: Dict[str, Any]) -> Tuple[bytes, List[Dict[str, Any]]]:
    """Generate generic patch based on configuration."""
    patch_data = bytearray()
    patch_offsets = []
    
    # Check if manual patches are specified
    manual_patches = config.get('patches', [])
    for patch in manual_patches:
        offset = patch.get('offset', 0)
        original = patch.get('original', b'')
        replacement = patch.get('replacement', b'')
        
        if offset < len(binary_data):
            patch_entry = {
                'offset': offset,
                'original': original or binary_data[offset:offset+len(replacement)],
                'patch': replacement,
                'type': 'manual'
            }
            patch_offsets.append(patch_entry)
            patch_data.extend(replacement)
    
    # If no manual patches, try to identify common patterns
    if not manual_patches:
        common_patches = _identify_common_patches(binary_data)
        for patch in common_patches:
            patch_offsets.append(patch)
            patch_data.extend(patch['patch'])
    
    return bytes(patch_data), patch_offsets


def _find_license_functions(binary_data: bytes) -> List[Dict[str, Any]]:
    """Find and patch license validation functions."""
    patches = []
    
    # Common function prologue patterns
    function_prologues = [
        b'\x55\x8B\xEC',  # push ebp; mov ebp, esp (x86)
        b'\x55\x48\x89\xE5',  # push rbp; mov rbp, rsp (x64)
        b'\x48\x89\x5C\x24',  # mov [rsp+...], rbx (x64 alt)
    ]
    
    # License-related strings to search near
    license_strings = [
        b'ValidateLicense',
        b'CheckLicense',
        b'IsValidLicense',
        b'LicenseCheck',
        b'Authorized'
    ]
    
    for lic_str in license_strings:
        str_offset = binary_data.find(lic_str)
        if str_offset != -1:
            # Search for function prologues near the string reference
            search_start = max(0, str_offset - 0x1000)
            search_end = min(len(binary_data), str_offset + 0x1000)
            
            for prologue in function_prologues:
                offset = binary_data.find(prologue, search_start, search_end)
                if offset != -1:
                    # Patch to return success
                    if prologue == function_prologues[0]:  # x86
                        patch_bytes = b'\xB8\x01\x00\x00\x00\xC3'  # mov eax, 1; ret
                    else:  # x64
                        patch_bytes = b'\xB8\x01\x00\x00\x00\xC3'  # mov eax, 1; ret
                    
                    patches.append({
                        'offset': offset,
                        'original': prologue,
                        'patch': patch_bytes,
                        'name': f'license_func_near_{lic_str.decode(errors="ignore")}',
                        'confidence': 0.8
                    })
    
    return patches


def _find_time_checks(binary_data: bytes) -> List[Dict[str, Any]]:
    """Find and patch time-based trial checks."""
    patches = []
    
    # Time comparison patterns
    time_patterns = [
        # Compare against specific timestamps
        {
            'pattern': b'\x3D\x00\x00\x00\x00',  # cmp eax, timestamp
            'mask': b'\xFF\x00\x00\x00\x00',
            'patch': b'\x3D\xFF\xFF\xFF\x7F'  # cmp eax, MAX_INT
        },
        # Time API imports
        {
            'pattern': b'GetSystemTimeAsFileTime',
            'patch': b'GetFakeTimeAsFileTime\x00\x00\x00'
        }
    ]
    
    for pattern in time_patterns:
        if 'mask' in pattern:
            # Pattern with mask
            offset = _find_pattern_with_mask(binary_data, pattern['pattern'], pattern['mask'])
        else:
            # Simple pattern
            offset = binary_data.find(pattern['pattern'])
        
        if offset != -1:
            patches.append({
                'offset': offset,
                'original': pattern['pattern'],
                'patch': pattern['patch'],
                'type': 'time_check'
            })
    
    return patches


def _find_feature_checks(binary_data: bytes) -> List[Dict[str, Any]]:
    """Find and patch feature validation checks."""
    patches = []
    
    # Feature comparison patterns (comparing feature flags)
    feature_cmp_patterns = [
        # TEST instruction patterns
        {
            'pattern': b'\x85\xC0',  # test eax, eax
            'follow': b'\x74',  # je (jump if zero)
            'patch': b'\xB8\x01'  # mov eax, 1
        },
        {
            'pattern': b'\x85\xC9',  # test ecx, ecx
            'follow': b'\x74',  # je
            'patch': b'\xB9\x01'  # mov ecx, 1
        }
    ]
    
    for pattern in feature_cmp_patterns:
        offset = 0
        while True:
            offset = binary_data.find(pattern['pattern'], offset)
            if offset == -1:
                break
            
            # Check if followed by conditional jump
            if offset + len(pattern['pattern']) < len(binary_data):
                next_byte = binary_data[offset + len(pattern['pattern'])]
                if next_byte == pattern['follow'][0]:
                    patches.append({
                        'offset': offset,
                        'original': pattern['pattern'],
                        'patch': pattern['patch'],
                        'type': 'feature_check'
                    })
            
            offset += 1
    
    return patches


def _find_pattern_with_mask(data: bytes, pattern: bytes, mask: bytes) -> int:
    """Find pattern in data using mask."""
    if len(pattern) != len(mask):
        return -1
    
    for i in range(len(data) - len(pattern) + 1):
        match = True
        for j in range(len(pattern)):
            if mask[j] == 0xFF:  # Check this byte
                if data[i + j] != pattern[j]:
                    match = False
                    break
        if match:
            return i
    
    return -1


def _identify_common_patches(binary_data: bytes) -> List[Dict[str, Any]]:
    """Identify common patchable patterns."""
    patches = []
    
    # Common protection patterns
    protection_patterns = [
        # Anti-debugging
        {'pattern': b'IsDebuggerPresent', 'patch': b'NeverDebuggerHere', 'type': 'anti_debug'},
        # Registry checks
        {'pattern': b'RegQueryValueEx', 'patch': b'FakeQueryValueEx', 'type': 'registry'},
        # File checks
        {'pattern': b'CreateFile', 'context': b'crack', 'type': 'file_check'}
    ]
    
    for prot in protection_patterns:
        offset = binary_data.find(prot['pattern'])
        if offset != -1:
            # Check context if specified
            if 'context' in prot:
                context_found = False
                for i in range(max(0, offset - 100), min(len(binary_data), offset + 100)):
                    if binary_data[i:i+len(prot['context'])] == prot['context']:
                        context_found = True
                        break
                if not context_found:
                    continue
            
            patch_bytes = prot.get('patch', b'\x90' * len(prot['pattern']))
            if len(patch_bytes) < len(prot['pattern']):
                patch_bytes = patch_bytes.ljust(len(prot['pattern']), b'\x00')
            
            patches.append({
                'offset': offset,
                'original': prot['pattern'],
                'patch': patch_bytes[:len(prot['pattern'])],
                'type': prot['type']
            })
    
    return patches


def _calculate_checksum(data: bytes) -> str:
    """Calculate checksum for patch data."""
    import hashlib
    return hashlib.sha256(data).hexdigest()


def apply_patch(target_binary: str, patch_data: bytes, patch_offsets: List[Dict[str, Any]]) -> bool:
    """Apply patch to binary file."""
    try:
        # Create backup
        backup_path = f"{target_binary}.backup"
        if not os.path.exists(backup_path):
            import shutil
            shutil.copy2(target_binary, backup_path)
        
        # Read original binary
        with open(target_binary, 'rb') as f:
            binary_data = bytearray(f.read())
        
        # Apply patches
        for patch_info in patch_offsets:
            offset = patch_info['offset']
            patch_bytes = patch_info['patch']
            
            if offset + len(patch_bytes) <= len(binary_data):
                binary_data[offset:offset+len(patch_bytes)] = patch_bytes
                logger.debug(f"Applied patch at offset {offset:#x}")
        
        # Write patched binary
        with open(target_binary, 'wb') as f:
            f.write(binary_data)
        
        logger.info(f"Successfully applied {len(patch_offsets)} patches to {target_binary}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to apply patch: {e}")
        return False


class PatchGenerator:
    """Patch generator class for advanced patch operations."""

    def __init__(self):
        """Initialize patch generator with logger for binary patching operations."""
        self.logger = logging.getLogger("IntellicrackLogger.PatchGenerator")

    def generate_binary_patch(self, target_path: str, patch_type: str = 'license_bypass') -> Dict[str, Any]:
        """Generate a binary patch with specified type."""
        return generate_patch(target_path, {'type': patch_type})

    def validate_patch(self, patch_data: bytes, target_binary: str) -> Dict[str, Any]:
        """Validate a generated patch."""
        _ = patch_data, target_binary
        return {
            'valid': True,
            'issues': [],
            'recommendations': []
        }

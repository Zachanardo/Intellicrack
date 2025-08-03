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
Advanced Patch Generator Module

Production-ready patch generation with comprehensive binary analysis,
pattern matching, and multi-architecture support.
"""

import logging
import os
import time
import hashlib
import re
import struct
import shutil
from typing import Any, Dict, Optional, List, Tuple, Union, Set
from pathlib import Path
from dataclasses import dataclass, field
from enum import Enum, auto
from collections import defaultdict

logger = logging.getLogger(__name__)

# Import audit logging
try:
    from ...core.logging.audit_logger import get_audit_logger, AuditEvent, AuditEventType, AuditSeverity
    audit_logger = get_audit_logger()
except ImportError:
    # Fallback if audit logger not available
    audit_logger = None


class PatchType(Enum):
    """Types of patches that can be generated."""
    LICENSE_BYPASS = "license_bypass"
    TRIAL_RESET = "trial_reset"
    FEATURE_UNLOCK = "feature_unlock"
    SIGNATURE_BYPASS = "signature_bypass"
    TIME_BOMB_DEFUSE = "time_bomb_defuse"
    HARDWARE_ID_SPOOF = "hardware_id_spoof"
    GENERIC = "generic"
    CUSTOM = "custom"


class Architecture(Enum):
    """Target architectures."""
    X86 = "x86"
    X64 = "x64"
    ARM = "arm"
    ARM64 = "arm64"
    UNKNOWN = "unknown"


@dataclass
class PatchPattern:
    """Represents a pattern to search for and patch."""
    name: str
    pattern: bytes
    replacement: bytes
    architecture: Architecture = Architecture.UNKNOWN
    description: str = ""
    confidence: float = 1.0
    context_required: bool = False
    max_occurrences: int = -1  # -1 means unlimited


@dataclass
class PatchEntry:
    """Represents a single patch operation."""
    offset: int
    original: bytes
    replacement: bytes
    pattern_name: str
    architecture: Architecture
    confidence: float = 1.0
    description: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'offset': self.offset,
            'original': self.original.hex(),
            'replacement': self.replacement.hex(),
            'pattern_name': self.pattern_name,
            'architecture': self.architecture.value,
            'confidence': self.confidence,
            'description': self.description,
            'size': len(self.original)
        }


@dataclass
class PatchResult:
    """Result of patch generation."""
    success: bool
    patch_type: PatchType
    entries: List[PatchEntry] = field(default_factory=list)
    target_path: str = ""
    architecture: Architecture = Architecture.UNKNOWN
    total_size: int = 0
    checksum: str = ""
    timestamp: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


class BinaryAnalyzer:
    """Analyzes binaries to detect architecture and protection schemes."""
    
    def __init__(self, binary_data: bytes):
        self.data = binary_data
        self.size = len(binary_data)
        self.architecture = Architecture.UNKNOWN
        self.is_pe = False
        self.is_elf = False
        self.is_macho = False
        self.entry_point = 0
        self.sections = []
        self._analyze()
    
    def _analyze(self):
        """Perform initial binary analysis."""
        # Check for PE signature
        if self.size > 64 and self.data[:2] == b'MZ':
            self.is_pe = True
            pe_offset = struct.unpack('<I', self.data[0x3C:0x40])[0]
            if pe_offset + 6 < self.size:
                machine = struct.unpack('<H', self.data[pe_offset+4:pe_offset+6])[0]
                if machine == 0x14c:
                    self.architecture = Architecture.X86
                elif machine == 0x8664:
                    self.architecture = Architecture.X64
                elif machine == 0x1c0:
                    self.architecture = Architecture.ARM
                elif machine == 0xaa64:
                    self.architecture = Architecture.ARM64
        
        # Check for ELF signature
        elif self.size > 20 and self.data[:4] == b'\x7fELF':
            self.is_elf = True
            ei_class = self.data[4]
            ei_machine = struct.unpack('<H', self.data[18:20])[0]
            
            if ei_machine == 0x03:  # EM_386
                self.architecture = Architecture.X86
            elif ei_machine == 0x3E:  # EM_X86_64
                self.architecture = Architecture.X64
            elif ei_machine == 0x28:  # EM_ARM
                self.architecture = Architecture.ARM
            elif ei_machine == 0xB7:  # EM_AARCH64
                self.architecture = Architecture.ARM64
        
        # Check for Mach-O signature
        elif self.size > 4 and self.data[:4] in [b'\xfe\xed\xfa\xce', b'\xce\xfa\xed\xfe',
                                                  b'\xfe\xed\xfa\xcf', b'\xcf\xfa\xed\xfe']:
            self.is_macho = True
            magic = struct.unpack('<I', self.data[:4])[0]
            if magic in [0xfeedface, 0xcefaedfe]:
                self.architecture = Architecture.X86
            elif magic in [0xfeedfacf, 0xcffaedfe]:
                self.architecture = Architecture.X64
    
    def find_all_occurrences(self, pattern: bytes) -> List[int]:
        """Find all occurrences of a pattern in the binary."""
        offsets = []
        start = 0
        while True:
            offset = self.data.find(pattern, start)
            if offset == -1:
                break
            offsets.append(offset)
            start = offset + 1
        return offsets
    
    def get_context(self, offset: int, size: int = 32) -> bytes:
        """Get context around an offset."""
        start = max(0, offset - size)
        end = min(self.size, offset + size)
        return self.data[start:end]
    
    def is_code_section(self, offset: int) -> bool:
        """Check if offset is likely in a code section."""
        # Simple heuristic based on common patterns
        if offset < 0x1000:  # Headers
            return False
        
        context = self.get_context(offset, 16)
        # Look for common instruction patterns
        code_indicators = [
            b'\x55\x89\xe5',  # push ebp; mov ebp, esp
            b'\x55\x48\x89\xe5',  # push rbp; mov rbp, rsp
            b'\x48\x83\xec',  # sub rsp, ...
            b'\x48\x89\x5c\x24',  # mov [rsp+...], rbx
            b'\xff\x25',  # jmp [...]
            b'\xe8',  # call
            b'\xc3',  # ret
        ]
        
        for indicator in code_indicators:
            if indicator in context:
                return True
        
        return False


class PatternDatabase:
    """Database of known protection patterns."""
    
    def __init__(self):
        self.patterns: Dict[PatchType, List[PatchPattern]] = defaultdict(list)
        self._initialize_patterns()
    
    def _initialize_patterns(self):
        """Initialize pattern database with known protection patterns."""
        
        # License bypass patterns
        self.patterns[PatchType.LICENSE_BYPASS].extend([
            # Common license check functions
            PatchPattern(
                name="license_valid_x86",
                pattern=b'\x55\x89\xe5\x83\xec',  # Function prologue
                replacement=b'\xb8\x01\x00\x00\x00\xc3',  # mov eax, 1; ret
                architecture=Architecture.X86,
                description="License validation function return true",
                context_required=True
            ),
            PatchPattern(
                name="license_valid_x64",
                pattern=b'\x55\x48\x89\xe5\x48\x83\xec',  # Function prologue
                replacement=b'\xb8\x01\x00\x00\x00\xc3',  # mov eax, 1; ret
                architecture=Architecture.X64,
                description="License validation function return true",
                context_required=True
            ),
            # String-based checks
            PatchPattern(
                name="license_string_check",
                pattern=b'IsLicenseValid',
                replacement=b'AlwaysReturnOK',
                description="License validation string replacement"
            ),
            PatchPattern(
                name="invalid_license_msg",
                pattern=b'Invalid license',
                replacement=b'Valid license!!',
                description="Invalid license message bypass"
            ),
            # Jump bypasses
            PatchPattern(
                name="conditional_jump_bypass",
                pattern=b'\x74',  # JE (Jump if Equal)
                replacement=b'\xeb',  # JMP (unconditional)
                description="Conditional jump to unconditional",
                context_required=True
            ),
            PatchPattern(
                name="conditional_jump_invert",
                pattern=b'\x75',  # JNE (Jump if Not Equal)
                replacement=b'\x74',  # JE
                description="Invert conditional jump",
                context_required=True
            ),
        ])
        
        # Trial reset patterns
        self.patterns[PatchType.TRIAL_RESET].extend([
            PatchPattern(
                name="trial_days_check",
                pattern=b'TrialDaysRemaining',
                replacement=b'UnlimitedTrialDays',
                description="Trial days string replacement"
            ),
            PatchPattern(
                name="trial_expired_check",
                pattern=b'Trial period has expired',
                replacement=b'Trial period is active!',
                description="Trial expiration message"
            ),
            PatchPattern(
                name="date_check_bypass",
                pattern=b'\x3d\x1e\x00\x00\x00',  # cmp eax, 30 (30 days)
                replacement=b'\x3d\xff\xff\xff\x7f',  # cmp eax, 0x7fffffff
                description="Extend trial period comparison",
                context_required=True
            ),
        ])
        
        # Feature unlock patterns
        self.patterns[PatchType.FEATURE_UNLOCK].extend([
            PatchPattern(
                name="feature_enabled_check",
                pattern=b'IsFeatureEnabled',
                replacement=b'AlwaysEnableFeat',
                description="Feature check string"
            ),
            PatchPattern(
                name="pro_version_check",
                pattern=b'IsProfessionalVersion',
                replacement=b'AlwaysProfessional___',
                description="Pro version check"
            ),
            PatchPattern(
                name="feature_flag_check",
                pattern=b'\x80\x3d',  # cmp byte ptr [...], 
                replacement=b'\xb0\x01',  # mov al, 1
                architecture=Architecture.X86,
                description="Feature flag check bypass",
                context_required=True
            ),
        ])
        
        # Signature bypass patterns
        self.patterns[PatchType.SIGNATURE_BYPASS].extend([
            PatchPattern(
                name="signature_verify",
                pattern=b'VerifySignature',
                replacement=b'AlwaysValidSig!',
                description="Signature verification string"
            ),
            PatchPattern(
                name="cert_check",
                pattern=b'CertificateValid',
                replacement=b'AlwaysValidCert!',
                description="Certificate validation"
            ),
            PatchPattern(
                name="hash_check_x86",
                pattern=b'\xe8',  # call
                replacement=b'\x90\x90\x90\x90\x90',  # nop sled
                architecture=Architecture.X86,
                description="Hash verification call bypass",
                context_required=True,
                max_occurrences=5
            ),
        ])
        
        # Time bomb defuse patterns
        self.patterns[PatchType.TIME_BOMB_DEFUSE].extend([
            PatchPattern(
                name="expiration_date",
                pattern=b'2024-12-31',
                replacement=b'2099-12-31',
                description="Expiration date extension"
            ),
            PatchPattern(
                name="time_check_function",
                pattern=b'CheckExpirationDate',
                replacement=b'NeverExpiresCheck!!',
                description="Expiration check function"
            ),
            PatchPattern(
                name="timestamp_compare",
                pattern=b'\x81\x3d',  # cmp dword ptr [...],
                replacement=b'\x90\x90\x90\x90\x90\x90',  # nop
                architecture=Architecture.X86,
                description="Timestamp comparison bypass",
                context_required=True
            ),
        ])
        
        # Hardware ID spoof patterns
        self.patterns[PatchType.HARDWARE_ID_SPOOF].extend([
            PatchPattern(
                name="hwid_check",
                pattern=b'GetHardwareID',
                replacement=b'ReturnValidID',
                description="Hardware ID retrieval"
            ),
            PatchPattern(
                name="machine_id",
                pattern=b'MachineGuid',
                replacement=b'ValidGuid!!',
                description="Machine GUID check"
            ),
            PatchPattern(
                name="mac_address_check",
                pattern=b'GetMACAddress',
                replacement=b'ReturnOKMAC!!',
                description="MAC address check"
            ),
        ])
    
    def get_patterns(self, patch_type: PatchType, architecture: Architecture = Architecture.UNKNOWN) -> List[PatchPattern]:
        """Get patterns for specific patch type and architecture."""
        patterns = self.patterns.get(patch_type, [])
        
        if architecture != Architecture.UNKNOWN:
            # Filter by architecture
            filtered = []
            for pattern in patterns:
                if pattern.architecture in [Architecture.UNKNOWN, architecture]:
                    filtered.append(pattern)
            return filtered
        
        return patterns


class IntelligentPatcher:
    """Intelligent patching engine with context awareness."""
    
    def __init__(self, analyzer: BinaryAnalyzer):
        self.analyzer = analyzer
        self.found_patterns: Dict[str, List[int]] = {}
    
    def verify_context(self, offset: int, pattern: PatchPattern) -> bool:
        """Verify if the context around the pattern is appropriate for patching."""
        if not pattern.context_required:
            return True
        
        # Check if in code section
        if not self.analyzer.is_code_section(offset):
            return False
        
        context = self.analyzer.get_context(offset, 32)
        
        # Pattern-specific context checks
        if pattern.name == "conditional_jump_bypass":
            # Verify it's actually a conditional jump in a comparison context
            # Look for common comparison instructions before the jump
            cmp_patterns = [b'\x3d', b'\x83\xf8', b'\x83\xf9', b'\x39', b'\x3b']
            for cmp in cmp_patterns:
                if cmp in context[:offset]:
                    return True
            return False
        
        elif pattern.name.startswith("license_valid_"):
            # Verify it's likely a function start
            # Should have typical function patterns nearby
            if offset > 5:
                before = self.analyzer.data[offset-5:offset]
                # Check for padding or alignment before function
                if before.count(b'\x90') > 2 or before.count(b'\xcc') > 2:
                    return True
                # Check for previous function end
                if b'\xc3' in before or b'\xc2' in before:
                    return True
        
        elif pattern.name == "hash_check_x86":
            # Verify it's a call instruction with proper context
            if offset + 5 <= self.analyzer.size:
                # Check if it's a relative call
                call_offset = struct.unpack('<I', self.analyzer.data[offset+1:offset+5])[0]
                # Reasonable call offset range
                if 0 < call_offset < 0x1000000:
                    return True
        
        return True
    
    def calculate_replacement_confidence(self, offset: int, pattern: PatchPattern) -> float:
        """Calculate confidence level for a replacement."""
        confidence = pattern.confidence
        
        # Reduce confidence if not in code section for code patterns
        if pattern.architecture != Architecture.UNKNOWN and not self.analyzer.is_code_section(offset):
            confidence *= 0.5
        
        # Check uniqueness
        if pattern.name in self.found_patterns:
            occurrences = len(self.found_patterns[pattern.name])
            if occurrences > pattern.max_occurrences > 0:
                confidence *= 0.3
        
        # Architecture mismatch
        if (pattern.architecture != Architecture.UNKNOWN and 
            self.analyzer.architecture != Architecture.UNKNOWN and
            pattern.architecture != self.analyzer.architecture):
            confidence *= 0.2
        
        return confidence


class PatchGenerator:
    """Advanced patch generator with comprehensive functionality."""
    
    def __init__(self):
        self.logger = logging.getLogger("IntellicrackLogger.PatchGenerator")
        self.pattern_db = PatternDatabase()
    
    def generate_patch(self, target_binary: str, patch_config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Generate a patch for the specified binary.
        
        Args:
            target_binary: Path to the target binary
            patch_config: Configuration options for patch generation
            
        Returns:
            Dictionary containing patch generation results
        """
        if patch_config is None:
            patch_config = {}
            
        # Audit log patch generation attempt
        if audit_logger:
            audit_logger.log_event(AuditEvent(
                event_type=AuditEventType.EXPLOIT_ATTEMPT,
                severity=AuditSeverity.HIGH,
                description=f"Patch generation: {os.path.basename(target_binary)}",
                target=target_binary,
                details={
                    "operation": "generate_patch",
                    "config": patch_config,
                    "patch_type": patch_config.get("patch_type", "unknown")
                }
            ))
        
        try:
            # Validate target binary
            if not os.path.exists(target_binary):
                raise FileNotFoundError(f"Target binary not found: {target_binary}")
            
            # Read binary file
            with open(target_binary, 'rb') as f:
                binary_data = f.read()
            
            # Analyze binary
            analyzer = BinaryAnalyzer(binary_data)
            self.logger.info(f"Analyzed binary: {os.path.basename(target_binary)}, "
                           f"Architecture: {analyzer.architecture.value}, "
                           f"Size: {analyzer.size} bytes")
            
            # Determine patch type
            patch_type_str = patch_config.get('type', 'license_bypass')
            try:
                patch_type = PatchType(patch_type_str)
            except ValueError:
                patch_type = PatchType.GENERIC
                self.logger.warning(f"Unknown patch type '{patch_type_str}', using generic")
            
            # Generate patches based on type
            result = self._generate_typed_patch(analyzer, patch_type, patch_config)
            
            # Create response
            if result.success:
                return {
                    'success': True,
                    'patch_data': self._serialize_patches(result.entries),
                    'patch_info': {
                        'target': target_binary,
                        'type': result.patch_type.value,
                        'architecture': result.architecture.value,
                        'total_patches': len(result.entries),
                        'total_size': sum(len(e.replacement) for e in result.entries),
                        'checksum': result.checksum,
                        'timestamp': result.timestamp,
                        'confidence_avg': sum(e.confidence for e in result.entries) / len(result.entries) if result.entries else 0
                    },
                    'entries': [e.to_dict() for e in result.entries],
                    'warnings': result.warnings,
                    'message': f'Successfully generated {len(result.entries)} patches'
                }
            else:
                return {
                    'success': False,
                    'error': '; '.join(result.errors),
                    'patch_data': b'',
                    'patch_info': {},
                    'entries': [],
                    'warnings': result.warnings
                }
        
        except Exception as e:
            self.logger.error(f"Patch generation failed: {e}", exc_info=True)
            return {
                'success': False,
                'error': str(e),
                'patch_data': b'',
                'patch_info': {},
                'entries': []
            }
    
    def _generate_typed_patch(self, analyzer: BinaryAnalyzer, patch_type: PatchType, 
                            config: Dict[str, Any]) -> PatchResult:
        """Generate patches for specific type."""
        result = PatchResult(
            success=False,
            patch_type=patch_type,
            architecture=analyzer.architecture
        )
        
        # Get patterns for this type
        patterns = self.pattern_db.get_patterns(patch_type, analyzer.architecture)
        if not patterns:
            result.errors.append(f"No patterns available for {patch_type.value}")
            return result
        
        # Create intelligent patcher
        patcher = IntelligentPatcher(analyzer)
        
        # Search and apply patterns
        for pattern in patterns:
            # Find all occurrences
            offsets = analyzer.find_all_occurrences(pattern.pattern)
            
            if not offsets:
                continue
            
            self.logger.debug(f"Found {len(offsets)} occurrences of pattern '{pattern.name}'")
            
            # Track found patterns
            patcher.found_patterns[pattern.name] = offsets
            
            # Process each occurrence
            applied = 0
            for offset in offsets:
                # Verify context if required
                if not patcher.verify_context(offset, pattern):
                    result.warnings.append(f"Context verification failed for {pattern.name} at {offset:#x}")
                    continue
                
                # Calculate confidence
                confidence = patcher.calculate_replacement_confidence(offset, pattern)
                
                # Skip low confidence patches unless forced
                min_confidence = config.get('min_confidence', 0.7)
                if confidence < min_confidence and not config.get('force', False):
                    result.warnings.append(f"Low confidence ({confidence:.2f}) for {pattern.name} at {offset:#x}")
                    continue
                
                # Create patch entry
                entry = PatchEntry(
                    offset=offset,
                    original=pattern.pattern,
                    replacement=pattern.replacement,
                    pattern_name=pattern.name,
                    architecture=pattern.architecture,
                    confidence=confidence,
                    description=pattern.description
                )
                
                result.entries.append(entry)
                applied += 1
                
                # Check max occurrences
                if pattern.max_occurrences > 0 and applied >= pattern.max_occurrences:
                    break
            
            if applied > 0:
                self.logger.info(f"Applied {applied} patches for pattern '{pattern.name}'")
        
        # Additional intelligent patching based on type
        if patch_type == PatchType.LICENSE_BYPASS:
            self._add_license_heuristics(analyzer, result, config)
        elif patch_type == PatchType.TRIAL_RESET:
            self._add_trial_heuristics(analyzer, result, config)
        elif patch_type == PatchType.FEATURE_UNLOCK:
            self._add_feature_heuristics(analyzer, result, config)
        
        # Calculate checksum
        if result.entries:
            patch_data = b''.join(e.replacement for e in result.entries)
            result.checksum = hashlib.sha256(patch_data).hexdigest()
            result.success = True
        else:
            result.errors.append("No patches could be generated")
        
        return result
    
    def _add_license_heuristics(self, analyzer: BinaryAnalyzer, result: PatchResult, config: Dict[str, Any]):
        """Add heuristic-based patches for license bypass."""
        # Search for common license-related strings
        license_strings = [
            b'license', b'License', b'LICENSE',
            b'serial', b'Serial', b'SERIAL',
            b'registration', b'Registration',
            b'activated', b'Activated',
            b'valid', b'Valid', b'invalid', b'Invalid'
        ]
        
        for string in license_strings:
            offsets = analyzer.find_all_occurrences(string)
            for offset in offsets:
                # Check surrounding context
                context = analyzer.get_context(offset, 100)
                
                # Look for nearby conditional jumps
                jump_patterns = [b'\x74', b'\x75', b'\x0f\x84', b'\x0f\x85']
                for jmp in jump_patterns:
                    jmp_offset = context.find(jmp)
                    if jmp_offset != -1:
                        actual_offset = offset - 100 + jmp_offset
                        if actual_offset not in [e.offset for e in result.entries]:
                            # Add heuristic patch
                            entry = PatchEntry(
                                offset=actual_offset,
                                original=jmp,
                                replacement=b'\x90' * len(jmp),  # NOP
                                pattern_name="heuristic_license_jump",
                                architecture=analyzer.architecture,
                                confidence=0.6,
                                description=f"Heuristic: jump near '{string.decode('ascii', errors='ignore')}'"
                            )
                            result.entries.append(entry)
                            result.warnings.append(f"Added heuristic patch at {actual_offset:#x}")
    
    def _add_trial_heuristics(self, analyzer: BinaryAnalyzer, result: PatchResult, config: Dict[str, Any]):
        """Add heuristic-based patches for trial reset."""
        # Search for date/time related patterns
        # Common epoch timestamps for recent years
        epoch_patterns = [
            struct.pack('<I', 1640995200),  # 2022-01-01
            struct.pack('<I', 1672531200),  # 2023-01-01
            struct.pack('<I', 1704067200),  # 2024-01-01
            struct.pack('<I', 1735689600),  # 2025-01-01
        ]
        
        for pattern in epoch_patterns:
            offsets = analyzer.find_all_occurrences(pattern)
            for offset in offsets:
                # Replace with far future date (2099-01-01)
                future_timestamp = struct.pack('<I', 4070908800)
                entry = PatchEntry(
                    offset=offset,
                    original=pattern,
                    replacement=future_timestamp,
                    pattern_name="heuristic_trial_timestamp",
                    architecture=analyzer.architecture,
                    confidence=0.7,
                    description="Trial timestamp replacement"
                )
                result.entries.append(entry)
    
    def _add_feature_heuristics(self, analyzer: BinaryAnalyzer, result: PatchResult, config: Dict[str, Any]):
        """Add heuristic-based patches for feature unlocking."""
        # Search for feature-related boolean checks
        # Common patterns for feature flags
        flag_patterns = [
            (b'\x80\x3d', b'\xc6\x05'),  # cmp byte ptr -> mov byte ptr
            (b'\x83\x3d', b'\xc7\x05'),  # cmp dword ptr -> mov dword ptr
        ]
        
        for search, replace in flag_patterns:
            offsets = analyzer.find_all_occurrences(search)
            for offset in offsets:
                if offset + 7 <= analyzer.size:
                    # Create replacement that sets flag to 1
                    replacement = replace + analyzer.data[offset+2:offset+6] + b'\x01\x00\x00\x00'
                    entry = PatchEntry(
                        offset=offset,
                        original=analyzer.data[offset:offset+7],
                        replacement=replacement[:7],
                        pattern_name="heuristic_feature_flag",
                        architecture=analyzer.architecture,
                        confidence=0.5,
                        description="Feature flag enablement"
                    )
                    result.entries.append(entry)
    
    def _serialize_patches(self, entries: List[PatchEntry]) -> bytes:
        """Serialize patch entries into binary format."""
        # Simple format: [count][entry1][entry2]...
        # Entry: [offset:4][size:2][data:size]
        data = bytearray()
        
        # Write count
        data.extend(struct.pack('<I', len(entries)))
        
        # Write entries
        for entry in entries:
            data.extend(struct.pack('<I', entry.offset))
            data.extend(struct.pack('<H', len(entry.replacement)))
            data.extend(entry.replacement)
        
        return bytes(data)
    
    def apply_patch(self, target_binary: str, patch_entries: List[Dict[str, Any]], 
                   create_backup: bool = True) -> bool:
        """
        Apply patches to a binary file.
        
        Args:
            target_binary: Path to target binary
            patch_entries: List of patch entry dictionaries
            create_backup: Whether to create a backup
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Create backup if requested
            if create_backup:
                backup_path = f"{target_binary}.backup"
                if not os.path.exists(backup_path):
                    shutil.copy2(target_binary, backup_path)
                    self.logger.info(f"Created backup: {backup_path}")
            
            # Read binary
            with open(target_binary, 'rb') as f:
                binary_data = bytearray(f.read())
            
            # Apply patches
            applied = 0
            for entry_dict in patch_entries:
                try:
                    offset = entry_dict['offset']
                    replacement = bytes.fromhex(entry_dict['replacement'])
                    original = bytes.fromhex(entry_dict['original'])
                    
                    # Verify original bytes match
                    if offset + len(original) <= len(binary_data):
                        if binary_data[offset:offset+len(original)] == original:
                            binary_data[offset:offset+len(replacement)] = replacement
                            applied += 1
                            self.logger.debug(f"Applied patch at offset {offset:#x}")
                        else:
                            self.logger.warning(f"Original bytes mismatch at offset {offset:#x}")
                    else:
                        self.logger.warning(f"Offset {offset:#x} out of bounds")
                        
                except Exception as e:
                    self.logger.error(f"Failed to apply patch entry: {e}")
            
            # Write patched binary
            if applied > 0:
                with open(target_binary, 'wb') as f:
                    f.write(binary_data)
                self.logger.info(f"Successfully applied {applied}/{len(patch_entries)} patches")
                return True
            else:
                self.logger.warning("No patches were applied")
                return False
                
        except Exception as e:
            self.logger.error(f"Failed to apply patches: {e}", exc_info=True)
            return False
    
    def validate_patch(self, target_binary: str, patch_entries: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Validate patches before applying.
        
        Args:
            target_binary: Path to target binary
            patch_entries: List of patch entries to validate
            
        Returns:
            Validation result dictionary
        """
        issues = []
        warnings = []
        
        try:
            # Read binary
            with open(target_binary, 'rb') as f:
                binary_data = f.read()
            
            analyzer = BinaryAnalyzer(binary_data)
            
            # Validate each entry
            for i, entry in enumerate(patch_entries):
                try:
                    offset = entry['offset']
                    original = bytes.fromhex(entry['original'])
                    replacement = bytes.fromhex(entry['replacement'])
                    
                    # Check bounds
                    if offset + len(original) > len(binary_data):
                        issues.append(f"Entry {i}: Offset {offset:#x} out of bounds")
                        continue
                    
                    # Verify original bytes
                    actual = binary_data[offset:offset+len(original)]
                    if actual != original:
                        issues.append(f"Entry {i}: Original bytes mismatch at {offset:#x}")
                    
                    # Check replacement size
                    if len(replacement) > len(original):
                        warnings.append(f"Entry {i}: Replacement larger than original")
                    
                    # Architecture compatibility
                    if 'architecture' in entry and entry['architecture'] != 'unknown':
                        if entry['architecture'] != analyzer.architecture.value:
                            warnings.append(f"Entry {i}: Architecture mismatch")
                    
                except Exception as e:
                    issues.append(f"Entry {i}: Validation error - {str(e)}")
            
            return {
                'valid': len(issues) == 0,
                'issues': issues,
                'warnings': warnings,
                'recommendations': self._generate_recommendations(issues, warnings)
            }
            
        except Exception as e:
            return {
                'valid': False,
                'issues': [f"Validation failed: {str(e)}"],
                'warnings': [],
                'recommendations': []
            }
    
    def _generate_recommendations(self, issues: List[str], warnings: List[str]) -> List[str]:
        """Generate recommendations based on validation results."""
        recommendations = []
        
        if any('out of bounds' in issue for issue in issues):
            recommendations.append("Some patches reference invalid offsets. Regenerate patches with the current binary.")
        
        if any('mismatch' in issue for issue in issues):
            recommendations.append("Original bytes don't match. The binary may have been modified or patches are for a different version.")
        
        if any('Architecture' in warning for warning in warnings):
            recommendations.append("Architecture mismatch detected. Ensure patches match the target binary architecture.")
        
        if len(warnings) > len(issues):
            recommendations.append("Several warnings detected. Review patches carefully before applying.")
        
        return recommendations


# Convenience function for backward compatibility
def generate_patch(target_binary: str, patch_config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Generate a patch for the specified binary."""
    generator = PatchGenerator()
    return generator.generate_patch(target_binary, patch_config)


def apply_patch(target_binary: str, patch_data: bytes, patch_offsets: List[Dict[str, Any]]) -> bool:
    """Apply patch to binary file."""
    generator = PatchGenerator()
    return generator.apply_patch(target_binary, patch_offsets)
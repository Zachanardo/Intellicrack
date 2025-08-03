"""Advanced pattern matching engine for protection detection.

This module provides sophisticated pattern matching capabilities for detecting
protection schemes with confidence scoring and false positive reduction.

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

import hashlib
import logging
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from .signature_database import (
    ArchitectureType, ProtectionSignature, ProtectionSignatureDatabase,
    ProtectionType
)
import logging

logger = logging.getLogger(__name__)


@dataclass
class MatchResult:
    """Result of a pattern match operation."""
    signature_id: str
    signature_name: str
    protection_type: ProtectionType
    confidence: float
    match_count: int
    matches: List[Dict[str, Any]] = field(default_factory=list)
    false_positive_score: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def adjusted_confidence(self) -> float:
        """Get confidence adjusted for false positives."""
        return max(0.0, self.confidence - self.false_positive_score)


@dataclass
class ScanResult:
    """Complete scan result with all matches."""
    file_path: str
    file_size: int
    file_hash: str
    architecture: Optional[ArchitectureType]
    matches: List[MatchResult] = field(default_factory=list)
    scan_time: float = 0.0
    error: Optional[str] = None
    
    @property
    def detected_protections(self) -> Set[str]:
        """Get set of detected protection names."""
        return {match.signature_name for match in self.matches if match.adjusted_confidence > 0.5}
    
    @property
    def high_confidence_matches(self) -> List[MatchResult]:
        """Get matches with high confidence (>0.8)."""
        return [match for match in self.matches if match.adjusted_confidence > 0.8]
    
    @property
    def protection_types(self) -> Set[ProtectionType]:
        """Get set of detected protection types."""
        return {match.protection_type for match in self.matches if match.adjusted_confidence > 0.5}


class AdvancedPatternMatcher:
    """Advanced pattern matching engine with confidence scoring."""
    
    def __init__(self, database: ProtectionSignatureDatabase):
        """Initialize the pattern matcher.
        
        Args:
            database: Protection signature database
        """
        self.database = database
        self.logger = logging.getLogger(__name__)
        
        # Configuration
        self.min_confidence = 0.3
        self.max_false_positive_score = 0.5
        self.enable_fuzzy_matching = True
        self.enable_composite_scoring = True
        
        # Cache for performance
        self.signature_cache = {}
        self.false_positive_patterns = set()
        
        # Load false positive patterns
        self._load_false_positive_patterns()
    
    def _load_false_positive_patterns(self):
        """Load known false positive patterns."""
        # Common strings that often cause false positives
        fp_patterns = {
            b"This program cannot be run in DOS mode",
            b"Microsoft Visual C++ Runtime",
            b"GetProcAddress",
            b"LoadLibrary",
            b"VirtualAlloc",
            b"CreateFile",
            # Add more patterns as needed
        }
        self.false_positive_patterns.update(fp_patterns)
    
    def scan_file(self, file_path: str, architecture: Optional[ArchitectureType] = None) -> ScanResult:
        """Scan a file for protection patterns.
        
        Args:
            file_path: Path to file to scan
            architecture: Optional architecture hint
            
        Returns:
            Complete scan results
        """
        import time
        start_time = time.time()
        
        try:
            file_path_obj = Path(file_path)
            if not file_path_obj.exists():
                return ScanResult(
                    file_path=file_path,
                    file_size=0,
                    file_hash="",
                    architecture=architecture,
                    error="File not found"
                )
            
            # Read file
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            file_size = len(file_data)
            file_hash = hashlib.sha256(file_data).hexdigest()
            
            # Detect architecture if not provided
            if architecture is None:
                architecture = self._detect_architecture(file_data)
            
            # Scan for patterns
            matches = self._scan_binary_data(file_data, architecture)
            
            scan_time = time.time() - start_time
            
            return ScanResult(
                file_path=file_path,
                file_size=file_size,
                file_hash=file_hash,
                architecture=architecture,
                matches=matches,
                scan_time=scan_time
            )
            
        except Exception as e:
            self.logger.error(f"Error scanning file {file_path}: {e}")
            return ScanResult(
                file_path=file_path,
                file_size=0,
                file_hash="",
                architecture=architecture,
                error=str(e),
                scan_time=time.time() - start_time
            )
    
    def _detect_architecture(self, data: bytes) -> Optional[ArchitectureType]:
        """Detect file architecture from binary data.
        
        Args:
            data: Binary file data
            
        Returns:
            Detected architecture or None
        """
        if len(data) < 64:
            return None
        
        # Check PE header
        if data[:2] == b'MZ':
            try:
                # Get PE header offset
                pe_offset = struct.unpack('<L', data[60:64])[0]
                if pe_offset + 24 < len(data) and data[pe_offset:pe_offset+4] == b'PE\x00\x00':
                    # Get machine type
                    machine = struct.unpack('<H', data[pe_offset+4:pe_offset+6])[0]
                    if machine == 0x014c:  # IMAGE_FILE_MACHINE_I386
                        return ArchitectureType.X86
                    elif machine == 0x8664:  # IMAGE_FILE_MACHINE_AMD64
                        return ArchitectureType.X64
                    elif machine == 0x01c0:  # IMAGE_FILE_MACHINE_ARM
                        return ArchitectureType.ARM
                    elif machine == 0xaa64:  # IMAGE_FILE_MACHINE_ARM64
                        return ArchitectureType.ARM64
            except (struct.error, IndexError):
                pass
        
        # Check ELF header
        elif data[:4] == b'\x7fELF':
            try:
                elf_class = data[4]
                elf_machine = struct.unpack('<H', data[18:20])[0]
                
                if elf_class == 1:  # 32-bit
                    if elf_machine == 0x03:  # EM_386
                        return ArchitectureType.X86
                    elif elf_machine == 0x28:  # EM_ARM
                        return ArchitectureType.ARM
                elif elf_class == 2:  # 64-bit
                    if elf_machine == 0x3e:  # EM_X86_64
                        return ArchitectureType.X64
                    elif elf_machine == 0xb7:  # EM_AARCH64
                        return ArchitectureType.ARM64
            except (struct.error, IndexError):
                pass
        
        return None
    
    def _scan_binary_data(self, data: bytes, architecture: Optional[ArchitectureType]) -> List[MatchResult]:
        """Scan binary data for protection patterns.
        
        Args:
            data: Binary data to scan
            architecture: Target architecture
            
        Returns:
            List of match results
        """
        matches = []
        
        # Get relevant signatures based on architecture
        signatures = self._get_relevant_signatures(architecture)
        
        for signature in signatures:
            match_result = self._match_signature(signature, data)
            if match_result and match_result.adjusted_confidence >= self.min_confidence:
                matches.append(match_result)
        
        # Apply composite scoring if enabled
        if self.enable_composite_scoring:
            matches = self._apply_composite_scoring(matches)
        
        # Sort by confidence
        matches.sort(key=lambda x: x.adjusted_confidence, reverse=True)
        
        return matches
    
    def _get_relevant_signatures(self, architecture: Optional[ArchitectureType]) -> List[ProtectionSignature]:
        """Get signatures relevant to the target architecture.
        
        Args:
            architecture: Target architecture
            
        Returns:
            List of relevant signatures
        """
        if not self.database.loaded:
            self.database.load_database()
        
        relevant_signatures = []
        
        for signature in self.database.signatures.values():
            # Check architecture compatibility
            if (signature.architecture == ArchitectureType.ANY or 
                architecture is None or 
                signature.architecture == architecture):
                relevant_signatures.append(signature)
        
        return relevant_signatures
    
    def _match_signature(self, signature: ProtectionSignature, data: bytes) -> Optional[MatchResult]:
        """Match a single signature against binary data.
        
        Args:
            signature: Signature to match
            data: Binary data
            
        Returns:
            Match result if signature matches
        """
        total_matches = 0
        all_matches = []
        base_confidence = signature.confidence
        
        # Match binary signatures
        for bin_sig in signature.binary_signatures:
            matches = bin_sig.matches(data)
            if matches:
                total_matches += len(matches)
                for offset in matches:
                    all_matches.append({
                        'type': 'binary',
                        'name': bin_sig.name,
                        'offset': offset,
                        'description': bin_sig.description
                    })
        
        # Match string signatures
        try:
            text_data = data.decode('utf-8', errors='ignore')
            for str_sig in signature.string_signatures:
                matches = str_sig.matches(text_data)
                if matches:
                    total_matches += len(matches)
                    for offset, match_text in matches:
                        all_matches.append({
                            'type': 'string',
                            'name': str_sig.name,
                            'offset': offset,
                            'text': match_text,
                            'description': str_sig.description
                        })
        except Exception:
            pass  # Skip string matching if decoding fails
        
        # If no matches found, return None
        if total_matches == 0:
            return None
        
        # Calculate false positive score
        fp_score = self._calculate_false_positive_score(signature, all_matches, data)
        
        # Adjust confidence based on match count and quality
        adjusted_confidence = self._calculate_adjusted_confidence(
            base_confidence, total_matches, len(signature.binary_signatures + signature.string_signatures)
        )
        
        return MatchResult(
            signature_id=signature.id,
            signature_name=signature.name,
            protection_type=signature.protection_type,
            confidence=adjusted_confidence,
            match_count=total_matches,
            matches=all_matches,
            false_positive_score=fp_score,
            metadata=signature.metadata.copy()
        )
    
    def _calculate_false_positive_score(self, signature: ProtectionSignature, 
                                      matches: List[Dict[str, Any]], data: bytes) -> float:
        """Calculate false positive score for matches.
        
        Args:
            signature: Matched signature
            matches: List of matches found
            data: Binary data
            
        Returns:
            False positive score (0.0 to 1.0)
        """
        fp_score = 0.0
        
        # Check for known false positive patterns
        for match in matches:
            if match['type'] == 'string' and match.get('text'):
                match_text = match['text'].encode('utf-8', errors='ignore')
                if match_text in self.false_positive_patterns:
                    fp_score += 0.2
        
        # Check for common system strings
        common_system_strings = [
            "kernel32.dll", "ntdll.dll", "user32.dll", "advapi32.dll",
            "GetModuleHandle", "GetCurrentProcess", "ExitProcess"
        ]
        
        for match in matches:
            if match['type'] == 'string' and match.get('text'):
                if any(common in match['text'].lower() for common in common_system_strings):
                    fp_score += 0.1
        
        # Penalize matches in common sections
        for match in matches:
            offset = match.get('offset', 0)
            if self._is_in_common_section(offset, data):
                fp_score += 0.05
        
        return min(fp_score, self.max_false_positive_score)
    
    def _is_in_common_section(self, offset: int, data: bytes) -> bool:
        """Check if offset is in a common section that often has false positives.
        
        Args:
            offset: Byte offset in file
            data: Binary data
            
        Returns:
            True if in common section
        """
        # For PE files, check if in import table or resource section
        if len(data) > 64 and data[:2] == b'MZ':
            try:
                pe_offset = struct.unpack('<L', data[60:64])[0]
                if pe_offset + 96 < len(data):
                    # Get import table RVA
                    import_rva = struct.unpack('<L', data[pe_offset+128:pe_offset+132])[0]
                    if import_rva > 0:
                        # Simple heuristic - if offset is near import table area
                        if abs(offset - import_rva) < 1024:
                            return True
            except (struct.error, IndexError):
                pass
        
        return False
    
    def _calculate_adjusted_confidence(self, base_confidence: float, 
                                     match_count: int, total_signatures: int) -> float:
        """Calculate adjusted confidence based on match quality.
        
        Args:
            base_confidence: Base confidence from signature
            match_count: Number of matches found
            total_signatures: Total number of signatures in the protection
            
        Returns:
            Adjusted confidence score
        """
        if total_signatures == 0:
            return base_confidence
        
        # Calculate match ratio
        match_ratio = min(1.0, match_count / total_signatures)
        
        # Boost confidence for multiple matches
        match_boost = min(0.2, (match_count - 1) * 0.05)
        
        # Calculate final confidence
        adjusted = base_confidence * (0.7 + 0.3 * match_ratio) + match_boost
        
        return min(1.0, adjusted)
    
    def _apply_composite_scoring(self, matches: List[MatchResult]) -> List[MatchResult]:
        """Apply composite scoring to reduce false positives.
        
        Args:
            matches: List of initial matches
            
        Returns:
            List of matches with adjusted scores
        """
        # Group matches by protection type
        type_groups = {}
        for match in matches:
            prot_type = match.protection_type
            if prot_type not in type_groups:
                type_groups[prot_type] = []
            type_groups[prot_type].append(match)
        
        # Apply composite scoring within each group
        for prot_type, group_matches in type_groups.items():
            if len(group_matches) > 1:
                # Boost confidence if multiple signatures of same type match
                for match in group_matches:
                    boost = min(0.1, (len(group_matches) - 1) * 0.03)
                    match.confidence = min(1.0, match.confidence + boost)
        
        return matches
    
    def search_patterns(self, query: str, protection_type: Optional[ProtectionType] = None) -> List[ProtectionSignature]:
        """Search for patterns matching a query.
        
        Args:
            query: Search query
            protection_type: Optional filter by protection type
            
        Returns:
            List of matching signatures
        """
        return self.database.search_signatures(query, protection_type)
    
    def get_protection_info(self, protection_name: str) -> Optional[Dict[str, Any]]:
        """Get detailed information about a protection scheme.
        
        Args:
            protection_name: Name of protection scheme
            
        Returns:
            Protection information dictionary
        """
        matches = self.database.search_signatures(protection_name)
        if not matches:
            return None
        
        # Return info for the best match
        signature = matches[0]
        
        return {
            'id': signature.id,
            'name': signature.name,
            'version': signature.version,
            'type': signature.protection_type.value,
            'architecture': signature.architecture.value,
            'confidence': signature.confidence,
            'description': signature.description,
            'references': signature.references,
            'metadata': signature.metadata,
            'binary_signatures_count': len(signature.binary_signatures),
            'string_signatures_count': len(signature.string_signatures),
            'import_signatures_count': len(signature.import_signatures),
            'section_signatures_count': len(signature.section_signatures)
        }
    
    def validate_signature(self, signature: ProtectionSignature, test_files: List[str]) -> Dict[str, Any]:
        """Validate a signature against test files.
        
        Args:
            signature: Signature to validate
            test_files: List of test file paths
            
        Returns:
            Validation results
        """
        results = {
            'signature_id': signature.id,
            'test_files': len(test_files),
            'true_positives': 0,
            'false_positives': 0,
            'true_negatives': 0,
            'false_negatives': 0,
            'accuracy': 0.0,
            'precision': 0.0,
            'recall': 0.0,
            'f1_score': 0.0,
            'details': []
        }
        
        for file_path in test_files:
            try:
                with open(file_path, 'rb') as f:
                    data = f.read()
                
                match_result = self._match_signature(signature, data)
                detected = match_result is not None and match_result.adjusted_confidence > 0.5
                
                # For validation, we need ground truth labels
                # This is a simplified version - in practice you'd have labeled test data
                file_name = Path(file_path).name.lower()
                expected = signature.name.lower() in file_name
                
                if detected and expected:
                    results['true_positives'] += 1
                elif detected and not expected:
                    results['false_positives'] += 1
                elif not detected and not expected:
                    results['true_negatives'] += 1
                else:
                    results['false_negatives'] += 1
                
                results['details'].append({
                    'file': file_path,
                    'detected': detected,
                    'expected': expected,
                    'confidence': match_result.adjusted_confidence if match_result else 0.0
                })
                
            except Exception as e:
                self.logger.error(f"Error validating file {file_path}: {e}")
        
        # Calculate metrics
        tp = results['true_positives']
        fp = results['false_positives']
        tn = results['true_negatives']
        fn = results['false_negatives']
        
        total = tp + fp + tn + fn
        if total > 0:
            results['accuracy'] = (tp + tn) / total
        
        if tp + fp > 0:
            results['precision'] = tp / (tp + fp)
        
        if tp + fn > 0:
            results['recall'] = tp / (tp + fn)
        
        if results['precision'] + results['recall'] > 0:
            results['f1_score'] = 2 * (results['precision'] * results['recall']) / (results['precision'] + results['recall'])
        
        return results
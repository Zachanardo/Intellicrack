"""Protection signature database implementation.

This module provides the core database functionality for storing and managing
protection signatures, patterns, and metadata for various protection schemes.

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

import json
import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from datetime import datetime

import logging

logger = logging.getLogger(__name__)


class ProtectionType(Enum):
    """Types of protection schemes supported by the database."""
    PACKER = "packer"
    DRM = "drm" 
    LICENSING = "licensing"
    ANTI_DEBUG = "anti_debug"
    ANTI_VM = "anti_vm"
    OBFUSCATION = "obfuscation"
    CODE_PROTECTION = "code_protection"
    INTEGRITY_CHECK = "integrity_check"
    CUSTOM = "custom"


class ArchitectureType(Enum):
    """Supported architectures."""
    X86 = "x86"
    X64 = "x64"
    ARM = "arm"
    ARM64 = "arm64"
    MIPS = "mips"
    ANY = "any"


class MatchType(Enum):
    """Types of pattern matching."""
    EXACT = "exact"
    REGEX = "regex"
    FUZZY = "fuzzy"
    WILDCARDS = "wildcards"


@dataclass
class BinarySignature:
    """Binary signature pattern definition."""
    name: str
    pattern: bytes
    mask: Optional[bytes] = None
    offset: Optional[int] = None
    section: Optional[str] = None
    description: str = ""
    
    def matches(self, data: bytes, start_offset: int = 0) -> List[int]:
        """Find all matches of this signature in binary data."""
        matches = []
        
        if self.offset is not None:
            # Fixed offset match
            if start_offset + self.offset + len(self.pattern) <= len(data):
                target = data[start_offset + self.offset:start_offset + self.offset + len(self.pattern)]
                if self._compare_with_mask(target, self.pattern, self.mask):
                    matches.append(start_offset + self.offset)
        else:
            # Search through data
            search_data = data[start_offset:]
            for i in range(len(search_data) - len(self.pattern) + 1):
                target = search_data[i:i + len(self.pattern)]
                if self._compare_with_mask(target, self.pattern, self.mask):
                    matches.append(start_offset + i)
                    
        return matches
    
    def _compare_with_mask(self, data: bytes, pattern: bytes, mask: Optional[bytes]) -> bool:
        """Compare data with pattern using optional mask."""
        if len(data) != len(pattern):
            return False
            
        if mask is None:
            return data == pattern
            
        if len(mask) != len(pattern):
            return False
            
        for i in range(len(pattern)):
            if mask[i] != 0 and data[i] != pattern[i]:
                return False
        return True


@dataclass 
class StringSignature:
    """String-based signature pattern definition."""
    name: str
    pattern: str
    match_type: MatchType = MatchType.EXACT
    case_sensitive: bool = False
    encoding: str = "utf-8"
    description: str = ""
    
    def matches(self, text: str) -> List[Tuple[int, str]]:
        """Find all matches of this signature in text."""
        matches = []
        search_text = text if self.case_sensitive else text.lower()
        search_pattern = self.pattern if self.case_sensitive else self.pattern.lower()
        
        if self.match_type == MatchType.EXACT:
            start = 0
            while True:
                pos = search_text.find(search_pattern, start)
                if pos == -1:
                    break
                matches.append((pos, text[pos:pos + len(self.pattern)]))
                start = pos + 1
                
        elif self.match_type == MatchType.REGEX:
            flags = 0 if self.case_sensitive else re.IGNORECASE
            for match in re.finditer(search_pattern, text, flags):
                matches.append((match.start(), match.group()))
                
        elif self.match_type == MatchType.WILDCARDS:
            # Convert wildcards to regex
            regex_pattern = search_pattern.replace('*', '.*').replace('?', '.')
            flags = 0 if self.case_sensitive else re.IGNORECASE
            for match in re.finditer(regex_pattern, text, flags):
                matches.append((match.start(), match.group()))
                
        return matches


@dataclass
class ImportSignature:
    """Import table signature pattern definition."""
    name: str
    dll_name: Optional[str] = None
    function_names: List[str] = field(default_factory=list)
    min_functions: int = 1
    description: str = ""
    
    def matches(self, imports: Dict[str, List[str]]) -> bool:
        """Check if import table matches this signature."""
        if self.dll_name:
            if self.dll_name.lower() not in [dll.lower() for dll in imports.keys()]:
                return False
            dll_imports = imports.get(self.dll_name, [])
        else:
            # Check across all DLLs
            dll_imports = []
            for dll_funcs in imports.values():
                dll_imports.extend(dll_funcs)
        
        found_functions = 0
        for func_name in self.function_names:
            if func_name.lower() in [f.lower() for f in dll_imports]:
                found_functions += 1
                
        return found_functions >= self.min_functions


@dataclass
class SectionSignature:
    """PE/ELF section signature pattern definition."""
    name: str
    section_name: Optional[str] = None
    characteristics: Optional[int] = None
    min_entropy: Optional[float] = None
    max_entropy: Optional[float] = None
    min_size: Optional[int] = None
    max_size: Optional[int] = None
    description: str = ""
    
    def matches(self, section_info: Dict[str, Any]) -> bool:
        """Check if section matches this signature."""
        if self.section_name and section_info.get('name', '').lower() != self.section_name.lower():
            return False
            
        if self.characteristics and section_info.get('characteristics', 0) & self.characteristics == 0:
            return False
            
        entropy = section_info.get('entropy', 0.0)
        if self.min_entropy and entropy < self.min_entropy:
            return False
        if self.max_entropy and entropy > self.max_entropy:
            return False
            
        size = section_info.get('size', 0)
        if self.min_size and size < self.min_size:
            return False
        if self.max_size and size > self.max_size:
            return False
            
        return True


@dataclass
class ProtectionSignature:
    """Complete protection signature definition."""
    id: str
    name: str
    version: Optional[str] = None
    protection_type: ProtectionType = ProtectionType.CUSTOM
    architecture: ArchitectureType = ArchitectureType.ANY
    confidence: float = 0.8
    binary_signatures: List[BinarySignature] = field(default_factory=list)
    string_signatures: List[StringSignature] = field(default_factory=list)
    import_signatures: List[ImportSignature] = field(default_factory=list)
    section_signatures: List[SectionSignature] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    description: str = ""
    references: List[str] = field(default_factory=list)
    created_date: Optional[datetime] = None
    updated_date: Optional[datetime] = None
    
    def __post_init__(self):
        """Initialize default dates."""
        if self.created_date is None:
            self.created_date = datetime.now()
        if self.updated_date is None:
            self.updated_date = datetime.now()


class ProtectionSignatureDatabase:
    """Protection signature database management."""
    
    def __init__(self, database_path: Optional[Path] = None):
        """Initialize the protection signature database.
        
        Args:
            database_path: Optional path to database directory
        """
        self.logger = logging.getLogger(__name__)
        
        if database_path is None:
            database_path = Path(__file__).parent / "databases"
        
        self.database_path = Path(database_path)
        self.database_path.mkdir(parents=True, exist_ok=True)
        
        self.signatures: Dict[str, ProtectionSignature] = {}
        self.signature_index: Dict[ProtectionType, List[str]] = {}
        self.loaded = False
        
        # Initialize database structure
        self._initialize_database_structure()
    
    def _initialize_database_structure(self):
        """Initialize the database directory structure."""
        subdirs = [
            "packers",
            "drm",
            "licensing", 
            "anti_debug",
            "anti_vm",
            "obfuscation",
            "code_protection",
            "integrity_check",
            "custom"
        ]
        
        for subdir in subdirs:
            (self.database_path / subdir).mkdir(exist_ok=True)
    
    def load_database(self) -> bool:
        """Load all signatures from database files.
        
        Returns:
            True if database loaded successfully
        """
        try:
            self.signatures.clear()
            self.signature_index.clear()
            
            # Load signatures from all subdirectories
            for signature_file in self.database_path.rglob("*.json"):
                if signature_file.is_file():
                    self._load_signature_file(signature_file)
            
            # Build index
            self._build_signature_index()
            
            self.loaded = True
            self.logger.info(f"Loaded {len(self.signatures)} protection signatures")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to load protection database: {e}")
            return False
    
    def _load_signature_file(self, file_path: Path):
        """Load signatures from a single JSON file."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            if 'signatures' in data:
                # Multiple signatures file
                for sig_data in data['signatures']:
                    signature = self._parse_signature(sig_data)
                    if signature:
                        self.signatures[signature.id] = signature
            else:
                # Single signature file
                signature = self._parse_signature(data)
                if signature:
                    self.signatures[signature.id] = signature
                    
        except Exception as e:
            self.logger.error(f"Failed to load signature file {file_path}: {e}")
    
    def _parse_signature(self, data: Dict[str, Any]) -> Optional[ProtectionSignature]:
        """Parse signature data from dictionary."""
        try:
            # Parse binary signatures
            binary_sigs = []
            for bin_sig in data.get('binary_signatures', []):
                pattern = bytes.fromhex(bin_sig['pattern'])
                mask = bytes.fromhex(bin_sig['mask']) if bin_sig.get('mask') else None
                binary_sigs.append(BinarySignature(
                    name=bin_sig['name'],
                    pattern=pattern,
                    mask=mask,
                    offset=bin_sig.get('offset'),
                    section=bin_sig.get('section'),
                    description=bin_sig.get('description', '')
                ))
            
            # Parse string signatures
            string_sigs = []
            for str_sig in data.get('string_signatures', []):
                string_sigs.append(StringSignature(
                    name=str_sig['name'],
                    pattern=str_sig['pattern'],
                    match_type=MatchType(str_sig.get('match_type', 'exact')),
                    case_sensitive=str_sig.get('case_sensitive', False),
                    encoding=str_sig.get('encoding', 'utf-8'),
                    description=str_sig.get('description', '')
                ))
            
            # Parse import signatures  
            import_sigs = []
            for imp_sig in data.get('import_signatures', []):
                import_sigs.append(ImportSignature(
                    name=imp_sig['name'],
                    dll_name=imp_sig.get('dll_name'),
                    function_names=imp_sig.get('function_names', []),
                    min_functions=imp_sig.get('min_functions', 1),
                    description=imp_sig.get('description', '')
                ))
            
            # Parse section signatures
            section_sigs = []
            for sec_sig in data.get('section_signatures', []):
                section_sigs.append(SectionSignature(
                    name=sec_sig['name'],
                    section_name=sec_sig.get('section_name'),
                    characteristics=sec_sig.get('characteristics'),
                    min_entropy=sec_sig.get('min_entropy'),
                    max_entropy=sec_sig.get('max_entropy'),
                    min_size=sec_sig.get('min_size'),
                    max_size=sec_sig.get('max_size'),
                    description=sec_sig.get('description', '')
                ))
            
            # Parse dates
            created_date = None
            if data.get('created_date'):
                created_date = datetime.fromisoformat(data['created_date'])
            
            updated_date = None  
            if data.get('updated_date'):
                updated_date = datetime.fromisoformat(data['updated_date'])
            
            return ProtectionSignature(
                id=data['id'],
                name=data['name'],
                version=data.get('version'),
                protection_type=ProtectionType(data.get('protection_type', 'custom')),
                architecture=ArchitectureType(data.get('architecture', 'any')),
                confidence=data.get('confidence', 0.8),
                binary_signatures=binary_sigs,
                string_signatures=string_sigs,
                import_signatures=import_sigs,
                section_signatures=section_sigs,
                metadata=data.get('metadata', {}),
                description=data.get('description', ''),
                references=data.get('references', []),
                created_date=created_date,
                updated_date=updated_date
            )
            
        except Exception as e:
            self.logger.error(f"Failed to parse signature: {e}")
            return None
    
    def _build_signature_index(self):
        """Build signature index for efficient lookups."""
        for protection_type in ProtectionType:
            self.signature_index[protection_type] = []
        
        for sig_id, signature in self.signatures.items():
            self.signature_index[signature.protection_type].append(sig_id)
    
    def get_signatures_by_type(self, protection_type: ProtectionType) -> List[ProtectionSignature]:
        """Get all signatures of a specific protection type.
        
        Args:
            protection_type: Type of protection to get signatures for
            
        Returns:
            List of matching signatures
        """
        if not self.loaded:
            self.load_database()
        
        sig_ids = self.signature_index.get(protection_type, [])
        return [self.signatures[sig_id] for sig_id in sig_ids]
    
    def get_signature_by_id(self, signature_id: str) -> Optional[ProtectionSignature]:
        """Get signature by ID.
        
        Args:
            signature_id: Unique signature identifier
            
        Returns:
            Signature if found, None otherwise
        """
        if not self.loaded:
            self.load_database()
        
        return self.signatures.get(signature_id)
    
    def search_signatures(self, query: str, protection_type: Optional[ProtectionType] = None) -> List[ProtectionSignature]:
        """Search signatures by name or description.
        
        Args:
            query: Search query string
            protection_type: Optional filter by protection type
            
        Returns:
            List of matching signatures
        """
        if not self.loaded:
            self.load_database()
        
        results = []
        query_lower = query.lower()
        
        for signature in self.signatures.values():
            if protection_type and signature.protection_type != protection_type:
                continue
                
            if (query_lower in signature.name.lower() or 
                query_lower in signature.description.lower()):
                results.append(signature)
        
        return results
    
    def add_signature(self, signature: ProtectionSignature) -> bool:
        """Add a new signature to the database.
        
        Args:
            signature: Signature to add
            
        Returns:
            True if signature added successfully
        """
        try:
            self.signatures[signature.id] = signature
            
            # Update index
            if signature.protection_type not in self.signature_index:
                self.signature_index[signature.protection_type] = []
            if signature.id not in self.signature_index[signature.protection_type]:
                self.signature_index[signature.protection_type].append(signature.id)
            
            # Save to file
            self._save_signature(signature)
            
            self.logger.info(f"Added signature: {signature.name}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to add signature {signature.id}: {e}")
            return False
    
    def _save_signature(self, signature: ProtectionSignature):
        """Save signature to database file."""
        subdir = signature.protection_type.value
        file_path = self.database_path / subdir / f"{signature.id}.json"
        
        # Convert signature to dictionary
        data = {
            'id': signature.id,
            'name': signature.name,
            'version': signature.version,
            'protection_type': signature.protection_type.value,
            'architecture': signature.architecture.value,
            'confidence': signature.confidence,
            'description': signature.description,
            'references': signature.references,
            'metadata': signature.metadata,
            'created_date': signature.created_date.isoformat() if signature.created_date else None,
            'updated_date': signature.updated_date.isoformat() if signature.updated_date else None,
            'binary_signatures': [],
            'string_signatures': [],
            'import_signatures': [],
            'section_signatures': []
        }
        
        # Convert binary signatures
        for bin_sig in signature.binary_signatures:
            sig_data = {
                'name': bin_sig.name,
                'pattern': bin_sig.pattern.hex(),
                'description': bin_sig.description
            }
            if bin_sig.mask:
                sig_data['mask'] = bin_sig.mask.hex()
            if bin_sig.offset is not None:
                sig_data['offset'] = bin_sig.offset
            if bin_sig.section:
                sig_data['section'] = bin_sig.section
            data['binary_signatures'].append(sig_data)
        
        # Convert string signatures
        for str_sig in signature.string_signatures:
            data['string_signatures'].append({
                'name': str_sig.name,
                'pattern': str_sig.pattern,
                'match_type': str_sig.match_type.value,
                'case_sensitive': str_sig.case_sensitive,
                'encoding': str_sig.encoding,
                'description': str_sig.description
            })
        
        # Convert import signatures
        for imp_sig in signature.import_signatures:
            sig_data = {
                'name': imp_sig.name,
                'function_names': imp_sig.function_names,
                'min_functions': imp_sig.min_functions,
                'description': imp_sig.description
            }
            if imp_sig.dll_name:
                sig_data['dll_name'] = imp_sig.dll_name
            data['import_signatures'].append(sig_data)
        
        # Convert section signatures
        for sec_sig in signature.section_signatures:
            sig_data = {
                'name': sec_sig.name,
                'description': sec_sig.description
            }
            if sec_sig.section_name:
                sig_data['section_name'] = sec_sig.section_name
            if sec_sig.characteristics is not None:
                sig_data['characteristics'] = sec_sig.characteristics
            if sec_sig.min_entropy is not None:
                sig_data['min_entropy'] = sec_sig.min_entropy
            if sec_sig.max_entropy is not None:
                sig_data['max_entropy'] = sec_sig.max_entropy
            if sec_sig.min_size is not None:
                sig_data['min_size'] = sec_sig.min_size
            if sec_sig.max_size is not None:
                sig_data['max_size'] = sec_sig.max_size
            data['section_signatures'].append(sig_data)
        
        # Write to file
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get database statistics.
        
        Returns:
            Dictionary containing database statistics
        """
        if not self.loaded:
            self.load_database()
        
        stats = {
            'total_signatures': len(self.signatures),
            'by_type': {},
            'by_architecture': {},
            'average_confidence': 0.0
        }
        
        # Count by type
        for protection_type in ProtectionType:
            count = len(self.signature_index.get(protection_type, []))
            stats['by_type'][protection_type.value] = count
        
        # Count by architecture
        arch_counts = {}
        total_confidence = 0.0
        
        for signature in self.signatures.values():
            arch = signature.architecture.value
            arch_counts[arch] = arch_counts.get(arch, 0) + 1
            total_confidence += signature.confidence
        
        stats['by_architecture'] = arch_counts
        
        if self.signatures:
            stats['average_confidence'] = total_confidence / len(self.signatures)
        
        return stats
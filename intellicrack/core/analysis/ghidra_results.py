"""Ghidra Analysis Results Storage.

This module provides structured storage for Ghidra analysis results.

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

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Optional


@dataclass
class GhidraAnalysisResult:
    """Structured storage for Ghidra analysis results.

    This dataclass provides a production-ready container for all data
    extracted from Ghidra headless analysis, including functions, strings,
    imports, and cross-references.
    """

    functions: List[Dict] = field(default_factory=list)
    strings: List[Dict] = field(default_factory=list)
    imports: List[Dict] = field(default_factory=list)
    cross_references: List[Dict] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)
    binary_path: str = ""

    # Additional metadata fields
    analysis_time: float = 0.0  # Time taken for analysis in seconds
    ghidra_version: str = ""
    script_used: str = ""
    total_size: int = 0  # Binary size in bytes
    architecture: str = ""
    file_format: str = ""  # PE, ELF, Mach-O, etc.

    def __post_init__(self):
        """Validate and process data after initialization."""
        # Ensure all lists are properly initialized
        if self.functions is None:
            self.functions = []
        if self.strings is None:
            self.strings = []
        if self.imports is None:
            self.imports = []
        if self.cross_references is None:
            self.cross_references = []

    def get_function_by_name(self, name: str) -> Optional[Dict]:
        """Find a function by its name.

        Args:
            name: Function name to search for

        Returns:
            Function dict if found, None otherwise
        """
        for func in self.functions:
            if func.get('name') == name:
                return func
        return None

    def get_function_by_address(self, address: int) -> Optional[Dict]:
        """Find a function by its address.

        Args:
            address: Function address to search for

        Returns:
            Function dict if found, None otherwise
        """
        for func in self.functions:
            if func.get('address') == address:
                return func
        return None

    def get_imports_by_library(self, library: str) -> List[Dict]:
        """Get all imports from a specific library.

        Args:
            library: Library name (e.g., 'kernel32.dll')

        Returns:
            List of import dicts from the specified library
        """
        return [imp for imp in self.imports if imp.get('library') == library]

    def get_xrefs_to_address(self, address: int) -> List[Dict]:
        """Get all cross-references pointing to a specific address.

        Args:
            address: Target address

        Returns:
            List of xref dicts pointing to the address
        """
        return [xref for xref in self.cross_references if xref.get('to_addr') == address]

    def get_xrefs_from_address(self, address: int) -> List[Dict]:
        """Get all cross-references originating from a specific address.

        Args:
            address: Source address

        Returns:
            List of xref dicts originating from the address
        """
        return [xref for xref in self.cross_references if xref.get('from_addr') == address]

    def get_strings_in_range(self, start_addr: int, end_addr: int) -> List[Dict]:
        """Get all strings within an address range.

        Args:
            start_addr: Start of address range
            end_addr: End of address range

        Returns:
            List of string dicts within the range
        """
        return [s for s in self.strings
                if start_addr <= s.get('address', 0) <= end_addr]

    def get_statistics(self) -> Dict:
        """Get analysis statistics.

        Returns:
            Dictionary containing analysis statistics
        """
        return {
            'total_functions': len(self.functions),
            'total_strings': len(self.strings),
            'total_imports': len(self.imports),
            'total_xrefs': len(self.cross_references),
            'unique_libraries': len(set(imp.get('library', '') for imp in self.imports)),
            'analysis_timestamp': self.timestamp.isoformat(),
            'binary_path': self.binary_path,
            'architecture': self.architecture,
            'file_format': self.file_format,
            'analysis_time_seconds': self.analysis_time
        }

    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization.

        Returns:
            Dictionary representation of the analysis results
        """
        return {
            'functions': self.functions,
            'strings': self.strings,
            'imports': self.imports,
            'cross_references': self.cross_references,
            'timestamp': self.timestamp.isoformat(),
            'binary_path': self.binary_path,
            'analysis_time': self.analysis_time,
            'ghidra_version': self.ghidra_version,
            'script_used': self.script_used,
            'total_size': self.total_size,
            'architecture': self.architecture,
            'file_format': self.file_format
        }

    @classmethod
    def from_dict(cls, data: Dict) -> 'GhidraAnalysisResult':
        """Create instance from dictionary.

        Args:
            data: Dictionary containing analysis data

        Returns:
            GhidraAnalysisResult instance
        """
        # Parse timestamp if it's a string
        timestamp = data.get('timestamp', datetime.now())
        if isinstance(timestamp, str):
            timestamp = datetime.fromisoformat(timestamp)

        return cls(
            functions=data.get('functions', []),
            strings=data.get('strings', []),
            imports=data.get('imports', []),
            cross_references=data.get('cross_references', []),
            timestamp=timestamp,
            binary_path=data.get('binary_path', ''),
            analysis_time=data.get('analysis_time', 0.0),
            ghidra_version=data.get('ghidra_version', ''),
            script_used=data.get('script_used', ''),
            total_size=data.get('total_size', 0),
            architecture=data.get('architecture', ''),
            file_format=data.get('file_format', '')
        )